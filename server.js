import http from 'node:http';
import https from 'node:https';
import { selfSignedCertificate } from './lib/selfsigned.js';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Store } from './lib/store.js';
import { Auth } from './lib/auth.js';
import { Sso } from './lib/sso.js';
import { scopeFor, pathDomain, siteScopedPath, scopeDomains } from './lib/access-scope.js';
import { remoteAccessConfig, RemoteAccessGate } from './lib/remote-access.js';
import { SecretStore } from './lib/secret-store.js';
import { TenantPolicy } from './lib/tenancy.js';
import { Domain } from './lib/domain.js';
import { localObservation } from './lib/local-collector.js';
import { normalizeWindowsExport } from './lib/windows-events.js';
import { toAr } from './lib/i18n-ar.js';
import { AppError, fail, equal, object, page, token, MAX_INGEST_BYTES } from './lib/common.js';
import { validateCloudResult } from './lib/ai-model-policy.js';

const ROOT=fileURLToPath(new URL('./',import.meta.url));
const MIME={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.webmanifest':'application/manifest+json; charset=utf-8'};
const FETCH_BLOCKED_PORTS=new Set([1,7,9,11,13,15,17,19,20,21,22,23,25,37,42,43,53,69,77,79,87,95,101,102,103,104,109,110,111,113,115,117,119,123,135,137,139,143,161,179,389,427,465,512,513,514,515,526,530,531,532,540,548,554,556,563,587,601,636,989,990,993,995,1719,1720,1723,2049,3659,4045,4190,5060,5061,6000,6566,6665,6666,6667,6668,6669,6679,6697,10080]);
const STATIC=new Set(['/','/app.js','/dashboard.js','/styles.css','/soc.css','/icon.svg','/manifest.webmanifest']);
const COOKIE='Path=/; HttpOnly; SameSite=Strict';
const OPERATING_MODES=['pc-local','enterprise-collectors','authorized-defense-validation-lab'];
const readJson=p=>JSON.parse(fs.readFileSync(path.join(ROOT,p),'utf8'));
const trace=()=>fs.readFileSync(path.join(ROOT,'docs/engineering/TRACEABILITY.jsonl'),'utf8').trim().split('\n').map(JSON.parse);

async function body(req) {
  fail(String(req.headers['content-type']||'').split(';')[0].trim()==='application/json',415,'json_content_type_required');
  const chunks=[]; let size=0;
  for await (const chunk of req) { size+=chunk.length; fail(size<=MAX_INGEST_BYTES,413,'request_too_large'); chunks.push(chunk); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new AppError(400,'invalid_json'); }
}
function send(res,status,value) { res.writeHead(status,{'Content-Type':'application/json; charset=utf-8'}); res.end(JSON.stringify(value)); }

export function createApp({dataDir=process.env.CG_DATA_DIR||path.join(ROOT,'data'),clock,setupToken,browserQa=process.env.CG_BROWSER_QA==='1',mode=process.env.CG_MODE||'pc-local',labAuthorizationRef=process.env.CG_LAB_AUTHORIZATION_REF||null,cloudAiInvoke=null,tls=process.env.CG_TLS_CERT&&process.env.CG_TLS_KEY?{certFile:process.env.CG_TLS_CERT,keyFile:process.env.CG_TLS_KEY}:process.env.CG_TLS==='self-signed'?'self-signed':null,tenant=process.env.CG_TENANT||'default',remoteAccess=process.env,clientCa=process.env.CG_TLS_CLIENT_CA?fs.readFileSync(process.env.CG_TLS_CLIENT_CA,'utf8'):null,jwksFetcher=null}={}) {
  fail(OPERATING_MODES.includes(mode),400,'invalid_operating_mode');
  // CG-052 HTTPS: an operator certificate (CG_TLS_CERT/CG_TLS_KEY) or a self-signed one kept in the data directory.
  let tlsMaterial=null;
  if(tls==='self-signed'){const dir=path.join(dataDir,'tls'),certFile=path.join(dir,'cert.pem'),keyFile=path.join(dir,'key.pem');fs.mkdirSync(dir,{recursive:true});if(!fs.existsSync(certFile)||!fs.existsSync(keyFile)){const c=selfSignedCertificate();fs.writeFileSync(keyFile,c.key,{mode:0o600});fs.writeFileSync(certFile,c.cert);}tlsMaterial={cert:fs.readFileSync(certFile,'utf8'),key:fs.readFileSync(keyFile,'utf8')};}
  else if(tls&&typeof tls==='object')tlsMaterial=tls.cert&&tls.key?{cert:tls.cert,key:tls.key}:{cert:fs.readFileSync(tls.certFile,'utf8'),key:fs.readFileSync(tls.keyFile,'utf8')};
  // CG-053 remote access: loopback, Zero Trust gateway or VPN (with optional device certificates).
  const accessConfig=remoteAccessConfig(remoteAccess,{tls:Boolean(tlsMaterial),clientCa:Boolean(clientCa&&tlsMaterial)}),gate=new RemoteAccessGate(accessConfig,{fetchJwks:jwksFetcher});
  const secureFor=req=>Boolean(tlsMaterial)||req.cgAccess?.via==='ztna',cookieFor=req=>secureFor(req)?`${COOKIE}; Secure`:COOKIE;
  fail(mode!=='authorized-defense-validation-lab'||(browserQa&&typeof labAuthorizationRef==='string'&&labAuthorizationRef.trim().length>=8),400,'lab_authorization_required');
  fs.mkdirSync(dataDir,{recursive:true,mode:0o700});
  const dbFile=path.join(dataDir,'cyberguard.sqlite'),store=new Store(dbFile);
  const auth=new Auth(store,{clock}), domain=new Domain(store,{clock}), sso=new Sso(store,auth,{clock,tenant}), secrets=new SecretStore(store,{clock}), tenancy=new TenantPolicy(store,{clock,tenant,dbFile,domain}); domain.tenantGuard=tenancy;
  const setupFile=path.join(dataDir,'setup-token');
  let bootstrap=setupToken;
  if (!store.get('SELECT id FROM users LIMIT 1') && !bootstrap) {
    bootstrap=fs.existsSync(setupFile)?fs.readFileSync(setupFile,'utf8').trim():token();
    if (!fs.existsSync(setupFile)) fs.writeFileSync(setupFile,bootstrap,{mode:0o600,flag:'wx'});
  }
  const requirements=trace(), coverage=readJson('docs/engineering/COVERAGE.json');
  function ingestInput(actor,source,input){
    if(input?.schema_version==='cg.windows-export/1'){const parsed=normalizeWindowsExport(input,clock?clock():Date.now());return {...domain.ingest(actor,source,parsed.batch),parser_report:parsed.report};}
    return domain.ingest(actor,source,input);
  }
  let monitorError=false;
  const rates=new Map();
  function rate(req) {
    const now=Date.now(), key=req.socket.remoteAddress||'unknown';
    for(const [k,v] of rates) if(v.until<=now) rates.delete(k);
    const r=rates.get(key)||{n:0,until:now+60000}; r.n++; rates.set(key,r);
    fail(r.n<=600,429,'request_rate_limit');
  }
  const handler=async(req,res)=>{
    let authenticatedActor=null;
    res.setHeader('Cache-Control','no-store');
    if(tlsMaterial)res.setHeader('Strict-Transport-Security','max-age=31536000');
    res.setHeader('X-Content-Type-Options','nosniff');
    res.setHeader('Referrer-Policy','no-referrer');
    res.setHeader('X-Frame-Options','DENY');
    res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy',`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; manifest-src 'self'; form-action 'self'; frame-ancestors ${browserQa?"'self'":"'none'"}`);
    try {
      const port=server.address()?.port;
      req.cgAccess=await gate.check(req,port);
      rate(req);
      const url=new URL(req.url,`http://${req.headers.host}`), p=url.pathname, method=req.method;
      fail(['GET','POST'].includes(method),405,'method_not_allowed');
      const mutation=!['GET','HEAD'].includes(method);
      const bearer=String(req.headers.authorization||'').startsWith('Bearer ')?String(req.headers.authorization).slice(7):null;
      const ingest=p.match(/^\/api\/sources\/([a-f0-9-]{36})\/events$/);
      const responseJobs=p.match(/^\/api\/sources\/([a-f0-9-]{36})\/response-jobs$/);
      const responseResult=p.match(/^\/api\/sources\/([a-f0-9-]{36})\/response-jobs\/([a-f0-9-]{36})\/result$/);
      const secretRelease=p.match(/^\/api\/sources\/([a-f0-9-]{36})\/secrets\/([a-z0-9._-]{3,100})$/);
      if(mutation) {
        fail(method==='POST',405,'method_not_allowed');
        if (!(bearer&&(ingest||responseResult||secretRelease))) fail(req.headers.origin===`${secureFor(req)?'https':'http'}://${req.headers.host}`,403,'origin_not_allowed');
      }
      if(method==='GET' && STATIC.has(p)) {
        const file=path.join(ROOT,'public',p==='/'?'index.html':p.slice(1));
        res.writeHead(200,{'Content-Type':MIME[path.extname(file)]}); res.end(fs.readFileSync(file)); return;
      }
      if(method==='GET'&&p==='/qa/responsive'&&browserQa) {
        res.setHeader('Content-Security-Policy',"default-src 'none'; frame-src 'self'; base-uri 'none'; frame-ancestors 'none'");
        res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});res.end(fs.readFileSync(path.join(ROOT,'public','responsive-qa.html')));return;
      }
      if(p==='/api/health'&&method==='GET') return send(res,monitorError?503:200,{status:monitorError?'health-monitor-failed':'running',stage:'engineering-preview',version:'0.1.0',network_access:'loopback-only',operating_mode:mode});
      if(p==='/api/setup/status'&&method==='GET') return send(res,200,{setup_required:!store.get('SELECT id FROM users LIMIT 1')});
      if(p==='/api/auth/setup'&&method==='POST') {
        auth.limit(req.socket.remoteAddress||'setup');
        fail(!store.get('SELECT id FROM users LIMIT 1'),409,'setup_complete');
        const input=object(await body(req),['setup_token','username','password'],'setup');
        fail(typeof input.setup_token==='string'&&bootstrap&&equal(input.setup_token,bootstrap),403,'invalid_setup_token');
        const user=await auth.createUser('setup',{username:input.username,password:input.password,role:'admin'},true);
        bootstrap=null; if(fs.existsSync(setupFile)) fs.unlinkSync(setupFile);
        return send(res,201,{user});
      }
      if(p==='/api/auth/login'&&method==='POST') {
        const input=object(await body(req),['username','password','mfa_code'],'login');
        const session=await auth.login(input,req.socket.remoteAddress||'unknown');
        res.setHeader('Set-Cookie',`cg_session=${session.token}; ${cookieFor(req)}; Max-Age=28800`);store.audit(session.user.id,'access.path','session',{via:req.cgAccess.via,identity:req.cgAccess.identity,device:req.cgAccess.device});
        return send(res,200,{user:session.user,csrf:session.csrf});
      }
      if(bearer && ingest && method==='POST') {
        const source=domain.sourceToken(bearer,ingest[1]);
        const result=ingestInput(`source:${source.id}`,source.id,await body(req));
        // CG-060 store-and-forward senders report their queue with each batch.
        if(req.headers['x-cg-queue-depth']!==undefined)result.delivery=domain.recordDelivery(source.id,{depth:Number(req.headers['x-cg-queue-depth']),oldest:String(req.headers['x-cg-oldest-queued-at']||'')||null,attempt:Number(req.headers['x-cg-delivery-attempt']||1)});
        return send(res,200,result);
      }
      if(bearer && responseJobs && method==='GET') {
        const source=domain.sourceToken(bearer,responseJobs[1]);
        return send(res,200,domain.responseJobs(source.id));
      }
      // CG-055 a delegated connector source fetches a secret with its own token, for a stated purpose (audited).
      if(bearer && secretRelease && method==='POST') { const source=domain.sourceToken(bearer,secretRelease[1]); const input=object(await body(req),['purpose'],'secret_release'); return send(res,200,secrets.release(source.id,secretRelease[2],input.purpose)); }
      if(bearer && responseResult && method==='POST') {
        const source=domain.sourceToken(bearer,responseResult[1]);
        return send(res,200,domain.completeResponseJob(source.id,responseResult[2],await body(req)));
      }
      // CG-052 SSO: the login start and the provider callback are reachable before a session exists.
      if(p==='/api/sso/status'&&method==='GET') return send(res,200,sso.publicStatus());
      if(p==='/api/sso/start'&&method==='GET') { const location=sso.start(`${secureFor(req)?'https':'http'}://${req.headers.host}/api/sso/callback`); res.writeHead(302,{Location:location}); res.end(); return; }
      if(p==='/api/sso/callback'&&method==='GET') {
        try { const session=await sso.callback({code:url.searchParams.get('code'),state:url.searchParams.get('state'),error:url.searchParams.get('error')}); res.writeHead(302,{Location:'/','Set-Cookie':`cg_session=${session.token}; ${cookieFor(req)}; Max-Age=28800`}); }
        catch(e) { res.writeHead(302,{Location:`/#sso_error=${encodeURIComponent(e.code||'sso_failed')}`}); }
        res.end(); return;
      }
      const user=auth.session(req.headers.cookie);
      authenticatedActor=user.id;
      // CG-052 ABAC: tenant, functional domain and site scope on top of the role.
      const scope=scopeFor(store,user.id,tenant);user.scope=scope;
      fail(scope.tenant===tenant,403,'tenant_scope_mismatch');
      const area=pathDomain(p);fail(!area||scope.domains.includes('*')||scope.domains.includes(area),403,'domain_out_of_scope');
      const allowedAssets=scope.restricted?domain.assetIdsForSites(scope.sites):null;
      if(allowedAssets){
        fail(siteScopedPath(p),403,'outside_site_scope');
        const allowed=new Set(allowedAssets),inScope=ids=>ids.length>0&&ids.every(id=>id&&allowed.has(id)),detail=p.match(/^\/api\/(alerts|events|assets|cases|actions|ai-analysis|ai-action-proposals|playbook-runs)\/([0-9a-f-]{36})/);
        if(detail)fail(inScope(domain.resourceAssetIds(detail[1],detail[2])),404,'not_found');
        if(method==='POST'&&['/api/actions/preview','/api/cases','/api/playbook-runs'].includes(p)){const input=await body(req);const ids=p==='/api/cases'?(Array.isArray(input?.alert_ids)?input.alert_ids.flatMap(a=>domain.resourceAssetIds('alerts',String(a))):[null]):p==='/api/playbook-runs'?domain.resourceAssetIds('alerts',String(input?.alert_id||'')):[input?.asset_id||null];fail(inScope(ids),403,'outside_site_scope');}
      }
      if(mutation) fail(equal(req.headers['x-csrf-token']||'',user.csrf),403,'csrf_required');
      const roles=(allowed)=>auth.require(user,allowed);
      if(mutation&&(user.jit||user.break_glass)&&!p.startsWith('/api/jit')&&!p.startsWith('/api/break-glass')&&!p.startsWith('/api/auth/mfa')&&p!=='/api/auth/logout') auth.recordPrivilegedUse(user,p);
      if(p==='/api/auth/mfa'&&method==='GET') return send(res,200,auth.mfaStatus(user));
      if(p==='/api/auth/mfa/enroll'&&method==='POST') return send(res,201,auth.enrollMfa(user));
      if(p==='/api/auth/mfa/confirm'&&method==='POST'){const input=object(await body(req),['code'],'mfa_confirmation');return send(res,200,auth.confirmMfa(user,input.code));}
      if(p==='/api/auth/mfa/verify'&&method==='POST'){const input=object(await body(req),['code'],'mfa_verification');return send(res,200,auth.verifyMfa(user,input.code));}
      if(p==='/api/break-glass'&&method==='GET') return send(res,200,auth.listBreakGlass(user));
      if(p==='/api/break-glass'&&method==='POST') return send(res,201,auth.requestBreakGlass(user,await body(req)));
      const breakGlassAction=p.match(/^\/api\/break-glass\/([0-9a-f-]{36})\/(approve|deny|revoke)$/);
      if(breakGlassAction&&method==='POST'){if(breakGlassAction[2]==='revoke')return send(res,200,auth.revokeBreakGlass(user,breakGlassAction[1]));return send(res,200,auth.decideBreakGlass(user,breakGlassAction[1],breakGlassAction[2]));}
      if(p==='/api/jit'&&method==='GET') return send(res,200,auth.listJit(user));
      if(p==='/api/jit'&&method==='POST') return send(res,201,auth.requestJit(user,await body(req)));
      const jitAction=p.match(/^\/api\/jit\/([0-9a-f-]{36})\/(approve|deny|revoke)$/);
      if(jitAction&&method==='POST'){const input=await body(req);if(jitAction[2]==='revoke')return send(res,200,auth.revokeJit(user,jitAction[1]));return send(res,200,auth.decideJit(user,jitAction[1],jitAction[2],typeof input?.note==='string'?input.note.slice(0,300):null));}
      if(p==='/api/secrets'&&method==='GET'){auth.require(user,['admin']);return send(res,200,{items:secrets.list(),claim:'Connector secrets are encrypted with a per-secret data key wrapped by a store key that never leaves the data directory. Values are write-only: users see metadata only, and a value is released only to a delegated connector source, for a stated purpose, with an audit record. Each secret has a rotation period; overdue secrets raise CG-SECRET-ROTATION-055.',claim_ar:'أسرار الموصلات مشفرة بمفتاح بيانات لكل سر، ومفتاح البيانات مغلف بمفتاح مخزن لا يغادر مجلد البيانات. القيم للكتابة فقط: يرى المستخدمون البيانات الوصفية فقط، ولا تُسلَّم القيمة إلا لمصدر موصل مفوض، لغرض مذكور، مع سجل تدقيق. لكل سر مدة تدوير، والأسرار المتأخرة ترفع CG-SECRET-ROTATION-055.'});}
      if(p==='/api/secrets'&&method==='POST'){auth.require(user,['admin']);auth.requireRecentMfa(user);fail(!scope.restricted&&scope.domains.includes('*'),403,'secret_admin_requires_full_scope');return send(res,201,secrets.put(user,object(await body(req),['ref','kind','value','purpose','rotation_days','delegated_sources'],'secret')));}
      const secretRevoke=p.match(/^\/api\/secrets\/([a-z0-9._-]{3,100})\/revoke$/);if(secretRevoke&&method==='POST'){auth.require(user,['admin']);auth.requireRecentMfa(user);return send(res,200,secrets.revoke(user,secretRevoke[1]));}
      if(p==='/api/tenant-policy'&&method==='GET'){auth.require(user,['admin']);return send(res,200,tenancy.status());}
      if(p==='/api/tenant-policy'&&method==='POST'){auth.require(user,['admin']);auth.requireRecentMfa(user);fail(!scope.restricted&&scope.domains.includes('*'),403,'tenant_policy_requires_full_scope');return send(res,200,tenancy.set(user.id,await body(req)));}
      if(p==='/api/tenant-policy/retention'&&method==='POST'){auth.require(user,['admin']);auth.requireRecentMfa(user);return send(res,200,tenancy.applyRetention(user.id));}
      if(p==='/api/remote-access'&&method==='GET') return send(res,200,{...gate.summary(),this_request:req.cgAccess,claim:'CyberGuard is reachable from this machine, through a Zero Trust gateway that signs every request with an access assertion (and, when required, a device posture claim), or over a VPN with TLS from the VPN address pools and, when a device CA is set, only from devices holding a certificate it issued. Direct exposure on other addresses is refused.',claim_ar:'يمكن الوصول إلى CyberGuard من هذا الجهاز، أو عبر بوابة Zero Trust توقّع كل طلب بتأكيد وصول (ومطالبة بحالة الجهاز عند اشتراطها)، أو عبر VPN مع TLS من نطاقات عناوين الـVPN، وعند ضبط جهة إصدار للأجهزة لا يُقبل إلا جهاز يحمل شهادة صادرة منها. ويُرفض التعريض المباشر على عناوين أخرى.'});
      if(p==='/api/scoped-overview'&&method==='GET') return send(res,200,domain.scopedOverview(allowedAssets||domain.list('assets',{limit:100000}).items.map(a=>a.id),scope.sites));
      if(p==='/api/user-scopes'&&method==='GET'){auth.require(user,['admin']);return send(res,200,{items:store.all('SELECT s.*,u.username FROM user_scopes s JOIN users u ON u.id=s.user_id ORDER BY u.username').map(r=>({...r,sites:JSON.parse(r.sites),domains:JSON.parse(r.domains)})),tenant,domains:scopeDomains});}
      if(p==='/api/user-scopes'&&method==='POST'){auth.require(user,['admin']);auth.requireRecentMfa(user);fail(!scope.restricted&&scope.domains.includes('*'),403,'scope_admin_requires_full_scope');const input=object(await body(req),['user_id','tenant','sites','domains'],'user_scope');const target=store.require('SELECT id FROM users WHERE id=?',[String(input.user_id)]);fail(target.id!==user.id,403,'cannot_change_own_scope');const list=(v,name,max,allowedValues)=>{fail(Array.isArray(v)&&v.length>=1&&v.length<=max&&v.every(x=>typeof x==='string'&&x.length>=1&&x.length<=200&&(!allowedValues||x==='*'||allowedValues.includes(x))),400,`invalid_${name}`);return [...new Set(v)];};const sites=list(input.sites,'scope_sites',100),domains=list(input.domains,'scope_domains',scopeDomains.length+1,scopeDomains),t=String(input.tenant||'');fail(/^[A-Za-z0-9_.-]{1,100}$/.test(t),400,'invalid_scope_tenant');const at=new Date().toISOString();store.transaction(()=>{store.run('INSERT INTO user_scopes VALUES (?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET tenant=excluded.tenant,sites=excluded.sites,domains=excluded.domains,source=excluded.source,updated_by=excluded.updated_by,updated_at=excluded.updated_at',target.id,t,JSON.stringify(sites),JSON.stringify(domains),'admin',user.id,at);store.audit(user.id,'user.scope.set',target.id,{tenant:t,sites,domains},at);});return send(res,200,{user_id:target.id,tenant:t,sites,domains});}
      if(p==='/api/sso/config'&&method==='POST') return send(res,200,await sso.configure(user,object(await body(req),['issuer','client_id','client_secret_env','tenant','tenant_claim','groups_claim','role_map','mfa_amr','mfa_acr'],'sso_config')));
      if(p==='/api/sso/config'&&method==='GET') { auth.require(user,['admin']); const c=sso.config(); return send(res,200,c?{issuer:c.issuer,client_id:c.client_id,client_secret_env:c.client_secret_env,tenant:c.tenant,tenant_claim:c.tenant_claim,groups_claim:c.groups_claim,role_map:c.role_map,mfa_amr:c.mfa_amr,mfa_acr:c.mfa_acr,updated_at:c.updated_at}:null); }
      if(p==='/api/auth/me'&&method==='GET') return send(res,200,{user:{scope:user.scope,id:user.id,username:user.username,role:user.role,base_role:user.base_role,jit:user.jit,break_glass:user.break_glass,mfa:user.mfa},csrf:user.csrf});
      if(p==='/api/auth/logout'&&method==='POST') {auth.logout(user);res.setHeader('Set-Cookie',`cg_session=; ${cookieFor(req)}; Max-Age=0`);return send(res,200,{logged_out:true});}
      if(p==='/api/modes'&&method==='GET') return send(res,200,{active_mode:mode,lab_authorization_configured:mode==='authorized-defense-validation-lab',items:[
        {id:'pc-local',status:mode==='pc-local'?'active':'available',capabilities:['explicit local host inventory','manual evidence import'],limitations:['This host alone cannot see device-to-device traffic behind a switch.','No active network scan is performed.']},
        {id:'enterprise-collectors',status:mode==='enterprise-collectors'?'active':'available',capabilities:['independently authenticated source identities','passive import','SPAN/TAP observations','flow logs','managed agents'],limitations:['Visibility is limited to configured and currently receiving sources.','Connector availability is reported independently.']},
        {id:'authorized-defense-validation-lab',status:mode==='authorized-defense-validation-lab'?'active':'requires-explicit-authorization',capabilities:['isolated synthetic validation data','responsive browser QA harness'],limitations:['Requires CG_BROWSER_QA and a non-secret authorization reference at process start.','Never represents production validation.']}
      ].map(m=>({...m,capabilities_ar:m.capabilities.map(toAr),limitations_ar:m.limitations.map(toAr)}))});
      if(p==='/api/users') {
        roles(['admin']);
        if(method==='GET') return send(res,200,{items:store.all('SELECT id,username,role,created_at FROM users ORDER BY username')});
        auth.requireRecentMfa(user);
        const input=object(await body(req),['username','password','role'],'user');
        fail(store.get('SELECT COUNT(*) n FROM users').n<100,409,'user_limit');
        return send(res,201,{user:await auth.createUser(user.id,input)});
      }
      if(p==='/api/overview'&&method==='GET') return send(res,200,domain.summary());
      const aiAnalysis=p.match(/^\/api\/ai-analysis\/([a-f0-9-]{36})$/);
      if(aiAnalysis&&method==='GET') return send(res,200,domain.aiAnalysis(aiAnalysis[1]));
      if(p==='/api/ai-model-policy'&&method==='GET') return send(res,200,domain.aiModelPolicy(typeof cloudAiInvoke==='function'));
      if(p==='/api/ai-cloud-consents'&&method==='POST'){roles(['admin']);auth.requireRecentMfa(user);return send(res,201,domain.createAiCloudConsent(user.id,await body(req)));}
      const aiPropose=p.match(/^\/api\/ai-analysis\/([a-f0-9-]{36})\/proposals$/);
      if(aiPropose&&method==='POST'){roles(['admin','analyst']);return send(res,201,domain.aiProposeAction(user.id,aiPropose[1],await body(req)));}
      if(p==='/api/ai-action-proposals'&&method==='GET') return send(res,200,domain.aiActionProposals({alert_id:url.searchParams.get('alert_id')||null}));
      const aiDecision=p.match(/^\/api\/ai-action-proposals\/([a-f0-9-]{36})\/(promote|dismiss)$/);
      if(aiDecision&&method==='POST'){roles(['admin','analyst']);if(aiDecision[2]==='promote'){auth.requireRecentMfa(user);return send(res,201,domain.promoteAiProposal(user.id,aiDecision[1],await body(req)));}return send(res,200,domain.dismissAiProposal(user.id,aiDecision[1]));}
      const cloudAnalysis=p.match(/^\/api\/ai-analysis\/([a-f0-9-]{36})\/cloud$/);
      if(cloudAnalysis&&method==='POST'){roles(['admin','analyst']);auth.requireRecentMfa(user);fail(typeof cloudAiInvoke==='function',503,'cloud_ai_connector_unavailable');const prepared=domain.prepareAiCloudAnalysis(user.id,cloudAnalysis[1],await body(req)),raw=await cloudAiInvoke({provider:prepared.consent.provider,payload:prepared.payload}),result=validateCloudResult(raw);return send(res,200,domain.recordAiCloudAnalysis(user.id,prepared,result));}
      if(p==='/api/reconciliation'&&method==='GET'){roles(['admin','analyst']);return send(res,200,domain.reconciliation());}
      if(p==='/api/quality-metrics'&&method==='GET') return send(res,200,domain.qualityMetrics({days:url.searchParams.get('days')||30}));
      if(p==='/api/dashboard'&&method==='GET') return send(res,200,domain.dashboard(url.searchParams.get('severity')||'all'));
      if(p==='/api/security-outcomes'&&method==='GET') return send(res,200,domain.securityOutcomes());
      if(p==='/api/threat-models'&&method==='GET') return send(res,200,domain.threatModels(page(url.searchParams)));
      if(p==='/api/risk-register'&&method==='GET') return send(res,200,domain.riskRegister(page(url.searchParams)));
      if(p==='/api/compatibility-matrix'&&method==='GET') return send(res,200,domain.compatibilityMatrix(page(url.searchParams)));
      if(p==='/api/compensating-controls'&&method==='GET') return send(res,200,domain.compensatingControls(page(url.searchParams)));
      if(p==='/api/backup-security'&&method==='GET') return send(res,200,domain.backupSecurity(page(url.searchParams)));
      if(p==='/api/restore-readiness'&&method==='GET') return send(res,200,domain.restoreReadiness(page(url.searchParams)));
      if(p==='/api/incident-recovery'&&method==='GET') return send(res,200,domain.incidentRecovery(page(url.searchParams)));
      if(p==='/api/resilience-controls'&&method==='GET') return send(res,200,domain.resilienceControls(page(url.searchParams)));
      if(p==='/api/directory-audits'&&method==='GET') return send(res,200,domain.directoryAudits(page(url.searchParams)));
      if(p==='/api/laps-posture'&&method==='GET') return send(res,200,domain.lapsPosture(page(url.searchParams)));
      if(p==='/api/adcs-kerberos-posture'&&method==='GET') return send(res,200,domain.adcsKerberosPosture(page(url.searchParams)));
      if(p==='/api/privileged-access'&&method==='GET') return send(res,200,domain.privilegedAccess(page(url.searchParams)));
      if(p==='/api/saas-service-inventory'&&method==='GET') return send(res,200,domain.saasServiceInventory(page(url.searchParams)));
      if(p==='/api/identity-attack-correlations'&&method==='GET') return send(res,200,domain.identityAttackCorrelations(page(url.searchParams)));
      if(p==='/api/helpdesk-resets'&&method==='GET') return send(res,200,domain.helpdeskResets(page(url.searchParams)));
      if(p==='/api/process-causality'&&method==='GET') return send(res,200,domain.processCausality(page(url.searchParams)));
      if(p==='/api/defense-tamper'&&method==='GET') return send(res,200,domain.defenseTamper(page(url.searchParams)));
      if(p==='/api/ransomware-posture'&&method==='GET') return send(res,200,domain.ransomwarePosture(page(url.searchParams)));
      if(p==='/api/discovery-sequences'&&method==='GET') return send(res,200,domain.discoverySequences(page(url.searchParams)));
      if(p==='/api/collector-capacity'&&method==='GET') return send(res,200,domain.collectorCapacity());
      if(p==='/api/agents'&&method==='GET') return send(res,200,domain.agentInventory(page(url.searchParams)));
      if(p==='/api/sensitive-changes'&&method==='GET') return send(res,200,domain.sensitiveChanges(page(url.searchParams)));
      if(p==='/api/detection-rules'&&method==='GET') return send(res,200,domain.detectionRulesStatus());
      if(p==='/api/device-capabilities'&&method==='GET') return send(res,200,domain.deviceCapabilities());
      if(p==='/api/nsg-flow-migration'&&method==='GET') return send(res,200,domain.nsgFlowMigration());
      if(p==='/api/cloud-unified'&&method==='GET') return send(res,200,domain.cloudUnified());
      if(p==='/api/cloud-access'&&method==='GET') return send(res,200,domain.cloudAccessReview());
      if(p==='/api/cloud-posture'&&method==='GET') return send(res,200,domain.cloudPosture(url.searchParams.get('provider')||'aws'));
      if(p==='/api/network-topology'&&method==='GET') return send(res,200,domain.networkTopology());
      if(p==='/api/detection-coverage'&&method==='GET') return send(res,200,domain.detectionCoverage(page(url.searchParams)));
      if(p==='/api/critical-production-protection'&&method==='GET') return send(res,200,domain.criticalProductionProtection());
      if(p==='/api/response-actions'&&method==='GET') return send(res,200,domain.responseActions());
      if(p==='/api/incident-playbooks'&&method==='GET') return send(res,200,domain.incidentPlaybooks());
      if(p==='/api/playbook-runs'&&method==='POST'){roles(['admin','analyst']);auth.requireRecentMfa(user);return send(res,201,domain.requestPlaybookRun(user.id,await body(req)));}
      const playbookRun=p.match(/^\/api\/playbook-runs\/([a-f0-9-]{36})\/(approve|deny|execute)$/);
      if(playbookRun&&method==='POST'){roles(['admin']);auth.requireRecentMfa(user);return send(res,200,playbookRun[2]==='execute'?domain.executePlaybookRun(user.id,playbookRun[1]):domain.decidePlaybookRun(user.id,playbookRun[1],playbookRun[2]));}
      if(p==='/api/temporary-permits'&&method==='GET') return send(res,200,domain.temporaryPermits());
      if(p==='/api/temporary-permits'&&method==='POST'){roles(['admin','analyst']);auth.requireRecentMfa(user);return send(res,201,domain.requestTemporaryPermit(user.id,await body(req)));}
      const permitAction=p.match(/^\/api\/temporary-permits\/([a-f0-9-]{36})\/(approve|revoke)$/);
      if(permitAction&&method==='POST'){roles(['admin']);auth.requireRecentMfa(user);return send(res,200,permitAction[2]==='approve'?domain.approveTemporaryPermit(user.id,permitAction[1]):domain.revokeTemporaryPermit(user.id,permitAction[1]));}
      if(p==='/api/validation-program'&&method==='GET') return send(res,200,domain.validationProgram(page(url.searchParams)));
      if(p==='/api/vulnerability-risk'&&method==='GET') return send(res,200,domain.vulnerabilityRisk({...page(url.searchParams),band:['critical','high','medium','low'].includes(url.searchParams.get('band'))?url.searchParams.get('band'):''}));
      if(p==='/api/vulnerability-assessments'&&method==='GET') return send(res,200,domain.vulnerabilityAssessments(page(url.searchParams)));
      if(p==='/api/software-vulnerabilities'&&method==='GET') return send(res,200,domain.softwareVulnerabilities(page(url.searchParams)));
      if(p==='/api/identity-directories'&&method==='GET') return send(res,200,domain.identityDirectories(page(url.searchParams)));
      if(p==='/api/identity-threats'&&method==='GET') return send(res,200,domain.identityThreats(page(url.searchParams)));
      if(p==='/api/security-integrations'&&method==='GET') return send(res,200,domain.securityIntegrations());
      if(p==='/api/device-configs'&&method==='GET') return send(res,200,domain.deviceConfigMonitoring());
      if(p==='/api/firewall-rules'&&method==='GET') return send(res,200,domain.firewallRuleAnalysis());
      if(p==='/api/network-analysis'&&method==='GET') return send(res,200,domain.networkAnalysis());
      if(p==='/api/normalized-logs'&&method==='GET') return send(res,200,domain.normalizedLogs({...page(url.searchParams),category:String(url.searchParams.get('category')||'').slice(0,20)}));
      if(p==='/api/visibility-gaps'&&method==='GET') return send(res,200,domain.visibilityGaps(page(url.searchParams)));
      if(p==='/api/discovery'&&method==='GET') return send(res,200,domain.discovery(page(url.searchParams)));
      if(p==='/api/sources') {
        if(method==='GET') return send(res,200,{items:domain.sources()});
        roles(['admin']);auth.requireRecentMfa(user);return send(res,201,domain.createSource(user.id,await body(req)));
      }
      if(p==='/api/collectors/local'&&method==='POST') {
        roles(['admin']);
        const input=object(await body(req),['confirm_read_only'],'local_collection');
        fail(input.confirm_read_only===true,400,'collection_confirmation_required');
        const name='Control-plane host / explicit local inventory';
        let source=store.get('SELECT id,revoked FROM sources WHERE name=?',name);
        if(!source) source=domain.createSource(user.id,{name,stale_seconds:86400});
        return send(res,200,domain.ingest(user.id,source.id,localObservation()));
      }
      const sourceAction=p.match(/^\/api\/sources\/([a-f0-9-]{36})\/(rotate|revoke)$/);
      if(sourceAction&&method==='POST') { roles(['admin']);auth.requireRecentMfa(user);return send(res,200,sourceAction[2]==='rotate'?domain.rotateSource(user.id,sourceAction[1]):domain.revokeSource(user.id,sourceAction[1])); }
      if(ingest&&method==='POST') {roles(['admin','analyst']);return send(res,200,ingestInput(user.id,ingest[1],await body(req)));}
      const tables={'/api/assets':'assets','/api/events':'events','/api/alerts':'alerts','/api/remote-sessions':'remote_sessions','/api/cases':'cases','/api/actions':'actions','/api/audit':'audit'};
      if(tables[p]&&method==='GET') {if(p==='/api/audit') roles(['admin']);return send(res,200,domain.list(tables[p],{...page(url.searchParams),assetIds:allowedAssets}));}
      const assetRoute=p.match(/^\/api\/assets\/([a-f0-9-]{36})(\/report)?$/);
      if(assetRoute&&method==='GET') return send(res,200,assetRoute[2]?domain.evidenceReport(assetRoute[1]):domain.asset(assetRoute[1]));
      const eventRoute=p.match(/^\/api\/events\/([a-f0-9-]{36})$/);
      if(eventRoute&&method==='GET') return send(res,200,domain.decode(store.require('SELECT * FROM events WHERE id=?',[eventRoute[1]])));
      const ack=p.match(/^\/api\/alerts\/([a-f0-9-]{36})\/ack$/);
      const alertRoute=p.match(/^\/api\/alerts\/([a-f0-9-]{36})$/);
      if(alertRoute&&method==='GET') return send(res,200,domain.decode(store.require('SELECT * FROM alerts WHERE id=?',[alertRoute[1]])));
      if(ack&&method==='POST') {roles(['admin','analyst']); return send(res,200,domain.acknowledge(user.id,ack[1]));}
      const disposition=p.match(/^\/api\/alerts\/([a-f0-9-]{36})\/disposition$/);
      if(disposition&&method==='POST') {roles(['admin','analyst']); return send(res,200,domain.dispositionAlert(user.id,disposition[1],await body(req)));}
      if(p==='/api/cases'&&method==='POST') {roles(['admin','analyst']);return send(res,201,domain.createCase(user.id,await body(req)));}
      const reconstruction=p.match(/^\/api\/cases\/([a-f0-9-]{36})\/reconstruction$/);
      if(reconstruction&&method==='GET') return send(res,200,domain.incidentReconstruction(reconstruction[1]));
      const caseRoute=p.match(/^\/api\/cases\/([a-f0-9-]{36})(\/report)?$/);
      if(caseRoute) {
        if(method==='GET') return send(res,200,caseRoute[2]?domain.caseReport(caseRoute[1]):domain.decode(store.require('SELECT * FROM cases WHERE id=?',[caseRoute[1]])));
        fail(!caseRoute[2],405,'method_not_allowed');
        roles(['admin','analyst']); return send(res,200,domain.updateCase(user.id,caseRoute[1],await body(req)));
      }
      if(p==='/api/actions/preview'&&method==='POST') {roles(['admin','analyst']);auth.requireRecentMfa(user);return send(res,201,domain.previewAction(user.id,await body(req)));}
      const action=p.match(/^\/api\/actions\/([a-f0-9-]{36})\/(approve|safety-approve|execute|rollback)$/);
      const actionDetail=p.match(/^\/api\/actions\/([a-f0-9-]{36})$/);
      if(actionDetail&&method==='GET') return send(res,200,domain.action(actionDetail[1]));
      if(action&&method==='POST') {roles(['admin']);auth.requireRecentMfa(user);const fn={approve:'approveAction','safety-approve':'safetyApproveAction',execute:'executeAction',rollback:'rollbackAction'}[action[2]];return send(res,200,domain[fn](user.id,action[1]));}
      if(p==='/api/audit/verify'&&method==='GET') {roles(['admin']);return send(res,200,store.verifyAudit());}
      if(p==='/api/coverage'&&method==='GET') return send(res,200,{...coverage,support:readJson('docs/engineering/SUPPORT_MATRIX.json'),capabilities:readJson('docs/engineering/CAPABILITIES.json')});
      if(p==='/api/accomplishments'&&method==='GET') {
        const from=Number(url.searchParams.get('from')||1),to=Number(url.searchParams.get('to')||600);
        fail(Number.isInteger(from)&&Number.isInteger(to)&&from>=1&&to<=600&&from<=to,400,'invalid_accomplishment_range');
        const {limit,offset,q}=page(url.searchParams),query=q.toLowerCase();
        const scoped=requirements.filter(r=>r.number>=from&&r.number<=to);
        const matching=scoped.filter(r=>!query||`${r.id} ${r.raw_requirement} ${r.area} ${r.status}`.toLowerCase().includes(query));
        const count=status=>scoped.filter(r=>r.status===status).length;
        const completed=count('acceptance-verified'),partial=count('partially-implemented')+count('implemented-unverified');
        const next=scoped.find(r=>r.status!=='acceptance-verified')||null;
        return send(res,200,{scope:{from,to,total:scoped.length},summary:{completed,partial,pending:scoped.length-completed-partial,validation_level:'Unit Tested',production_validated:false},next_requirement:next?.id||null,items:matching.slice(offset,offset+limit),total:matching.length,limit,offset});
      }
      if(p==='/api/requirements'&&method==='GET') {
        const {limit,offset,q}=page(url.searchParams), query=q.toLowerCase();
        const matching=requirements.filter(r=>!query||`${r.id} ${r.raw_requirement} ${r.area}`.toLowerCase().includes(query));
        return send(res,200,{items:matching.slice(offset,offset+limit),total:matching.length,limit,offset});
      }
      throw new AppError(404,'not_found');
    } catch(e) {
      if(authenticatedActor && e instanceof AppError && e.status===403) {
        try {store.audit(authenticatedActor,'request.denied','http-api',{reason:e.code});} catch {monitorError=true;}
      }
      if(!res.headersSent) send(res,e instanceof AppError?e.status:500,{error:e instanceof AppError?e.code:'internal_error'});
      else res.end();
    }
  };
  const server=tlsMaterial?https.createServer({...tlsMaterial,minVersion:'TLSv1.2',...(accessConfig.device_certificates?{ca:clientCa,requestCert:true,rejectUnauthorized:true}:{})},handler):http.createServer(handler);
  server.requestTimeout=15000; server.headersTimeout=10000; server.keepAliveTimeout=5000; server.maxHeadersCount=50;
  const checkSecretRotation=()=>{for(const x of secrets.list().filter(x=>x.status==='rotation-overdue'))domain.alert({key:`CG-SECRET-ROTATION-055:${x.ref}:v${x.version}`,rule:'CG-SECRET-ROTATION-055',severity:'medium',title:`Secret rotation overdue / سر متأخر عن التدوير: ${x.ref} (due ${x.rotation_due_at.slice(0,10)})`});};
  const monitor=setInterval(()=>{try{domain.checkHealth();checkSecretRotation();tenancy.maybeRetention();domain.expireStaleResponseJobs();monitorError=false;}catch{monitorError=true;}},30000); monitor.unref();
  const permitExpiryMonitor=setInterval(()=>{try{domain.expireTemporaryPermits();}catch{monitorError=true;}},1000);permitExpiryMonitor.unref();
  return {server,store,auth,domain,secrets,tenancy,checkSecretRotation,setupFile,operatingMode:mode,scheme:tlsMaterial?'https':'http',certificate:tlsMaterial?tlsMaterial.cert:null,listen(port=4310,host='127.0.0.1'){
    fail(['127.0.0.1','::1'].includes(host)||(accessConfig.mode==='vpn'&&host===accessConfig.vpn.listen_host),400,'loopback_only');
    fail(Number.isInteger(port)&&port>=0&&port<=65535,400,'invalid_port');
    // A random port (0) never lands on a port that browsers and fetch refuse by specification (Windows may hand out ports from 1024).
    const once=()=>new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,()=>{server.removeListener('error',reject);resolve(server.address());});});
    return (async()=>{for(let i=0;i<20;i++){const a=await once();if(port!==0||!FETCH_BLOCKED_PORTS.has(a.port))return a;await new Promise(r=>server.close(r));}throw new AppError(500,'no_usable_port');})();
  },async close(){clearInterval(monitor);clearInterval(permitExpiryMonitor);if(server.listening){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}store.close();}};
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const app=createApp();
  const port=Number(process.env.CG_PORT||4310);
  await app.listen(port);
  console.log(`CyberGuard AI engineering preview: ${app.scheme}://${app.scheme==='https'?'localhost':'127.0.0.1'}:${port}`);
  if(!app.store.get('SELECT id FROM users LIMIT 1')) console.log(`First-run token is in ${app.setupFile}. Keep it private; the file is removed after setup.`);
  for(const signal of ['SIGINT','SIGTERM']) process.once(signal,()=>app.close().then(()=>process.exit(0)));
}
