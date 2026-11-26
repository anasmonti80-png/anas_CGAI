import http from 'node:http';
import { EvidenceVault, MAX_EVIDENCE_BYTES } from './lib/evidence-vault.js';
import { ValidationLab } from './lib/validation-lab.js';
import { HuntWorkbench } from './lib/hunt.js';
import { ResponsePreflight } from './lib/response-preflight.js';
import { ControlOutcomes } from './lib/control-outcome.js';
import { SafetyGate } from './lib/safety-tiers.js';
import { Orchestrator } from './lib/orchestration.js';
import { SYSTEM_POLICY, POLICY_SHA256, PATTERNS as INJECTION_PATTERNS, envelope as promptEnvelope } from './lib/prompt-guard.js';
import { EvidenceRag } from './lib/evidence-rag.js';
import { AiEvaluation } from './lib/ai-eval.js';
import { NcaCompliance } from './lib/compliance-nca.js';
import { MsocReadiness } from './lib/msoc-readiness.js';
import { DataGovernance, bindTenant } from './lib/data-governance.js';
import { SocWorkflow } from './lib/soc-workflow.js';
import { SelfDefense } from './lib/self-defense.js';
import { plan as capacityPlan, live as capacityLive, loadProfile } from './lib/capacity-model.js';
import { registerView } from './lib/research-register.js';
import { ChangeSafety } from './lib/change-safety.js';
import { IntendedState } from './lib/intended-state.js';
import { ImpactGraph } from './lib/impact-graph.js';
import { l2View } from './lib/l2-security.js';
import { routingView } from './lib/routing-security.js';
import { wirelessView } from './lib/wireless.js';
import { mgmtView } from './lib/mgmt-plane.js';
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
import { Rollout } from './lib/rollout.js';
import { Hypotheses } from './lib/hypotheses.js';
import { ThreatIntelligence } from './lib/threat-intelligence.js';
import { Sandbox } from './lib/sandbox.js';
import { OtSafety } from './lib/ot-safety.js';
import { RuleSigner } from './lib/rule-signing.js';
import { evidenceKinds } from './lib/domain.js';
import { readiness as developmentPromptReadiness } from './scripts/development-prompt.js';
import { Domain } from './lib/domain.js';
import { localObservation } from './lib/local-collector.js';
import { normalizeWindowsExport } from './lib/windows-events.js';
import { toAr } from './lib/i18n-ar.js';
import { AppError, fail, equal, object, page, token, text, choice, MAX_INGEST_BYTES } from './lib/common.js';
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
// CG-114 evidence upload: raw bytes (application/octet-stream), streamed with a size cap.
async function rawBody(req,max) {
  fail(String(req.headers['content-type']||'').split(';')[0].trim()==='application/octet-stream',415,'octet_stream_content_type_required');
  const chunks=[]; let size=0; for await (const chunk of req) { size+=chunk.length; fail(size<=max,413,'evidence_too_large'); chunks.push(chunk); } return Buffer.concat(chunks);
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
  const auth=new Auth(store,{clock}), domain=new Domain(store,{clock}), sso=new Sso(store,auth,{clock,tenant}), secrets=new SecretStore(store,{clock}), tenancy=new TenantPolicy(store,{clock,tenant,dbFile,domain}); domain.tenantGuard=tenancy; const rollout=new Rollout(store,{clock,domain,verificationFile:path.join(ROOT,'artifacts','verification.json')}); domain.rolloutGuard=rollout; const hypotheses=new Hypotheses(store,{clock,domain,evidenceKinds,signer:new RuleSigner(dataDir)}); domain.hypothesisEngine=hypotheses; const evidenceVault=new EvidenceVault(store,{dataDir,clock,signer:hypotheses.signer,domain}); const validationLab=new ValidationLab(store,{clock,domain,Domain}); const hunts=new HuntWorkbench(store,{clock}); const responsePreflight=new ResponsePreflight(store,{domain,clock}); const controlOutcomes=new ControlOutcomes(store,{domain,clock}); const safetyGate=new SafetyGate(store,{clock}); domain.safetyGate=safetyGate; const orchestrator=new Orchestrator(store,{domain,clock}); const evidenceRag=new EvidenceRag(store,{clock}); const aiEvaluation=new AiEvaluation(store,{clock,domain,Domain}); const ncaCompliance=new NcaCompliance(store,{clock}); const msocReadiness=new MsocReadiness(store,{clock}); bindTenant(store,tenant); const dataGovernance=new DataGovernance(store,{clock,tenant,dataDir,dbFile}); const socWorkflow=new SocWorkflow(store,{clock,hypotheses}); const changeSafety=new ChangeSafety(store,{clock}); const intendedState=new IntendedState(store,{clock}); const impactGraph=new ImpactGraph(store,{clock,domain}); domain.impactGraph=impactGraph; domain.socWorkflow=socWorkflow; const releaseKeyFile=path.join(ROOT,'deploy','release-signing-public.pem'); const selfDefense=new SelfDefense(store,{clock,root:ROOT,dataDir,dbFile,tls:Boolean(tlsMaterial),accessMode:accessConfig.mode,releasePublicKeyPem:fs.existsSync(releaseKeyFile)?fs.readFileSync(releaseKeyFile,'utf8'):null,domain}); const threatIntelligence=new ThreatIntelligence(store,{clock}),sandbox=new Sandbox(store,{clock,domain}), otSafety=new OtSafety(store,{clock,domain}); domain.otGuard=otSafety;
  const setupFile=path.join(dataDir,'setup-token'), anonBuckets=new Map();
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
      // CG-107 unauthenticated API requests are rate limited per client address (120 per minute) with RateLimit headers.
      if(p.startsWith('/api/')&&!bearer&&!/(^|;\s*)cg_session=/.test(String(req.headers.cookie||''))){const key=req.socket.remoteAddress||'unknown',now=Date.now(),b=anonBuckets.get(key)||{start:now,count:0};if(now-b.start>=60000){b.start=now;b.count=0;}b.count++;anonBuckets.set(key,b);if(anonBuckets.size>10000)anonBuckets.clear();
        res.setHeader('RateLimit-Limit','120');res.setHeader('RateLimit-Remaining',String(Math.max(0,120-b.count)));res.setHeader('RateLimit-Reset',String(Math.ceil((b.start+60000-now)/1000)));
        if(b.count>120){res.setHeader('Retry-After',String(Math.ceil((b.start+60000-now)/1000)));return send(res,429,{error:'rate_limited'});}}
      const ingest=p.match(/^\/api\/sources\/([a-f0-9-]{36})\/events$/);
      const responseJobs=p.match(/^\/api\/sources\/([a-f0-9-]{36})\/response-jobs$/);
      const responseResult=p.match(/^\/api\/sources\/([a-f0-9-]{36})\/response-jobs\/([a-f0-9-]{36})\/result$/);
      const secretRelease=p.match(/^\/api\/sources\/([a-f0-9-]{36})\/secrets\/([a-z0-9._-]{3,100})$/);
      const sandboxIsolation=p.match(/^\/api\/sources\/([a-f0-9-]{36})\/sandbox\/isolation$/),sandboxJobs=p.match(/^\/api\/sources\/([a-f0-9-]{36})\/sandbox\/jobs$/),sandboxReport=p.match(/^\/api\/sources\/([a-f0-9-]{36})\/sandbox\/jobs\/(\d{1,9})\/report$/);
      if(mutation) {
        fail(method==='POST',405,'method_not_allowed');
        if (!(bearer&&(ingest||responseResult||secretRelease||sandboxIsolation||sandboxReport))) fail(req.headers.origin===`${secureFor(req)?'https':'http'}://${req.headers.host}`,403,'origin_not_allowed');
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
      // CG-093 the registered isolated sandbox reports its isolation, fetches approved jobs and reports results with its own token.
      if(bearer&&sandboxIsolation&&method==='POST'){const source=domain.sourceToken(bearer,sandboxIsolation[1]);return send(res,200,sandbox.isolationCheck(source.id,await body(req)));}
      if(bearer&&sandboxJobs&&method==='GET'){const source=domain.sourceToken(bearer,sandboxJobs[1]);return send(res,200,sandbox.jobsFor(source.id));}
      if(bearer&&sandboxReport&&method==='POST'){const source=domain.sourceToken(bearer,sandboxReport[1]);return send(res,200,sandbox.report(source.id,Number(sandboxReport[2]),await body(req)));}
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
      if(p==='/api/rollout'&&method==='GET'){auth.require(user,['admin','analyst']);return send(res,200,rollout.status());}
      if(p==='/api/rollout'&&method==='POST'){auth.require(user,['admin']);auth.requireRecentMfa(user);fail(!scope.restricted&&scope.domains.includes('*'),403,'rollout_requires_full_scope');return send(res,201,rollout.request(user.id,await body(req)));}
      const rolloutDecision=p.match(/^\/api\/rollout\/(\d{1,9})\/(approve|reject)$/);if(rolloutDecision&&method==='POST'){auth.require(user,['admin']);auth.requireRecentMfa(user);fail(!scope.restricted&&scope.domains.includes('*'),403,'rollout_requires_full_scope');return send(res,200,rollout.decide(user.id,Number(rolloutDecision[1]),rolloutDecision[2]));}
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
      // CG-122 the analysis is grounded in dated source snapshots, stored, and redacted for the reader's role.
      if(aiAnalysis&&method==='GET') return send(res,200,evidenceRag.ground(user,domain.aiAnalysis(aiAnalysis[1])));
      if(p==='/api/ai-answers'&&method==='GET') return send(res,200,{items:evidenceRag.recent(user)});
      {const m=p.match(/^\/api\/ai-answers\/([a-f0-9-]{36})$/);if(m&&method==='GET'){const a=evidenceRag.get(user,m[1]);fail(a,404,'not_found');return send(res,200,a);}}
      {const m=p.match(/^\/api\/ai-snapshots\/([a-f0-9-]{36})$/);if(m&&method==='GET'){const a=evidenceRag.snapshotFor(user,m[1]);fail(a,404,'not_found');return send(res,200,a);}}
      if(p==='/api/ai-model-policy'&&method==='GET') return send(res,200,domain.aiModelPolicy(typeof cloudAiInvoke==='function'));
      if(p==='/api/ai-cloud-consents'&&method==='POST'){roles(['admin']);auth.requireRecentMfa(user);return send(res,201,domain.createAiCloudConsent(user.id,await body(req)));}
      const aiPropose=p.match(/^\/api\/ai-analysis\/([a-f0-9-]{36})\/proposals$/);
      if(aiPropose&&method==='POST'){roles(['admin','analyst']);return send(res,201,domain.aiProposeAction(user.id,aiPropose[1],await body(req)));}
      if(p==='/api/ai-action-proposals'&&method==='GET') return send(res,200,domain.aiActionProposals({alert_id:url.searchParams.get('alert_id')||null}));
      const aiDecision=p.match(/^\/api\/ai-action-proposals\/([a-f0-9-]{36})\/(promote|dismiss)$/);
      if(aiDecision&&method==='POST'){roles(['admin','analyst']);if(aiDecision[2]==='promote'){auth.requireRecentMfa(user);return send(res,201,domain.promoteAiProposal(user.id,aiDecision[1],await body(req)));}return send(res,200,domain.dismissAiProposal(user.id,aiDecision[1]));}
      const cloudAnalysis=p.match(/^\/api\/ai-analysis\/([a-f0-9-]{36})\/cloud$/);
      if(cloudAnalysis&&method==='POST'){roles(['admin','analyst']);auth.requireRecentMfa(user);fail(typeof cloudAiInvoke==='function',503,'cloud_ai_connector_unavailable');const prepared=domain.prepareAiCloudAnalysis(user.id,cloudAnalysis[1],await body(req)),raw=await cloudAiInvoke({provider:prepared.consent.provider,payload:prepared.payload}),result=validateCloudResult(raw);return send(res,200,domain.recordAiCloudAnalysis(user.id,prepared,result));}
      if(p==='/api/hypotheses'&&method==='GET'){roles(['admin','analyst']);return send(res,200,{items:hypotheses.list(),operators:['equals','not-equals','contains','starts-with','ends-with','in','gte','lte','exists'],detection_as_code:{requirement:'CG-111',signed_versions:true,independent_review:true,unit_and_quality_test:true,environment_tuning:true,false_positive_analysis:true,safe_update:true,signed_rollback:true,claim:'A rule update remains a non-running draft until its labelled unit samples and replay quality check pass and a different administrator approves it. Environment exclusions and false-positive budgets are versioned and signed with the rule. A failed update leaves the last signed version active; rollback accepts only a previously signed version.',claim_ar:'يبقى تحديث القاعدة مسودة غير عاملة حتى تنجح عيناته المعلّمة وفحص جودة الإعادة ويعتمده مسؤول مختلف. تُحفظ استثناءات البيئة وميزانية الإيجابيات الكاذبة وتُوقّع مع القاعدة. التحديث الفاشل يترك آخر إصدار موقّع عاملًا، والاستعادة لا تقبل إلا إصدارًا سابقًا موقّعًا.'},claim:'Published evidence becomes a declarative detection hypothesis that cites its source; nothing from the source is executed. It is tested against labelled samples and replayed over 30 days of stored evidence, a person attests the manual review, and a different administrator with recent MFA approves it before it can raise alerts.',claim_ar:'تتحول الأدلة المنشورة إلى فرضية كشف وصفية تذكر مصدرها؛ ولا يُنفذ شيء من المصدر. تُختبر على عينات معلَّمة وتُعاد على أدلة 30 يومًا مخزنة، ويقر شخص بالمراجعة اليدوية، ويعتمدها مسؤول آخر بتحقق MFA حديث قبل أن ترفع أي تنبيه.'});}
      if(p==='/api/threat-intelligence'&&method==='GET'){roles(['admin','analyst']);return send(res,200,{items:threatIntelligence.list(),claim:'Every indicator keeps its source, publication date, confidence, expiry and redistribution rights. A match is investigation context only; CyberGuard never blocks automatically from an indicator.',claim_ar:'يحتفظ كل مؤشر بمصدره وتاريخ نشره وثقته وانتهائه وحقوق إعادة توزيعه. المطابقة سياق للتحقيق فقط؛ لا يحظر CyberGuard تلقائيًا بسبب مؤشر.'});}
      if(p==='/api/threat-intelligence'&&method==='POST'){auth.require(user,['admin']);auth.requireRecentMfa(user);return send(res,201,threatIntelligence.add(user.id,await body(req)));}
      if(p==='/api/threat-intelligence/check'&&method==='POST'){roles(['admin','analyst']);return send(res,200,threatIntelligence.check(await body(req)));}
      if(p==='/api/threat-intelligence/export'&&method==='GET'){roles(['admin','analyst']);return send(res,200,threatIntelligence.exportable());}
      if(p==='/api/hypotheses'&&method==='POST'){roles(['admin','analyst']);return send(res,201,hypotheses.create(user.id,await body(req)));}
      const hypothesisRevise=p.match(/^\/api\/hypotheses\/(\d{1,9})\/revise$/);if(hypothesisRevise&&method==='POST'){roles(['admin','analyst']);return send(res,200,hypotheses.revise(user.id,Number(hypothesisRevise[1]),await body(req)));}
      const hypothesisRollback=p.match(/^\/api\/hypotheses\/(\d{1,9})\/rollback$/);if(hypothesisRollback&&method==='POST'){auth.require(user,['admin']);auth.requireRecentMfa(user);const input=object(await body(req),['version','reason'],'hypothesis_rollback');fail(Number.isInteger(input.version)&&input.version>=1,400,'invalid_hypothesis_version');return send(res,200,hypotheses.rollback(user.id,Number(hypothesisRollback[1]),input.version,input.reason));}
      if(p==='/api/rule-keys'&&method==='GET'){roles(['admin','analyst']);return send(res,200,{items:hypotheses.trustedKeys()});}
      if(p==='/api/rule-keys'&&method==='POST'){auth.require(user,['admin']);auth.requireRecentMfa(user);return send(res,201,hypotheses.trustKey(user.id,await body(req)));}
      if(p==='/api/rule-packs/export'&&method==='GET'){auth.require(user,['admin']);store.audit(user.id,'rule_pack.exported','rule-pack',{items:hypotheses.active().length});return send(res,200,hypotheses.exportPack());}
      if(p==='/api/rule-packs/import'&&method==='POST'){auth.require(user,['admin']);auth.requireRecentMfa(user);return send(res,201,hypotheses.importPack(user.id,await body(req)));}
      const hypothesisTest=p.match(/^\/api\/hypotheses\/(\d{1,9})\/test$/);if(hypothesisTest&&method==='POST'){roles(['admin','analyst']);return send(res,200,hypotheses.test(user.id,Number(hypothesisTest[1]),await body(req)));}
      const hypothesisDecision=p.match(/^\/api\/hypotheses\/(\d{1,9})\/(approve|reject|retire)$/);if(hypothesisDecision&&method==='POST'){auth.require(user,['admin']);auth.requireRecentMfa(user);const input=object(await body(req),['note'],'hypothesis_decision');return send(res,200,hypotheses.decide(user.id,Number(hypothesisDecision[1]),hypothesisDecision[2],input.note));}
      if(p==='/api/vulnerability-governance'&&method==='GET') return send(res,200,domain.vulnerabilityGovernance());
      if(p==='/api/vulnerability-exceptions'&&method==='POST'){auth.require(user,['admin']);auth.requireRecentMfa(user);return send(res,201,domain.createVulnerabilityException(user.id,await body(req)));}
      if(p==='/api/detonations'&&method==='GET'){roles(['admin','analyst']);return send(res,200,sandbox.overview());}
      if(p==='/api/sandboxes'&&method==='POST'){auth.require(user,['admin']);auth.requireRecentMfa(user);return send(res,201,sandbox.register(user.id,await body(req)));}
      if(p==='/api/detonations'&&method==='POST'){roles(['admin','analyst']);return send(res,201,sandbox.request(user.id,await body(req)));}
      const detonationDecision=p.match(/^\/api\/detonations\/(\d{1,9})\/(approve|reject)$/);if(detonationDecision&&method==='POST'){auth.require(user,['admin']);auth.requireRecentMfa(user);return send(res,200,sandbox.decide(user.id,Number(detonationDecision[1]),detonationDecision[2]));}
      if(p==='/api/firewall-rules/what-if'&&method==='POST'){roles(['admin','analyst']);return send(res,200,domain.firewallChangeImpact(await body(req)));}
      const pathRoute=p.match(/^\/api\/assets\/([a-f0-9-]{36})\/network-path$/);if(pathRoute&&method==='GET') return send(res,200,domain.networkPath(pathRoute[1]));
      if(p==='/api/attack-mapping'&&method==='GET') return send(res,200,domain.attackMapping());
      if(p==='/api/attack-mapping/navigator-layer'&&method==='GET') return send(res,200,domain.attackNavigatorLayer());
      // CG-132 intended (source of truth) versus observed state.
      // CG-137 management-plane audit.
      if(p==='/api/mgmt-plane'&&method==='GET'){roles(['admin','analyst']);return send(res,200,mgmtView(store));}
      // CG-136 wireless and guest network assurance.
      if(p==='/api/wireless'&&method==='GET'){roles(['admin','analyst']);return send(res,200,wirelessView(store,domain.portMaps()));}
      // CG-135 BGP routing security.
      if(p==='/api/routing-security'&&method==='GET'){roles(['admin','analyst']);return send(res,200,routingView(store));}
      // CG-134 layer-2 security posture.
      if(p==='/api/l2-security'&&method==='GET'){roles(['admin','analyst']);return send(res,200,l2View(store,clock?clock():Date.now()));}
      // CG-133 network change impact graph.
      if(p==='/api/impact-graph'&&method==='GET'){roles(['admin','analyst']);return send(res,200,impactGraph.view());}
      if(p==='/api/impact-graph/roles'&&method==='POST'){roles(['admin']);auth.requireRecentMfa(user);return send(res,201,impactGraph.declare(user.id,await body(req)));}
      {const m=p.match(/^\/api\/impact-graph\/roles\/([a-f0-9-]{36})\/remove$/);if(m&&method==='POST'){roles(['admin']);auth.requireRecentMfa(user);return send(res,200,impactGraph.remove(user.id,m[1]));}}
      if(p==='/api/impact-graph/assess'&&method==='POST'){roles(['admin','analyst']);return send(res,200,impactGraph.assess(await body(req)));}
      if(p==='/api/intended-state'&&method==='GET'){roles(['admin','analyst']);return send(res,200,intendedState.view());}
      if(p==='/api/intended-state/review'&&method==='POST'){roles(['admin','analyst']);return send(res,200,intendedState.review(user.id,await body(req)));}
      if(p==='/api/intended-state/patch'&&method==='GET'){roles(['admin','analyst']);const x=intendedState.patch();store.audit(user.id,'intended_state.patch_exported','netbox',{changes:x.changes.length},new Date().toISOString());res.writeHead(200,{'Content-Type':'application/json; charset=utf-8','Content-Disposition':'attachment; filename="netbox-review-patch.json"'});return res.end(JSON.stringify(x,null,2));}
      // CG-131 network change safety (pre-change reachability of required flows).
      if(p==='/api/change-safety'&&method==='GET'){roles(['admin','analyst']);return send(res,200,{flows:changeSafety.flows(),history:changeSafety.history(),claim:'Required flows are checked against the current and the proposed configuration before an ACL, firewall or route change; unsupported rule features block a safe decision; this is configuration analysis, not a guarantee of live network behaviour.',claim_ar:'تُفحص التدفقات المطلوبة مقابل الإعدادات الحالية والمقترحة قبل أي تغيير في ACL أو الجدار الناري أو المسارات؛ والميزات غير المدعومة تمنع قرار «آمن»؛ وهذا تحليل للإعدادات وليس ضمانًا لسلوك الشبكة الفعلي.'});}
      if(p==='/api/change-safety/flows'&&method==='POST'){roles(['admin','analyst']);return send(res,201,changeSafety.addFlow(user.id,await body(req)));}
      if(p==='/api/change-safety/analyse'&&method==='POST'){roles(['admin','analyst']);return send(res,200,changeSafety.analyseChange(user.id,await body(req)));}
      // CG-130 research evidence register (versioned in docs/research/register.json).
      if(p==='/api/research-register'&&method==='GET'){roles(['admin','analyst']);return send(res,200,registerView(ROOT));}
      // CG-129 budget and capacity model from the measured profile.
      if(p==='/api/capacity'&&method==='GET'){roles(['admin','analyst']);const profile=loadProfile(path.join(ROOT,'artifacts','capacity-profile.json')),pol=tenancy.get(),q=Object.fromEntries(url.searchParams.entries());
        const current=capacityLive(store,{maxDbMb:pol.max_db_mb,dbBytes:tenancy.dbMegabytes()*1048576,retentionDays:pol.retention_days});
        return send(res,200,{profile,live:current,plan:profile?capacityPlan({eps:q.eps||Math.max(1,Math.ceil(current.average_eps)),retention_days:q.retention_days||pol.retention_days,sources:q.sources,api_calls_per_day:q.api_calls_per_day,ai_analyses_per_day:q.ai_analyses_per_day,price_storage_gb_month:q.price_storage_gb_month,price_api_call:q.price_api_call,price_ai_1k_tokens:q.price_ai_1k_tokens},profile):null,
          claim:'Capacity planned from a measured benchmark on this hardware (event rate, stored bytes per event, CPU and memory) with detection checked under load; cost appears only for prices you enter.',claim_ar:'السعة مخططة من قياس فعلي على هذا الجهاز (معدل الأحداث، البايتات المخزنة لكل حدث، المعالج والذاكرة) مع التحقق من الكشف تحت الضغط؛ وتظهر الكلفة فقط للأسعار التي تدخلها.'});}
      // CG-128 product self-defense posture.
      if(p==='/api/self-defense'&&method==='GET'){roles(['admin']);return send(res,200,selfDefense.posture());}
      // CG-127 SOC workflow.
      if(p==='/api/soc'&&method==='GET'){roles(['admin','analyst']);return send(res,200,socWorkflow.view());}
      if(p==='/api/soc/sla'&&method==='POST'){roles(['admin']);auth.requireRecentMfa(user);return send(res,200,socWorkflow.setSla(user.id,await body(req)));}
      if(p==='/api/soc/shifts'&&method==='POST'){roles(['admin']);return send(res,201,socWorkflow.addShift(user.id,await body(req)));}
      if(p==='/api/soc/escalations/run'&&method==='POST'){roles(['admin','analyst']);return send(res,200,{escalated:socWorkflow.escalate(user.id)});}
      if(p==='/api/soc/lessons'&&method==='POST'){roles(['admin','analyst']);return send(res,201,socWorkflow.addLesson(user.id,await body(req)));}
      if(p==='/api/soc/exercises'&&method==='POST'){roles(['admin','analyst']);return send(res,201,socWorkflow.planExercise(user.id,await body(req)));}
      {let m;
        if((m=p.match(/^\/api\/cases\/([a-f0-9-]{36})\/(assign|closure|closure-review)$/))&&method==='POST'){roles(['admin','analyst']);const input=await body(req);return send(res,200,m[2]==='assign'?socWorkflow.assign(user.id,m[1],input):m[2]==='closure'?socWorkflow.requestClosure(user.id,m[1],input):socWorkflow.reviewClosure(user.id,m[1],input.approve===true));}
        if((m=p.match(/^\/api\/soc\/lessons\/([a-f0-9-]{36})$/))&&method==='GET'){roles(['admin','analyst']);return send(res,200,socWorkflow.lesson(m[1]));}
        if((m=p.match(/^\/api\/soc\/lessons\/([a-f0-9-]{36})\/detection$/))&&method==='POST'){roles(['admin','analyst']);return send(res,201,socWorkflow.lessonToDetection(user.id,m[1],await body(req)));}
        if((m=p.match(/^\/api\/soc\/exercises\/([a-f0-9-]{36})\/complete$/))&&method==='POST'){roles(['admin','analyst']);return send(res,200,socWorkflow.completeExercise(user.id,m[1],await body(req)));}
      }
      // CG-126 data residency, export, erasure and tenant binding.
      if(p==='/api/data-governance'&&method==='GET'){roles(['admin']);return send(res,200,dataGovernance.view());}
      if(p==='/api/data-governance/residency'&&method==='POST'){roles(['admin']);auth.requireRecentMfa(user);return send(res,200,dataGovernance.declareRegion(user.id,await body(req)));}
      if(p==='/api/data-governance/export'&&method==='GET'){roles(['admin']);auth.requireRecentMfa(user);const x=dataGovernance.exportAll(user.id);res.writeHead(200,{'Content-Type':'application/x-ndjson; charset=utf-8','Content-Disposition':`attachment; filename="cyberguard-${tenant}-export.ndjson"`,'X-Export-SHA256':x.manifest.sha256});return res.end(x.body);}
      if(p==='/api/data-governance/erasures'&&method==='POST'){roles(['admin']);auth.requireRecentMfa(user);return send(res,201,dataGovernance.requestErasure(user.id,await body(req)));}
      {const m=p.match(/^\/api\/data-governance\/erasures\/([a-f0-9-]{36})\/approve$/);if(m&&method==='POST'){roles(['admin']);auth.requireRecentMfa(user);return send(res,200,dataGovernance.approveErasure(user.id,m[1],await body(req)));}}
      // CG-125 managed SOC regulatory readiness (NPMSOC-1:2024, RFMSOC-1:2024).
      if(p==='/api/msoc/readiness'&&method==='GET'){roles(['admin']);return send(res,200,msocReadiness.readiness());}
      if(p==='/api/msoc/provider'&&method==='POST'){roles(['admin']);auth.requireRecentMfa(user);return send(res,200,msocReadiness.saveProvider(user.id,await body(req)));}
      if(p==='/api/msoc/customers'&&method==='POST'){roles(['admin']);auth.requireRecentMfa(user);return send(res,201,msocReadiness.addCustomer(user.id,await body(req)));}
      // CG-124 NCA compliance evidence mapping (ECC-2:2024, CCC-2:2024; OTCC/CSCC/DCC applicability).
      if(p==='/api/compliance/nca'&&method==='GET') return send(res,200,ncaCompliance.view());
      if(p==='/api/compliance/nca/profile'&&method==='POST'){roles(['admin']);auth.requireRecentMfa(user);return send(res,200,ncaCompliance.saveProfile(user.id,await body(req)));}
      if(p==='/api/compliance/nca/export'&&method==='GET'){roles(['admin','analyst']);const v=ncaCompliance.view();store.audit(user.id,'compliance.evidence.exported','nca',{ecc:v.ecc.summary},new Date().toISOString());res.writeHead(200,{'Content-Type':'application/json; charset=utf-8','Content-Disposition':'attachment; filename="cyberguard-nca-evidence.json"'});return res.end(JSON.stringify({schema_version:'cg.nca-evidence/1',generated_at:new Date().toISOString(),...v},null,2));}
      // CG-123 AI evaluation and guardrails.
      if(p==='/api/ai-evaluation'&&method==='GET'){roles(['admin','analyst']);const usage=store.all("SELECT details FROM audit WHERE action='ai.cloud-analysis.completed' AND at>=?",new Date(Date.now()).toISOString().slice(0,10)+'T00:00:00.000Z').map(r=>JSON.parse(r.details));return send(res,200,{...aiEvaluation.view(),cloud_budget:{daily_limit:domain.aiCloudDailyLimit,used_today:usage.length,estimated_tokens_today:usage.reduce((n,u)=>n+(u.estimated_tokens||0),0)}});}
      if(p==='/api/ai-evaluation/run'&&method==='POST'){roles(['admin','analyst']);return send(res,200,aiEvaluation.run(user.id));}
      // CG-121 prompt-injection defense: policy, recent refusals and a scan endpoint for connectors.
      if(p==='/api/ai-guard'&&method==='GET'){roles(['admin','analyst']);const refused=store.all("SELECT at,actor,action,target,details FROM audit WHERE action='ai.proposal.rejected' ORDER BY seq DESC LIMIT 50").map(r=>({...r,details:JSON.parse(r.details)}));return send(res,200,{policy_sha256:POLICY_SHA256,policy:SYSTEM_POLICY,patterns:INJECTION_PATTERNS.map(x=>({id:x.id,severity:x.severity})),flagged_alerts:store.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-AI-INJECTION-121'").n,refusals:refused,claim:'Evidence is untrusted data: it is scanned for instructions, cleaned of hidden characters, labelled with its source and hash and kept apart from the fixed system policy. Proposals whose rationale carries instructions or whose target appears only in instructing text, and model answers that carry instructions, are refused.',claim_ar:'الأدلة بيانات غير موثوقة: تُفحص بحثًا عن تعليمات، وتُنظف من الأحرف المخفية، وتُوسم بمصدرها وبصمتها، وتُعزل عن سياسة النظام الثابتة. تُرفض المقترحات التي يحمل مبررها تعليمات أو يظهر هدفها فقط في نص يوجه التعليمات، وتُرفض إجابات النموذج التي تحمل تعليمات.'});}
      if(p==='/api/ai-guard/scan'&&method==='POST'){roles(['admin','analyst']);const input=object(await body(req),['items'],'ai_guard_scan');fail(Array.isArray(input.items)&&input.items.length>=1&&input.items.length<=50,400,'invalid_ai_guard_items');const env=promptEnvelope(input.items.map((x,i)=>{object(x,['source_type','source_ref','content'],`ai_guard_item_${i}`);return {source_type:choice(x.source_type,['log','email','ticket','search-result','document'],'ai_guard_source_type'),source_ref:text(x.source_ref,'ai_guard_source_ref',300),content:text(x.content,'ai_guard_content',20000)};}));return send(res,200,{policy_sha256:env.policy.sha256,data:env.data});}
      // CG-120 cross-provider playbooks.
      if(p==='/api/orchestrations'&&method==='GET'){roles(['admin','analyst']);return send(res,200,orchestrator.view());}
      if(p==='/api/orchestrations/plan'&&method==='POST'){roles(['admin','analyst']);const input=await body(req);return send(res,200,orchestrator.plan(String(input.playbook_id||''),String(input.asset_id||''),input.params||{}));}
      if(p==='/api/orchestrations'&&method==='POST'){roles(['admin']);auth.requireRecentMfa(user);return send(res,201,orchestrator.start(user.id,await body(req)));}
      {const m=p.match(/^\/api\/orchestrations\/([a-f0-9-]{36})\/advance$/);if(m&&method==='POST'){roles(['admin']);auth.requireRecentMfa(user);return send(res,200,orchestrator.advance(user.id,m[1]));}}
      // CG-119 safety tiers: confirmation, change windows and status.
      if(p==='/api/safety-tiers'&&method==='GET'){roles(['admin','analyst']);return send(res,200,safetyGate.view());}
      if(p==='/api/change-windows'&&method==='POST'){roles(['admin']);auth.requireRecentMfa(user);return send(res,201,safetyGate.addWindow(user.id,await body(req)));}
      {const m=p.match(/^\/api\/actions\/([a-f0-9-]{36})\/(confirm|safety-status)$/);if(m){roles(['admin']);if(m[2]==='safety-status'&&method==='GET')return send(res,200,safetyGate.status(m[1]));if(m[2]==='confirm'&&method==='POST'){auth.requireRecentMfa(user);return send(res,200,safetyGate.confirm(user.id,m[1],await body(req)));}}}
      // CG-118 control outcome verification.
      if(p==='/api/control-outcomes'&&method==='GET'){roles(['admin','analyst']);return send(res,200,controlOutcomes.list());}
      {const m=p.match(/^\/api\/control-outcomes\/([\w-]+)$/);if(m&&method==='GET'){roles(['admin','analyst']);const o=controlOutcomes.outcome(m[1]);fail(o,404,'not_found');return send(res,200,o);}}
      // CG-117 read-only response preflight report.
      if(p==='/api/response-preflight'&&method==='POST'){roles(['admin','analyst']);return send(res,200,responsePreflight.run(await body(req)));}
      // CG-116 hunt workbench.
      {let m;
        if(p==='/api/hunts/run'&&method==='POST'){roles(['admin','analyst']);return send(res,200,hunts.run(await body(req)));}
        if(p==='/api/hunts'&&method==='GET'){roles(['admin','analyst']);return send(res,200,{items:hunts.list()});}
        if(p==='/api/hunts'&&method==='POST'){roles(['admin','analyst']);return send(res,201,hunts.save(user.id,await body(req)));}
        if((m=p.match(/^\/api\/hunts\/([\w-]+)$/))&&method==='GET'){roles(['admin','analyst']);return send(res,200,hunts.get(m[1]));}
        if((m=p.match(/^\/api\/hunts\/([\w-]+)\/notes$/))&&method==='POST'){roles(['admin','analyst']);return send(res,201,hunts.note(user.id,m[1],await body(req)));}
        if((m=p.match(/^\/api\/hunts\/([\w-]+)\/reports$/))&&method==='POST'){roles(['admin','analyst']);return send(res,201,hunts.report(user.id,m[1],await body(req)));}
        if((m=p.match(/^\/api\/hunt-reports\/([\w-]+)$/))&&method==='GET'){roles(['admin','analyst']);return send(res,200,hunts.getReport(m[1]));}
      }
      // CG-115 detection validation lab (isolated synthetic scenarios and replay of stored events).
      if(p==='/api/validation-lab'&&method==='GET'){roles(['admin','analyst']);return send(res,200,validationLab.view());}
      if(p==='/api/validation-lab/run'&&method==='POST'){roles(['admin','analyst']);const input=await body(req);return send(res,200,input.scenario_id==='all'?validationLab.runAll(user.id):validationLab.runScenario(user.id,input.scenario_id));}
      if(p==='/api/validation-lab/replay'&&method==='POST'){roles(['admin','analyst']);return send(res,200,validationLab.replay(user.id,await body(req)));}
      // CG-114 evidence vault and chain of custody.
      {const q=k=>url.searchParams.get(k);let m;
        if((m=p.match(/^\/api\/cases\/([\w-]+)\/evidence$/))){roles(['admin','analyst']);if(method==='GET')return send(res,200,{items:evidenceVault.list(m[1])});if(method==='POST')return send(res,201,evidenceVault.collect(user.id,m[1],{name:q('name'),media_type:q('media_type'),source_ref:q('source_ref'),acquisition:q('acquisition'),collected_at:q('collected_at'),collected_by:q('collected_by'),expected_sha256:q('expected_sha256')},await rawBody(req,MAX_EVIDENCE_BYTES)));}
        if(p==='/api/evidence'&&method==='GET'){roles(['admin','analyst']);return send(res,200,{items:evidenceVault.list(null)});}
        if(p==='/api/evidence-integrity'&&method==='GET'){roles(['admin','analyst']);return send(res,200,evidenceVault.integrity(user.id));}
        if((m=p.match(/^\/api\/evidence\/([\w-]+)$/))&&method==='GET'){roles(['admin','analyst']);return send(res,200,evidenceVault.item(m[1]));}
        if((m=p.match(/^\/api\/evidence\/([\w-]+)\/content$/))&&method==='POST'){roles(['admin','analyst']);const {item,bytes}=evidenceVault.read(user.id,m[1],(await body(req)).purpose);res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Disposition':`attachment; filename="${encodeURIComponent(item.name)}"`,'X-Evidence-SHA256':item.sha256,'Cache-Control':'no-store'});return res.end(bytes);}
        if((m=p.match(/^\/api\/evidence\/([\w-]+)\/derive$/))&&method==='POST'){roles(['admin','analyst']);return send(res,201,evidenceVault.derive(user.id,m[1],{name:q('name'),transform:q('transform'),media_type:q('media_type')},await rawBody(req,MAX_EVIDENCE_BYTES)));}
        if((m=p.match(/^\/api\/evidence\/([\w-]+)\/verify$/))&&method==='POST'){roles(['admin','analyst']);return send(res,200,evidenceVault.verify(user.id,m[1]));}
        if((m=p.match(/^\/api\/evidence\/([\w-]+)\/custody-export$/))&&method==='POST'){roles(['admin','analyst']);return send(res,200,evidenceVault.exportCustody(user.id,m[1],(await body(req)).purpose));}
      }
      if(p==='/api/data-security'&&method==='GET') return send(res,200,domain.dataSecurity({allowedRegions:(url.searchParams.get('allowed_regions')||'').split(',').filter(Boolean)}));
      if(p==='/api/email-security'&&method==='GET') return send(res,200,domain.emailSecurity());
      if(p==='/api/web-security'&&method==='GET') return send(res,200,domain.webSecurity());
      if(p==='/api/supply-chain'&&method==='GET') return send(res,200,domain.supplyChain());
      if(p==='/api/kubernetes-security'&&method==='GET') return send(res,200,domain.kubernetesSecurity());
      if(p==='/api/cloud-detection-coverage'&&method==='GET') return send(res,200,domain.cloudDetectionCoverage());
      if(p==='/api/ocsf/export'&&method==='GET'){roles(['admin','analyst']);return send(res,200,domain.ocsfExport({hours:url.searchParams.get('hours')||24,limit:url.searchParams.get('limit')||1000}));}
      if(p==='/api/management-plane'&&method==='GET') return send(res,200,domain.managementPlane());
      if(p==='/api/ot-safety'&&method==='GET'){roles(['admin','analyst']);return send(res,200,otSafety.overview());}
      if(p==='/api/ot-safety/approvers'&&method==='POST'){auth.require(user,['admin']);auth.requireRecentMfa(user);return send(res,201,otSafety.designate(user.id,await body(req)));}
      if(p==='/api/ot-safety/approvals'&&method==='POST'){roles(['admin','analyst']);auth.requireRecentMfa(user);return send(res,201,otSafety.approve(user.id,await body(req)));}
      if(p==='/api/network-correlation'&&method==='GET') return send(res,200,domain.networkCorrelation());
      if(p==='/api/multi-signal-correlation'&&method==='GET') return send(res,200,domain.multiSignalCorrelation());
      if(p==='/api/nac-posture'&&method==='GET') return send(res,200,domain.nacPosture());
      if(p==='/api/network-posture'&&method==='GET') return send(res,200,domain.networkPosture());
      if(p==='/api/mobile-coverage'&&method==='GET') return send(res,200,domain.mobileCoverage());
      if(p==='/api/linux-security'&&method==='GET') return send(res,200,domain.linuxSecurity());
      if(p==='/api/file-triage'&&method==='GET'){roles(['admin','analyst']);return send(res,200,domain.fileTriage());}
      if(p==='/api/attack-surface'&&method==='GET') return send(res,200,domain.attackSurface());
      if(p==='/api/incident-studies'&&method==='GET') return send(res,200,domain.incidentStudies({q:url.searchParams.get('q')||''}));
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
      const remediationRoute=p.match(/^\/api\/alerts\/([a-f0-9-]{36})\/remediation$/);
      if(remediationRoute&&method==='GET') return send(res,200,domain.remediation(remediationRoute[1]));
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
        // CG-063 the final development prompt is generated only when every requirement is reviewed and accepted.
        const dp=developmentPromptReadiness(ROOT);
        return send(res,200,{scope:{from,to,total:scoped.length},summary:{completed,partial,pending:scoped.length-completed-partial,validation_level:'Unit Tested',production_validated:false},development_prompt:{ready:dp.ready,accepted:dp.accepted,in_scope:dp.in_scope,blockers:dp.blockers,command:'node scripts/development-prompt.js --write'},next_requirement:next?.id||null,items:matching.slice(offset,offset+limit),total:matching.length,limit,offset});
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
  return {server,store,auth,domain,secrets,tenancy,rollout,hypotheses,threatIntelligence,sandbox,otSafety,checkSecretRotation,setupFile,operatingMode:mode,scheme:tlsMaterial?'https':'http',certificate:tlsMaterial?tlsMaterial.cert:null,listen(port=4310,host='127.0.0.1'){
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
