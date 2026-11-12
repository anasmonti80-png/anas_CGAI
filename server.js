import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Store } from './lib/store.js';
import { Auth } from './lib/auth.js';
import { Domain } from './lib/domain.js';
import { localObservation } from './lib/local-collector.js';
import { normalizeWindowsExport } from './lib/windows-events.js';
import { AppError, fail, equal, object, page, token } from './lib/common.js';

const ROOT=fileURLToPath(new URL('./',import.meta.url));
const MIME={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml'};
const STATIC=new Set(['/','/app.js','/dashboard.js','/styles.css','/soc.css','/icon.svg']);
const COOKIE='Path=/; HttpOnly; SameSite=Strict';
const OPERATING_MODES=['pc-local','enterprise-collectors','authorized-defense-validation-lab'];
const readJson=p=>JSON.parse(fs.readFileSync(path.join(ROOT,p),'utf8'));
const trace=()=>fs.readFileSync(path.join(ROOT,'docs/engineering/TRACEABILITY.jsonl'),'utf8').trim().split('\n').map(JSON.parse);

async function body(req) {
  fail(String(req.headers['content-type']||'').split(';')[0].trim()==='application/json',415,'json_content_type_required');
  const chunks=[]; let size=0;
  for await (const chunk of req) { size+=chunk.length; fail(size<=2*1024*1024,413,'request_too_large'); chunks.push(chunk); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new AppError(400,'invalid_json'); }
}
function send(res,status,value) { res.writeHead(status,{'Content-Type':'application/json; charset=utf-8'}); res.end(JSON.stringify(value)); }

export function createApp({dataDir=process.env.CG_DATA_DIR||path.join(ROOT,'data'),clock,setupToken,browserQa=process.env.CG_BROWSER_QA==='1',mode=process.env.CG_MODE||'pc-local',labAuthorizationRef=process.env.CG_LAB_AUTHORIZATION_REF||null}={}) {
  fail(OPERATING_MODES.includes(mode),400,'invalid_operating_mode');
  fail(mode!=='authorized-defense-validation-lab'||(browserQa&&typeof labAuthorizationRef==='string'&&labAuthorizationRef.trim().length>=8),400,'lab_authorization_required');
  fs.mkdirSync(dataDir,{recursive:true,mode:0o700});
  const store=new Store(path.join(dataDir,'cyberguard.sqlite'));
  const auth=new Auth(store,{clock}), domain=new Domain(store,{clock});
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
  const server=http.createServer(async(req,res)=>{
    let authenticatedActor=null;
    res.setHeader('Cache-Control','no-store');
    res.setHeader('X-Content-Type-Options','nosniff');
    res.setHeader('Referrer-Policy','no-referrer');
    res.setHeader('X-Frame-Options','DENY');
    res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy',`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors ${browserQa?"'self'":"'none'"}`);
    try {
      const port=server.address()?.port;
      fail([`127.0.0.1:${port}`,`localhost:${port}`,`[::1]:${port}`].includes(req.headers.host),403,'host_not_allowed');
      rate(req);
      const url=new URL(req.url,`http://${req.headers.host}`), p=url.pathname, method=req.method;
      fail(['GET','POST'].includes(method),405,'method_not_allowed');
      const mutation=!['GET','HEAD'].includes(method);
      const bearer=String(req.headers.authorization||'').startsWith('Bearer ')?String(req.headers.authorization).slice(7):null;
      const ingest=p.match(/^\/api\/sources\/([a-f0-9-]{36})\/events$/);
      if(mutation) {
        fail(method==='POST',405,'method_not_allowed');
        if (!(bearer&&ingest)) fail(req.headers.origin===`http://${req.headers.host}`,403,'origin_not_allowed');
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
        const input=object(await body(req),['username','password'],'login');
        const session=await auth.login(input,req.socket.remoteAddress||'unknown');
        res.setHeader('Set-Cookie',`cg_session=${session.token}; ${COOKIE}; Max-Age=28800`);
        return send(res,200,{user:session.user,csrf:session.csrf});
      }
      if(bearer && ingest && method==='POST') {
        const source=domain.sourceToken(bearer,ingest[1]);
        return send(res,200,ingestInput(`source:${source.id}`,source.id,await body(req)));
      }
      const user=auth.session(req.headers.cookie);
      authenticatedActor=user.id;
      if(mutation) fail(equal(req.headers['x-csrf-token']||'',user.csrf),403,'csrf_required');
      const roles=(allowed)=>auth.require(user,allowed);
      if(p==='/api/auth/me'&&method==='GET') return send(res,200,{user:{id:user.id,username:user.username,role:user.role},csrf:user.csrf});
      if(p==='/api/auth/logout'&&method==='POST') {auth.logout(user);res.setHeader('Set-Cookie',`cg_session=; ${COOKIE}; Max-Age=0`);return send(res,200,{logged_out:true});}
      if(p==='/api/modes'&&method==='GET') return send(res,200,{active_mode:mode,lab_authorization_configured:mode==='authorized-defense-validation-lab',items:[
        {id:'pc-local',status:mode==='pc-local'?'active':'available',capabilities:['explicit local host inventory','manual evidence import'],limitations:['This host alone cannot see device-to-device traffic behind a switch.','No active network scan is performed.']},
        {id:'enterprise-collectors',status:mode==='enterprise-collectors'?'active':'available',capabilities:['independently authenticated source identities','passive import','SPAN/TAP observations','flow logs','managed agents'],limitations:['Visibility is limited to configured and currently receiving sources.','Connector availability is reported independently.']},
        {id:'authorized-defense-validation-lab',status:mode==='authorized-defense-validation-lab'?'active':'requires-explicit-authorization',capabilities:['isolated synthetic validation data','responsive browser QA harness'],limitations:['Requires CG_BROWSER_QA and a non-secret authorization reference at process start.','Never represents production validation.']}
      ]});
      if(p==='/api/users') {
        roles(['admin']);
        if(method==='GET') return send(res,200,{items:store.all('SELECT id,username,role,created_at FROM users ORDER BY username')});
        const input=object(await body(req),['username','password','role'],'user');
        fail(store.get('SELECT COUNT(*) n FROM users').n<100,409,'user_limit');
        return send(res,201,{user:await auth.createUser(user.id,input)});
      }
      if(p==='/api/overview'&&method==='GET') return send(res,200,domain.summary());
      if(p==='/api/dashboard'&&method==='GET') return send(res,200,domain.dashboard(url.searchParams.get('severity')||'all'));
      if(p==='/api/discovery'&&method==='GET') return send(res,200,domain.discovery(page(url.searchParams)));
      if(p==='/api/sources') {
        if(method==='GET') return send(res,200,{items:domain.sources()});
        roles(['admin']); return send(res,201,domain.createSource(user.id,await body(req)));
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
      if(sourceAction&&method==='POST') { roles(['admin']); return send(res,200,sourceAction[2]==='rotate'?domain.rotateSource(user.id,sourceAction[1]):domain.revokeSource(user.id,sourceAction[1])); }
      if(ingest&&method==='POST') {roles(['admin','analyst']);return send(res,200,ingestInput(user.id,ingest[1],await body(req)));}
      const tables={'/api/assets':'assets','/api/events':'events','/api/alerts':'alerts','/api/remote-sessions':'remote_sessions','/api/cases':'cases','/api/actions':'actions','/api/audit':'audit'};
      if(tables[p]&&method==='GET') {if(p==='/api/audit') roles(['admin']);return send(res,200,domain.list(tables[p],page(url.searchParams)));}
      const assetRoute=p.match(/^\/api\/assets\/([a-f0-9-]{36})(\/report)?$/);
      if(assetRoute&&method==='GET') return send(res,200,assetRoute[2]?domain.evidenceReport(assetRoute[1]):domain.asset(assetRoute[1]));
      const eventRoute=p.match(/^\/api\/events\/([a-f0-9-]{36})$/);
      if(eventRoute&&method==='GET') return send(res,200,domain.decode(store.require('SELECT * FROM events WHERE id=?',[eventRoute[1]])));
      const ack=p.match(/^\/api\/alerts\/([a-f0-9-]{36})\/ack$/);
      const alertRoute=p.match(/^\/api\/alerts\/([a-f0-9-]{36})$/);
      if(alertRoute&&method==='GET') return send(res,200,domain.decode(store.require('SELECT * FROM alerts WHERE id=?',[alertRoute[1]])));
      if(ack&&method==='POST') {roles(['admin','analyst']); return send(res,200,domain.acknowledge(user.id,ack[1]));}
      if(p==='/api/cases'&&method==='POST') {roles(['admin','analyst']);return send(res,201,domain.createCase(user.id,await body(req)));}
      const caseRoute=p.match(/^\/api\/cases\/([a-f0-9-]{36})(\/report)?$/);
      if(caseRoute) {
        if(method==='GET') return send(res,200,caseRoute[2]?domain.caseReport(caseRoute[1]):domain.decode(store.require('SELECT * FROM cases WHERE id=?',[caseRoute[1]])));
        fail(!caseRoute[2],405,'method_not_allowed');
        roles(['admin','analyst']); return send(res,200,domain.updateCase(user.id,caseRoute[1],await body(req)));
      }
      if(p==='/api/actions/preview'&&method==='POST') {roles(['admin','analyst']);return send(res,201,domain.previewAction(user.id,await body(req)));}
      const action=p.match(/^\/api\/actions\/([a-f0-9-]{36})\/(approve|execute|rollback)$/);
      const actionDetail=p.match(/^\/api\/actions\/([a-f0-9-]{36})$/);
      if(actionDetail&&method==='GET') return send(res,200,store.require('SELECT * FROM actions WHERE id=?',[actionDetail[1]]));
      if(action&&method==='POST') {roles(['admin']);const fn={approve:'approveAction',execute:'executeAction',rollback:'rollbackAction'}[action[2]];return send(res,200,domain[fn](user.id,action[1]));}
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
  });
  server.requestTimeout=15000; server.headersTimeout=10000; server.keepAliveTimeout=5000; server.maxHeadersCount=50;
  const monitor=setInterval(()=>{try{domain.checkHealth();monitorError=false;}catch{monitorError=true;}},30000); monitor.unref();
  return {server,store,auth,domain,setupFile,operatingMode:mode,listen(port=4310,host='127.0.0.1'){
    fail(['127.0.0.1','::1'].includes(host),400,'loopback_only');
    fail(Number.isInteger(port)&&port>=0&&port<=65535,400,'invalid_port');
    return new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,()=>{server.removeListener('error',reject);resolve(server.address());});});
  },async close(){clearInterval(monitor);if(server.listening){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}store.close();}};
}
if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const app=createApp();
  const port=Number(process.env.CG_PORT||4310);
  await app.listen(port);
  console.log(`CyberGuard AI engineering preview: http://127.0.0.1:${port}`);
  if(!app.store.get('SELECT id FROM users LIMIT 1')) console.log(`First-run token is in ${app.setupFile}. Keep it private; the file is removed after setup.`);
  for(const signal of ['SIGINT','SIGTERM']) process.once(signal,()=>app.close().then(()=>process.exit(0)));
}
