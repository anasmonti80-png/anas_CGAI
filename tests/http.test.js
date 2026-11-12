import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { createApp } from '../server.js';

async function fixture(t) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cg-http-test-'));
  const setupToken=randomBytes(32).toString('hex'),password=randomBytes(20).toString('hex');
  let now=Date.now(); const app=createApp({dataDir:dir,setupToken,clock:()=>now});
  const address=await app.listen(0), base=`http://127.0.0.1:${address.port}`;
  t.after(async()=>{await app.close();fs.rmSync(dir,{recursive:true,force:true});});
  async function req(p,{method='GET',data,user,headers={}}={}) {
    const response=await fetch(base+p,{method,headers:{...(data?{'Content-Type':'application/json','Origin':base}:{}),...(user?{'Cookie':user.cookie,'X-CSRF-Token':user.csrf}:{}),...headers},body:data?JSON.stringify(data):undefined});
    const result=await response.json();return {status:response.status,data:result,headers:response.headers};
  }
  async function setup(){return req('/api/auth/setup',{method:'POST',data:{setup_token:setupToken,username:'admin',password}});}
  async function login(username='admin',pass=password){const r=await req('/api/auth/login',{method:'POST',data:{username,password:pass}});assert.equal(r.status,200);return {cookie:r.headers.get('set-cookie').split(';')[0],csrf:r.data.csrf,...r.data.user};}
  return {app,req,setup,login,password,base,advance:ms=>{now+=ms;}};
}
test('first-run setup is token-gated, one-time, and creates hashed credentials and secure session attributes',async t=>{
  const f=await fixture(t);
  assert.equal((await f.req('/api/setup/status')).data.setup_required,true);
  assert.equal((await f.req('/api/auth/setup',{method:'POST',data:{setup_token:'wrong',username:'admin',password:f.password}})).status,403);
  assert.equal((await f.setup()).status,201);assert.equal((await f.setup()).status,409);
  const stored=f.app.store.get('SELECT password_hash FROM users');assert.ok(!stored.password_hash.includes(f.password));
  const login=await f.req('/api/auth/login',{method:'POST',data:{username:'admin',password:f.password}});
  assert.equal(login.status,200);assert.match(login.headers.get('set-cookie'),/HttpOnly; SameSite=Strict/);
  assert.ok(!JSON.stringify(login.data).includes(f.password));
  const user=await f.login();assert.equal((await f.req('/api/auth/me',{user})).status,200);
  f.advance(31*60*1000);assert.equal((await f.req('/api/auth/me',{user})).status,401);
});
test('unauthenticated, cross-origin, forged host, CSRF and viewer mutations are rejected',async t=>{
  const f=await fixture(t);await f.setup();const admin=await f.login();
  assert.equal((await f.req('/api/assets')).status,401);
  const create={method:'POST',data:{name:'test-source'},user:admin};
  assert.equal((await f.req('/api/sources',{...create,headers:{Origin:'https://untrusted.example'}})).status,403);
  assert.equal((await f.req('/api/sources',{...create,headers:{'X-CSRF-Token':'wrong'}})).status,403);
  const forgedHostStatus=await new Promise((resolve,reject)=>{
    const request=http.get(f.base+'/api/health',{headers:{Host:'evil.example'}},response=>{response.resume();resolve(response.statusCode);});
    request.on('error',reject);
  });
  assert.equal(forgedHostStatus,403);
  assert.equal((await f.req('/api/users',{method:'POST',user:admin,data:{username:'viewer',password:f.password,role:'viewer'}})).status,201);
  const viewer=await f.login('viewer');
  assert.equal((await f.req('/api/assets',{user:viewer})).status,200);
  for(const p of ['/api/sources','/api/users','/api/cases','/api/actions/preview']) assert.equal((await f.req(p,{method:'POST',user:viewer,data:{}})).status,403);
  assert.equal((await f.req('/api/audit',{user:viewer})).status,403);
  const denied=await f.req('/api/audit?limit=100',{user:admin});
  assert.ok(denied.data.items.some(x=>x.action==='request.denied' && x.actor===viewer.id));
  assert.equal((await f.req('/api/assets?limit=1000',{user:admin})).status,400);
  assert.equal((await f.req('/api/assets?offset=-1',{user:admin})).status,400);
});

test('unsupported HTTP methods cannot mutate routes that accept both reads and writes',async t=>{
  const f=await fixture(t);await f.setup();const admin=await f.login();
  for(const method of ['HEAD','PUT','PATCH','DELETE']) {
    const response=await fetch(f.base+'/api/users',{method,headers:{Cookie:admin.cookie}});
    assert.equal(response.status,405);
  }
  assert.equal(f.app.store.get('SELECT COUNT(*) n FROM users').n,1);
  for(const resource of ['/','/app.js','/dashboard.js','/styles.css','/soc.css','/icon.svg']) {
    const r=await fetch(f.base+resource);
    assert.equal(r.status,200);
    assert.equal(r.headers.get('x-content-type-options'),'nosniff');
    assert.match(r.headers.get('content-security-policy'),/default-src 'none'/);
  }
  const refused=await f.req('/api/collectors/local',{method:'POST',user:admin,data:{confirm_read_only:false}});
  assert.equal(refused.status,400);assert.equal(f.app.store.get('SELECT COUNT(*) n FROM assets').n,0);
});

test('Windows export HTTP import records parser provenance, reports skipped records and deduplicates safely',async t=>{
  const f=await fixture(t);await f.setup();const admin=await f.login();
  const source=(await f.req('/api/sources',{method:'POST',user:admin,data:{name:'Windows synthetic HTTP'}})).data;
  const now=Date.now();
  const record={event_id:4624,record_id:10,time_created:new Date(now-60000).toISOString(),provider:'Microsoft-Windows-Security-Auditing',channel:'Security',data:{LogonType:'10',TargetLogonId:'0x100',TargetUserName:'synthetic-user',IpAddress:'192.0.2.15'}};
  const data={schema_version:'cg.windows-export/1',computer:'SYNTHETIC-WIN',boot_time:new Date(now-3600000).toISOString(),events:[record,{...record,record_id:11,data:{LogonType:'3'}}]};
  const request={method:'POST',user:admin,data};
  const imported=await f.req(`/api/sources/${source.id}/events`,request);
  assert.equal(imported.status,200);assert.equal(imported.data.accepted,1);assert.equal(imported.data.parser_report.skipped.length,1);
  const sessions=(await f.req('/api/remote-sessions',{user:admin})).data.items;
  assert.equal(sessions[0].phase,'authenticated');assert.equal(sessions[0].source_a.account,null);
  const events=(await f.req('/api/events',{user:admin})).data.items;
  assert.equal(events[0].payload.origin.parser,'windows-security/1');
  assert.equal((await f.req(`/api/sources/${source.id}/events`,request)).data.duplicates,1);
  const invalid={...data,events:[{...record,record_id:20},{...record,record_id:21,unexpected:'reject'}]};
  assert.equal((await f.req(`/api/sources/${source.id}/events`,{...request,data:invalid})).status,400);
  assert.equal((await f.req('/api/events',{user:admin})).data.total,1);
});
test('real HTTP ingestion persists evidence, exposes actual metrics and keeps collector tokens out of reads',async t=>{
  const f=await fixture(t);await f.setup();const admin=await f.login();
  const source=await f.req('/api/sources',{method:'POST',user:admin,data:{name:'API fixture'}});assert.equal(source.status,201);
  const batch={schema_version:'cg.telemetry/1',events:[{event_id:'e1',kind:'asset.observed',observed_at:new Date().toISOString(),asset:{external_id:'test-1',hostname:'LAB-API',addresses:['192.0.2.1']},details:{}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:batch,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);
  const overview=await f.req('/api/overview',{user:admin});assert.equal(overview.data.assets,1);assert.equal(overview.data.events,1);assert.equal(overview.data.prevention,'not-verified');
  const dashboard=await f.req('/api/dashboard?severity=critical',{user:admin});assert.equal(dashboard.status,200);assert.equal(dashboard.data.events,1);assert.equal(dashboard.data.security_score,null);assert.equal(dashboard.data.daily.length,28);
  assert.equal((await f.req('/api/dashboard?severity=invalid',{user:admin})).status,400);
  const sources=await f.req('/api/sources',{user:admin});assert.ok(!JSON.stringify(sources.data).includes(source.data.token));assert.ok(!JSON.stringify(sources.data).includes('token_hash'));
  const assets=await f.req('/api/assets',{user:admin});const assetId=assets.data.items[0].id;
  const report=await f.req(`/api/assets/${assetId}/report`,{user:admin});assert.equal(report.data.asset_id,assetId);assert.match(report.data.method,/no language model/);
  const finding={schema_version:'cg.telemetry/1',events:[{...batch.events[0],event_id:'finding-1',kind:'security.finding',details:{title:'Synthetic API finding',severity:'high',description:'Synthetic evidence only'}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:finding,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);
  const alert=(await f.req('/api/alerts',{user:admin})).data.items[0];
  const investigation=await f.req('/api/cases',{method:'POST',user:admin,data:{title:'Synthetic investigation',alert_ids:[alert.id]}});assert.equal(investigation.status,201);
  const caseReport=await f.req(`/api/cases/${investigation.data.id}/report`,{user:admin});assert.equal(caseReport.status,200);assert.equal(caseReport.data.events.length,1);assert.equal(caseReport.data.chain_of_custody.verification.valid,true);
  const revoked=await f.req(`/api/sources/${source.data.id}/revoke`,{method:'POST',user:admin,data:{}});assert.equal(revoked.status,200);
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:batch,headers:{Authorization:`Bearer ${source.data.token}`}})).status,401);
  assert.equal((await f.req('/api/audit/verify',{user:admin})).data.valid,true);
  assert.equal((await f.req('/api/coverage',{user:admin})).data.verified,0);
  assert.equal((await f.req('/api/requirements?q=CG-1440',{user:admin})).data.items[0].id,'CG-1440');
  assert.equal((await f.req('/api/auth/logout',{method:'POST',user:admin,data:{}})).status,200);
  assert.equal((await f.req('/api/assets',{user:admin})).status,401);
});
test('login attempts are bounded and unknown accounts use the same public failure',async t=>{
  const f=await fixture(t);await f.setup();
  for(let i=0;i<9;i++) assert.equal((await f.req('/api/auth/login',{method:'POST',data:{username:'missing',password:f.password}})).status,401);
  assert.equal((await f.req('/api/auth/login',{method:'POST',data:{username:'admin',password:f.password}})).status,429);
});
