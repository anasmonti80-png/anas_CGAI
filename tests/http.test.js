import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { createApp } from '../server.js';

async function fixture(t,options={}) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cg-http-test-'));
  const setupToken=randomBytes(32).toString('hex'),password=randomBytes(20).toString('hex');
  let now=Date.now(); const app=createApp({...options,dataDir:dir,setupToken,clock:()=>now});
  const address=await app.listen(0), base=`http://127.0.0.1:${address.port}`;
  t.after(async()=>{await app.close();fs.rmSync(dir,{recursive:true,force:true});});
  async function req(p,{method='GET',data,user,headers={}}={}) {
    const response=await fetch(base+p,{method,headers:{...(data?{'Content-Type':'application/json','Origin':base}:{}),...(user?{'Cookie':user.cookie,'X-CSRF-Token':user.csrf}:{}),...headers},body:data?JSON.stringify(data):undefined});
    const result=await response.json();return {status:response.status,data:result,headers:response.headers};
  }
  async function setup(){return req('/api/auth/setup',{method:'POST',data:{setup_token:setupToken,username:'admin',password}});}
  async function login(username='admin',pass=password){const r=await req('/api/auth/login',{method:'POST',data:{username,password:pass}});assert.equal(r.status,200);return {cookie:r.headers.get('set-cookie').split(';')[0],csrf:r.data.csrf,...r.data.user};}
  return {app,dir,req,setup,login,password,base,advance:ms=>{now+=ms;}};
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
  assert.throws(()=>f.app.listen(0,'0.0.0.0'),/loopback_only/);
  assert.equal(path.resolve(f.app.store.filename),path.resolve(f.dir,'cyberguard.sqlite'));
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
  assert.equal((await f.req('/qa/responsive',{user:admin})).status,404);
  const refused=await f.req('/api/collectors/local',{method:'POST',user:admin,data:{confirm_read_only:false}});
  assert.equal(refused.status,400);assert.equal(f.app.store.get('SELECT COUNT(*) n FROM assets').n,0);
});

test('three explicit operating modes expose their capabilities and visibility boundaries without leaking lab authorization',async t=>{
  const local=await fixture(t);await local.setup();const localAdmin=await local.login();
  const health=await local.req('/api/health');assert.equal(health.data.operating_mode,'pc-local');
  const localModes=await local.req('/api/modes',{user:localAdmin});assert.equal(localModes.status,200);assert.equal(localModes.data.active_mode,'pc-local');assert.equal(localModes.data.items.length,3);
  const pc=localModes.data.items.find(x=>x.id==='pc-local'),enterprise=localModes.data.items.find(x=>x.id==='enterprise-collectors');
  assert.match(pc.limitations.join(' '),/cannot see device-to-device traffic behind a switch/);
  for(const capability of ['SPAN/TAP observations','flow logs','managed agents']) assert.ok(enterprise.capabilities.includes(capability));

  assert.throws(()=>createApp({mode:'invalid-mode'}),/invalid_operating_mode/);
  assert.throws(()=>createApp({mode:'authorized-defense-validation-lab',browserQa:true,labAuthorizationRef:null}),/lab_authorization_required/);
  assert.throws(()=>createApp({mode:'authorized-defense-validation-lab',browserQa:false,labAuthorizationRef:'AUTH-LAB-007'}),/lab_authorization_required/);

  const lab=await fixture(t,{mode:'authorized-defense-validation-lab',browserQa:true,labAuthorizationRef:'AUTH-LAB-007'});await lab.setup();const labAdmin=await lab.login();
  const labModes=await lab.req('/api/modes',{user:labAdmin});assert.equal(labModes.data.active_mode,'authorized-defense-validation-lab');assert.equal(labModes.data.lab_authorization_configured,true);
  assert.equal(labModes.data.items.find(x=>x.id==='authorized-defense-validation-lab').status,'active');assert.ok(!JSON.stringify(labModes.data).includes('AUTH-LAB-007'));
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
  const source=await f.req('/api/sources',{method:'POST',user:admin,data:{name:'API fixture',source_type:'managed-agent'}});assert.equal(source.status,201);assert.equal(source.data.source_type,'managed-agent');
  const batch={schema_version:'cg.telemetry/1',events:[{event_id:'e1',kind:'asset.observed',observed_at:new Date().toISOString(),asset:{external_id:'test-1',hostname:'LAB-API',addresses:['192.0.2.1']},details:{}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:batch,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);
  const overview=await f.req('/api/overview',{user:admin});assert.equal(overview.data.assets,1);assert.equal(overview.data.events,1);assert.equal(overview.data.prevention,'not-verified');
  const dashboard=await f.req('/api/dashboard?severity=critical',{user:admin});assert.equal(dashboard.status,200);assert.equal(dashboard.data.events,1);assert.ok(dashboard.data.security_score>0);assert.equal(dashboard.data.security_score_components.coverage,100);assert.match(dashboard.data.security_score_claim,/not a security guarantee/);assert.equal(dashboard.data.daily.length,28);
  const outcomes=await f.req('/api/security-outcomes',{user:admin});assert.equal(outcomes.status,200);assert.equal(outcomes.data.outcomes.length,6);assert.match(outcomes.data.claim,/not a compliance assessment/);
  assert.equal((await f.req('/api/dashboard?severity=invalid',{user:admin})).status,400);
  const discovery={schema_version:'cg.telemetry/1',events:[{...batch.events[0],event_id:'discovery-api-1',kind:'discovery.observed',details:{authorization_ref:'SYNTHETIC-HTTP-AUTH',acquisition:'passive-import',availability:'up',networks:['192.0.2.0/24'],routes:[{destination:'0.0.0.0/0',gateway:'192.0.2.254',interface:'uplink'}],vlans:[{id:10,name:'Synthetic'}],interfaces:[{name:'eth0',status:'up',vlan:10}],services:[{transport:'tcp',port:443,state:'observed-open',name:'https',evidence:'source-report'}]}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:discovery,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);
  const discoveryView=await f.req('/api/discovery?q=LAB-API',{user:admin});assert.equal(discoveryView.status,200);assert.equal(discoveryView.data.total,1);assert.equal(discoveryView.data.items[0].change,'added');assert.equal(discoveryView.data.items[0].observation.vlans[0].id,10);assert.match(discoveryView.data.scope,/no network probe/);
  const gapBatch={schema_version:'cg.telemetry/1',events:[{...batch.events[0],event_id:'gap-api-1',kind:'visibility.gap',details:{entity_type:'network',entity_ref:'192.0.2.0/24',reason:'no-span',last_seen:null,recommendation:'Configure an authorized SPAN or flow source.',status:'open'}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:gapBatch,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);
  const gaps=await f.req('/api/visibility-gaps?q=no-span',{user:admin});assert.equal(gaps.status,200);assert.equal(gaps.data.total,1);assert.equal(gaps.data.items[0].entity_type,'network');
  const sources=await f.req('/api/sources',{user:admin});assert.ok(!JSON.stringify(sources.data).includes(source.data.token));assert.ok(!JSON.stringify(sources.data).includes('token_hash'));assert.equal(sources.data.items[0].monitor_state,'agent-online');
  const assets=await f.req('/api/assets',{user:admin});const assetId=assets.data.items[0].id;
  const context={schema_version:'cg.telemetry/1',events:[{...batch.events[0],event_id:'context-api-1',kind:'asset.context',details:{owner:{owner_id:'api-owner',display_name:'Synthetic API owner',contact:null},business_service:'Synthetic service',service_name:'Evidence API',site:'Synthetic lab',data_sensitivity:'internal',maintenance_windows:['Friday 02:00-03:00 UTC'],service_criticality:'high'}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:context,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);const assetDetail=await f.req(`/api/assets/${assetId}`,{user:admin});assert.equal(assetDetail.data.governance_context.owner.owner_id,'api-owner');assert.equal(assetDetail.data.governance_context.service_criticality,'high');
  const lifecycle={schema_version:'cg.telemetry/1',events:[{...batch.events[0],event_id:'lifecycle-api-1',kind:'asset.lifecycle',details:{product:{vendor:'Synthetic Vendor',name:'Synthetic API Server',version:'1.0',edition:null},operating_system:{name:'Synthetic OS',version:'2026',build:'QA'},vendor_support:{status:'supported',standard_support_end:'2027-01-01T00:00:00.000Z',security_updates_end:'2029-01-01T00:00:00.000Z',extended_support:{available:true,enrolled:false,end_at:'2031-01-01T00:00:00.000Z'}},plan:{action:'replace',target:'Synthetic API Server 2.0',owner_id:'api-platform-owner',due_at:'2028-01-01T00:00:00.000Z',status:'planned'}}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:lifecycle,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);const lifecycleDetail=await f.req(`/api/assets/${assetId}`,{user:admin});assert.equal(lifecycleDetail.data.lifecycle.product.version,'1.0');assert.equal(lifecycleDetail.data.lifecycle.vendor_support.security_updates_end,'2029-01-01T00:00:00.000Z');assert.equal(lifecycleDetail.data.lifecycle.plan.action,'replace');
  const compatibility={schema_version:'cg.telemetry/1',events:[{...batch.events[0],event_id:'compatibility-api-1',kind:'asset.compatibility',details:{profile:'unsupported-linux',support_state:'end-of-support',agent:{status:'unknown',reason:'Synthetic HTTP fixture has no validated agent'},access_mode:'manual-import',read_only_supported:true,network_isolation:{required:true,status:'isolated',zone:'Synthetic API legacy zone'},tested_capabilities:[],performance_constraints:['Synthetic low-resource host'],licensing_constraints:['Synthetic entitlement not assessed'],recommendation:'Retain isolation and replace the unsupported platform',evidence_basis:{level:'not-tested',reference:null}}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:compatibility,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);const compatibilityMatrix=await f.req('/api/compatibility-matrix?q=unsupported-linux',{user:admin});assert.equal(compatibilityMatrix.status,200);assert.equal(compatibilityMatrix.data.total,1);assert.equal(compatibilityMatrix.data.items[0].asset.id,assetId);assert.equal(compatibilityMatrix.data.items[0].evidence_basis.level,'not-tested');
  const controls={schema_version:'cg.telemetry/1',events:[{...batch.events[0],event_id:'controls-api-1',kind:'asset.compensating_controls',details:{network_segmentation:{status:'partial',boundary:'Synthetic API legacy segment',evidence_ref:'SYNTHETIC-API-FW-077'},jump_host:{status:'enforced',host_ref:'SYNTHETIC-API-JUMP',evidence_ref:'SYNTHETIC-API-JUMP-077'},internet_access:{status:'restricted',exceptions:['Synthetic update relay'],evidence_ref:'SYNTHETIC-API-EGRESS-077'},entry_mfa:{status:'enforced',method:'Synthetic TOTP',evidence_ref:'SYNTHETIC-API-MFA-077'},backups:{status:'operational',last_success_at:'2026-11-10T02:00:00.000Z',restore_test_status:'not-tested',last_restore_test_at:null,evidence_ref:'SYNTHETIC-API-BACKUP-077'},monitoring:{status:'operational',coverage:'Synthetic API asset events',last_signal_at:'2026-11-11T20:00:00.000Z',evidence_ref:'SYNTHETIC-API-MONITOR-077'},migration:{status:'planned',owner_id:'api-platform-owner',target:'Synthetic supported API host',due_at:'2027-06-01T00:00:00.000Z'}}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:controls,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);const controlMatrix=await f.req('/api/compensating-controls?q=api-platform-owner',{user:admin});assert.equal(controlMatrix.status,200);assert.equal(controlMatrix.data.total,1);assert.equal(controlMatrix.data.items[0].asset.id,assetId);assert.equal(controlMatrix.data.items[0].backups.restore_test_status,'not-tested');
  const backupSecurity={schema_version:'cg.telemetry/1',events:[{...batch.events[0],event_id:'backup-security-api-1',kind:'resilience.backup_security',details:{backup_set_id:'API-BACKUP-078',copies:[{copy_id:'primary',platform:'Synthetic API backup',separation:'separate-account',immutability_support:'supported',immutability_status:'enabled',retention_days:30,encryption:'enabled'},{copy_id:'offsite',platform:'Synthetic API offsite',separation:'offsite',immutability_support:'unknown',immutability_status:'unknown',retention_days:60,encryption:'enabled'}],monitoring:{modification_events:'monitored',deletion_events:'monitored',last_signal_at:'2026-11-11T21:00:00.000Z',evidence_ref:'SYNTHETIC-API-MONITOR-078'},permissions:{model:'least-privilege',privileged_principal_count:2,review_status:'current',last_review_at:'2026-11-01T00:00:00.000Z',evidence_ref:'SYNTHETIC-API-ACCESS-078'}}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:backupSecurity,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);const backupMatrix=await f.req('/api/backup-security?q=API-BACKUP-078',{user:admin});assert.equal(backupMatrix.status,200);assert.equal(backupMatrix.data.total,1);assert.equal(backupMatrix.data.items[0].copies.length,2);assert.equal(backupMatrix.data.items[0].permissions.review_status,'current');
  const readiness={schema_version:'cg.telemetry/1',events:[{...batch.events[0],event_id:'restore-readiness-api-1',kind:'resilience.restore_readiness',details:{service:{service_id:'API-SERVICE-079',name:'Synthetic API service',owner_id:'api-service-owner'},objectives:{rpo_minutes:60,rto_minutes:120},backup_presence:'present',integrity:{status:'not-tested',checked_at:null,evidence_ref:null},schedule:{frequency_days:30,next_due_at:'2027-01-01T00:00:00.000Z'},restore_tests:[{test_id:'API-RESTORE-079',scheduled_at:'2026-11-12T00:00:00.000Z',executed_at:null,status:'not-run',scope:'Synthetic API restore',recovered_to_time:null,duration_minutes:null,evidence_ref:null}]}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:readiness,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);const readinessMatrix=await f.req('/api/restore-readiness?q=API-SERVICE-079',{user:admin});assert.equal(readinessMatrix.status,200);assert.equal(readinessMatrix.data.total,1);assert.equal(readinessMatrix.data.items[0].backup_presence,'present');assert.equal(readinessMatrix.data.items[0].recoverability_state,'unverified');
  const waiting={status:'not-started',started_at:null,completed_at:null,evidence_refs:[]},recovery={schema_version:'cg.telemetry/1',events:[{...batch.events[0],event_id:'incident-recovery-api-1',kind:'resilience.incident_recovery',details:{recovery_id:'API-RECOVERY-080',incident_ref:'API-INCIDENT-080',containment:{status:'completed',started_at:'2026-11-11T01:00:00.000Z',completed_at:'2026-11-11T02:00:00.000Z',evidence_refs:['SYNTHETIC-API-CONTAIN-080']},identity_recovery:{status:'in-progress',started_at:'2026-11-11T03:00:00.000Z',completed_at:null,evidence_refs:[]},configuration_recovery:waiting,device_recovery:waiting,threat_clearance:{...waiting,findings_remaining:0},reconnection:{...waiting,approved_by:null,approved_at:null}}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:recovery,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);const recoveryMatrix=await f.req('/api/incident-recovery?q=API-INCIDENT-080',{user:admin});assert.equal(recoveryMatrix.status,200);assert.equal(recoveryMatrix.data.total,1);assert.equal(recoveryMatrix.data.items[0].workflow_state,'recovering');
  const resilience={schema_version:'cg.telemetry/1',events:[{...batch.events[0],event_id:'resilience-controls-api-1',kind:'resilience.controls',details:{control_id:'API-RESILIENCE-081',scope:'Synthetic API management plane',network_configuration_backups:{status:'current',scope:'Synthetic API network devices',last_success_at:'2026-11-11T08:00:00.000Z',storage_separation:'offsite',evidence_ref:'SYNTHETIC-API-CONFIG-081'},out_of_band_management:{status:'degraded',path_ref:'SYNTHETIC-API-OOB',last_test_at:null,evidence_ref:null},alternate_management_connector:{status:'ready',connector_ref:'SYNTHETIC-API-ALT',last_test_at:'2026-11-11T08:45:00.000Z',evidence_ref:'SYNTHETIC-API-ALT-081'},soc_engine_outage_playbook:{status:'draft',playbook_ref:'SYNTHETIC-API-PLAYBOOK',last_exercised_at:null,evidence_ref:null},temporary_policy_fail_safe:{status:'unarmed',mode:'unknown',policy_scope:null,owner_id:null,expires_at:null,evidence_ref:null}}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:resilience,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);const resilienceMatrix=await f.req('/api/resilience-controls?q=API-RESILIENCE-081',{user:admin});assert.equal(resilienceMatrix.status,200);assert.equal(resilienceMatrix.data.total,1);assert.equal(resilienceMatrix.data.items[0].resilience_state,'not-ready');assert.equal(resilienceMatrix.data.items[0].alternate_management_connector.status,'ready');
  const directoryAudit={schema_version:'cg.telemetry/1',events:[{...batch.events[0],event_id:'directory-audit-api-1',kind:'identity.directory_audit',details:{audit_id:'API-DIRECTORY-AUDIT-082',directory:{directory_id:'API-DIR-082',type:'entra-id',domain_or_tenant:'api.synthetic.invalid'},tier0_control_plane:{status:'gaps',reviewed_at:'2026-11-11T08:00:00.000Z',evidence_ref:'SYNTHETIC-API-TIER0-082',principals:[]},domain_admin_changes:[],service_accounts:[{account_ref:'api-svc',privilege_scope:'Synthetic API',interactive_sign_in:'allowed',credential_rotation:'overdue',last_rotated_at:null,evidence_ref:'SYNTHETIC-API-SVC-082'}],trust_relationships:[],sign_in_policies:[{policy_ref:'API-POLICY-082',name:'Synthetic API sign-in',scope:'Synthetic users',status:'partial',mfa_requirement:'conditional',evidence_ref:'SYNTHETIC-API-POLICY-082'}]}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:directoryAudit,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);const directoryAudits=await f.req('/api/directory-audits?q=api.synthetic.invalid',{user:admin});assert.equal(directoryAudits.status,200);assert.equal(directoryAudits.data.total,1);assert.equal(directoryAudits.data.items[0].audit_state,'gaps');assert.equal(directoryAudits.data.items[0].service_account_gaps,1);
  const lapsPosture={schema_version:'cg.telemetry/1',events:[{...batch.events[0],event_id:'laps-posture-api-1',kind:'identity.laps_posture',details:{posture_id:'API-LAPS-083',policy:{status:'configured',policy_ref:'SYNTHETIC-API-LAPS-POLICY-083',rotation_days:30,evidence_ref:'SYNTHETIC-API-LAPS-POLICY-EVIDENCE-083'},local_administrator:{account_ref:'api-local-admin',management_state:'managed',evidence_ref:'SYNTHETIC-API-LAPS-ACCOUNT-083'},rotation:{status:'overdue',last_success_at:'2026-10-01T00:00:00.000Z',last_failure_at:null,failure_code:null,evidence_ref:'SYNTHETIC-API-LAPS-OVERDUE-083'},laps_access_audit:{status:'enabled',last_review_at:'2026-11-11T00:00:00.000Z',evidence_ref:'SYNTHETIC-API-LAPS-AUDIT-083',events:[]}}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:lapsPosture,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);const laps=await f.req('/api/laps-posture?q=API-LAPS-083',{user:admin});assert.equal(laps.status,200);assert.equal(laps.data.total,1);assert.equal(laps.data.items[0].posture_state,'gaps');assert.equal(laps.data.items[0].secret_values_collected,false);assert.ok(!JSON.stringify(laps.data).includes(source.data.token));
  const threatModel={schema_version:'cg.telemetry/1',events:[{...batch.events[0],event_id:'threat-model-api-1',kind:'governance.threat_model',details:{environment:{environment_id:'api-lab',name:'Synthetic API lab',scope:'Synthetic HTTP validation'},valuable_assets:[{asset_ref:'test-1',name:'LAB-API',value_reason:'Synthetic validation target'}],trust_boundaries:[{boundary_id:'api-edge',name:'Synthetic API edge',from_zone:'External',to_zone:'Lab',controls:['Source authentication']}],attack_scenarios:[{scenario_id:'api-entry',title:'Synthetic credential scenario',description:'Synthetic HTTP-only scenario',entry_point:'API',target_asset_refs:['test-1'],trust_boundary_refs:['api-edge'],likelihood:'low'}],service_outage_impact:{severity:'medium',description:'Synthetic lab API unavailable'},data_disclosure_impact:{severity:'high',description:'Synthetic lab evidence disclosed'}}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:threatModel,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);const threatModels=await f.req('/api/threat-models?q=api-lab',{user:admin});assert.equal(threatModels.status,200);assert.equal(threatModels.data.total,1);assert.equal(threatModels.data.items[0].valuable_assets[0].central_asset_ids[0],assetId);
  const evidenceId=(await f.req('/api/events',{user:admin})).data.items.find(item=>item.external_id==='e1').id;const riskRecord={schema_version:'cg.telemetry/1',events:[{...batch.events[0],event_id:'risk-api-1',kind:'governance.risk_record',details:{risk_id:'RISK-API-001',title:'Synthetic API risk',description:'Synthetic HTTP risk record',category:'api-availability',inherent_severity:'high',residual_severity:'medium',likelihood:'medium',status:'mitigating',coverage:{state:'partial',requirement_ids:['CG-073'],control_refs:['CTRL-API-01']},evidence_refs:[{type:'event',id:evidenceId}],owner:{owner_id:'api-risk-owner',display_name:'Synthetic API Risk Owner',contact:null},remediation:{status:'in-progress',plan:'Complete the synthetic HTTP control',due_at:'2026-12-01T00:00:00.000Z'},exception:{status:'none',reason:null,expires_at:null,approved_by:null},risk_acceptance:{status:'not-accepted',accepted_by:null,accepted_at:null,review_due_at:null,review_interval_days:null,rationale:null}}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:riskRecord,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);const riskRegister=await f.req('/api/risk-register?q=RISK-API',{user:admin});assert.equal(riskRegister.status,200);assert.equal(riskRegister.data.total,1);assert.equal(riskRegister.data.items[0].evidence_refs[0].resolved,true);assert.equal(riskRegister.data.items[0].owner.owner_id,'api-risk-owner');
  const report=await f.req(`/api/assets/${assetId}/report`,{user:admin});assert.equal(report.data.asset_id,assetId);assert.match(report.data.method,/no language model/);
  const finding={schema_version:'cg.telemetry/1',events:[{...batch.events[0],event_id:'finding-1',kind:'security.finding',details:{title:'Synthetic API finding',severity:'high',description:'Synthetic evidence only'}}]};
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:finding,headers:{Authorization:`Bearer ${source.data.token}`}})).status,200);
  const alert=(await f.req('/api/alerts',{user:admin})).data.items[0];
  const investigation=await f.req('/api/cases',{method:'POST',user:admin,data:{title:'Synthetic investigation',alert_ids:[alert.id]}});assert.equal(investigation.status,201);
  const caseReport=await f.req(`/api/cases/${investigation.data.id}/report`,{user:admin});assert.equal(caseReport.status,200);assert.equal(caseReport.data.events.length,1);assert.equal(caseReport.data.chain_of_custody.verification.valid,true);
  const revoked=await f.req(`/api/sources/${source.data.id}/revoke`,{method:'POST',user:admin,data:{}});assert.equal(revoked.status,200);
  assert.equal((await f.req(`/api/sources/${source.data.id}/events`,{method:'POST',data:batch,headers:{Authorization:`Bearer ${source.data.token}`}})).status,401);
  assert.equal((await f.req('/api/audit/verify',{user:admin})).data.valid,true);
  const coverage=await f.req('/api/coverage',{user:admin});
  const accomplishments=await f.req('/api/accomplishments?from=1&to=600&limit=10',{user:admin});
  assert.equal(accomplishments.status,200);assert.equal(accomplishments.data.scope.total,600);assert.equal(accomplishments.data.items.length,10);
  assert.equal(accomplishments.data.summary.completed,coverage.data.verified);assert.match(accomplishments.data.next_requirement,/^CG-\d{3,4}$/);
  assert.equal((await f.req('/api/accomplishments?from=0&to=600',{user:admin})).status,400);
  assert.equal((await f.req('/api/accomplishments?from=500&to=601',{user:admin})).status,400);
  assert.equal((await f.req('/api/requirements?q=CG-1440',{user:admin})).data.items[0].id,'CG-1440');
  assert.equal((await f.req('/api/auth/logout',{method:'POST',user:admin,data:{}})).status,200);
  assert.equal((await f.req('/api/assets',{user:admin})).status,401);
});
test('login attempts are bounded and unknown accounts use the same public failure',async t=>{
  const f=await fixture(t);await f.setup();
  for(let i=0;i<9;i++) assert.equal((await f.req('/api/auth/login',{method:'POST',data:{username:'missing',password:f.password}})).status,401);
  assert.equal((await f.req('/api/auth/login',{method:'POST',data:{username:'admin',password:f.password}})).status,429);
});
