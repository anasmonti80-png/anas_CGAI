import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { redact } from '../lib/common.js';

function fixture(t) {
  const s=new Store(':memory:'); t.after(()=>s.close());
  let now=Date.parse('2026-11-11T10:00:00.000Z');
  const d=new Domain(s,{clock:()=>now});
  for(const id of ['admin-a','admin-b','analyst']) s.run('INSERT INTO users VALUES (?,?,?,?,?)',id,id,'fixture-not-a-password-hash',id==='analyst'?'analyst':'admin',new Date(now).toISOString());
  const source=d.createSource('admin-a',{name:'Synthetic lab',stale_seconds:60});
  const event=(id,kind='asset.observed',details={},asset={})=>({event_id:id,kind,observed_at:new Date(now).toISOString(),asset:{external_id:'synthetic-01',hostname:'LAB-01',os_family:'windows',device_type:'workstation',addresses:['192.0.2.10'],...asset},details});
  const ingest=events=>d.ingest('admin-a',source.id,{schema_version:'cg.telemetry/1',events});
  return {s,d,source,event,ingest,advance:ms=>{now+=ms;}};
}

test('SOC dashboard uses actual counts and exposes a bounded evidence-readiness score without claiming security',t=>{
  const {d,event,ingest,advance}=fixture(t);
  let dash=d.dashboard();
  assert.equal(dash.daily.length,28);assert.ok(dash.daily.every(day=>day.events===0&&day.alerts===0));
  for(const key of ['security_score','vulnerability_scan','mean_detection_minutes','mean_acknowledge_minutes'])assert.equal(dash[key],null);
  ingest([event('reported','security.finding',{severity:'critical',title:'SYNTHETIC critical',description:'Synthetic only'}),event('observed')]);
  dash=d.dashboard();assert.equal(dash.events,2);assert.equal(dash.daily.at(-1).events,2);assert.equal(dash.severity_counts.critical,1);
  assert.equal(dash.security_score,1000);assert.deepEqual(dash.security_score_components,{coverage:100,evidence:100,freshness:100,confidence:100});
  assert.match(dash.security_score_claim,/not a security guarantee/);assert.deepEqual(dash.security_score_scope,{configured_sources:1,observed_assets:1,evidence_events:2});
  assert.equal(d.dashboard('low').recent_alerts.length,0);assert.equal(d.dashboard('critical').recent_alerts.length,1);
  advance(30000);d.acknowledge('admin-a',dash.recent_alerts[0].id);
  const older=d.dashboard();assert.equal(older.mean_acknowledge_minutes,.5);assert.equal(older.mean_detection_minutes,null);assert.ok(older.security_score<dash.security_score);assert.equal(older.security_score_components.freshness,50);
  assert.throws(()=>d.dashboard('invalid'),/invalid_severity/);
});
test('source credentials are hashed, scoped, rotatable and revocable',t=>{
  const {s,d,source}=fixture(t);
  assert.notEqual(s.get('SELECT token_hash FROM sources').token_hash,source.token);
  assert.equal(d.sourceToken(source.token,source.id).id,source.id);
  assert.throws(()=>d.sourceToken(source.token,'different-source'),/invalid_source_token/);
  const rotated=d.rotateSource('admin-a',source.id);
  assert.throws(()=>d.sourceToken(source.token,source.id),/invalid_source_token/);
  d.sourceToken(rotated.token,source.id);
  d.revokeSource('admin-a',source.id);
  assert.throws(()=>d.sourceToken(rotated.token,source.id),/invalid_source_token/);
  assert.equal(d.sources()[0].health,'revoked');
});
test('ingestion is durable, idempotent, atomic and rejects changed event identifiers',t=>{
  const {s,d,event,ingest}=fixture(t);
  const e=event('one');
  assert.equal(ingest([e]).accepted,1);
  assert.equal(ingest([e]).duplicates,1);
  assert.equal(d.summary().events,1);
  const changed={...e,asset:{...e.asset,hostname:'changed'}};
  assert.throws(()=>ingest([event('two'),changed]),/event_id_content_conflict/);
  assert.equal(s.get('SELECT COUNT(*) n FROM events').n,1);
  assert.throws(()=>ingest([event('two'),{...e,event_id:'three',kind:'shell.execute'}]),/invalid_event_kind/);
  assert.equal(s.get('SELECT COUNT(*) n FROM events').n,1);
  assert.equal(s.verifyAudit().valid,true);
});
test('shared IP does not merge DHCP identities and older observations do not overwrite new identity',t=>{
  const {d,event,ingest,advance}=fixture(t);
  const earlier=event('old');
  ingest([earlier,event('other','asset.observed',{}, {external_id:'synthetic-02'})]);
  advance(10000); ingest([event('new','asset.observed',{}, {hostname:'NEW-NAME'})]);
  ingest([{...earlier,event_id:'late'}]);
  assert.equal(d.list('assets').total,2);
  assert.equal(d.list('assets',{q:'NEW-NAME'}).total,1);
});
test('authorized passive discovery preserves topology evidence and reports additions, changes and outages',t=>{
  const {d,event,ingest,advance}=fixture(t);
  const details={authorization_ref:'AUTH-LAB-001',acquisition:'passive-import',availability:'up',networks:['192.0.2.0/24'],routes:[{destination:'0.0.0.0/0',gateway:'192.0.2.1',interface:'uplink'}],vlans:[{id:10,name:'Synthetic lab'}],interfaces:[{name:'Gi1/0/1',status:'up',vlan:10}],services:[{transport:'tcp',port:443,state:'observed-open',name:'https',evidence:'source-report'}]};
  ingest([event('discovery-1','discovery.observed',details,{device_type:'switch',os_family:'network'})]);
  let discovered=d.discovery();assert.equal(discovered.total,1);assert.equal(discovered.items[0].change,'added');assert.equal(discovered.items[0].observation.authorization_ref,'AUTH-LAB-001');assert.equal(discovered.items[0].observation.routes[0].destination,'0.0.0.0/0');assert.equal(discovered.items[0].observation.services[0].port,443);
  assert.ok(d.list('alerts',{limit:20}).items.some(alert=>alert.rule_id==='CG-ASSET-ADDED'));
  advance(1000);ingest([event('discovery-2','discovery.observed',{...details,vlans:[...details.vlans,{id:20,name:'Synthetic guest'}]},{device_type:'switch',os_family:'network'})]);
  discovered=d.discovery({q:'LAB-01'});assert.equal(discovered.items[0].change,'changed');assert.equal(discovered.items[0].observation.vlans.length,2);
  advance(1000);ingest([event('discovery-3','discovery.observed',{...details,availability:'down'},{device_type:'switch',os_family:'network'})]);
  discovered=d.discovery();assert.equal(discovered.items[0].change,'unavailable');assert.ok(d.list('alerts',{limit:20}).items.some(alert=>alert.rule_id==='CG-ASSET-UNREACHABLE'));
  assert.throws(()=>ingest([event('public-discovery','discovery.observed',details,{addresses:['8.8.8.8']})]),/public_discovery_address_not_allowed/);
  assert.throws(()=>ingest([event('active-scan','discovery.observed',{...details,acquisition:'active-scan'})]),/invalid_acquisition/);
  assert.equal(redact({authorization:'secret',authorization_ref:'AUTH-REF'}).authorization,'[REDACTED]');assert.equal(redact({authorization_ref:'AUTH-REF'}).authorization_ref,'AUTH-REF');
});
test('network service ports never replace or merge with physical switch interfaces',t=>{
  const {d,event,ingest}=fixture(t);
  const details={authorization_ref:'AUTH-PORT-TYPES',acquisition:'authenticated-collector',availability:'up',networks:['192.0.2.0/24'],routes:[],vlans:[{id:22,name:'Synthetic'}],interfaces:[{name:'Gi1/0/22',status:'up',vlan:22}],services:[{transport:'udp',port:53,state:'observed-open',name:'dns',evidence:'authenticated-observation'}]};
  ingest([event('typed-ports','discovery.observed',details,{device_type:'switch',os_family:'network'})]);
  const observation=d.discovery().items[0].observation;
  assert.deepEqual(observation.interfaces,[{name:'Gi1/0/22',status:'up',vlan:22}]);
  assert.deepEqual(observation.services,[{transport:'udp',port:53,state:'observed-open',name:'dns',evidence:'authenticated-observation'}]);
  assert.equal(Object.hasOwn(observation.interfaces[0],'port'),false);assert.equal(Object.hasOwn(observation.services[0],'vlan'),false);
});
test('visibility evidence accepts SPAN/TAP, flow-log and managed-agent acquisition paths independently',t=>{
  const {d,event,ingest,advance}=fixture(t);
  const base={authorization_ref:'AUTH-VISIBILITY-008',availability:'up',networks:['192.0.2.0/24'],routes:[],vlans:[],interfaces:[],services:[]};
  for(const [index,acquisition] of ['span-tap','flow-logs','agent'].entries()) {
    ingest([event(`visibility-${index}`,'discovery.observed',{...base,acquisition},{external_id:`visibility-${index}`,hostname:`VISIBILITY-${index}`})]);
    advance(1);
  }
  const items=d.discovery({limit:10}).items;assert.equal(items.length,3);assert.deepEqual(new Set(items.map(x=>x.observation.acquisition)),new Set(['span-tap','flow-logs','agent']));
});
test('unsupported fields, secret-bearing text and future timestamps are handled safely',t=>{
  const {s,event,ingest}=fixture(t);
  assert.throws(()=>ingest([{...event('invalid'),command:'whoami'}]),/unknown_event_field/);
  assert.throws(()=>ingest([{...event('future'),observed_at:'2030-01-01T00:00:00.000Z'}]),/invalid_observed_at/);
  ingest([event('secret','security.finding',{title:'Synthetic report',severity:'high',description:'password=fixture-value Authorization: Bearer abcdefgh token="secret-value"'})]);
  const stored=s.get('SELECT payload,original_sha256,sanitized_sha256 FROM events');
  assert.ok(!stored.payload.includes('fixture-value'));
  assert.ok(!stored.payload.includes('secret-value'));
  assert.ok(!stored.payload.includes('abcdefgh'));
  assert.notEqual(stored.original_sha256,stored.sanitized_sha256);
  assert.equal(redact({password:'x'}).password,'[REDACTED]');
});
test('open port is exposure only; active sessions require session evidence and relay keeps A unknown',t=>{
  const {d,event,ingest,advance}=fixture(t);
  const details={session_id:'s1',protocol:'rdp',source_a:{ip:'192.0.2.20',account:'synthetic-source'},target_b:{ip:'192.0.2.10',account:'synthetic-target'},evidence_type:'port_observation'};
  ingest([event('port','remote.port_open',details)]);
  assert.equal(d.list('remote_sessions').items[0].phase,'port_open');
  assert.throws(()=>ingest([event('bad','remote.active',details)]),/invalid_evidence_type/);
  advance(1000); ingest([event('session','remote.active',{...details,evidence_type:'session_log'})]);
  const session=d.list('remote_sessions').items[0];
  assert.equal(session.phase,'active');
  assert.equal(session.source_a.account,'synthetic-source');
  assert.equal(session.target_b.account,'synthetic-target');
  advance(1000);ingest([event('port-later','remote.port_open',details)]);
  assert.equal(d.list('remote_sessions').items[0].phase,'active');
  ingest([event('relay','remote.active',{...details,session_id:'s2',protocol:'anydesk',relay:true,evidence_type:'session_log'})]);
  const relay=d.list('remote_sessions').items.find(x=>x.session_key==='s2');
  assert.deepEqual(relay.source_a,{hostname:null,ip:null,account:null});
});
test('remote access separates application presence from confirmed sessions and evidence-backed authorized or suspicious assessment',t=>{
  const {d,event,ingest,advance}=fixture(t);
  const parties={source_a:{ip:'192.0.2.20',account:'synthetic-source'},target_b:{ip:'192.0.2.10',account:'synthetic-target'},relay:false};
  ingest([event('app-present','remote.application_present',{session_id:'app-anydesk',protocol:'anydesk',...parties,evidence_type:'software_inventory',assessment:'unknown',assessment_basis:'source-report'})]);
  advance(1);ingest([event('authorized-session','remote.active',{session_id:'authorized-rdp',protocol:'rdp',...parties,evidence_type:'session_log',assessment:'authorized',assessment_basis:'policy-match',authorization_ref:'AUTH-REMOTE-016'})]);
  advance(1);ingest([event('suspicious-attempt','remote.attempt',{session_id:'suspicious-ssh',protocol:'ssh',...parties,evidence_type:'connection_attempt',assessment:'suspicious',assessment_basis:'analyst-reviewed',rationale:'Synthetic policy mismatch'})]);
  const sessions=Object.fromEntries(d.list('remote_sessions',{limit:20}).items.map(session=>[session.session_key,session]));
  assert.equal(sessions['app-anydesk'].phase,'application_present');assert.equal(sessions['app-anydesk'].confidence,'unknown');
  assert.equal(sessions['authorized-rdp'].phase,'active');assert.equal(sessions['authorized-rdp'].confidence,'authorized');
  assert.equal(sessions['suspicious-ssh'].phase,'attempt');assert.equal(sessions['suspicious-ssh'].confidence,'suspicious');
  assert.ok(d.list('alerts',{limit:20}).items.some(alert=>alert.rule_id==='CG-REMOTE-SUSPICIOUS'));
  assert.throws(()=>ingest([event('bad-authorized','remote.active',{session_id:'bad',protocol:'rdp',...parties,evidence_type:'session_log',assessment:'authorized'})]),/authorized_remote_requires_reference/);
});
test('protection separates installed/running/collection from independently tested prevention',t=>{
  const {d,event,ingest}=fixture(t);
  ingest([event('p1','protection.observed',{engine:'Fixture engine',installed:true,running:false,collecting:false,mode:'unknown'})]);
  const a=d.list('assets').items[0];
  assert.equal(a.protection.installed,true);
  assert.equal(a.protection.running,false);
  assert.equal(a.protection.prevention_verified,false);
  assert.equal(d.list('alerts').items[0].rule_id,'CG-PROTECTION-NOT-RUNNING');
  assert.throws(()=>ingest([event('p2','protection.observed',{engine:'Fixture engine',installed:false,running:true,collecting:false,mode:'active'})]),/running_requires_installed/);
});
test('five failed authentications correlate by target account/source and alerts are deduplicated',t=>{
  const {d,event,ingest,advance}=fixture(t);
  for(let i=0;i<4;i++) {ingest([event(`fail-${i}`,'auth.failed',{account:'lab-user',source_ip:'192.0.2.20',protocol:'rdp'})]);advance(1000);}
  assert.equal(d.list('alerts').total,0);
  ingest([event('unrelated','auth.failed',{account:'other-user',source_ip:'192.0.2.20',protocol:'rdp'})]);
  assert.equal(d.list('alerts').total,0);
  ingest([event('fifth','auth.failed',{account:'lab-user',source_ip:'192.0.2.20',protocol:'rdp'})]);
  const a=d.list('alerts').items[0]; assert.equal(a.severity,'high');
  d.acknowledge('analyst',a.id);
  assert.equal(d.list('alerts').items[0].status,'acknowledged');
  ingest([event('sixth','auth.failed',{account:'lab-user',source_ip:'192.0.2.20',protocol:'rdp'})]);
  assert.equal(d.list('alerts').total,1);
  assert.equal(d.list('alerts').items[0].status,'open');
  assert.equal(d.list('alerts').items[0].occurrences,2);
});
test('lost source visibility creates a distinct alert, not a healthy no-threat claim',t=>{
  const {d,event,ingest,advance}=fixture(t);
  assert.equal(d.sources()[0].health,'awaiting-data');
  ingest([event('a')]); assert.equal(d.summary().visibility,'receiving');
  advance(61000); d.checkHealth(); d.checkHealth();
  assert.equal(d.summary().visibility,'visibility-gap');
  assert.equal(d.list('alerts').total,1);
  assert.equal(d.list('alerts').items[0].occurrences,1);
  assert.equal(d.list('alerts').items[0].rule_id,'CG-LOST-COVERAGE');
  ingest([event('b')]); assert.equal(d.sources()[0].health,'receiving');
});
test('managed-agent loss and log-delivery failure have distinct health states, alerts and coverage statistics',t=>{
  const {s,d,advance}=fixture(t);
  d.createSource('admin-a',{name:'Synthetic managed agent',source_type:'managed-agent',stale_seconds:30});
  d.createSource('admin-a',{name:'Synthetic log forwarder',source_type:'log-forwarder',stale_seconds:30});
  let summary=d.summary();assert.deepEqual(summary.coverage_health.agents,{configured:1,online:0,lost:0});assert.deepEqual(summary.coverage_health.log_forwarders,{configured:1,flowing:0,failed:0});
  advance(31000);summary=d.summary();assert.equal(summary.coverage_health.visibility_gaps,2);assert.equal(summary.coverage_health.agents.lost,1);assert.equal(summary.coverage_health.log_forwarders.failed,1);
  const states=Object.fromEntries(d.sources().map(source=>[source.source_type,source.monitor_state]));assert.equal(states['managed-agent'],'agent-lost');assert.equal(states['log-forwarder'],'log-delivery-failed');
  const rules=new Set(d.list('alerts',{limit:20}).items.map(alert=>alert.rule_id));assert.ok(rules.has('CG-AGENT-LOST'));assert.ok(rules.has('CG-LOG-DELIVERY-FAILED'));
  const healthAudit=s.all("SELECT action,details FROM audit WHERE actor='health-service'");assert.equal(healthAudit.length,2);assert.ok(healthAudit.every(row=>JSON.parse(row.details).source_type));assert.equal(s.verifyAudit().valid,true);
});
test('cases preserve notes, audit and evidence links; ACK is not incident closure',t=>{
  const {d,event,ingest}=fixture(t);
  ingest([event('finding','security.finding',{title:'Lab finding',severity:'critical',description:'Synthetic evidence'})]);
  const a=d.list('alerts').items[0];
  const c=d.createCase('analyst',{title:'Investigate',alert_ids:[a.id]});
  d.acknowledge('analyst',a.id);
  assert.equal(d.list('cases').items[0].status,'open');
  const changed=d.updateCase('analyst',c.id,{status:'investigating',note:'Review password=secret-note'});
  assert.equal(changed.notes.length,1); assert.ok(!changed.notes[0].text.includes('secret-note'));
  const report=d.caseReport(c.id);
  assert.equal(report.schema_version,'cg.case-report/1');assert.equal(report.case.id,c.id);
  assert.equal(report.alerts.length,1);assert.equal(report.events.length,1);assert.equal(report.assets.length,1);
  assert.ok(report.timeline.some(item=>item.type==='evidence-observed'));
  assert.equal(report.chain_of_custody.verification.valid,true);
  assert.ok(!JSON.stringify(report).includes('secret-note'));
  assert.throws(()=>d.createCase('analyst',{title:'Invalid',alert_ids:['missing']}),/not_found/);
});
test('approval requires another administrator, binds state/TTL, verifies local changes and supports guarded rollback',t=>{
  const {d,event,ingest}=fixture(t);ingest([event('a')]);
  const asset=d.list('assets').items[0];
  const a=d.previewAction('admin-a',{type:'asset.set-criticality',asset_id:asset.id,criticality:'critical',reason:'Lab impact review'});
  assert.equal(a.dry_run.result,'passed');assert.equal(a.dry_run.side_effects,false);assert.deepEqual([a.impact_analysis.endpoint_changes,a.impact_analysis.network_changes],[0,0]);assert.equal(a.rollback_plan.before_value,'standard');
  assert.throws(()=>d.executeAction('admin-a',a.id),/action_not_approved/);
  assert.throws(()=>d.approveAction('admin-a',a.id),/independent_approver_required/);
  d.approveAction('admin-b',a.id);
  assert.equal(d.executeAction('admin-a',a.id).status,'verified');
  assert.equal(d.executeAction('admin-a',a.id).status,'verified');
  assert.equal(d.asset(asset.id).criticality,'critical');
  const rolledBack=d.rollbackAction('admin-b',a.id);assert.equal(rolledBack.status,'rolled-back');assert.equal(rolledBack.audit_chain.valid,true);
  assert.deepEqual(rolledBack.lifecycle.map(x=>x.action),['action.previewed','action.approved','action.executed','action.verified','action.rollback.executed','action.rollback.verified']);
  assert.equal(d.asset(asset.id).criticality,'standard');
});
test('expired approvals and changed preflight state prevent execution',t=>{
  const {d,event,ingest,advance}=fixture(t);ingest([event('a')]);
  const asset=d.list('assets').items[0];
  const input={type:'asset.set-criticality',asset_id:asset.id,criticality:'critical',reason:'Lab',ttl_seconds:60};
  const a=d.previewAction('admin-a',input);d.approveAction('admin-b',a.id);
  advance(61000);assert.throws(()=>d.executeAction('admin-a',a.id),/approval_expired/);
  const b=d.previewAction('admin-a',input);d.approveAction('admin-b',b.id);
  ingest([event('new')]);assert.throws(()=>d.executeAction('admin-a',b.id),/preflight_state_changed/);
  assert.equal(d.asset(asset.id).criticality,'standard');
  assert.throws(()=>d.previewAction('admin-a',{...input,type:'shell.execute'}),/invalid_action_type/);
});
test('5,000 synthetic assets have bounded pages, escaped search, stable identities and no truncation',t=>{
  const {s,d,source}=fixture(t);
  s.transaction(()=>{for(let i=0;i<5000;i++)d.observe(source.id,{external_id:`scale-${i}`,hostname:`HOST-${String(i).padStart(5,'0')}`,os_family:'unknown',device_type:'unknown',addresses:[]},d.now());});
  const first=d.list('assets',{limit:25,offset:0}),last=d.list('assets',{limit:25,offset:4975});
  assert.equal(first.total,5000);assert.equal(first.items.length,25);assert.equal(last.items.length,25);
  assert.equal(new Set([...first.items,...last.items].map(x=>x.id)).size,50);
  assert.equal(d.list('assets',{q:'HOST-04999'}).total,1);
  assert.equal(d.list('assets',{q:'%'}).total,0);
});
test('database survives reopen; migration rerun preserves records; audit rejects modification and detects tampering',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cg-store-test-')),file=path.join(dir,'test.sqlite');
  let s;
  try {
    s=new Store(file);s.audit('synthetic','test','record');s.close();
    s=new Store(file);s.migrate();assert.equal(s.verifyAudit().checked,1);
    assert.throws(()=>s.run('UPDATE audit SET action=\'changed\''),/audit_append_only/);
    s.db.exec('DROP TRIGGER audit_no_update');s.run('UPDATE audit SET action=\'changed\'');
    assert.equal(s.verifyAudit().valid,false);s.close();s=null;
    assert.throws(()=>new Store(file),/audit_integrity_failure/);
  } finally {s?.close();fs.rmSync(dir,{recursive:true,force:true});}
});
