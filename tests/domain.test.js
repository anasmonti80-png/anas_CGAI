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
test('NIST CSF 2.0 outcome map exposes evidence and explicit gaps for all six functions without claiming compliance',t=>{
  const {d,event,ingest}=fixture(t);
  ingest([event('asset'),event('protection','protection.observed',{engine:'Synthetic',installed:true,running:true,collecting:true,mode:'active'}),event('finding','security.finding',{title:'Synthetic finding',severity:'high',description:'Synthetic evidence'})]);
  const alert=d.list('alerts').items.find(item=>item.rule_id==='CG-REPORTED-FINDING');d.createCase('analyst',{title:'Synthetic response',alert_ids:[alert.id]});
  const asset=d.list('assets').items[0],action=d.previewAction('admin-a',{type:'asset.set-criticality',asset_id:asset.id,criticality:'important',reason:'Synthetic recovery evidence'});d.approveAction('admin-b',action.id);d.executeAction('admin-a',action.id);d.rollbackAction('admin-b',action.id);
  const map=d.securityOutcomes();assert.equal(map.framework,'NIST CSF 2.0');assert.match(map.claim,/not a compliance assessment/);assert.deepEqual(map.outcomes.map(item=>item.function),['GOVERN','IDENTIFY','PROTECT','DETECT','RESPOND','RECOVER']);
  assert.ok(map.outcomes.every(item=>Array.isArray(item.evidence)&&Array.isArray(item.gaps)));assert.equal(map.outcomes.find(item=>item.function==='RECOVER').evidence[0].count,1);assert.ok(map.outcomes.find(item=>item.function==='PROTECT').gaps.some(gap=>/not been independently validated/.test(gap)));
});
test('versioned threat model covers valuable assets, trust boundaries, attack scenarios and both impact classes per environment',t=>{
  const {d,event,ingest,advance}=fixture(t),model={environment:{environment_id:'riyadh-prod',name:'Synthetic Riyadh production',scope:'Synthetic customer-facing service'},valuable_assets:[{asset_ref:'synthetic-01',name:'Synthetic application server',value_reason:'Provides the monitored service'}],trust_boundaries:[{boundary_id:'internet-edge',name:'Internet to service edge',from_zone:'Internet',to_zone:'Application',controls:['Synthetic reverse proxy']}],attack_scenarios:[{scenario_id:'credential-entry',title:'Stolen credential reaches the application',description:'Synthetic scenario for validation only',entry_point:'Public sign-in',target_asset_refs:['synthetic-01'],trust_boundary_refs:['internet-edge'],likelihood:'medium'}],service_outage_impact:{severity:'high',description:'Synthetic service becomes unavailable'},data_disclosure_impact:{severity:'critical',description:'Synthetic confidential records may be disclosed'}};
  ingest([event('threat-model-1','governance.threat_model',model)]);let registry=d.threatModels();assert.equal(registry.total,1);assert.equal(registry.items[0].environment.environment_id,'riyadh-prod');assert.equal(registry.items[0].valuable_assets[0].central_asset_ids.length,1);assert.equal(registry.items[0].trust_boundaries[0].boundary_id,'internet-edge');assert.equal(registry.items[0].attack_scenarios[0].target_asset_refs[0],'synthetic-01');assert.equal(registry.items[0].data_disclosure_impact.severity,'critical');
  advance(1);ingest([event('threat-model-2','governance.threat_model',{...model,service_outage_impact:{severity:'critical',description:'Updated synthetic outage impact'}})]);registry=d.threatModels({q:'Riyadh'});assert.equal(registry.total,1);assert.equal(registry.items[0].event_id,d.list('events').items[0].id);assert.equal(registry.items[0].service_outage_impact.severity,'critical');
  const invalid={...model,attack_scenarios:[{...model.attack_scenarios[0],target_asset_refs:['missing-asset']}]};assert.throws(()=>ingest([event('bad-threat-model','governance.threat_model',invalid)]),/unknown_scenario_asset_ref/);
});
test('institutional risk register links coverage, resolved evidence, owner, remediation, exception and time-bounded acceptance',t=>{
  const {d,event,ingest,advance}=fixture(t);ingest([event('risk-evidence')]);const evidenceId=d.list('events').items[0].id;
  const risk={risk_id:'RISK-SYNTHETIC-001',title:'Synthetic service exposure',description:'Synthetic governance test only',category:'service-availability',inherent_severity:'high',residual_severity:'medium',likelihood:'medium',status:'accepted',coverage:{state:'partial',requirement_ids:['CG-069','CG-073'],control_refs:['CTRL-SYNTHETIC-01']},evidence_refs:[{type:'event',id:evidenceId}],owner:{owner_id:'risk-owner',display_name:'Synthetic Risk Owner',contact:null},remediation:{status:'in-progress',plan:'Apply the synthetic compensating control',due_at:'2026-12-01T00:00:00.000Z'},exception:{status:'active',reason:'Synthetic dependency window',expires_at:'2026-11-30T00:00:00.000Z',approved_by:'synthetic-approver'},risk_acceptance:{status:'accepted',accepted_by:'synthetic-executive',accepted_at:'2026-11-10T00:00:00.000Z',review_due_at:'2026-11-20T00:00:00.000Z',review_interval_days:30,rationale:'Synthetic acceptance while remediation is in progress'}};
  ingest([event('risk-record-1','governance.risk_record',risk)]);let register=d.riskRegister();assert.equal(register.total,1);assert.equal(register.items[0].coverage.requirement_ids[1],'CG-073');assert.equal(register.items[0].evidence_refs[0].resolved,true);assert.equal(register.items[0].owner.owner_id,'risk-owner');assert.equal(register.items[0].exception_state,'active');assert.equal(register.items[0].review_state,'scheduled');
  advance(1);ingest([event('risk-record-2','governance.risk_record',{...risk,remediation:{...risk.remediation,status:'implemented'}})]);register=d.riskRegister({q:'RISK-SYNTHETIC'});assert.equal(register.total,1);assert.equal(register.items[0].remediation.status,'implemented');
  assert.throws(()=>ingest([event('bad-risk-review','governance.risk_record',{...risk,risk_acceptance:{...risk.risk_acceptance,review_due_at:'2027-01-01T00:00:00.000Z'}})]),/invalid_risk_review_window/);
  assert.throws(()=>ingest([event('bad-risk-acceptance','governance.risk_record',{...risk,risk_acceptance:{status:'accepted',accepted_by:null,accepted_at:null,review_due_at:null,review_interval_days:null,rationale:null}})]),/accepted_risk_requires_review/);
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
test('visibility-gap registry records known systems, networks and accounts with reason, last sighting, recommendation and resolution',t=>{
  const {d,event,ingest,advance}=fixture(t),lastSeen='2026-11-11T09:59:00.000Z';
  const gap=(id,entity_type,entity_ref,reason,status='open')=>event(id,'visibility.gap',{entity_type,entity_ref,reason,last_seen:lastSeen,recommendation:`Restore synthetic ${entity_type} visibility`,status});
  ingest([gap('gap-system','system','LAB-02','no-agent'),gap('gap-network','network','192.0.2.0/24','no-span'),gap('gap-account','account','synthetic-account','no-authorization')]);
  let registry=d.visibilityGaps({limit:20});assert.equal(registry.items.filter(item=>item.origin==='reported-gap').length,3);assert.match(registry.scope,/Known registered systems, networks, accounts/);
  for(const item of registry.items.filter(item=>item.origin==='reported-gap')){assert.equal(item.last_seen,lastSeen);assert.match(item.recommendation,/Restore synthetic/);assert.equal(item.status,'open');}
  advance(1);ingest([gap('gap-system-resolved','system','LAB-02','no-agent','resolved')]);registry=d.visibilityGaps({q:'LAB-02'});assert.equal(registry.items[0].status,'resolved');
  const resolvedAlert=d.list('alerts',{limit:20}).items.find(alert=>alert.title.includes('no-agent'));assert.equal(resolvedAlert.status,'resolved');
  assert.throws(()=>ingest([gap('public-network','network','8.8.8.0/24','no-span')]),/public_entity_ref_not_allowed/);
  assert.throws(()=>ingest([gap('invalid-account','account','synthetic-account','no-agent')]),/invalid_gap_reason/);
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
test('asset context links the central device to owner, service, site, sensitivity, maintenance and service criticality evidence',t=>{
  const {d,event,ingest,advance}=fixture(t),details={owner:{owner_id:'team-soc',display_name:'Synthetic SOC owner',contact:'soc@example.invalid'},business_service:'Synthetic monitoring',service_name:'Evidence API',site:'Synthetic Riyadh lab',data_sensitivity:'confidential',maintenance_windows:['Friday 02:00-03:00 UTC'],service_criticality:'high'};
  ingest([event('context-1','asset.context',details)]);let asset=d.asset(d.list('assets').items[0].id);assert.equal(asset.governance_context.owner.owner_id,'team-soc');assert.equal(asset.governance_context.business_service,'Synthetic monitoring');assert.equal(asset.governance_context.site,'Synthetic Riyadh lab');assert.equal(asset.governance_context.data_sensitivity,'confidential');assert.deepEqual(asset.governance_context.maintenance_windows,['Friday 02:00-03:00 UTC']);assert.equal(asset.governance_context.service_criticality,'high');
  advance(1);ingest([event('context-2','asset.context',{...details,service_criticality:'critical'})]);asset=d.asset(asset.id);assert.equal(asset.governance_context.service_criticality,'critical');assert.equal(asset.governance_context.event_id,d.list('events').items[0].id);
  assert.throws(()=>ingest([event('bad-context','asset.context',{...details,data_sensitivity:'secret'})]),/invalid_data_sensitivity/);
});
test('asset lifecycle records versions, vendor support, security-update end, extended support and an owned upgrade or replacement plan',t=>{
  const {d,event,ingest,advance}=fixture(t),details={product:{vendor:'Synthetic Vendor',name:'Synthetic Server',version:'12.0',edition:'Enterprise'},operating_system:{name:'Synthetic OS',version:'2022',build:'20348'},vendor_support:{status:'extended',standard_support_end:'2026-01-01T00:00:00.000Z',security_updates_end:'2028-01-01T00:00:00.000Z',extended_support:{available:true,enrolled:true,end_at:'2030-01-01T00:00:00.000Z'}},plan:{action:'upgrade',target:'Synthetic OS 2028',owner_id:'platform-team',due_at:'2027-06-01T00:00:00.000Z',status:'approved'}};
  ingest([event('lifecycle-1','asset.lifecycle',details)]);let asset=d.asset(d.list('assets').items[0].id);assert.equal(asset.lifecycle.product.version,'12.0');assert.equal(asset.lifecycle.operating_system.build,'20348');assert.equal(asset.lifecycle.vendor_support.security_updates_end,'2028-01-01T00:00:00.000Z');assert.equal(asset.lifecycle.vendor_support.extended_support.enrolled,true);assert.equal(asset.lifecycle.plan.owner_id,'platform-team');
  advance(1);ingest([event('lifecycle-2','asset.lifecycle',{...details,plan:{...details.plan,status:'in-progress'}})]);asset=d.asset(asset.id);assert.equal(asset.lifecycle.plan.status,'in-progress');assert.equal(asset.lifecycle.event_id,d.list('events').items[0].id);
  assert.throws(()=>ingest([event('bad-lifecycle','asset.lifecycle',{...details,vendor_support:{...details.vendor_support,extended_support:{available:false,enrolled:true,end_at:null}}})]),/extended_support_enrollment_requires_availability/);
});
test('legacy compatibility matrix keeps agent, read-only, isolation, tested capability, performance and licensing evidence explicit',t=>{
  const {d,event,ingest,advance}=fixture(t),details={profile:'windows-server-2008-r2',support_state:'end-of-support',agent:{status:'unsupported',reason:'Synthetic agent contract does not support this profile'},access_mode:'read-only-remote',read_only_supported:true,network_isolation:{required:true,status:'partial',zone:'Synthetic legacy VLAN'},tested_capabilities:[],performance_constraints:['Limit collection frequency on the synthetic legacy host'],licensing_constraints:['Synthetic extended support entitlement not verified'],recommendation:'Keep isolated and schedule replacement',evidence_basis:{level:'not-tested',reference:null}};
  ingest([event('compatibility-1','asset.compatibility',details,{device_type:'server'})]);let matrix=d.compatibilityMatrix();assert.equal(matrix.total,1);assert.equal(matrix.items[0].profile,'windows-server-2008-r2');assert.equal(matrix.items[0].agent.status,'unsupported');assert.equal(matrix.items[0].read_only_supported,true);assert.equal(matrix.items[0].tested_capabilities.length,0);assert.equal(matrix.items[0].evidence_basis.level,'not-tested');
  advance(1);ingest([event('compatibility-2','asset.compatibility',{...details,tested_capabilities:['inventory','network-read'],evidence_basis:{level:'authorized-lab',reference:'SYNTHETIC-LAB-076'}},{device_type:'server'})]);matrix=d.compatibilityMatrix({q:'LAB-01'});assert.deepEqual(matrix.items[0].tested_capabilities,['inventory','network-read']);assert.equal(matrix.items[0].event_id,d.list('events').items[0].id);
  assert.throws(()=>ingest([event('bad-compatibility','asset.compatibility',{...details,tested_capabilities:['inventory']})]),/not_tested_cannot_claim_capability/);
});
test('legacy compensating controls require evidence for segmentation, jump host, internet restriction, MFA, backup and monitoring until migration',t=>{
  const {d,event,ingest,advance}=fixture(t),details={network_segmentation:{status:'enforced',boundary:'Synthetic legacy microsegment',evidence_ref:'SYNTHETIC-FW-077'},jump_host:{status:'enforced',host_ref:'SYNTHETIC-JUMP-01',evidence_ref:'SYNTHETIC-JUMP-POLICY-077'},internet_access:{status:'blocked',exceptions:[],evidence_ref:'SYNTHETIC-EGRESS-077'},entry_mfa:{status:'enforced',method:'Synthetic TOTP at jump host',evidence_ref:'SYNTHETIC-MFA-077'},backups:{status:'operational',last_success_at:'2026-11-10T02:00:00.000Z',restore_test_status:'not-tested',last_restore_test_at:null,evidence_ref:'SYNTHETIC-BACKUP-077'},monitoring:{status:'operational',coverage:'Synthetic host and network events',last_signal_at:'2026-11-11T20:00:00.000Z',evidence_ref:'SYNTHETIC-MONITOR-077'},migration:{status:'planned',owner_id:'platform-team',target:'Synthetic supported replacement',due_at:'2027-06-01T00:00:00.000Z'}};
  ingest([event('controls-1','asset.compensating_controls',details,{device_type:'server'})]);let controls=d.compensatingControls();assert.equal(controls.total,1);assert.equal(controls.items[0].network_segmentation.status,'enforced');assert.equal(controls.items[0].jump_host.host_ref,'SYNTHETIC-JUMP-01');assert.equal(controls.items[0].internet_access.status,'blocked');assert.equal(controls.items[0].entry_mfa.status,'enforced');assert.equal(controls.items[0].backups.restore_test_status,'not-tested');assert.equal(controls.items[0].monitoring.status,'operational');assert.equal(controls.items[0].migration.owner_id,'platform-team');
  advance(1);ingest([event('controls-2','asset.compensating_controls',{...details,migration:{...details.migration,status:'in-progress'}},{device_type:'server'})]);controls=d.compensatingControls({q:'platform-team'});assert.equal(controls.items[0].migration.status,'in-progress');assert.equal(controls.items[0].event_id,d.list('events').items[0].id);
  assert.throws(()=>ingest([event('bad-controls','asset.compensating_controls',{...details,entry_mfa:{status:'enforced',method:'Synthetic TOTP',evidence_ref:null}})]),/entry_mfa_evidence_required/);
  assert.throws(()=>ingest([event('bad-restore','asset.compensating_controls',{...details,backups:{...details.backups,restore_test_status:'passed',last_restore_test_at:null}})]),/passed_restore_test_requires_evidence/);
});
test('backup security keeps multiple separated copies, platform immutability, change monitoring and permissions explicit',t=>{
  const {d,event,ingest,advance}=fixture(t),details={backup_set_id:'BACKUP-SET-078',copies:[{copy_id:'primary',platform:'Synthetic backup appliance',separation:'separate-account',immutability_support:'supported',immutability_status:'enabled',retention_days:30,encryption:'enabled'},{copy_id:'offline',platform:'Synthetic offline vault',separation:'offline',immutability_support:'unsupported',immutability_status:'not-applicable',retention_days:90,encryption:'enabled'}],monitoring:{modification_events:'monitored',deletion_events:'monitored',last_signal_at:'2026-11-11T21:00:00.000Z',evidence_ref:'SYNTHETIC-BACKUP-MONITOR-078'},permissions:{model:'least-privilege',privileged_principal_count:2,review_status:'current',last_review_at:'2026-11-01T00:00:00.000Z',evidence_ref:'SYNTHETIC-BACKUP-ACCESS-078'}};
  ingest([event('backup-security-1','resilience.backup_security',details,{device_type:'server'})]);let matrix=d.backupSecurity();assert.equal(matrix.total,1);assert.equal(matrix.items[0].copies.length,2);assert.equal(matrix.items[0].copies[1].separation,'offline');assert.equal(matrix.items[0].copies[1].immutability_status,'not-applicable');assert.equal(matrix.items[0].monitoring.deletion_events,'monitored');assert.equal(matrix.items[0].permissions.model,'least-privilege');
  advance(1);ingest([event('backup-security-2','resilience.backup_security',{...details,permissions:{...details.permissions,privileged_principal_count:1}},{device_type:'server'})]);matrix=d.backupSecurity({q:'BACKUP-SET-078'});assert.equal(matrix.items[0].permissions.privileged_principal_count,1);assert.equal(matrix.items[0].event_id,d.list('events').items[0].id);
  assert.throws(()=>ingest([event('bad-backup-count','resilience.backup_security',{...details,copies:[details.copies[0]]})]),/backup_security_requires_multiple_copies/);
  assert.throws(()=>ingest([event('bad-backup-monitor','resilience.backup_security',{...details,monitoring:{...details.monitoring,evidence_ref:null}})]),/monitored_backup_changes_require_signal_and_evidence/);
});
test('restore readiness keeps periodic tests, service RPO and RTO, integrity and backup presence independent',t=>{
  const {d,event,ingest,advance}=fixture(t),base={service:{service_id:'SERVICE-079',name:'Synthetic critical service',owner_id:'service-owner'},objectives:{rpo_minutes:60,rto_minutes:120},backup_presence:'present',integrity:{status:'intact',checked_at:'2026-11-10T00:00:00.000Z',evidence_ref:'SYNTHETIC-INTEGRITY-079'},schedule:{frequency_days:30,next_due_at:'2027-01-01T00:00:00.000Z'},restore_tests:[{test_id:'RESTORE-079-A',scheduled_at:'2026-11-12T00:00:00.000Z',executed_at:null,status:'not-run',scope:'Synthetic service restore',recovered_to_time:null,duration_minutes:null,evidence_ref:null}]};
  ingest([event('readiness-1','resilience.restore_readiness',base,{device_type:'server'})]);let rows=d.restoreReadiness();assert.equal(rows.total,1);assert.equal(rows.items[0].backup_presence,'present');assert.equal(rows.items[0].recoverability_state,'unverified');assert.equal(rows.items[0].rpo_actual_minutes,null);
  const passed={...base,restore_tests:[{...base.restore_tests[0],executed_at:'2026-11-12T02:00:00.000Z',status:'passed',recovered_to_time:'2026-11-12T01:30:00.000Z',duration_minutes:90,evidence_ref:'SYNTHETIC-RESTORE-079'}]};advance(1);ingest([event('readiness-2','resilience.restore_readiness',passed,{device_type:'server'})]);rows=d.restoreReadiness({q:'SERVICE-079'});assert.equal(rows.items[0].recoverability_state,'ready');assert.equal(rows.items[0].rpo_actual_minutes,30);assert.equal(rows.items[0].rto_actual_minutes,90);assert.equal(rows.items[0].event_id,d.list('events').items[0].id);
  assert.throws(()=>ingest([event('bad-readiness','resilience.restore_readiness',{...base,restore_tests:[{...base.restore_tests[0],status:'passed'}]})]),/passed_restore_test_requires_measurements_and_evidence/);
  assert.throws(()=>ingest([event('bad-integrity','resilience.restore_readiness',{...base,integrity:{status:'intact',checked_at:null,evidence_ref:null}})]),/verified_backup_integrity_requires_evidence/);
});
test('incident recovery enforces containment, identity configuration and device recovery, threat clearance, then approved reconnection',t=>{
  const {d,event,ingest,advance}=fixture(t),done=(ref)=>({status:'completed',started_at:'2026-11-11T01:00:00.000Z',completed_at:'2026-11-11T02:00:00.000Z',evidence_refs:[ref]}),waiting={status:'not-started',started_at:null,completed_at:null,evidence_refs:[]},base={recovery_id:'RECOVERY-080',incident_ref:'INCIDENT-080',containment:done('SYNTHETIC-CONTAIN-080'),identity_recovery:{status:'in-progress',started_at:'2026-11-11T03:00:00.000Z',completed_at:null,evidence_refs:[]},configuration_recovery:waiting,device_recovery:waiting,threat_clearance:{...waiting,findings_remaining:0},reconnection:{...waiting,approved_by:null,approved_at:null}};
  ingest([event('recovery-1','resilience.incident_recovery',base,{device_type:'server'})]);let rows=d.incidentRecovery();assert.equal(rows.total,1);assert.equal(rows.items[0].workflow_state,'recovering');
  const complete={...base,identity_recovery:done('SYNTHETIC-IDENTITY-080'),configuration_recovery:done('SYNTHETIC-CONFIG-080'),device_recovery:done('SYNTHETIC-DEVICE-080'),threat_clearance:{...done('SYNTHETIC-CLEAR-080'),findings_remaining:0},reconnection:{...done('SYNTHETIC-RECONNECT-080'),approved_by:'recovery-approver',approved_at:'2026-11-11T03:00:00.000Z'}};advance(1);ingest([event('recovery-2','resilience.incident_recovery',complete,{device_type:'server'})]);rows=d.incidentRecovery({q:'INCIDENT-080'});assert.equal(rows.items[0].workflow_state,'reconnected');assert.equal(rows.items[0].reconnection.approved_by,'recovery-approver');
  assert.throws(()=>ingest([event('bad-reconnect','resilience.incident_recovery',{...base,reconnection:{...done('EARLY-RECONNECT'),approved_by:'approver',approved_at:'2026-11-11T03:00:00.000Z'}})]),/reconnection_requires_completed_threat_clearance/);
  assert.throws(()=>ingest([event('bad-clearance','resilience.incident_recovery',{...complete,threat_clearance:{...done('FAILED-CLEAR'),findings_remaining:1}})]),/threat_clearance_requires_zero_findings/);
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
