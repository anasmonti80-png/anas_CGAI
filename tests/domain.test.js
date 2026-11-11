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
test('cases preserve notes, audit and evidence links; ACK is not incident closure',t=>{
  const {d,event,ingest}=fixture(t);
  ingest([event('finding','security.finding',{title:'Lab finding',severity:'critical',description:'Synthetic evidence'})]);
  const a=d.list('alerts').items[0];
  const c=d.createCase('analyst',{title:'Investigate',alert_ids:[a.id]});
  d.acknowledge('analyst',a.id);
  assert.equal(d.list('cases').items[0].status,'open');
  const changed=d.updateCase('analyst',c.id,{status:'investigating',note:'Review password=secret-note'});
  assert.equal(changed.notes.length,1); assert.ok(!changed.notes[0].text.includes('secret-note'));
  assert.throws(()=>d.createCase('analyst',{title:'Invalid',alert_ids:['missing']}),/not_found/);
});
test('approval requires another administrator, binds state/TTL, verifies local changes and supports guarded rollback',t=>{
  const {d,event,ingest}=fixture(t);ingest([event('a')]);
  const asset=d.list('assets').items[0];
  const a=d.previewAction('admin-a',{type:'asset.set-criticality',asset_id:asset.id,criticality:'critical',reason:'Lab impact review'});
  assert.throws(()=>d.executeAction('admin-a',a.id),/action_not_approved/);
  assert.throws(()=>d.approveAction('admin-a',a.id),/independent_approver_required/);
  d.approveAction('admin-b',a.id);
  assert.equal(d.executeAction('admin-a',a.id).status,'verified');
  assert.equal(d.executeAction('admin-a',a.id).status,'verified');
  assert.equal(d.asset(asset.id).criticality,'critical');
  assert.equal(d.rollbackAction('admin-b',a.id).status,'rolled-back');
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
