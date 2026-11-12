import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeWindowsExport} from '../lib/windows-events.js';
import {validateEvent,Domain} from '../lib/domain.js';
import {Store} from '../lib/store.js';
const now=Date.parse('2026-11-11T10:00:00.000Z');
const record=(id,type='10',recordId=1)=>({event_id:id,record_id:recordId,time_created:'2026-11-11T09:30:00.000Z',provider:'Microsoft-Windows-Security-Auditing',channel:'Security',data:{LogonType:type,TargetLogonId:'0x123',TargetUserName:'synthetic-target',TargetDomainName:'LAB',IpAddress:'192.0.2.20',WorkstationName:'LAB-SOURCE'}});
const input=events=>({schema_version:'cg.windows-export/1',computer:'LAB-TARGET',boot_time:'2026-11-11T09:00:00.000Z',events});
test('Windows 4624 type10 maps to authentication, preserves A/B separation and raw provenance',()=>{
  const r=normalizeWindowsExport(input([record(4624)]),now),e=r.batch.events[0];
  assert.equal(e.kind,'remote.authenticated');assert.equal(e.details.source_a.account,null);assert.equal(e.details.target_b.account,'LAB\\synthetic-target');
  assert.equal(e.details.source_a.ip,'192.0.2.20');assert.equal(e.origin.parser,'windows-security/1');
  assert.match(e.origin.raw_sha256,/^[a-f0-9]{64}$/);validateEvent(e,now);
});
test('non-RDP logons are explicitly skipped; failure without source remains unknown',()=>{
  const r=normalizeWindowsExport(input([record(4624,'3'),{...record(4625,'3',2),data:{LogonType:'3',TargetUserName:'lab-user',IpAddress:'-'}}]),now);
  assert.equal(r.report.skipped.length,1);assert.equal(r.batch.events.length,1);
  assert.equal(r.batch.events[0].kind,'auth.failed');assert.equal(r.batch.events[0].details.protocol,'unknown');assert.equal(r.batch.events[0].details.source_ip,null);
  assert.throws(()=>normalizeWindowsExport(input([record(4624,'3')]),now),/no_supported_windows_events/);
});
test('Windows logon correlation is scoped to boot and rejects records from before boot',()=>{
  const a=normalizeWindowsExport(input([record(4624)]),now).batch.events[0];
  const b=normalizeWindowsExport({...input([record(4624)]),boot_time:'2026-11-11T09:15:00.000Z'},now).batch.events[0];
  assert.notEqual(a.details.session_id,b.details.session_id);
  assert.throws(()=>normalizeWindowsExport({...input([record(4624)]),boot_time:'2026-11-11T09:45:00.000Z'},now),/event_precedes_declared_boot/);
  assert.throws(()=>normalizeWindowsExport(input([{...record(4624),provider:'untrusted-provider'}]),now),/unsupported_windows_provider/);
  assert.throws(()=>normalizeWindowsExport(input([{...record(4624),data:{...record(4624).data,password:'not-allowed'}}]),now),/unknown_windows_data_field/);
});
test('Windows logoff closes the correlated session without erasing previously observed source identity',t=>{
  const s=new Store(':memory:');t.after(()=>s.close());const d=new Domain(s,{clock:()=>now});const source=d.createSource('synthetic',{name:'Windows fixture'});
  const ended={...record(4634,'10',2),time_created:'2026-11-11T09:45:00.000Z',data:{LogonType:'10',TargetLogonId:'0x123',TargetUserName:'synthetic-target',TargetDomainName:'LAB'}};
  d.ingest('synthetic',source.id,normalizeWindowsExport(input([record(4624),ended]),now).batch);
  const session=d.list('remote_sessions').items[0];assert.equal(session.phase,'ended');assert.equal(session.source_a.ip,'192.0.2.20');assert.equal(session.target_b.account,'LAB\\synthetic-target');assert.equal(session.evidence_ids.length,2);
  assert.equal(d.list('events').items[0].parser_version,'windows-security/1');
});
