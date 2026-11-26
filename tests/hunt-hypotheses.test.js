import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { HuntWorkbench } from '../lib/hunt.js';
import { HuntHypotheses, LIBRARY } from '../lib/hunt-hypotheses.js';

function fixture(t) {
  const s = new Store(':memory:'); t.after(() => s.close()); const now = Date.now(), d = new Domain(s, { clock: () => now }), at = m => new Date(now - m * 60000).toISOString();
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', at(0)); const src = d.createSource('a', { name: 'Sensors', stale_seconds: 86400 });
  const host = ref => ({ external_id: ref, hostname: ref.toUpperCase(), os_family: 'windows', device_type: 'server', addresses: ['10.60.0.' + (ref.length + 10)] });
  const put = (id, kind, details, asset, m) => d.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: id, kind, observed_at: at(m), asset, details }] });
  const remote = (id, asset, m, ip, account) => put(id, 'remote.authenticated', { session_id: id, protocol: 'rdp', source_a: { hostname: null, ip, account: null }, target_b: { hostname: null, ip: null, account }, relay: false, evidence_type: 'authentication_log', assessment: 'unknown', assessment_basis: 'source-report', authorization_ref: null, rationale: null }, asset, m);
  const proc = (id, asset, m, extra) => put(id, 'endpoint.process_causality', { causality_id: id, collector: { type: 'edr', name: 'Synthetic EDR', trust: 'high', evidence_ref: 'SYN' }, window: { starts_at: at(m + 5), ends_at: at(Math.max(m - 5, 0)) }, processes: [{ process_id: 'p', parent_process_id: null, image_path: 'C:\\Windows\\System32\\services.exe', command_line: 'services.exe', user_ref: 'SYSTEM', started_at: at(m), signer: { status: 'signed', publisher: 'Microsoft' }, integrity: 'system', evidence_ref: 'edr:1' }], service_changes: extra.services || [], scheduled_task_changes: [], connections: [] }, asset, m);
  return { s, now, at, host, put, remote, proc, hh: new HuntHypotheses(s, { workbench: new HuntWorkbench(s, { clock: () => now }), clock: () => now }) };
}

test('the library covers initial access, persistence, lateral movement and exfiltration, each with data, a safe query, exclusions and retention (CG-143)', t => {
  assert.deepEqual([...new Set(LIBRARY.map(h => h.stage))], ['initial-access', 'persistence', 'lateral-movement', 'exfiltration']);
  for (const h of LIBRARY) { assert.ok(h.data.length && h.data.every(x => x.kinds.length), h.id); assert.ok(['account', 'process', 'connection', 'movement', 'change'].includes(h.query.entity), h.id); assert.ok(h.exclusions.length >= 1 && h.retention_days >= 1, h.id); assert.ok(!('sql' in h.query)); }
  const { hh } = fixture(t), r = hh.run('H-IA-01'); assert.equal(r.outcome, 'insufficient-visibility'); assert.match(r.verdict, /absence of results proves nothing/); assert.equal(r.total, 0);
  assert.throws(() => hh.run('H-XX-99'), /hunt_hypothesis_not_found/);
});

test('a found result survives the exclusions, a not-found result needs the data present, and short retention is stated (CG-143)', t => {
  const { s, host, put, remote, hh } = fixture(t), sv = host('srv'), attacker = '203.0.113.61';
  for (let i = 0; i < 6; i++) put(`f${i}`, 'auth.failed', { account: 'administrator', source_ip: attacker, protocol: 'rdp' }, sv, 60 - i);
  remote('ok', sv, 50, attacker, 'administrator');
  for (let i = 0; i < 6; i++) put(`g${i}`, 'auth.failed', { account: 'svc-backup', source_ip: '10.60.0.5', protocol: 'rdp' }, sv, 40 - i);
  remote('svc', sv, 30, '10.60.0.5', 'svc-backup');
  let r = hh.run('H-IA-01'); assert.equal(r.outcome, 'found'); assert.equal(r.total, 1, 'the internal service account with a stale password is excluded'); assert.match(r.rows[0].summary, /6 failures then success/);
  assert.equal(r.partial_window, true, 'the data is only an hour old, shorter than the 14-day hunt window'); assert.ok(r.visibility.every(v => v.state === 'short-retention'));
  r = hh.run('H-IA-02', { exclusions: { approved_sources: [attacker] } }); assert.equal(r.outcome, 'not-found'); assert.match(r.verdict, /required data present/);
  assert.equal(hh.run('H-IA-02').total, 1);
  assert.ok(hh.list().find(x => x.id === 'H-EX-01').visibility.every(v => v.state === 'missing'));
});

test('persistence and lateral movement hunts exclude updaters and admins and find new services and account spread (CG-143)', t => {
  const { host, remote, proc, hh, at } = fixture(t), ws = host('ws');
  proc('upd', ws, 90, { services: [{ change_id: 'u', process_id: 'p', service_name: 'GoogleUpdaterService', action: 'created', binary_path: 'C:\\Program Files\\Google\\Update\\GoogleUpdate.exe', occurred_at: at(89), evidence_ref: 'e' }] });
  assert.equal(hh.run('H-P-01').outcome, 'not-found', 'a signed vendor updater is a legitimate exclusion');
  proc('bad', ws, 80, { services: [{ change_id: 'b', process_id: 'p', service_name: 'SyntheticSvcX', action: 'created', binary_path: 'C:\\ProgramData\\x.exe', occurred_at: at(79), evidence_ref: 'e' }] });
  const p = hh.run('H-P-01'); assert.equal(p.outcome, 'found'); assert.match(p.rows[0].summary, /SyntheticSvcX/);
  for (const [i, ref] of ['h1', 'h2', 'h3'].entries()) remote(`m${i}`, host(ref), 20 - i * 10, '10.60.1.9', 'mallory');
  const lm = hh.run('H-LM-02'); assert.equal(lm.outcome, 'found'); assert.match(lm.rows[0].summary, /mallory on 3 hosts within an hour/);
  assert.equal(hh.run('H-LM-02', { exclusions: { admin_accounts: ['mallory'] } }).outcome, 'not-found');
});
