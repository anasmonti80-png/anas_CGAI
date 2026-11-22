import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { ValidationLab, SCENARIOS } from '../lib/validation-lab.js';

function fixture(t, LabDomain = Domain) {
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.parse('2026-11-22T10:00:00.000Z'); const d = new Domain(s, { clock: () => now });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'analyst-a', 'analyst-a', 'fixture-not-a-password-hash', 'analyst', new Date(now).toISOString());
  const lab = new ValidationLab(s, { clock: () => now, domain: d, Domain: LabDomain });
  return { s, d, lab, advance: ms => { now += ms; } };
}
// A deliberately broken build of the rules: the repeated-failure rule no longer fires.
class BrokenDomain extends Domain { correlate(e) { if (e.kind === 'auth.failed') return; return super.correlate(e); } }

test('every safe scenario raises exactly its expected alerts in isolation and production is untouched (CG-115)', t => {
  const { s, lab } = fixture(t);
  assert.ok(SCENARIOS.length >= 9 && SCENARIOS.some(x => !x.expected.length), 'includes a benign false-positive check');
  const r = lab.runAll('analyst-a');
  for (const x of r.results) assert.equal(x.passed, true, `${x.ref}: missing ${x.missing} unexpected ${x.unexpected}`);
  assert.equal(r.passed, r.total);
  assert.equal(s.get('SELECT COUNT(*) n FROM events').n, 0, 'no lab event reaches production'); assert.equal(s.get('SELECT COUNT(*) n FROM alerts').n, 0, 'no lab alert reaches production');
  assert.equal(s.get('SELECT COUNT(*) n FROM validation_lab_runs').n, SCENARIOS.length); assert.throws(() => s.run('UPDATE validation_lab_runs SET passed=1'), /validation_runs_append_only/);
  const v = lab.view(); assert.ok(v.scenarios.every(x => x.last_run?.passed)); assert.ok(v.claim_ar.includes('معزولة'));
  assert.throws(() => lab.runScenario('analyst-a', 'nope'), /validation_scenario_not_found/);
});

test('a broken rule is caught: the missed detection is reported and raises CG-VALIDATION-MISS-115 (CG-115)', t => {
  const { s, lab } = fixture(t, BrokenDomain);
  const r = lab.runScenario('analyst-a', 'brute-force-rdp');
  assert.equal(r.passed, false); assert.deepEqual(r.missing, ['CG-AUTH-FAILURES-5-IN-5M']); assert.deepEqual(r.observed, []);
  const a = s.all("SELECT severity,title FROM alerts WHERE rule_id='CG-VALIDATION-MISS-115'"); assert.equal(a.length, 1); assert.equal(a[0].severity, 'high'); assert.match(a[0].title, /CG-AUTH-FAILURES-5-IN-5M/);
  assert.ok(s.all("SELECT 1 FROM audit WHERE action='validation_lab.scenario'").length);
});

test('stored lab events replay through the current rules and are compared with what production raised (CG-115)', t => {
  const { s, d, lab, advance } = fixture(t), src = d.createSource('analyst-a', { name: 'Lab sensors', stale_seconds: 86400 }), asset = { external_id: 'lab-01', hostname: 'LAB-01', os_family: 'windows', device_type: 'workstation', addresses: ['10.0.0.20'] };
  for (let i = 0; i < 5; i++) { d.ingest('analyst-a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: `f${i}`, kind: 'auth.failed', observed_at: new Date(Date.parse('2026-11-22T10:00:00.000Z') + i * 20000).toISOString(), asset, details: { account: 'lab-user', source_ip: '192.0.2.20', protocol: 'rdp' } }] }); advance(20000); }
  d.ingest('analyst-a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'dns', kind: 'log.batch', observed_at: new Date(Date.parse('2026-11-22T10:01:50.000Z')).toISOString(), asset, details: { batch_id: 'DNS-1', source_name: 'bind', format: 'bind-query', lines: ['22-Nov-2026 10:01:00.000 client @0x1 10.0.0.7#53000 (x9q7z2kd8w4m1p0r6t3y5vbn.tunnel.example.net): query: x9q7z2kd8w4m1p0r6t3y5vbn.tunnel.example.net IN TXT + (10.0.0.53)'] } }] });
  const prodAlerts = s.get('SELECT COUNT(*) n FROM alerts').n, prodEvents = s.get('SELECT COUNT(*) n FROM events').n;
  const r = lab.replay('analyst-a', { source_id: src.id }); assert.equal(r.passed, true, JSON.stringify(r)); assert.deepEqual(r.expected, ['CG-AUTH-FAILURES-5-IN-5M', 'CG-NET-DNS-017']); assert.equal(r.details.events, 6);
  assert.equal(s.get('SELECT COUNT(*) n FROM alerts').n, prodAlerts); assert.equal(s.get('SELECT COUNT(*) n FROM events').n, prodEvents, 'replay writes nothing to production');
  const broken = new ValidationLab(s, { clock: () => Date.parse('2026-11-22T10:05:00.000Z'), domain: d, Domain: BrokenDomain }).replay('analyst-a', { source_id: src.id });
  assert.equal(broken.passed, false); assert.deepEqual(broken.missing, ['CG-AUTH-FAILURES-5-IN-5M']); assert.equal(s.all("SELECT 1 FROM alerts WHERE rule_id='CG-VALIDATION-MISS-115'").length, 1);
  assert.throws(() => lab.replay('analyst-a', { source_id: 'missing' }), /source_not_found/); assert.throws(() => lab.replay('analyst-a', { source_id: src.id, since: '2030-01-01T00:00:00.000Z' }), /no_events_to_replay/);
});
