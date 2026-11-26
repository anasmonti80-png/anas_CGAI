import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { ValidationLab } from '../lib/validation-lab.js';
import { CoverageEvidence, LIMITS } from '../lib/coverage-evidence.js';
import { MAPPINGS } from '../lib/attack-mapping.js';

function fixture(t) {
  const s = new Store(':memory:'); t.after(() => s.close()); let now = Date.now(); const d = new Domain(s, { clock: () => now });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date(now).toISOString()); const src = d.createSource('a', { name: 'Sensors', stale_seconds: 86400 });
  const host = { external_id: 'ws-1', hostname: 'WS-1', os_family: 'windows', device_type: 'workstation', addresses: ['10.80.0.1'] };
  const fail = () => d.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: `f-${now}`, kind: 'auth.failed', observed_at: new Date(now).toISOString(), asset: host, details: { account: 'bob', source_ip: '10.80.0.9', protocol: 'rdp' } }] });
  return { s, d, ce: new CoverageEvidence(s, { clock: () => now }), lab: new ValidationLab(s, { clock: () => now, domain: d, Domain }), fail, advance: days => { now += days * 86400000; } };
}
const tech = (v, id) => v.techniques.find(t => t.technique === id), rule = (v, id) => v.rules.find(r => r.rule === id);

test('a technique is not covered because a rule exists: telemetry, a passing detection test and documented limits are all required (CG-145)', t => {
  const { ce, lab, fail } = fixture(t);
  let v = ce.view(); assert.equal(v.summary.covered, 0, 'nothing is covered by rule existence alone'); assert.ok(v.summary.rules_existing > 20);
  assert.deepEqual(rule(v, 'CG-AUTH-FAILURES-5-IN-5M').missing, ['telemetry', 'detection-test']); assert.equal(tech(v, 'T1110').state, 'partial');
  fail(); v = ce.view(); assert.deepEqual(rule(v, 'CG-AUTH-FAILURES-5-IN-5M').missing, ['detection-test'], 'telemetry arriving is not enough');
  lab.runScenario('a', 'brute-force-rdp'); v = ce.view(); const r = rule(v, 'CG-AUTH-FAILURES-5-IN-5M');
  assert.equal(r.covered, true); assert.equal(r.test.method, 'validation-lab'); assert.equal(tech(v, 'T1110').state, 'covered'); assert.deepEqual(tech(v, 'T1110').covered_by, ['CG-AUTH-FAILURES-5-IN-5M']);
  assert.ok(Object.keys(LIMITS).every(k => MAPPINGS.some(m => m.rule === k && m.category === 'detection')), 'limits are documented for detection rules only');
  const undocumented = v.rules.find(x => x.category === 'detection' && !LIMITS[x.rule]); assert.ok(undocumented.missing.includes('performance-limits'));
  assert.ok(v.techniques.some(x => x.state === 'posture-only'), 'posture rules never count as detection coverage');
  const layer = ce.layer(); assert.equal(layer.techniques.find(x => x.techniqueID === 'T1110').score, 100); assert.ok(layer.techniques.every(x => x.score === 100 || x.score === 50));
});

test('coverage expires: stale telemetry or a test older than 90 days removes it, and recorded tests count only for detection rules (CG-145)', t => {
  const { s, ce, lab, fail, advance } = fixture(t);
  fail(); lab.runScenario('a', 'brute-force-rdp'); assert.equal(rule(ce.view(), 'CG-AUTH-FAILURES-5-IN-5M').covered, true);
  advance(8); assert.deepEqual(rule(ce.view(), 'CG-AUTH-FAILURES-5-IN-5M').missing, ['telemetry'], 'telemetry older than 7 days is stale');
  fail(); advance(91); fail(); assert.deepEqual(rule(ce.view(), 'CG-AUTH-FAILURES-5-IN-5M').missing, ['detection-test'], 'a test older than 90 days no longer counts');
  ce.recordTest('a', { rule: 'CG-AUTH-FAILURES-5-IN-5M', result: 'pass', method: 'purple-team', evidence_ref: 'PT-145' }); assert.equal(rule(ce.view(), 'CG-AUTH-FAILURES-5-IN-5M').covered, true);
  ce.recordTest('a', { rule: 'CG-AUTH-FAILURES-5-IN-5M', result: 'fail', method: 'replay', evidence_ref: 'RP-145' }); assert.equal(rule(ce.view(), 'CG-AUTH-FAILURES-5-IN-5M').test.state, 'fail', 'the latest test decides');
  assert.throws(() => ce.recordTest('a', { rule: 'CG-NETPOSTURE-096', result: 'pass', method: 'replay', evidence_ref: 'X' }), /coverage_rule_not_a_detection_rule/);
  assert.equal(s.all("SELECT 1 FROM audit WHERE action='coverage.detection_test_recorded'").length, 2);
});
