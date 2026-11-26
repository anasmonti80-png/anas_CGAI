import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain, evidenceKinds } from '../lib/domain.js';
import { BUILTIN_RULES, evaluate, testRule, validateRule, CorrelationRules } from '../lib/correlation-rules.js';

const asset = { external_id: 'srv', hostname: 'srv', os_family: 'windows', device_type: 'server', addresses: [] };
const mins = (base, m) => new Date(base + m * 60000).toISOString();

test('built-in correlation rules fire on every malicious sample and on no benign sample, honour order, windows, distinct counts and allow-lists, and raise alerts from stored events (CG-161)', t => {
  for (const r of BUILTIN_RULES) assert.deepEqual(testRule(r), { passed: true, malicious_fired: r.samples.malicious.length, malicious_total: r.samples.malicious.length, benign_fired: 0, benign_total: r.samples.benign.length }, r.id);
  const brute = BUILTIN_RULES[0], m = evaluate(brute, brute.samples.malicious[0]);
  assert.equal(m.length, 1); assert.deepEqual([m[0].key, m[0].counts], ['203.0.113.10', [5, 1]]);
  assert.equal(evaluate({ ...brute, allow_keys: ['203.0.113.10'] }, brute.samples.malicious[0]).length, 0, 'an allow-listed scanner never matches');
  assert.equal(evaluate({ ...brute, ordered: false }, brute.samples.benign[2]).length, 1, 'without order, success before failures would match');
  const spray = BUILTIN_RULES[1]; assert.deepEqual(evaluate(spray, spray.samples.malicious[0])[0].counts, [10, 1], 'ten distinct accounts, then the success');

  const s = new Store(':memory:'); t.after(() => s.close()); const dom = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); const src = dom.createSource('a', { name: 'Logs', stale_seconds: 86400 });
  const base = Date.now() - 3600000;
  const events = [...Array.from({ length: 6 }, (_, i) => ({ event_id: `f${i}`, kind: 'auth.failed', observed_at: mins(base, i), asset, details: { account: 'svc', source_ip: '198.51.100.7', protocol: 'rdp' } })),
    { event_id: 'ok', kind: 'remote.authenticated', observed_at: mins(base, 9), asset, details: { session_id: 's1', protocol: 'rdp', source_a: { hostname: null, ip: '198.51.100.7', account: 'svc' }, target_b: { hostname: 'srv', ip: '192.0.2.10', account: 'svc' }, relay: false, evidence_type: 'authentication_log' } }];
  dom.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events });
  const alerts = s.all("SELECT title,evidence_ids FROM alerts WHERE rule_id='CG-CORR-BRUTE-SUCCESS-161'"); assert.equal(alerts.length, 1); assert.match(alerts[0].title, /198\.51\.100\.7 \(5 → 1\)/);
  assert.equal(new CorrelationRules(s, { kinds: evidenceKinds }).replay(BUILTIN_RULES[0]).matches, 1, 'replay over stored events finds it too');
});

test('a custom correlation rule is tested on its samples and runs only after a second administrator approves it (CG-161)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); const dom = new Domain(s, {});
  for (const u of ['author', 'approver']) s.run('INSERT INTO users VALUES (?,?,?,?,?)', u, u, 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const fwd = (m, actor) => ({ kind: 'change.sensitive', observed_at: mins(Date.UTC(2026, 10, 1), m), details: { actor_ref: actor, category: 'account', action: 'added' } });
  const def = { title: 'Three account additions by one actor in ten minutes', severity: 'medium', window_seconds: 600, ordered: false, allow_keys: ['svc-provisioning'],
    stages: [{ name: 'adds', kind: 'change.sensitive', key: 'actor_ref', conditions: [{ field: 'category', operator: 'equals', value: 'account' }, { field: 'action', operator: 'equals', value: 'added' }], min_count: 3 }],
    samples: { malicious: [[fwd(0, 'x'), fwd(2, 'x'), fwd(4, 'x')]], benign: [[fwd(0, 'x'), fwd(20, 'x'), fwd(40, 'x')], [fwd(0, 'svc-provisioning'), fwd(1, 'svc-provisioning'), fwd(2, 'svc-provisioning')]] } };
  const cr = new CorrelationRules(s, { kinds: evidenceKinds });
  const bad = cr.create('author', { ...def, samples: { ...def.samples, benign: [[fwd(0, 'y'), fwd(1, 'y'), fwd(2, 'y')]] } });
  assert.deepEqual([bad.test.passed, bad.test.benign_fired], [false, 1]); assert.throws(() => cr.approve('approver', bad.row_id), /correlation_samples_must_pass/);
  const r = cr.create('author', def); assert.equal(r.test.passed, true); assert.equal(r.status, 'draft');
  assert.throws(() => cr.approve('author', r.row_id), /correlation_rule_needs_second_approver/);
  assert.equal(cr.active().some(x => x.id === r.id), false, 'a draft does not run');
  assert.equal(cr.approve('approver', r.row_id).status, 'active'); assert.ok(cr.active().some(x => x.id === r.id));
  assert.throws(() => validateRule({ ...def, stages: [{ ...def.stages[0], kind: 'not.a.kind' }] }, evidenceKinds), /correlation_stage_0_kind/);
  assert.throws(() => validateRule({ ...def, samples: { malicious: [], benign: def.samples.benign } }, evidenceKinds), /correlation_requires_malicious_samples/);
  assert.equal(cr.disable('approver', r.row_id).status, 'disabled'); assert.equal(cr.view().rules.length, 4);
});
