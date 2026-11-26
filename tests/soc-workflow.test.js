import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { Hypotheses } from '../lib/hypotheses.js';
import { evidenceKinds } from '../lib/domain.js';
import { SocWorkflow } from '../lib/soc-workflow.js';

const T0 = Date.parse('2026-11-26T08:00:00.000Z'), iso = ms => new Date(ms).toISOString();
function fixture(t) {
  const s = new Store(':memory:'); t.after(() => s.close()); let now = T0; const d = new Domain(s, { clock: () => now });
  for (const [id, role] of [['lead', 'admin'], ['ana', 'analyst'], ['omar', 'analyst'], ['mgr', 'admin'], ['view', 'viewer']]) s.run('INSERT INTO users VALUES (?,?,?,?,?)', id, id, 'fixture-not-a-password-hash', role, iso(now));
  const signer = { fingerprint: 'f', publicKeyPem: 'k', sign: () => 'sig', verify: () => true }, hyp = new Hypotheses(s, { clock: () => now, domain: d, evidenceKinds, signer });
  const soc = new SocWorkflow(s, { clock: () => now, hypotheses: hyp }); d.socWorkflow = soc;
  const src = d.createSource('lead', { name: 'Logs', stale_seconds: 86400 }), asset = { external_id: 'srv', hostname: 'SRV', os_family: 'windows', device_type: 'server', addresses: ['10.0.0.5'] };
  for (let i = 0; i < 5; i++) d.ingest('lead', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: `f${i}`, kind: 'auth.failed', observed_at: iso(now), asset, details: { account: 'svc', source_ip: '203.0.113.7', protocol: 'rdp' } }] });
  const alert = s.get('SELECT id,severity FROM alerts').id, kase = d.createCase('lead', { title: 'Brute force on SRV', alert_ids: [alert] });
  return { s, d, soc, alert, kase, setNow: ms => { now = ms; } };
}

test('on-call shifts refuse overlaps, show coverage gaps and drive escalation by severity service level (CG-127)', t => {
  const { s, soc, alert, setNow } = fixture(t);
  soc.addShift('lead', { user_id: 'ana', role: 'primary', starts_at: iso(T0), ends_at: iso(T0 + 12 * 3600000) });
  soc.addShift('lead', { user_id: 'omar', role: 'secondary', starts_at: iso(T0), ends_at: iso(T0 + 12 * 3600000) });
  soc.addShift('lead', { user_id: 'mgr', role: 'manager', starts_at: iso(T0), ends_at: iso(T0 + 12 * 3600000) });
  assert.throws(() => soc.addShift('lead', { user_id: 'omar', role: 'primary', starts_at: iso(T0 + 3600000), ends_at: iso(T0 + 7200000) }), /overlapping_shift_for_role/);
  assert.throws(() => soc.addShift('lead', { user_id: 'view', role: 'primary', starts_at: iso(T0 + 13 * 3600000), ends_at: iso(T0 + 14 * 3600000) }), /shift_user_must_be_an_analyst_or_admin/);
  assert.equal(soc.onCall().primary.username, 'ana'); assert.equal(soc.coverageGaps(24)[0].from, iso(T0 + 12 * 3600000), 'the night is uncovered');
  const sev = s.get('SELECT severity FROM alerts WHERE id=?', alert).severity, ack = soc.sla()[sev].ack_minutes * 60000;
  assert.deepEqual(soc.escalate(), []); setNow(T0 + ack + 1000); assert.deepEqual(soc.escalate().map(e => [e.level, e.to]), [[1, 'ana']]);
  assert.deepEqual(soc.escalate(), [], 'each level is raised once'); setNow(T0 + 3 * ack + 1000); assert.deepEqual(soc.escalate().map(e => [e.level, e.to]), [[2, 'omar'], [3, 'mgr']]);
  assert.throws(() => soc.setSla('lead', { critical: { ack_minutes: 500, resolve_hours: 4 } }), /sla_must_not_be_shorter_for_lower_severity/);
});

test('tickets get priority and due dates; closure needs a root cause, lessons for true positives and a second reviewer for high cases (CG-127)', t => {
  const { s, d, soc, kase } = fixture(t);
  assert.throws(() => d.updateCase('ana', kase.id, { status: 'closed', note: 'done' }), /case_closure_requires_closure_policy/);
  const tk = soc.assign('lead', kase.id, { assignee: 'ana' }); assert.equal(tk.priority, 'high'); assert.equal(tk.assignee_name, 'ana'); assert.equal(tk.due_at, iso(Date.parse(kase.created_at) + 24 * 3600000));
  assert.throws(() => soc.requestClosure('ana', kase.id, { resolution: 'true-positive-contained', root_cause: 'short' }), /root_cause_must_be_described/);
  assert.throws(() => soc.requestClosure('ana', kase.id, { resolution: 'true-positive-contained', root_cause: 'Password spraying from an exposed RDP service' }), /true_positive_requires_lessons_learned/);
  const lesson = soc.addLesson('ana', { case_id: kase.id, what_happened: 'RDP exposed to the internet was sprayed', to_improve: 'Detect sprays across accounts sooner', detection_gap: true, actions: [{ owner: 'network', due_at: iso(T0 + 7 * 86400000), text: 'Close RDP to the internet' }] });
  const cl = soc.requestClosure('ana', kase.id, { resolution: 'true-positive-contained', root_cause: 'Password spraying from an exposed RDP service' });
  assert.equal(cl.status, 'awaiting-review'); assert.equal(s.get('SELECT status FROM cases WHERE id=?', kase.id).status, 'open');
  assert.throws(() => soc.reviewClosure('ana', kase.id, true), /independent_reviewer_required/);
  assert.equal(soc.reviewClosure('lead', kase.id, true).status, 'closed'); assert.equal(s.get('SELECT status FROM cases WHERE id=?', kase.id).status, 'closed');
  const out = soc.lessonToDetection('ana', lesson.id, { title: 'Spray across many accounts from one source', technique_ids: ['T1110.003'], severity: 'high', logic: { kind: 'auth.failed', match: 'all', conditions: [{ field: 'protocol', operator: 'equals', value: 'rdp' }] } });
  assert.equal(out.hypothesis.status, 'draft', 'the new detection still needs a test and approval'); assert.equal(out.hypothesis.source_ref, `lesson:${lesson.id}`); assert.throws(() => soc.lessonToDetection('ana', lesson.id, {}), /lesson_already_has_detection/);
  assert.deepEqual(s.all("SELECT action FROM audit WHERE action LIKE 'case.%' ORDER BY seq").map(x => x.action).filter(a => a !== 'case.created'), ['case.assigned', 'case.closure.requested', 'case.closure.approved', 'case.closed']);
});

test('tabletop exercises record participants and findings and can produce lessons (CG-127)', t => {
  const { soc } = fixture(t);
  assert.throws(() => soc.planExercise('lead', { title: 'Ransomware', scenario: 'x', scheduled_at: iso(T0 + 86400000), participants: ['ana'] }), /exercise_requires_at_least_two_participants/);
  const e = soc.planExercise('lead', { title: 'Ransomware on the file server', scenario: 'Encryption starts on FS01 at 02:00 during a holiday', scheduled_at: iso(T0 + 86400000), participants: ['ana', 'omar', 'mgr'] });
  assert.throws(() => soc.completeExercise('lead', e.id, { findings: [] }), /exercise_requires_findings/);
  const done = soc.completeExercise('lead', e.id, { findings: ['Nobody knew who approves isolation at night', 'Backups restore took 6 hours'] }); assert.equal(done.status, 'completed'); assert.equal(done.findings.length, 2);
  const l = soc.addLesson('lead', { exercise_id: e.id, what_happened: 'Tabletop exposed an approval gap at night', to_improve: 'Name a night-time safety approver' }); assert.equal(l.exercise_id, e.id);
  const v = soc.view(); assert.equal(v.exercises[0].status, 'completed'); assert.equal(v.lessons.length, 1); assert.ok(v.claim_ar.includes('تمارين محاكاة'));
});
