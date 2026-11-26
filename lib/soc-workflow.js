// CG-127 Operational SOC workflow: on-call rotation, case assignment (tickets) with priority and due dates, escalation
// by severity service levels, a closure policy, lessons-learned reports that can become improved detection hypotheses,
// and tabletop exercises. Everything is recorded and audited; escalation runs whenever the workflow view is read or the
// run endpoint is called, so it needs no background scheduler.
import { randomUUID } from 'node:crypto';
import { fail, text, choice, timestamp } from './common.js';

export const ROLES = ['primary', 'secondary', 'manager'];
export const SLA_DEFAULTS = { critical: { ack_minutes: 15, resolve_hours: 4 }, high: { ack_minutes: 60, resolve_hours: 24 }, medium: { ack_minutes: 240, resolve_hours: 72 }, low: { ack_minutes: 1440, resolve_hours: 168 }, info: { ack_minutes: 2880, resolve_hours: 336 } };
export const RESOLUTIONS = ['true-positive-contained', 'true-positive-accepted-risk', 'false-positive', 'benign-expected', 'duplicate'];
const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }, parse = s => JSON.parse(s);

export class SocWorkflow {
  constructor(store, { clock, hypotheses }) { Object.assign(this, { s: store, clock: clock || (() => Date.now()), hypotheses }); }
  now() { return new Date(this.clock()).toISOString(); }
  sla() { const r = this.s.get('SELECT policy FROM soc_sla WHERE id=1'); return r ? parse(r.policy) : SLA_DEFAULTS; }
  setSla(actor, input) {
    const p = {}; for (const sev of Object.keys(SLA_DEFAULTS)) { const v = input?.[sev] || SLA_DEFAULTS[sev]; fail(Number.isInteger(v.ack_minutes) && v.ack_minutes >= 1 && v.ack_minutes <= 10080 && Number.isInteger(v.resolve_hours) && v.resolve_hours >= 1 && v.resolve_hours <= 2160, 400, `invalid_sla_${sev}`); p[sev] = { ack_minutes: v.ack_minutes, resolve_hours: v.resolve_hours }; }
    fail(Object.keys(SLA_DEFAULTS).every((s, i, a) => i === 0 || p[s].ack_minutes >= p[a[i - 1]].ack_minutes), 400, 'sla_must_not_be_shorter_for_lower_severity');
    this.s.run('INSERT INTO soc_sla(id,policy,updated_by,updated_at) VALUES (1,?,?,?) ON CONFLICT(id) DO UPDATE SET policy=excluded.policy,updated_by=excluded.updated_by,updated_at=excluded.updated_at', JSON.stringify(p), actor, this.now());
    this.s.audit(actor, 'soc.sla.updated', 'sla', p, this.now()); return p;
  }
  // On-call rotation
  addShift(actor, input) {
    const user_id = text(input.user_id, 'shift_user', 64), role = choice(input.role, ROLES, 'shift_role'), starts_at = timestamp(input.starts_at, 'shift_starts_at', this.clock() + 400 * 86400000), ends_at = timestamp(input.ends_at, 'shift_ends_at', this.clock() + 401 * 86400000);
    fail(this.s.get("SELECT id FROM users WHERE id=? AND role IN ('admin','analyst')", user_id), 400, 'shift_user_must_be_an_analyst_or_admin'); fail(ends_at > starts_at && Date.parse(ends_at) - Date.parse(starts_at) <= 24 * 3600000, 400, 'shift_must_be_positive_and_at_most_24_hours');
    fail(!this.s.get('SELECT id FROM soc_shifts WHERE role=? AND starts_at<? AND ends_at>?', role, ends_at, starts_at), 409, 'overlapping_shift_for_role');
    const id = randomUUID(); this.s.run('INSERT INTO soc_shifts(id,user_id,role,starts_at,ends_at,created_by,created_at) VALUES (?,?,?,?,?,?,?)', id, user_id, role, starts_at, ends_at, actor, this.now());
    this.s.audit(actor, 'soc.shift.added', id, { user_id, role, starts_at, ends_at }, this.now()); return this.s.get('SELECT * FROM soc_shifts WHERE id=?', id);
  }
  onCall(at = this.now()) { return Object.fromEntries(ROLES.map(r => [r, this.s.get('SELECT s.user_id,u.username,s.ends_at FROM soc_shifts s JOIN users u ON u.id=s.user_id WHERE s.role=? AND s.starts_at<=? AND s.ends_at>? LIMIT 1', r, at, at) || null])); }
  coverageGaps(hours = 168) {
    const from = this.clock(), to = from + hours * 3600000, shifts = this.s.all("SELECT starts_at,ends_at FROM soc_shifts WHERE role='primary' AND ends_at>? AND starts_at<? ORDER BY starts_at", new Date(from).toISOString(), new Date(to).toISOString()), gaps = [];
    let cursor = from; for (const s of shifts) { const a = Date.parse(s.starts_at), b = Date.parse(s.ends_at); if (a > cursor) gaps.push({ from: new Date(cursor).toISOString(), to: new Date(a).toISOString() }); cursor = Math.max(cursor, b); }
    if (cursor < to) gaps.push({ from: new Date(cursor).toISOString(), to: new Date(to).toISOString() }); return gaps;
  }
  // Escalation: an open alert not acknowledged within its severity service level goes to primary, then secondary, then manager.
  escalate(actor = 'soc-escalation') {
    const sla = this.sla(), now = this.clock(), made = [], oc = this.onCall();
    for (const a of this.s.all("SELECT id,severity,first_seen,status FROM alerts WHERE status='open'")) {
      const ack = (sla[a.severity] || sla.info).ack_minutes * 60000, overdue = now - Date.parse(a.first_seen), level = overdue >= 3 * ack ? 3 : overdue >= 2 * ack ? 2 : overdue >= ack ? 1 : 0;
      for (let l = 1; l <= level; l++) { if (this.s.get('SELECT 1 FROM soc_escalations WHERE alert_id=? AND level=?', a.id, l)) continue; const to = oc[ROLES[l - 1]];
        this.s.run('INSERT INTO soc_escalations(alert_id,level,role,to_user,at,overdue_minutes) VALUES (?,?,?,?,?,?)', a.id, l, ROLES[l - 1], to?.user_id || null, this.now(), Math.floor(overdue / 60000));
        this.s.audit(actor, 'soc.alert.escalated', a.id, { level: l, role: ROLES[l - 1], to_user: to?.user_id || null, unassigned: !to }, this.now()); made.push({ alert_id: a.id, level: l, role: ROLES[l - 1], to: to?.username || null }); }
    }
    return made;
  }
  // Tickets: a case gets an assignee, a priority from its most severe alert, and a due date from the resolve service level.
  assign(actor, caseId, input) {
    const c = this.s.get('SELECT * FROM cases WHERE id=?', caseId); fail(c, 404, 'case_not_found'); fail(c.status !== 'closed', 409, 'case_closed');
    const assignee = text(input.assignee, 'case_assignee', 64); fail(this.s.get("SELECT id FROM users WHERE id=? AND role IN ('admin','analyst')", assignee), 400, 'assignee_must_be_an_analyst_or_admin');
    const sev = parse(c.alert_ids).map(a => this.s.get('SELECT severity FROM alerts WHERE id=?', a)?.severity).filter(Boolean).sort((x, y) => RANK[y] - RANK[x])[0] || 'low', due = new Date(Date.parse(c.created_at) + this.sla()[sev].resolve_hours * 3600000).toISOString();
    this.s.run('INSERT INTO case_tickets(case_id,assignee,priority,due_at,assigned_by,assigned_at) VALUES (?,?,?,?,?,?) ON CONFLICT(case_id) DO UPDATE SET assignee=excluded.assignee,assigned_by=excluded.assigned_by,assigned_at=excluded.assigned_at', caseId, assignee, sev, due, actor, this.now());
    this.s.audit(actor, 'case.assigned', caseId, { assignee, priority: sev, due_at: due }, this.now()); return this.ticket(caseId);
  }
  ticket(caseId) { const t = this.s.get('SELECT t.*,u.username assignee_name FROM case_tickets t JOIN users u ON u.id=t.assignee WHERE t.case_id=?', caseId); return t ? { ...t, overdue: t.due_at < this.now() } : null; }
  // Closure policy: a resolution and a root cause are required; true positives need a lessons-learned report; high and
  // critical cases are closed only when a second person reviews the closure.
  requestClosure(actor, caseId, input) {
    const c = this.s.get('SELECT * FROM cases WHERE id=?', caseId); fail(c, 404, 'case_not_found'); fail(c.status !== 'closed', 409, 'case_already_closed');
    const resolution = choice(input.resolution, RESOLUTIONS, 'case_resolution'), root_cause = text(input.root_cause, 'case_root_cause', 2000); fail(root_cause.length >= 20, 400, 'root_cause_must_be_described');
    if (resolution.startsWith('true-positive')) fail(this.s.get('SELECT id FROM soc_lessons WHERE case_id=?', caseId), 409, 'true_positive_requires_lessons_learned');
    const priority = this.ticket(caseId)?.priority || 'low', needsReview = RANK[priority] >= RANK.high;
    this.s.run('INSERT INTO case_closures(case_id,resolution,root_cause,requested_by,requested_at,needs_review,status) VALUES (?,?,?,?,?,?,?) ON CONFLICT(case_id) DO UPDATE SET resolution=excluded.resolution,root_cause=excluded.root_cause,requested_by=excluded.requested_by,requested_at=excluded.requested_at,needs_review=excluded.needs_review,status=excluded.status', caseId, resolution, root_cause, actor, this.now(), needsReview ? 1 : 0, needsReview ? 'awaiting-review' : 'closed');
    this.s.audit(actor, 'case.closure.requested', caseId, { resolution, needs_review: needsReview }, this.now());
    if (!needsReview) this.close(actor, caseId); return this.closure(caseId);
  }
  reviewClosure(actor, caseId, approve) {
    const cl = this.s.get('SELECT * FROM case_closures WHERE case_id=?', caseId); fail(cl && cl.status === 'awaiting-review', 409, 'closure_not_awaiting_review'); fail(actor !== cl.requested_by, 403, 'independent_reviewer_required');
    this.s.run('UPDATE case_closures SET status=?,reviewed_by=?,reviewed_at=? WHERE case_id=?', approve ? 'closed' : 'rejected', actor, this.now(), caseId); this.s.audit(actor, approve ? 'case.closure.approved' : 'case.closure.rejected', caseId, {}, this.now());
    if (approve) this.close(actor, caseId); return this.closure(caseId);
  }
  close(actor, caseId) { this.closeGate?.(caseId); this.s.run("UPDATE cases SET status='closed',updated_at=? WHERE id=?", this.now(), caseId); this.s.audit(actor, 'case.closed', caseId, {}, this.now()); }
  closure(caseId) { return this.s.get('SELECT * FROM case_closures WHERE case_id=?', caseId) || null; }
  // Lessons learned, and turning a detection gap into a draft detection hypothesis (still tested and approved by people).
  addLesson(actor, input) {
    const case_id = input.case_id ? text(input.case_id, 'lesson_case', 64) : null, exercise_id = input.exercise_id ? text(input.exercise_id, 'lesson_exercise', 64) : null; fail(case_id || exercise_id, 400, 'lesson_requires_case_or_exercise');
    if (case_id) fail(this.s.get('SELECT id FROM cases WHERE id=?', case_id), 404, 'case_not_found');
    const actions = Array.isArray(input.actions) ? input.actions.slice(0, 20).map((a, i) => ({ owner: text(a.owner, `lesson_action_${i}_owner`, 100), due_at: timestamp(a.due_at, `lesson_action_${i}_due`, this.clock() + 400 * 86400000), text: text(a.text, `lesson_action_${i}_text`, 500) })) : [];
    const l = { id: randomUUID(), case_id, exercise_id, what_happened: text(input.what_happened, 'lesson_what_happened', 4000), went_well: text(input.went_well, 'lesson_went_well', 4000, true), to_improve: text(input.to_improve, 'lesson_to_improve', 4000), detection_gap: input.detection_gap === true, actions };
    this.s.run('INSERT INTO soc_lessons(id,case_id,exercise_id,what_happened,went_well,to_improve,detection_gap,actions,hypothesis_id,created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)', l.id, case_id, exercise_id, l.what_happened, l.went_well, l.to_improve, l.detection_gap ? 1 : 0, JSON.stringify(actions), null, actor, this.now());
    this.s.audit(actor, 'soc.lesson.recorded', l.id, { case_id, exercise_id, detection_gap: l.detection_gap, actions: actions.length }, this.now()); return this.lesson(l.id);
  }
  lesson(id) { const r = this.s.get('SELECT * FROM soc_lessons WHERE id=?', id); fail(r, 404, 'lesson_not_found'); return { ...r, detection_gap: Boolean(r.detection_gap), actions: parse(r.actions) }; }
  lessonToDetection(actor, id, input) {
    const l = this.lesson(id); fail(l.detection_gap, 409, 'lesson_has_no_detection_gap'); fail(!l.hypothesis_id, 409, 'lesson_already_has_detection');
    const h = this.hypotheses.create(actor, { title: input.title, source_type: 'internal-observation', source_ref: `lesson:${id}`, technique_ids: input.technique_ids || [], severity: input.severity || 'medium', rationale: `From lessons learned ${id}: ${l.to_improve}`.slice(0, 1000), logic: input.logic });
    this.s.run('UPDATE soc_lessons SET hypothesis_id=? WHERE id=?', String(h.id), id); this.s.audit(actor, 'soc.lesson.detection_drafted', id, { hypothesis_id: h.id }, this.now()); return { lesson: this.lesson(id), hypothesis: h };
  }
  // Tabletop exercises
  planExercise(actor, input) {
    const id = randomUUID(), participants = (Array.isArray(input.participants) ? input.participants : []).slice(0, 30).map((p, i) => text(p, `exercise_participant_${i}`, 100)); fail(participants.length >= 2, 400, 'exercise_requires_at_least_two_participants');
    this.s.run('INSERT INTO soc_exercises(id,title,scenario,scheduled_at,participants,status,created_by,created_at) VALUES (?,?,?,?,?,?,?,?)', id, text(input.title, 'exercise_title', 200), text(input.scenario, 'exercise_scenario', 4000), timestamp(input.scheduled_at, 'exercise_scheduled_at', this.clock() + 400 * 86400000), JSON.stringify(participants), 'planned', actor, this.now());
    this.s.audit(actor, 'soc.exercise.planned', id, { participants: participants.length }, this.now()); return this.exercise(id);
  }
  completeExercise(actor, id, input) {
    const e = this.exercise(id); fail(e.status === 'planned', 409, 'exercise_not_planned'); const findings = (Array.isArray(input.findings) ? input.findings : []).slice(0, 50).map((f, i) => text(f, `exercise_finding_${i}`, 1000)); fail(findings.length >= 1, 400, 'exercise_requires_findings');
    this.s.run("UPDATE soc_exercises SET status='completed',findings=?,completed_at=? WHERE id=?", JSON.stringify(findings), this.now(), id); this.s.audit(actor, 'soc.exercise.completed', id, { findings: findings.length }, this.now()); return this.exercise(id);
  }
  exercise(id) { const r = this.s.get('SELECT * FROM soc_exercises WHERE id=?', id); fail(r, 404, 'exercise_not_found'); return { ...r, participants: parse(r.participants), findings: r.findings ? parse(r.findings) : [] }; }
  view() {
    const escalations = this.escalate();
    return { staff: this.s.all("SELECT id,username,role FROM users WHERE role IN ('admin','analyst') ORDER BY username"), on_call: this.onCall(), coverage_gaps: this.coverageGaps(), sla: this.sla(), new_escalations: escalations, escalations: this.s.all('SELECT e.*,u.username to_name FROM soc_escalations e LEFT JOIN users u ON u.id=e.to_user ORDER BY e.at DESC LIMIT 50'),
      tickets: this.s.all("SELECT c.id,c.title,c.status FROM cases c WHERE c.status<>'closed' ORDER BY c.created_at DESC LIMIT 100").map(c => ({ ...c, ticket: this.ticket(c.id), closure: this.closure(c.id) })),
      shifts: this.s.all('SELECT s.*,u.username FROM soc_shifts s JOIN users u ON u.id=s.user_id WHERE s.ends_at>? ORDER BY s.starts_at LIMIT 100', this.now()),
      lessons: this.s.all('SELECT id,case_id,exercise_id,detection_gap,hypothesis_id,created_at FROM soc_lessons ORDER BY created_at DESC LIMIT 50').map(r => ({ ...r, detection_gap: Boolean(r.detection_gap) })),
      exercises: this.s.all('SELECT id,title,scheduled_at,status,completed_at FROM soc_exercises ORDER BY scheduled_at DESC LIMIT 50'),
      claim: 'On-call rotation with coverage gaps, escalation by severity service level, case tickets with priority and due dates, a closure policy with root cause and second review, lessons learned that can become detection hypotheses, and tabletop exercises.',
      claim_ar: 'مناوبات مع كشف فجوات التغطية، وتصعيد حسب مستوى خدمة الخطورة، وتذاكر حالات بأولوية وموعد استحقاق، وسياسة إغلاق بسبب جذري ومراجعة ثانية، ودروس مستفادة يمكن تحويلها لفرضيات كشف، وتمارين محاكاة.' };
  }
}
