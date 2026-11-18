// CG-062 Staged rollout: isolated lab with test data -> limited authorized pilot -> expansion, each step gated by
// measured evidence and approved by a second administrator. While the lab or pilot stage is active, response actions
// are accepted only for assets inside the declared stage scope. Gates are computed from this installation's own data:
// lab validation runs, the test evidence of the running build, the audit chain and the pilot's measured quality.
import fs from 'node:fs';
import { fail, object, text, choice } from './common.js';

export const STAGES = ['isolated-lab', 'limited-pilot', 'expansion'];
export const PILOT_MIN_DAYS = 7, PILOT_MAX_ASSETS = 50;
export const EXPANSION_FLOOR = { min_dispositions: 10, min_precision: 0.7, min_triage_completion: 0.8, max_action_failure_rate: 0.2, min_device_coverage: 0.9 };
const parse = v => JSON.parse(v || '[]');
const STAGE_AR = { 'isolated-lab': 'مختبر معزول', 'limited-pilot': 'تجربة محدودة', expansion: 'توسع' };
const LABELS = { 'test-evidence': ['Test evidence of this build', 'دليل اختبارات هذه النسخة'], 'audit-chain': ['Audit chain', 'سلسلة التدقيق'], 'current-stage': ['Current stage', 'المرحلة الحالية'], 'lab-validation': ['Lab validation run', 'تشغيل تحقق في المختبر'], 'explicit-scope': ['Explicit pilot scope', 'نطاق تجربة صريح'], 'pilot-duration': ['Pilot duration', 'مدة التجربة'], 'triage-sample': ['Triaged alerts', 'تنبيهات مصنفة'], precision: ['Precision', 'الدقة'], 'triage-completion': ['Triage completion', 'اكتمال التصنيف'], 'response-failures': ['Response failure rate', 'نسبة فشل الاستجابة'], 'device-coverage': ['Device coverage', 'تغطية الأجهزة'], demotion: ['Move back', 'رجوع لمرحلة سابقة'] };

export class Rollout {
  constructor(store, { clock, domain, verificationFile }) { Object.assign(this, { s: store, clock: clock || (() => Date.now()), domain, verificationFile }); }
  now() { return new Date(this.clock()).toISOString(); }
  row(r) { return r ? { id: r.id, stage: r.stage, asset_refs: parse(r.asset_refs), sites: parse(r.sites), authorization_ref: r.authorization_ref, requested_by: r.requested_by, approved_by: r.approved_by, requested_at: r.requested_at, approved_at: r.approved_at, status: r.status, gate: r.gate_json ? JSON.parse(r.gate_json) : null } : null; }
  active() { return this.row(this.s.get("SELECT * FROM rollout_stages WHERE status='active' ORDER BY id DESC LIMIT 1")); }
  testEvidence() {
    try { const v = JSON.parse(fs.readFileSync(this.verificationFile, 'utf8')); return { passed: v.passed === true && v.fail === 0, tests: v.tests ?? null, at: v.at ?? null, level: v.level ?? null }; }
    catch { return { passed: false, tests: null, at: null, level: null }; }
  }
  // Every check states what was measured; a stage is reachable only when all its checks pass.
  gate(stage, scope) {
    const checks = [], add = (id, ok, measured, required, measured_ar = measured, required_ar = required) => checks.push({ id, label: LABELS[id][0], label_ar: LABELS[id][1], ok: Boolean(ok), measured, required, measured_ar, required_ar });
    const current = this.active(), audit = this.s.verifyAudit(), evidence = this.testEvidence();
    add('test-evidence', evidence.passed, evidence.passed ? `${evidence.tests} tests passed (${evidence.level})` : 'no passing verification for this build', 'artifacts/verification.json passed', evidence.passed ? `اختبارات ناجحة: ${evidence.tests}` : 'لا يوجد تحقق ناجح لهذه النسخة', 'نجاح artifacts/verification.json');
    add('audit-chain', audit.valid, audit.valid ? `${audit.checked} records intact` : 'audit chain broken', 'intact audit chain', audit.valid ? `سجلات سليمة: ${audit.checked}` : 'سلسلة التدقيق مكسورة', 'سلسلة تدقيق سليمة');
    if (stage === 'isolated-lab') return { stage, ready: checks.every(c => c.ok), checks };
    if (stage === 'limited-pilot') {
      const program = this.domain.validationProgram({ limit: 1000 }), labRuns = program.items.filter(p => p.environment === 'lab').flatMap(p => p.runs.filter(r => r.compliance === 'within-plan'));
      add('current-stage', current?.stage === 'isolated-lab' || current?.stage === 'limited-pilot', current ? current.stage : 'none', 'isolated lab active', current ? STAGE_AR[current.stage] : 'لا توجد', 'المختبر المعزول نشط');
      add('lab-validation', labRuns.length > 0, `${labRuns.length} within-plan lab run(s)`, 'at least one approved lab validation run', `تشغيلات مختبر داخل الخطة: ${labRuns.length}`, 'تشغيل تحقق معتمد واحد على الأقل في المختبر');
      add('explicit-scope', scope && (scope.asset_refs.length + scope.sites.length) > 0 && scope.asset_refs.length <= PILOT_MAX_ASSETS && ![...scope.asset_refs, ...scope.sites].some(x => /[*?]|^(any|all)$/i.test(x)), scope ? `${scope.asset_refs.length} asset(s), ${scope.sites.length} site(s)` : 'none', `explicit assets (max ${PILOT_MAX_ASSETS}) or sites, no wildcard`, scope ? `${scope.asset_refs.length} أصل، ${scope.sites.length} موقع` : 'لا يوجد', `أصول صريحة (حتى ${PILOT_MAX_ASSETS}) أو مواقع، بلا رموز عامة`);
      return { stage, ready: checks.every(c => c.ok), checks };
    }
    const days = current?.stage === 'limited-pilot' ? (this.clock() - Date.parse(current.approved_at)) / 86400000 : 0;
    add('current-stage', current?.stage === 'limited-pilot' || current?.stage === 'expansion', current ? current.stage : 'none', 'limited pilot active', current ? STAGE_AR[current.stage] : 'لا توجد', 'التجربة المحدودة نشطة');
    add('pilot-duration', days >= PILOT_MIN_DAYS, `${Math.floor(days)} day(s)`, `${PILOT_MIN_DAYS} days of pilot`, `الأيام: ${Math.floor(days)}`, `${PILOT_MIN_DAYS} أيام تجربة`);
    const m = this.domain.qualityMetrics({ days: Math.max(1, Math.min(365, Math.ceil(days) || 1)) }), q = m.detection_quality, f = EXPANSION_FLOOR;
    add('triage-sample', q.dispositioned >= f.min_dispositions, `${q.dispositioned} dispositioned alerts`, `${f.min_dispositions} dispositioned alerts`, `تنبيهات مصنفة: ${q.dispositioned}`, `${f.min_dispositions} تنبيهات مصنفة`);
    add('precision', q.precision !== null && q.precision >= f.min_precision, q.precision === null ? 'not measured' : `${q.precision}`, `>= ${f.min_precision}`, q.precision === null ? 'غير مُقاس' : `${q.precision}`);
    add('triage-completion', q.triage_completion !== null && q.triage_completion >= f.min_triage_completion, q.triage_completion === null ? 'not measured' : `${q.triage_completion}`, `>= ${f.min_triage_completion}`, q.triage_completion === null ? 'غير مُقاس' : `${q.triage_completion}`);
    const afr = m.response_failures.action_failure_rate; add('response-failures', afr === null || afr <= f.max_action_failure_rate, afr === null ? 'no completed actions' : `${afr}`, `<= ${f.max_action_failure_rate}`, afr === null ? 'لا إجراءات مكتملة' : `${afr}`);
    const cov = m.device_coverage.coverage; add('device-coverage', cov !== null && cov >= f.min_device_coverage, cov === null ? 'no assets' : `${cov}`, `>= ${f.min_device_coverage}`, cov === null ? 'لا أصول' : `${cov}`);
    return { stage, ready: checks.every(c => c.ok), checks };
  }
  request(actor, input) {
    object(input, ['stage', 'asset_refs', 'sites', 'authorization_ref'], 'rollout');
    const stage = choice(input.stage, STAGES, 'rollout_stage'), list = (v, n) => { fail(v === undefined || (Array.isArray(v) && v.length <= 200), 400, `invalid_${n}`); return [...new Set((v || []).map((x, i) => text(x, `${n}_${i}`, 200)))]; };
    const scope = { asset_refs: list(input.asset_refs, 'rollout_asset_refs'), sites: list(input.sites, 'rollout_sites') }, authorization_ref = text(input.authorization_ref, 'rollout_authorization_ref', 200);
    fail(authorization_ref.length >= 6, 400, 'invalid_rollout_authorization_ref');
    if (stage === 'isolated-lab') fail(scope.asset_refs.length > 0 || scope.sites.length > 0, 400, 'lab_scope_required');
    const current = this.active(), demotion = current && STAGES.indexOf(stage) < STAGES.indexOf(current.stage);
    const gate = demotion ? { stage, ready: true, checks: [{ id: 'demotion', label: LABELS.demotion[0], label_ar: LABELS.demotion[1], ok: true, measured: `${current.stage} -> ${stage}`, required: 'moving back never needs a gate', measured_ar: `${STAGE_AR[current.stage]} ← ${STAGE_AR[stage]}`, required_ar: 'الرجوع لا يحتاج شروطًا' }] } : this.gate(stage, scope);
    fail(gate.ready, 409, 'rollout_gate_not_met');
    fail(!this.s.get("SELECT id FROM rollout_stages WHERE status='pending'"), 409, 'rollout_request_pending');
    const id = this.s.transaction(() => { const r = this.s.run("INSERT INTO rollout_stages(stage,asset_refs,sites,authorization_ref,requested_by,requested_at,status,gate_json) VALUES (?,?,?,?,?,?,'pending',?)", stage, JSON.stringify(scope.asset_refs), JSON.stringify(scope.sites), authorization_ref, actor, this.now(), JSON.stringify(gate));
      this.s.audit(actor, 'rollout.requested', String(r.lastInsertRowid), { stage, assets: scope.asset_refs.length, sites: scope.sites.length, authorization_ref }, this.now()); return Number(r.lastInsertRowid); });
    return this.row(this.s.get('SELECT * FROM rollout_stages WHERE id=?', id));
  }
  decide(actor, id, decision) {
    choice(decision, ['approve', 'reject'], 'rollout_decision');
    const r = this.row(this.s.get('SELECT * FROM rollout_stages WHERE id=?', id)); fail(r, 404, 'not_found'); fail(r.status === 'pending', 409, 'rollout_not_pending');
    fail(r.requested_by !== actor, 403, 'independent_rollout_approver_required');
    const current = this.active(), demotion = current && STAGES.indexOf(r.stage) < STAGES.indexOf(current.stage);
    const gate = decision === 'approve' && !demotion ? this.gate(r.stage, { asset_refs: r.asset_refs, sites: r.sites }) : r.gate;
    if (decision === 'approve') fail(gate.ready, 409, 'rollout_gate_not_met');
    this.s.transaction(() => {
      if (decision === 'approve') this.s.run("UPDATE rollout_stages SET status='superseded' WHERE status='active'");
      this.s.run('UPDATE rollout_stages SET status=?,approved_by=?,approved_at=?,gate_json=? WHERE id=?', decision === 'approve' ? 'active' : 'rejected', actor, this.now(), JSON.stringify(gate), id);
      this.s.audit(actor, decision === 'approve' ? 'rollout.approved' : 'rollout.rejected', String(id), { stage: r.stage }, this.now());
    });
    return this.row(this.s.get('SELECT * FROM rollout_stages WHERE id=?', id));
  }
  // Response guard: in the lab and the pilot, actions only for assets inside the declared scope.
  allowsAsset(asset) {
    const a = this.active(); if (!a || a.stage === 'expansion') return true;
    if (a.asset_refs.includes(asset.external_id)) return true;
    const site = this.s.get("SELECT payload FROM events WHERE asset_id=? AND kind='asset.context' ORDER BY observed_at DESC,received_at DESC LIMIT 1", asset.id);
    return Boolean(site && a.sites.includes(JSON.parse(site.payload).details.site));
  }
  status() {
    const active = this.active(), next = active ? STAGES[STAGES.indexOf(active.stage) + 1] || null : 'isolated-lab';
    return { active, declared: Boolean(active), pending: this.row(this.s.get("SELECT * FROM rollout_stages WHERE status='pending' ORDER BY id DESC LIMIT 1")), next_stage: next, next_gate: next ? this.gate(next, next === 'limited-pilot' ? { asset_refs: [], sites: [] } : null) : null,
      history: this.s.all('SELECT * FROM rollout_stages ORDER BY id DESC LIMIT 20').map(r => this.row(r)), stages: STAGES, expansion_floor: EXPANSION_FLOOR, pilot_min_days: PILOT_MIN_DAYS, pilot_max_assets: PILOT_MAX_ASSETS,
      claim: 'Rollout runs in stages: an isolated lab with test data, then a limited pilot on explicitly authorized assets or sites, then expansion only after measured results (pilot duration, analyst-confirmed precision, triage completion, response failures and coverage). Each stage needs a second administrator; during the lab and the pilot, response actions outside the stage scope are refused.',
      claim_ar: 'يتم التشغيل على مراحل: مختبر معزول ببيانات اختبار، ثم تجربة محدودة على أصول أو مواقع مصرح بها صراحة، ثم التوسع فقط بعد نتائج مقاسة (مدة التجربة، والدقة المؤكدة من المحللين، واكتمال التصنيف، وفشل الاستجابة، والتغطية). كل مرحلة تحتاج مسؤولًا ثانيًا، وأثناء المختبر والتجربة تُرفض إجراءات الاستجابة خارج نطاق المرحلة.' };
  }
}
