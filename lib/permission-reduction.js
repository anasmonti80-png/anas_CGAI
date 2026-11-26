// CG-152 Permission reduction recommendations. CyberGuard proposes removing excess permissions after usage analysis,
// an identified owner and a change request, publishes a dry-run report of what would change, and never revokes
// anything itself. A permission is not recommended for removal because it went unused for a short window: the
// observation window must be at least 90 days (400 for permissions the owner marks seasonal), break-glass principals
// are excluded, and a principal without an owner waits for one. A recommendation becomes "verified removed" only when
// a later usage import no longer contains the permission.
import { randomUUID } from 'node:crypto';
import { fail, text } from './common.js';

export const MIN_WINDOW_DAYS = 90, SEASONAL_WINDOW_DAYS = 400;
export const ACTIONS = { permission: 'remove-permission', role: 'remove-unused-role', 'access-key': 'deactivate-access-key', password: 'remove-console-password', grant: 'remove-grant' };
export const DECISIONS = ['recommend', 'in-use', 'insufficient-window', 'needs-owner', 'excluded'];
export const DECISION_AR = { recommend: 'يُوصى بالتقليل', 'in-use': 'مستخدمة', 'insufficient-window': 'نافذة المراقبة قصيرة — لا توصية', 'needs-owner': 'تحتاج مالكًا قبل أي توصية', excluded: 'مستثناة (حساب طوارئ)' };
export const STATES = ['proposed', 'change-requested', 'owner-approved', 'dismissed'];
const DAY = 86400000;
export const keyOf = e => `${e.source}|${e.principal}|${e.kind}|${e.permission}`;

// AWS IAM Access Analyzer GetFindingV2 responses for unused access findings, normalised to usage entries.
export function fromAccessAnalyzer(findings, { windowDays, owners = {}, breakGlass = [], seasonal = [] }) {
  fail(Array.isArray(findings), 400, 'not_get_finding_v2_list');
  const out = [];
  for (const f of findings) {
    const principal = String(f.resource || ''), d = f.findingDetails || [], base = { source: 'aws-access-analyzer', principal, owner: owners[principal] || null, window_days: windowDays, break_glass: breakGlass.includes(principal) };
    if (f.status && f.status !== 'ACTIVE') continue;
    for (const x of d) {
      if (x.unusedPermissionDetails) { const u = x.unusedPermissionDetails; const actions = (u.actions || []).map(a => a.action).filter(Boolean);
        out.push({ ...base, kind: 'permission', permission: actions.length ? actions.join(',').slice(0, 300) : `${u.serviceNamespace}:*`, service: u.serviceNamespace || null, last_used: u.lastAccessed || null, seasonal: seasonal.includes(u.serviceNamespace) }); }
      if (x.unusedIamRoleDetails) out.push({ ...base, kind: 'role', permission: principal, service: null, last_used: x.unusedIamRoleDetails.lastAccessed || null, seasonal: false });
      if (x.unusedIamUserAccessKeyDetails) out.push({ ...base, kind: 'access-key', permission: String(x.unusedIamUserAccessKeyDetails.accessKeyId || 'access-key'), service: null, last_used: x.unusedIamUserAccessKeyDetails.lastAccessed || null, seasonal: false });
      if (x.unusedIamUserPasswordDetails) out.push({ ...base, kind: 'password', permission: 'console-password', service: null, last_used: x.unusedIamUserPasswordDetails.lastAccessed || null, seasonal: false });
    }
  }
  return out;
}

export function decide(e, now = Date.now()) {
  if (e.break_glass) return { decision: 'excluded', reason: 'Break-glass principal: never reduced by recommendation.', reason_ar: 'حساب طوارئ: لا يُقلَّص بالتوصيات أبدًا.' };
  const need = e.seasonal ? SEASONAL_WINDOW_DAYS : MIN_WINDOW_DAYS;
  if (!(e.window_days >= need)) return { decision: 'insufficient-window', reason: `Observed for ${e.window_days} days; at least ${need} are needed${e.seasonal ? ' for a seasonal permission' : ''}.`, reason_ar: `رُصدت ${e.window_days} يومًا فقط؛ والمطلوب ${need} يومًا على الأقل${e.seasonal ? ' للصلاحية الموسمية' : ''}.` };
  if (e.last_used && now - Date.parse(e.last_used) < e.window_days * DAY) return { decision: 'in-use', reason: `Used on ${String(e.last_used).slice(0, 10)}, inside the window.`, reason_ar: `استُخدمت في ${String(e.last_used).slice(0, 10)} ضمن النافذة.` };
  if (!e.owner) return { decision: 'needs-owner', reason: 'No accountable owner: assign one before any change is proposed.', reason_ar: 'لا مالك مسؤول: عيّن مالكًا قبل اقتراح أي تغيير.' };
  return { decision: 'recommend', reason: e.last_used ? `Last used ${String(e.last_used).slice(0, 10)}, before the ${e.window_days}-day window.` : `Never used in the ${e.window_days}-day window.`, reason_ar: e.last_used ? `آخر استخدام ${String(e.last_used).slice(0, 10)}، قبل نافذة ${e.window_days} يومًا.` : `لم تُستخدم إطلاقًا خلال ${e.window_days} يومًا.` };
}

export class PermissionReduction {
  constructor(store, { clock } = {}) { Object.assign(this, { s: store, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  imports() { return this.s.all("SELECT observed_at,payload FROM events WHERE kind='identity.permission_usage' ORDER BY observed_at,received_at").map(r => ({ ...JSON.parse(r.payload).details, observed_at: r.observed_at })); }
  state(key) { return this.s.get('SELECT * FROM permission_reduction WHERE key=?', key) || null; }
  view() {
    const imports = this.imports(), now = this.clock(), latestBySource = new Map(); for (const i of imports) latestBySource.set(i.source_ref, i);
    const current = [...latestBySource.values()].flatMap(i => i.entries.map(e => ({ ...e, source_ref: i.source_ref, imported_at: i.observed_at }))), currentKeys = new Set(current.map(keyOf));
    const items = current.map(e => { const k = keyOf(e), d = decide(e, now), st = this.state(k);
      return { key: k, ...e, ...d, action: ACTIONS[e.kind], workflow: st ? { state: st.state, change_ref: st.change_ref, approver: st.approver, note: st.note, updated_at: st.updated_at } : d.decision === 'recommend' ? { state: 'proposed' } : null }; });
    const removed = this.s.all("SELECT * FROM permission_reduction WHERE state='owner-approved'").filter(r => !currentKeys.has(r.key)).map(r => ({ key: r.key, principal: r.principal, permission: r.permission, change_ref: r.change_ref, approver: r.approver, approved_at: r.updated_at }));
    const count = d => items.filter(x => x.decision === d).length;
    return { items, verified_removed: removed, summary: Object.fromEntries(DECISIONS.map(d => [d, count(d)])), min_window_days: MIN_WINDOW_DAYS, seasonal_window_days: SEASONAL_WINDOW_DAYS, decision_ar: DECISION_AR,
      claim: 'Recommendations only: CyberGuard never removes a permission. A removal is proposed after at least 90 days of usage data (400 for seasonal permissions), with an accountable owner, then needs a change request and owner approval; it is verified when a later import no longer shows the permission.',
      claim_ar: 'توصيات فقط: لا يزيل CyberGuard أي صلاحية. يُقترح التقليل بعد 90 يومًا على الأقل من بيانات الاستخدام (400 للصلاحيات الموسمية) ومع مالك مسؤول، ثم يحتاج طلب تغيير وموافقة المالك، ويُتحقق منه حين لا تظهر الصلاحية في استيراد لاحق.' };
  }
  dryRun() { const v = this.view(), rec = v.items.filter(x => x.decision === 'recommend' && x.workflow?.state !== 'dismissed');
    return { generated_at: this.now(), mode: 'dry-run', changes_made: 0, statement: 'Dry run only: nothing was changed. Each line is what the owner would change through their own change process.',
      changes: rec.map(x => ({ principal: x.principal, owner: x.owner, action: x.action, permission: x.permission, service: x.service, last_used: x.last_used, window_days: x.window_days, evidence: `${x.source} ${x.source_ref} imported ${x.imported_at}`, workflow_state: x.workflow?.state || 'proposed', change_ref: x.workflow?.change_ref || null, rollback: x.kind === 'access-key' ? 'Reactivate the access key' : x.kind === 'password' ? 'Create a new console password' : `Re-attach ${x.permission} to ${x.principal}` })),
      not_recommended: v.items.filter(x => x.decision !== 'recommend').map(x => ({ principal: x.principal, permission: x.permission, decision: x.decision, reason: x.reason })) }; }
  transition(actor, key, to, input) {
    const item = this.view().items.find(x => x.key === key); fail(item, 404, 'permission_recommendation_not_found'); fail(item.decision === 'recommend', 409, 'permission_not_recommended');
    const cur = this.state(key)?.state || 'proposed', allowed = { 'change-requested': ['proposed'], 'owner-approved': ['change-requested'], dismissed: ['proposed', 'change-requested'] }[to];
    fail(allowed && allowed.includes(cur), 409, 'invalid_permission_workflow_transition');
    const row = { change_ref: to === 'change-requested' ? text(input?.change_ref, 'permission_change_ref', 120) : this.state(key)?.change_ref || null,
      approver: to === 'owner-approved' ? text(input?.approver, 'permission_approver', 200) : this.state(key)?.approver || null, note: text(input?.note, 'permission_note', 1000, to !== 'dismissed') || null };
    if (to === 'owner-approved') fail(row.approver === item.owner, 409, 'permission_approver_must_be_owner');
    const at = this.now();
    this.s.transaction(() => { this.s.run('INSERT INTO permission_reduction(key,principal,permission,state,change_ref,approver,note,updated_at,updated_by) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET state=excluded.state,change_ref=excluded.change_ref,approver=excluded.approver,note=excluded.note,updated_at=excluded.updated_at,updated_by=excluded.updated_by', key, item.principal, item.permission, to, row.change_ref, row.approver, row.note, at, actor);
      this.s.audit(actor, `permission_reduction.${to}`, randomUUID(), { key, principal: item.principal, permission: item.permission, change_ref: row.change_ref }, at); });
    return { key, state: to, ...row };
  }
}
