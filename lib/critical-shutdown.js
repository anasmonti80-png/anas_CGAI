// CG-174 No single-action critical shutdown. Domain controllers, core switches and uplinks, backup controllers,
// ESXi/Hyper-V hosts and security platforms cannot be disrupted by a single command. A disruptive action on them is
// accepted only as a step of an approved composite plan:
//  - the plan names the asset, its critical role, at least two ordered steps (for example drain, then shut down), the
//    change reference, and either a maintenance window (CG-119 change window) or an out-of-band recovery method with
//    owner and evidence;
//  - two different administrators approve it, neither of them the requester;
//  - each step is used once, only inside the window, and the plan expires.
// Critical roles come from an owner declaration, from the device type (domain controller) and from roles declared in
// the impact graph (AD, core, shared uplink, hypervisor).
import { randomUUID } from 'node:crypto';
import { fail, object, text, choice } from './common.js';

export const ROLES = ['domain-controller', 'core-uplink', 'backup-controller', 'hypervisor-host', 'security-platform'];
export const DISRUPTIVE = ['endpoint.isolate-device', 'endpoint.shutdown-host', 'endpoint.stop-service', 'endpoint.disable-service', 'endpoint.remove-service', 'endpoint.change-service-permanent', 'network.switch-port-admin-down', 'network.nac-quarantine-endpoint', 'cloud.isolate-instance'];
const FROM_IMPACT = { ad: 'domain-controller', core: 'core-uplink', 'shared-uplink': 'core-uplink', hypervisor: 'hypervisor-host' };
const OOB = ['ilo-idrac-ipmi', 'hypervisor-console', 'console-server', 'physical-access'];

export class CriticalShutdown {
  constructor(store, { clock } = {}) { Object.assign(this, { s: store, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  declare(actor, input) {
    object(input, ['asset_ref', 'role', 'evidence_ref'], 'critical_asset'); const asset_ref = text(input.asset_ref, 'critical_asset_ref', 200), role = choice(input.role, ROLES, 'critical_role'), at = this.now();
    this.s.transaction(() => { this.s.run('INSERT INTO critical_assets(asset_ref,role,evidence_ref,declared_by,declared_at) VALUES (?,?,?,?,?) ON CONFLICT(asset_ref) DO UPDATE SET role=excluded.role,evidence_ref=excluded.evidence_ref,declared_by=excluded.declared_by,declared_at=excluded.declared_at', asset_ref, role, text(input.evidence_ref, 'critical_evidence_ref', 300), actor, at); this.s.audit(actor, 'critical_asset.declared', asset_ref, { role }, at); });
    return { asset_ref, role };
  }
  roleOf(asset) {
    const d = this.s.get('SELECT role FROM critical_assets WHERE asset_ref=?', asset.external_id); if (d) return { role: d.role, basis: 'declared' };
    if (asset.device_type === 'domain-controller') return { role: 'domain-controller', basis: 'device-type' };
    const r = this.s.all('SELECT role FROM impact_roles WHERE asset_ref=?', asset.external_id).map(x => FROM_IMPACT[x.role]).find(Boolean);
    return r ? { role: r, basis: 'impact-graph' } : null;
  }
  plan(actor, input) {
    object(input, ['asset_ref', 'steps', 'change_ref', 'reason', 'window_id', 'oob'], 'composite_plan');
    const asset = this.s.get('SELECT * FROM assets WHERE external_id=? LIMIT 1', text(input.asset_ref, 'plan_asset_ref', 200)); fail(asset, 404, 'plan_asset_not_found');
    const role = this.roleOf(asset); fail(role, 409, 'plan_asset_is_not_critical');
    fail(Array.isArray(input.steps) && input.steps.length >= 2 && input.steps.length <= 10, 400, 'composite_plan_requires_2_to_10_steps');
    const steps = input.steps.map((t, i) => choice(t, DISRUPTIVE, `plan_step_${i}`));
    let window = null, oob = null;
    if (input.window_id) { window = this.s.get('SELECT * FROM change_windows WHERE id=? AND revoked_at IS NULL', text(input.window_id, 'plan_window_id', 64)); fail(window && (window.asset_ref === asset.external_id || window.asset_ref === '*'), 400, 'plan_window_not_for_this_asset'); }
    if (input.oob) { object(input.oob, ['method', 'owner', 'evidence_ref'], 'plan_oob'); oob = { method: choice(input.oob.method, OOB, 'plan_oob_method'), owner: text(input.oob.owner, 'plan_oob_owner', 200), evidence_ref: text(input.oob.evidence_ref, 'plan_oob_evidence', 300) }; }
    fail(window || oob, 400, 'composite_plan_requires_window_or_out_of_band_recovery');
    const id = randomUUID(), at = this.now(), expires = window ? window.ends_at : new Date(this.clock() + 24 * 3600000).toISOString();
    this.s.transaction(() => { this.s.run("INSERT INTO composite_plans(id,asset_ref,role,steps,change_ref,reason,window_id,oob,requested_by,requested_at,expires_at,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,'pending')", id, asset.external_id, role.role, JSON.stringify(steps), text(input.change_ref, 'plan_change_ref', 120), text(input.reason, 'plan_reason', 1000), window?.id || null, oob ? JSON.stringify(oob) : null, actor, at, expires);
      this.s.audit(actor, 'composite_plan.requested', id, { asset_ref: asset.external_id, role: role.role, steps }, at); });
    return this.get(id);
  }
  get(id) { const p = this.s.require('SELECT * FROM composite_plans WHERE id=?', [id]); return { ...p, steps: JSON.parse(p.steps), oob: p.oob ? JSON.parse(p.oob) : null, used: this.s.all('SELECT step,action_id,used_at FROM composite_plan_steps WHERE plan_id=? ORDER BY step', id) }; }
  approve(actor, id) {
    const p = this.get(id); fail(p.status === 'pending', 409, 'plan_not_pending'); fail(actor !== p.requested_by && actor !== p.approver1, 409, 'plan_needs_two_distinct_approvers');
    fail(this.s.get('SELECT role FROM users WHERE id=?', actor)?.role === 'admin', 403, 'plan_approval_requires_admin'); const at = this.now();
    this.s.transaction(() => { if (!p.approver1) this.s.run('UPDATE composite_plans SET approver1=? WHERE id=?', actor, id); else this.s.run("UPDATE composite_plans SET approver2=?,approved_at=?,status='approved' WHERE id=?", actor, at, id); this.s.audit(actor, 'composite_plan.approved', id, { second: !!p.approver1 }, at); });
    return this.get(id);
  }
  // A plan step may be used only in order, once, before expiry and inside its window.
  allows(asset, type, planId) {
    const p = this.get(text(planId, 'plan_id', 64)), now = this.now(); fail(p.status === 'approved', 409, 'composite_plan_not_approved'); fail(p.asset_ref === asset.external_id, 409, 'composite_plan_for_another_asset'); fail(now < p.expires_at, 409, 'composite_plan_expired');
    if (p.window_id) { const w = this.s.get('SELECT * FROM change_windows WHERE id=?', p.window_id); fail(w && w.starts_at <= now && w.ends_at >= now && !w.revoked_at, 409, 'composite_plan_outside_maintenance_window'); }
    const next = p.used.length; fail(next < p.steps.length && p.steps[next] === type, 409, `composite_plan_next_step_is_${p.steps[next] || 'none'}`);
    return { ...p, step: next };
  }
  consume(plan, actionId) { this.s.run('INSERT INTO composite_plan_steps(plan_id,step,action_id,used_at) VALUES (?,?,?,?)', plan.id, plan.step, actionId, this.now()); if (plan.step + 1 === plan.steps.length) this.s.run("UPDATE composite_plans SET status='completed' WHERE id=?", plan.id); this.s.audit('composite-plan', 'composite_plan.step_used', plan.id, { step: plan.step, action_id: actionId }, this.now()); }
  // Called by the governed preview for every response action.
  gate(asset, type, plan) { if (!DISRUPTIVE.includes(type)) return null; const r = this.roleOf(asset); if (!r) return null; fail(plan, 409, `critical_asset_requires_composite_plan:${r.role}`); return r; }
  view() {
    const assets = this.s.all('SELECT DISTINCT external_id,hostname,device_type FROM assets').map(a => ({ ...a, critical: this.roleOf(a) })).filter(a => a.critical);
    return { assets, plans: this.s.all('SELECT id FROM composite_plans ORDER BY requested_at DESC LIMIT 100').map(r => this.get(r.id)), roles: ROLES,
      claim: 'Domain controllers, core switches and uplinks, backup controllers, ESXi/Hyper-V hosts and security platforms are never disrupted by a single command: a disruptive action on them must be the next step of a composite plan approved by two administrators other than the requester, inside a maintenance window or with out-of-band recovery.',
      claim_ar: 'لا تتعطل متحكمات المجال والمبدّلات الأساسية والوصلات الصاعدة ومتحكمات النسخ الاحتياطي ومضيفات ESXi/Hyper-V ومنصات الأمن بأمر منفرد: يجب أن يكون الإجراء المعطِّل عليها الخطوة التالية في خطة مركبة يعتمدها مسؤولان غير الطالب، داخل نافذة صيانة أو مع استعادة خارج النطاق.' };
  }
}
