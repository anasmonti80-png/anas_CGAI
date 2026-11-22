// CG-119 Safety tiers for response. Every action type belongs to one tier and the tier decides the approvals, a
// separate typed confirmation by the person executing it, and whether it must run inside a declared change window:
//   read-only     previews, preflight, hunts, reports: no change, no approval
//   low-impact    narrow and reversible (block/allow an address, port, app or domain; release; record changes): one independent approver
//   sensitive     interrupts a host or service but is reversible (isolate, quarantine, port down, stop/disable service):
//                 independent approver + typed confirmation + change window, or a declared emergency with an incident reference
//   destructive   not automatically reversible or takes a host down (shutdown, permanent service removal or change):
//                 independent approver + a separate safety approver + typed confirmation + change window (no emergency override)
import { randomUUID } from 'node:crypto';
import { fail, text, timestamp } from './common.js';

export const TIERS = ['read-only', 'low-impact', 'sensitive', 'destructive'];
const SENSITIVE = ['cloud.isolate-instance', 'cloud.disable-access-key', 'endpoint.isolate-device', 'network.nac-quarantine-endpoint', 'network.switch-port-admin-down', 'endpoint.stop-service', 'endpoint.disable-service', 'endpoint.quarantine-file'];
const DESTRUCTIVE = ['endpoint.shutdown-host', 'endpoint.remove-service', 'endpoint.change-service-permanent'];
export const tierOf = type => DESTRUCTIVE.includes(type) ? 'destructive' : SENSITIVE.includes(type) ? 'sensitive' : 'low-impact';
export const REQUIREMENTS = {
  'read-only': { approvers: 0, typed_confirmation: false, change_window: 'not-required', emergency_override: false },
  'low-impact': { approvers: 1, typed_confirmation: false, change_window: 'not-required', emergency_override: false },
  sensitive: { approvers: 1, typed_confirmation: true, change_window: 'required-or-emergency', emergency_override: true },
  destructive: { approvers: 2, typed_confirmation: true, change_window: 'required', emergency_override: false },
};
const CONFIRMATION_TTL_MS = 10 * 60000;

export class SafetyGate {
  constructor(store, { clock }) { Object.assign(this, { s: store, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  tierOf(type) { return tierOf(type); }
  target(a) { const asset = this.s.get('SELECT hostname,external_id FROM assets WHERE id=?', a.asset_id); return { name: asset?.hostname || asset?.external_id || '', ref: asset?.external_id || '' }; }
  windowFor(assetRef, at = this.now()) { return this.s.get("SELECT * FROM change_windows WHERE (asset_ref=? OR asset_ref='*') AND starts_at<=? AND ends_at>=? AND revoked_at IS NULL ORDER BY ends_at DESC LIMIT 1", assetRef, at, at) || null; }
  addWindow(actor, input) {
    const asset_ref = text(input.asset_ref, 'window_asset_ref', 200), starts_at = timestamp(input.starts_at, 'window_starts_at', this.clock() + 365 * 86400000), ends_at = timestamp(input.ends_at, 'window_ends_at', this.clock() + 366 * 86400000), change_ref = text(input.change_ref, 'window_change_ref', 200);
    fail(ends_at > starts_at && Date.parse(ends_at) - Date.parse(starts_at) <= 24 * 3600000, 400, 'change_window_must_be_positive_and_at_most_24_hours');
    const id = randomUUID(); this.s.run('INSERT INTO change_windows(id,asset_ref,starts_at,ends_at,change_ref,created_by,created_at) VALUES (?,?,?,?,?,?,?)', id, asset_ref, starts_at, ends_at, change_ref, actor, this.now());
    this.s.audit(actor, 'change_window.created', id, { asset_ref, starts_at, ends_at, change_ref }, this.now()); return this.s.get('SELECT * FROM change_windows WHERE id=?', id);
  }
  // Separate confirmation: the person who will execute types the target name after approval.
  confirm(actor, id, input) {
    const a = this.s.get('SELECT * FROM actions WHERE id=?', id); fail(a, 404, 'not_found'); const tier = tierOf(a.type), req = REQUIREMENTS[tier];
    fail(req.typed_confirmation, 409, 'action_tier_does_not_need_confirmation'); fail(a.status === 'approved' && a.approved_by, 409, 'action_requires_approval_before_confirmation');
    const t = this.target(a), typed = text(input?.typed_target, 'typed_target', 253); fail(typed.toLowerCase() === t.name.toLowerCase(), 400, 'typed_target_does_not_match');
    let emergency = null; if (input?.emergency) { fail(req.emergency_override, 409, 'emergency_override_not_allowed_for_destructive_actions'); emergency = { incident_ref: text(input.emergency.incident_ref, 'emergency_incident_ref', 200), reason: text(input.emergency.reason, 'emergency_reason', 1000) }; fail(emergency.reason.length >= 10, 400, 'emergency_reason_too_short'); }
    this.s.run('INSERT INTO action_confirmations(action_id,confirmed_by,confirmed_at,typed_target,emergency) VALUES (?,?,?,?,?) ON CONFLICT(action_id) DO UPDATE SET confirmed_by=excluded.confirmed_by,confirmed_at=excluded.confirmed_at,typed_target=excluded.typed_target,emergency=excluded.emergency', id, actor, this.now(), typed, emergency ? JSON.stringify(emergency) : null);
    this.s.audit(actor, 'action.confirmed', id, { tier, emergency: Boolean(emergency) }, this.now()); return this.status(id);
  }
  // Second (safety) approver for destructive actions that have no recovery-plan safety approval of their own.
  secondApprove(actor, id) {
    const a = this.s.get('SELECT * FROM actions WHERE id=?', id); fail(a, 404, 'not_found'); fail(tierOf(a.type) === 'destructive', 409, 'action_does_not_require_safety_approval');
    fail(a.status === 'approved' && a.approved_by, 409, 'action_requires_primary_approval_first'); fail(actor !== a.requested_by && actor !== a.approved_by, 403, 'separate_safety_approver_required');
    fail(this.s.get('SELECT role FROM users WHERE id=?', actor)?.role === 'admin', 403, 'safety_approval_requires_standing_admin'); fail(!this.s.get('SELECT action_id FROM action_safety_approvals WHERE action_id=?', id), 409, 'safety_approval_already_recorded');
    this.s.run('INSERT INTO action_safety_approvals(action_id,approved_by,approved_at,recovery_plan_hash) VALUES (?,?,?,?)', id, actor, this.now(), 'tier-destructive'); this.s.audit(actor, 'action.safety_approved', id, { tier: 'destructive' }, this.now()); return this.status(id);
  }
  status(id) {
    const a = this.s.get('SELECT * FROM actions WHERE id=?', id), tier = tierOf(a.type), req = REQUIREMENTS[tier], t = this.target(a), c = this.s.get('SELECT * FROM action_confirmations WHERE action_id=?', id), safety = this.s.get('SELECT approved_by,approved_at FROM action_safety_approvals WHERE action_id=?', id), w = this.windowFor(t.ref);
    const confirmationFresh = Boolean(c && this.clock() - Date.parse(c.confirmed_at) <= CONFIRMATION_TTL_MS), emergency = c?.emergency ? JSON.parse(c.emergency) : null;
    const missing = [];
    if (!a.approved_by) missing.push('independent-approval');
    if (req.approvers >= 2 && !safety) missing.push('safety-approval');
    if (req.typed_confirmation && !confirmationFresh) missing.push(c ? 'confirmation-expired' : 'typed-confirmation');
    if (req.change_window === 'required' && !w) missing.push('change-window');
    if (req.change_window === 'required-or-emergency' && !w && !(confirmationFresh && emergency)) missing.push('change-window-or-emergency');
    return { action_id: id, type: a.type, tier, requirements: req, target_name: t.name, approved_by: a.approved_by, safety_approval: safety || null, confirmation: c ? { confirmed_by: c.confirmed_by, confirmed_at: c.confirmed_at, fresh: confirmationFresh, emergency } : null, change_window: w, missing, ready: !missing.length };
  }
  checkExecute(actor, a) {
    const st = this.status(a.id); if (st.tier === 'low-impact') return st;
    for (const m of st.missing.filter(m => m !== 'independent-approval')) fail(false, 409, `safety_tier_${st.tier}_requires_${m.replace(/-/g, '_')}`);
    fail(st.confirmation.confirmed_by === actor, 403, 'the_confirming_user_must_execute'); return st;
  }
  view() {
    const types = ['asset.set-criticality', 'network.block-ip', 'network.allow-ip', 'network.block-port', 'network.allow-port', 'endpoint.block-app', 'endpoint.allow-app', 'dns.block-domain', 'dns.allow-domain', 'endpoint.reconnect-device', 'network.switch-port-admin-up', 'network.nac-release-endpoint', ...SENSITIVE, ...DESTRUCTIVE];
    const pending = this.s.all("SELECT id FROM actions WHERE status='approved' ORDER BY requested_at DESC LIMIT 100").map(r => this.status(r.id)).filter(x => x.tier !== 'low-impact');
    return { tiers: TIERS.map(t => ({ tier: t, requirements: REQUIREMENTS[t], action_types: t === 'read-only' ? [] : types.filter(x => tierOf(x) === t) })), windows: this.s.all('SELECT * FROM change_windows WHERE ends_at>=? AND revoked_at IS NULL ORDER BY starts_at LIMIT 100', this.now()), awaiting: pending,
      claim: 'Four safety tiers decide approvals, a separate typed confirmation by the executor and change windows: low-impact needs one independent approver; sensitive also needs the confirmation and a change window or a declared emergency; destructive needs a second safety approver, the confirmation and a change window with no emergency override.',
      claim_ar: 'أربعة مستويات أمان تحدد الموافقات والتأكيد المنفصل المكتوب من المنفذ وأوقات التغيير: منخفض التأثير يحتاج موافقًا مستقلًا؛ والحساس يحتاج أيضًا التأكيد ونافذة تغيير أو طوارئ معلنة؛ والمدمر يحتاج موافقًا ثانيًا للسلامة والتأكيد ونافذة تغيير دون استثناء طوارئ.' };
  }
}
