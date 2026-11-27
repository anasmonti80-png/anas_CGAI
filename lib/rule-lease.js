// CG-172 Just-in-time rule lease engine. A lease is an exact policy exception with scope (asset, source, destination,
// protocol, port), TTL, owner, change ticket, approver (a different administrator with recent MFA) and a revocation
// deadline. Expiry is enforced on the enforcement layer, not by CyberGuard's clock: the response connector that installs
// the rule reports the expiry timer configured on the device (time-based ACL, firewall schedule, agent timer), and a lease
// is "installed" only when that device-side expiry is no later than the approved expiry; otherwise it is flagged.
// Reconciliation (on every connector report and on the health check, so it also runs after CyberGuard was down)
// compares device state with the leases: a rule still installed after its revocation deadline is overdue (high alert),
// a rule the device holds with no lease is an orphan, and a rule removed before expiry is shown as removed early.
import { randomUUID } from 'node:crypto';
import { fail, object, text, choice, integer } from './common.js';

const EXPLICIT = v => !['*', 'any', '0.0.0.0/0', '::/0'].includes(String(v).toLowerCase());
export const GRACE_MINUTES = 15;

export class RuleLeases {
  constructor(store, { clock, domain } = {}) { Object.assign(this, { s: store, clock: clock || (() => Date.now()), domain }); }
  now() { return new Date(this.clock()).toISOString(); }
  get(id) { const r = this.s.require('SELECT * FROM rule_leases WHERE id=?', [id]); return { ...r, scope: JSON.parse(r.scope) }; }
  request(actor, input) {
    object(input, ['asset_ref', 'source', 'destination', 'protocol', 'port', 'ttl_minutes', 'owner_ref', 'ticket_ref', 'reason', 'connector_id'], 'rule_lease');
    const scope = { asset_ref: text(input.asset_ref, 'lease_asset_ref', 200), source: text(input.source, 'lease_source', 100), destination: text(input.destination, 'lease_destination', 100), protocol: choice(input.protocol, ['tcp', 'udp'], 'lease_protocol'), port: integer(input.port, 1, 65535, 'lease_port') };
    fail(EXPLICIT(scope.source) && EXPLICIT(scope.destination), 400, 'lease_scope_must_be_explicit');
    const ttl = integer(input.ttl_minutes, 5, 1440, 'lease_ttl_minutes'), id = randomUUID(), at = this.now();
    this.s.transaction(() => { this.s.run("INSERT INTO rule_leases(id,scope,ttl_minutes,owner_ref,ticket_ref,reason,connector_id,requested_by,requested_at,status) VALUES (?,?,?,?,?,?,?,?,?,'pending')", id, JSON.stringify(scope), ttl, text(input.owner_ref, 'lease_owner', 200), text(input.ticket_ref, 'lease_ticket', 120), text(input.reason, 'lease_reason', 500), text(input.connector_id, 'lease_connector', 200), actor, at);
      this.s.audit(actor, 'lease.requested', id, { scope, ttl_minutes: ttl, ticket_ref: input.ticket_ref }, at); });
    return this.get(id);
  }
  approve(actor, id) {
    const l = this.get(id); fail(l.status === 'pending', 409, 'lease_not_pending'); fail(l.requested_by !== actor, 409, 'lease_needs_second_approver');
    const at = this.now(), expires = new Date(this.clock() + l.ttl_minutes * 60000).toISOString(), deadline = new Date(this.clock() + (l.ttl_minutes + GRACE_MINUTES) * 60000).toISOString();
    this.s.transaction(() => { this.s.run("UPDATE rule_leases SET status='approved',approved_by=?,approved_at=?,expires_at=?,revocation_deadline=? WHERE id=?", actor, at, expires, deadline, id); this.s.audit(actor, 'lease.approved', id, { expires_at: expires, revocation_deadline: deadline }, at); });
    return this.get(id);
  }
  revoke(actor, id, reason) {
    const l = this.get(id); fail(['approved', 'installed', 'expiry-not-enforced'].includes(l.status), 409, 'lease_not_revocable');
    const at = this.now(), deadline = new Date(this.clock() + GRACE_MINUTES * 60000).toISOString();
    this.s.transaction(() => { this.s.run("UPDATE rule_leases SET status='revoke-requested',revocation_deadline=? WHERE id=?", deadline, id); this.s.audit(actor, 'lease.revoke_requested', id, { reason: text(reason, 'lease_revoke_reason', 500), revocation_deadline: deadline }, at); });
    return this.get(id);
  }
  // A response connector report: { lease_id, connector_id, rule_ref, state: installed|removed, enforcement_expires_at, evidence_ref }.
  report(sourceId, d, observedAt) {
    const l = this.s.get('SELECT * FROM rule_leases WHERE id=?', d.lease_id), at = this.now();
    if (!l) { this.alert(`orphan:${d.connector_id}:${d.rule_ref}`, 'medium', `Enforcement layer holds rule ${d.rule_ref} with no lease (${d.connector_id}) / قاعدة على طبقة التنفيذ دون عقد إيجار`, sourceId); return; }
    fail(l.connector_id === d.connector_id, 409, 'lease_connector_mismatch');
    if (d.state === 'installed') {
      const enforced = d.enforcement_expires_at && Date.parse(d.enforcement_expires_at) <= Date.parse(l.expires_at) + 60000, status = l.status === 'revoke-requested' ? 'revoke-requested' : enforced ? 'installed' : 'expiry-not-enforced';
      this.s.run('UPDATE rule_leases SET status=?,rule_ref=?,enforcement_expires_at=?,installed_at=COALESCE(installed_at,?),last_device_state=?,last_device_report_at=?,evidence_ref=? WHERE id=?', status, d.rule_ref, d.enforcement_expires_at || null, observedAt, 'installed', observedAt, d.evidence_ref, l.id);
      if (!enforced) this.alert(`unenforced:${l.id}`, 'high', `Lease ${l.id.slice(0, 8)} installed without a device-side expiry at or before ${l.expires_at} / قاعدة مؤقتة دون انتهاء مفروض على الجهاز`, sourceId);
    } else {
      const early = Date.parse(observedAt) < Date.parse(l.expires_at) && l.status !== 'revoke-requested';
      this.s.run('UPDATE rule_leases SET status=?,last_device_state=?,last_device_report_at=?,removed_at=?,evidence_ref=? WHERE id=?', early ? 'removed-early' : l.status === 'revoke-requested' ? 'revoked' : 'expired', 'removed', observedAt, observedAt, d.evidence_ref, l.id);
    }
    this.s.audit(`source:${sourceId}`, 'lease.device_report', l.id, { state: d.state, enforcement_expires_at: d.enforcement_expires_at || null }, at);
    this.reconcile();
  }
  // Runs on reports and on the health check: leases past their revocation deadline that the device has not confirmed removed.
  reconcile() {
    const now = this.now(), overdue = this.s.all("SELECT * FROM rule_leases WHERE status IN ('approved','installed','expiry-not-enforced','revoke-requested') AND revocation_deadline<?", now);
    for (const l of overdue) { this.s.run("UPDATE rule_leases SET status='overdue',reconciled_at=? WHERE id=?", now, l.id);
      this.alert(`overdue:${l.id}`, 'high', `Lease ${l.id.slice(0, 8)} (${l.ticket_ref}) is past its revocation deadline and the enforcement layer has not confirmed removal / قاعدة مؤقتة تجاوزت موعد إلغائها دون تأكيد إزالتها`, null); }
    this.s.run("UPDATE rule_leases SET reconciled_at=? WHERE status NOT IN ('pending')", now);
    return overdue.length;
  }
  alert(key, severity, title, sourceId) { this.domain?.alert({ key: `CG-LEASE-172:${key}`, sourceId, rule: 'CG-LEASE-172', severity, title }); }
  view() {
    const items = this.s.all('SELECT * FROM rule_leases ORDER BY requested_at DESC LIMIT 200').map(r => ({ ...r, scope: JSON.parse(r.scope) }));
    const by = {}; for (const i of items) by[i.status] = (by[i.status] || 0) + 1;
    return { items, by_status: by, grace_minutes: GRACE_MINUTES,
      claim: 'Rule leases are exact, ticketed, approved by a second administrator and bounded by a revocation deadline. Expiry is enforced on the device: a lease counts as installed only when the enforcement layer reports its own timer at or before the approved expiry. Reconciliation runs on every report and health check, so after an outage overdue, orphan and early-removed rules are found.',
      claim_ar: 'عقود إيجار القواعد دقيقة النطاق، ولها تذكرة، ويعتمدها مسؤول ثانٍ، وتحدها مهلة إلغاء. والانتهاء مفروض على الجهاز: لا يُعد العقد مثبتًا إلا إذا أبلغت طبقة التنفيذ عن مؤقتها الخاص عند الانتهاء المعتمد أو قبله. وتجري المصالحة مع كل بلاغ وكل فحص صحة، فتُكتشف بعد أي انقطاع القواعد المتأخرة واليتيمة والمزالة مبكرًا.' };
  }
}
