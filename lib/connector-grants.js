// CG-177 Least-privilege connector grants. Every source is read-only by default: it may send telemetry and nothing else.
// A connector may change something only through a separate write grant, per tenant, cloud account or site, that lists
// the exact target IDs it may act on, is approved by a different administrator, expires (1 to 365 days) and can be
// revoked. The governed preview checks the grant for the target ID of every response action, so a connector that
// declares a capability on its own still cannot act on a target it was not granted. The token inventory lists each
// source's credential age, rotation state, privilege and grants.
import { randomUUID } from 'node:crypto';
import { fail, object, text, choice, integer } from './common.js';

export const SCOPES = ['tenant', 'cloud-account', 'site'];
const ROTATE_DAYS = 90;
const WILDCARD = /^(\*|any|all)$|[*?]/i;

export class ConnectorGrants {
  constructor(store, { clock } = {}) { Object.assign(this, { s: store, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  get(id) { const g = this.s.require('SELECT * FROM connector_grants WHERE id=?', [id]); return { ...g, target_ids: JSON.parse(g.target_ids), state: this.state(g) }; }
  state(g) { return g.status === 'active' && g.expires_at <= this.now() ? 'expired' : g.status; }
  request(actor, input) {
    object(input, ['source_id', 'scope_type', 'scope_ref', 'target_ids', 'days', 'reason'], 'connector_grant');
    const src = this.s.require('SELECT id,kind,revoked FROM sources WHERE id=?', [text(input.source_id, 'grant_source_id', 64)]); fail(!src.revoked, 409, 'source_revoked');
    fail(src.kind === 'response-connector', 409, 'write_grants_are_for_response_connectors');
    fail(Array.isArray(input.target_ids) && input.target_ids.length >= 1 && input.target_ids.length <= 500, 400, 'grant_requires_explicit_target_ids');
    const targets = [...new Set(input.target_ids.map((t, i) => text(String(t), `grant_target_${i}`, 300)))]; fail(targets.every(t => !WILDCARD.test(t)), 400, 'grant_target_ids_must_be_explicit');
    const id = randomUUID(), at = this.now(), scope_type = choice(input.scope_type, SCOPES, 'grant_scope_type'), scope_ref = text(input.scope_ref, 'grant_scope_ref', 200), days = integer(input.days ?? 30, 1, 365, 'grant_days');
    this.s.transaction(() => { this.s.run("INSERT INTO connector_grants(id,source_id,scope_type,scope_ref,mode,target_ids,days,reason,requested_by,requested_at,status) VALUES (?,?,?,?,'write',?,?,?,?,?,'pending')", id, src.id, scope_type, scope_ref, JSON.stringify(targets), days, text(input.reason, 'grant_reason', 500), actor, at);
      this.s.audit(actor, 'connector_grant.requested', id, { source_id: src.id, scope_type, scope_ref, targets: targets.length, days }, at); });
    return this.get(id);
  }
  approve(actor, id) {
    const g = this.get(id); fail(g.status === 'pending', 409, 'grant_not_pending'); fail(g.requested_by !== actor, 409, 'grant_needs_second_approver');
    fail(this.s.get('SELECT role FROM users WHERE id=?', actor)?.role === 'admin', 403, 'grant_approval_requires_admin');
    const at = this.now(), expires = new Date(this.clock() + g.days * 86400000).toISOString();
    this.s.transaction(() => { this.s.run("UPDATE connector_grants SET status='active',approved_by=?,approved_at=?,expires_at=? WHERE id=?", actor, at, expires, id); this.s.audit(actor, 'connector_grant.approved', id, { expires_at: expires }, at); });
    return this.get(id);
  }
  revoke(actor, id, reason) {
    const g = this.get(id); fail(['pending', 'active'].includes(g.status), 409, 'grant_not_revocable'); const at = this.now();
    this.s.transaction(() => { this.s.run("UPDATE connector_grants SET status='revoked',revoked_by=?,revoked_at=? WHERE id=?", actor, at, id); this.s.audit(actor, 'connector_grant.revoked', id, { reason: text(reason, 'grant_revoke_reason', 500) }, at); });
    return this.get(id);
  }
  // Target-level authorisation for a write by a connector source.
  requireWrite(sourceId, targetId) {
    const now = this.now(), ok = this.s.all("SELECT target_ids FROM connector_grants WHERE source_id=? AND status='active' AND expires_at>?", sourceId, now).some(g => JSON.parse(g.target_ids).includes(targetId));
    fail(ok, 403, 'connector_write_grant_required_for_target');
  }
  inventory() {
    const now = this.clock();
    return this.s.all('SELECT id,name,kind,created_at,last_received,revoked FROM sources ORDER BY name').map(s => {
      const rotated = this.s.get("SELECT MAX(at) at FROM audit WHERE target=? AND action IN ('source.rotated','source.created')", s.id)?.at || s.created_at, age = Math.floor((now - Date.parse(rotated)) / 86400000);
      const grants = this.s.all('SELECT * FROM connector_grants WHERE source_id=? ORDER BY requested_at DESC', s.id).map(g => ({ id: g.id, scope_type: g.scope_type, scope_ref: g.scope_ref, targets: JSON.parse(g.target_ids).length, state: this.state(g), expires_at: g.expires_at }));
      return { source_id: s.id, name: s.name, kind: s.kind, privilege: grants.some(g => g.state === 'active') ? 'write-granted' : 'read-only', token: s.revoked ? 'revoked' : age > ROTATE_DAYS ? 'rotation-due' : 'current', token_age_days: age, token_issued_or_rotated_at: rotated, grants };
    });
  }
  view() {
    return { sources: this.inventory(), rotate_days: ROTATE_DAYS, scopes: SCOPES,
      claim: 'Every source is read-only by default. A connector writes only under a separate grant per tenant, cloud account or site that lists exact target IDs, approved by a second administrator, expiring and revocable; each response action is checked against the grant for its target ID. The token inventory shows each credential age, rotation state, privilege and grants.',
      claim_ar: 'كل مصدر للقراءة فقط افتراضيًا. ولا يكتب الموصل إلا بمنح منفصل لكل مستأجر أو حساب سحابي أو موقع، يذكر معرّفات الأهداف بالضبط، ويعتمده مسؤول ثانٍ، وله انتهاء ويمكن إلغاؤه؛ ويُتحقق من المنح لمعرّف هدف كل إجراء استجابة. ويعرض جرد الرموز عمر كل بيانات اعتماد وحالة تدويرها وصلاحيتها ومنوحها.' };
  }
}
