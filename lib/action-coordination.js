// CG-175 Adapter idempotency and conflict detection.
//  - Every response action gets a deterministic change ID from its type, asset and canonical target. A request whose
//    change ID matches an action still in flight or in force is refused as a duplicate, so retries and double clicks
//    from several people or tools never run the same change twice.
//  - Opposing actions on the same target (block against allow, isolate against reconnect, quarantine against release,
//    disable against enable) and a block against an active rule lease (CG-172) on the same address are conflicts: they
//    are refused unless the new request names the action it supersedes.
//  - The connector reports the provider request ID of the API call; a provider request ID already recorded for another
//    action is refused (a replayed or mixed-up completion).
//  - Each action records how it is restored. On shared resources (switches, routers, firewalls, access points and
//    assets with declared impact roles) an action without an inverse must state its restore method.
import { createHash } from 'node:crypto';
import { fail, text } from './common.js';
import { responseActionCatalog } from './response-actions.js';

export const ACTIVE = ['pending-approval', 'approved', 'dispatched', 'verified', 'rollback-pending'];
const SHARED_TYPES = ['switch', 'router', 'firewall', 'access-point'];
const canon = t => JSON.stringify(Object.keys(t || {}).sort().reduce((o, k) => ({ ...o, [k]: typeof t[k] === 'string' ? t[k].toLowerCase() : t[k] }), {}));
export const targetKey = (assetRef, target) => `${assetRef}|${canon(target)}`;
export const changeId = (type, assetRef, target) => `chg-${createHash('sha256').update(`${type}|${targetKey(assetRef, target)}`).digest('hex').slice(0, 24)}`;
const opposite = type => { const spec = responseActionCatalog[type]; if (spec?.inverse) return spec.inverse; return Object.keys(responseActionCatalog).find(k => responseActionCatalog[k].inverse === type) || null; };

export class ActionCoordination {
  constructor(store, { clock } = {}) { this.s = store; this.clock = clock || (() => Date.now()); }
  active() { return this.s.all(`SELECT a.id,a.type,a.status,a.change_id,a.target_key,a.restore_method,a.requested_by,a.requested_at,j.provider_request_id FROM actions a LEFT JOIN response_jobs j ON j.action_id=a.id WHERE a.status IN (${ACTIVE.map(() => '?').join(',')}) AND a.change_id IS NOT NULL AND (a.status NOT IN ('pending-approval','approved') OR a.expires_at>?) ORDER BY a.requested_at`, ...ACTIVE, new Date(this.clock()).toISOString()); }
  // A request or approval past its expiry no longer counts as in flight.
  // Called by the governed preview before the action is stored.
  check({ type, asset, target, supersedes = null, restore_method = null }) {
    const key = targetKey(asset.external_id, target), id = changeId(type, asset.external_id, target), live = this.active();
    const dup = live.find(a => a.change_id === id); fail(!dup, 409, `duplicate_action_in_flight:${dup?.id}`);
    const opp = opposite(type), conflicts = live.filter(a => a.target_key === key && a.type === opp).map(a => ({ id: a.id, type: a.type, status: a.status }));
    if (type === 'network.block-ip' && target?.ip) for (const l of this.s.all("SELECT id,scope,ticket_ref FROM rule_leases WHERE status IN ('approved','installed','expiry-not-enforced')")) { const sc = JSON.parse(l.scope); if ([sc.source, sc.destination].includes(target.ip)) conflicts.push({ id: l.id, type: 'rule-lease', status: l.ticket_ref }); }
    const sup = supersedes ? text(supersedes, 'supersedes', 64) : null;
    fail(!conflicts.length || conflicts.every(c => c.id === sup), 409, `conflicting_action_in_flight:${conflicts.map(c => `${c.type}:${c.id}`).join(',')}`);
    const spec = responseActionCatalog[type], shared = SHARED_TYPES.includes(asset.device_type) || !!this.s.get('SELECT 1 x FROM impact_roles WHERE asset_ref=?', asset.external_id);
    const restore = restore_method ? text(restore_method, 'restore_method', 500) : spec.inverse ? `inverse:${spec.inverse}` : null;
    fail(restore || !shared, 409, 'shared_resource_requires_restore_method');
    return { change_id: id, target_key: key, restore_method: restore || 'none-declared', shared, supersedes: sup };
  }
  // Called when the connector completes a job.
  checkProviderRequest(actionId, providerRequestId) {
    if (!providerRequestId) return null; const v = text(providerRequestId, 'provider_request_id', 200);
    const other = this.s.get('SELECT action_id FROM response_jobs WHERE provider_request_id=? AND action_id!=?', v, actionId); fail(!other, 409, 'provider_request_id_reused');
    return v;
  }
  view() {
    const live = this.active(), byTarget = new Map();
    for (const a of live) byTarget.set(a.target_key, [...(byTarget.get(a.target_key) || []), a]);
    return { active: live, targets: [...byTarget.entries()].map(([key, items]) => ({ target_key: key, actions: items })),
      recent: this.s.all('SELECT a.id,a.type,a.status,a.change_id,a.restore_method,a.supersedes,j.provider_request_id FROM actions a LEFT JOIN response_jobs j ON j.action_id=a.id WHERE a.change_id IS NOT NULL ORDER BY a.requested_at DESC LIMIT 50'),
      claim: 'Each response change has a deterministic change ID: a duplicate of a change in flight or in force is refused, opposing changes on the same target (or a block against an active rule lease) need an explicit supersede, provider request IDs are unique per action, and every change records how it is restored, which shared network resources must state when there is no inverse action.',
      claim_ar: 'لكل تغيير استجابة معرّف تغيير حتمي: يُرفض تكرار تغيير جارٍ أو مطبّق، وتحتاج التغييرات المتعاكسة على الهدف نفسه (أو حظر يعارض عقد قاعدة نافذًا) إلى إحلال صريح، ومعرّف طلب المزود فريد لكل إجراء، ويسجل كل تغيير طريقة استعادته، وعلى موارد الشبكة المشتركة ذكرها إن لم يكن له إجراء عكسي.' };
  }
}
