// CG-169 IOC and KEV feed change governance. A feed update is staged, never applied directly:
//  - each staged version keeps its source URL, source date and licence, and a diff against the active version
//    (added, removed, changed) is computed before anything changes;
//  - a version becomes active only when a different administrator with recent MFA approves it; a mass change (more than
//    500 items or 25% of the feed added or removed) also needs an explicit acknowledgement and raises CG-FEED-MASS-169;
//  - applying a threat-intelligence version records or expires indicators (never deletes them) and never creates a
//    response action: indicators stay manual-review-only (CG-112), so a feed change can never cause a mass block;
//  - applying a KEV version stores the catalogue as a vulnerability.intel event from the CyberGuard internal source;
//  - any earlier approved version can be restored the same way (rollback), with its own diff.
import { randomUUID } from 'node:crypto';
import { fail, object, text, choice, integer, digest } from './common.js';
import { indicator } from './threat-intelligence.js';
import { parseKev } from './vulnerability-intel.js';

export const KINDS = ['threat-intel', 'cisa-kev'];
// The ratio applies only to feeds of at least 100 items, so a small curated list can be edited normally.
export const MASS = { items: 500, ratio: 0.25, min_for_ratio: 100 };
const keyOf = (kind, x) => kind === 'cisa-kev' ? x.cve_id : `${x.type}|${x.value}`;
const sig = (kind, x) => kind === 'cisa-kev' ? JSON.stringify([x.due_date, x.known_ransomware]) : JSON.stringify([x.confidence, x.expires_at]);

export function diffItems(kind, before, after) {
  const b = new Map(before.map(x => [keyOf(kind, x), x])), a = new Map(after.map(x => [keyOf(kind, x), x]));
  const added = [...a.keys()].filter(k => !b.has(k)), removed = [...b.keys()].filter(k => !a.has(k)), changed = [...a.keys()].filter(k => b.has(k) && sig(kind, a.get(k)) !== sig(kind, b.get(k)));
  const base = Math.max(1, before.length), mass = added.length + removed.length > MASS.items || (before.length >= MASS.min_for_ratio && (added.length + removed.length) / base > MASS.ratio);
  return { added: added.length, removed: removed.length, changed: changed.length, unchanged: after.length - added.length - changed.length, mass_change: mass, sample: { added: added.slice(0, 20), removed: removed.slice(0, 20), changed: changed.slice(0, 20) } };
}

export class FeedGovernance {
  constructor(store, { clock, domain, threatIntel } = {}) { Object.assign(this, { s: store, clock: clock || (() => Date.now()), domain, ti: threatIntel }); }
  now() { return new Date(this.clock()).toISOString(); }
  row(r) { return r && { ...r, items: JSON.parse(r.items), diff: JSON.parse(r.diff), mass_change: !!r.mass_change, source_verified: !!r.source_verified }; }
  active(feed) { return this.row(this.s.get("SELECT * FROM feed_versions WHERE feed=? AND status='active'", feed)); }
  stage(actor, input) {
    object(input, ['feed', 'kind', 'source_ref', 'source_date', 'license', 'redistribution_rights', 'source_verified', 'items', 'kev_catalog'], 'feed_version');
    const feed = text(input.feed, 'feed_name', 100), kind = choice(input.kind, KINDS, 'feed_kind'), source_ref = text(input.source_ref, 'feed_source_ref', 500); fail(/^https:\/\/\S+$/.test(source_ref), 400, 'feed_source_must_be_https');
    const license = text(input.license, 'feed_license', 300), rights = choice(input.redistribution_rights, ['permitted', 'restricted', 'prohibited', 'unknown'], 'feed_redistribution_rights');
    let items, source_date;
    if (kind === 'cisa-kev') { let k; try { k = parseKev(input.kev_catalog); } catch { fail(false, 400, 'not_a_kev_catalog'); } items = k.entries; source_date = k.published_at; }
    else { fail(Array.isArray(input.items) && input.items.length >= 1 && input.items.length <= 50000, 400, 'feed_requires_items'); source_date = text(input.source_date, 'feed_source_date', 40); fail(!Number.isNaN(Date.parse(source_date)), 400, 'invalid_feed_source_date');
      items = input.items.map((x, i) => { object(x, ['type', 'value', 'confidence', 'expires_at'], `feed_item_${i}`); const type = choice(x.type, ['ipv4', 'ipv6', 'domain', 'url', 'sha256'], 'indicator_type'); return { type, value: indicator(type, x.value), confidence: integer(x.confidence, 0, 100, 'indicator_confidence'), expires_at: new Date(text(x.expires_at, 'indicator_expires_at', 40)).toISOString() }; }); }
    fail(typeof (input.source_verified ?? false) === 'boolean', 400, 'invalid_feed_source_verified');
    const cur = this.active(feed); fail(!cur || cur.kind === kind, 409, 'feed_kind_mismatch');
    const diff = diffItems(kind, cur?.items || [], items), version_no = (this.s.get('SELECT MAX(version_no) v FROM feed_versions WHERE feed=?', feed).v || 0) + 1, id = randomUUID(), at = this.now();
    this.s.transaction(() => {
      this.s.run("INSERT INTO feed_versions(id,feed,kind,version_no,source_ref,source_date,license,redistribution_rights,source_verified,items,items_sha256,diff,mass_change,status,staged_by,staged_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'staged',?,?)", id, feed, kind, version_no, source_ref, new Date(source_date).toISOString(), license, rights, input.source_verified ? 1 : 0, JSON.stringify(items), digest(items), JSON.stringify(diff), diff.mass_change ? 1 : 0, actor, at);
      this.s.audit(actor, 'feed.staged', `${feed}:v${version_no}`, { added: diff.added, removed: diff.removed, changed: diff.changed, mass_change: diff.mass_change, source_date }, at);
    });
    if (diff.mass_change) this.domain?.alert({ key: `CG-FEED-MASS-169:${feed}:${version_no}`, rule: 'CG-FEED-MASS-169', severity: 'medium', title: `Feed ${feed} v${version_no} is a mass change (+${diff.added} −${diff.removed}); staged for review, nothing applied / تغيير جماعي في تغذية ${feed} بانتظار المراجعة دون أي تطبيق` });
    return this.row(this.s.get('SELECT * FROM feed_versions WHERE id=?', id));
  }
  approve(actor, id, input = {}) {
    object(input, ['acknowledge_mass_change', 'note'], 'feed_approval'); const v = this.row(this.s.require('SELECT * FROM feed_versions WHERE id=?', [id]));
    fail(v.status === 'staged', 409, 'feed_version_not_staged'); fail(v.staged_by !== actor, 409, 'feed_needs_second_approver'); fail(!v.mass_change || input.acknowledge_mass_change === true, 409, 'feed_mass_change_needs_acknowledgement');
    return this.activate(actor, v, 'feed.approved', text(input.note, 'feed_note', 500, true));
  }
  reject(actor, id, input = {}) { const v = this.row(this.s.require('SELECT * FROM feed_versions WHERE id=?', [id])); fail(v.status === 'staged', 409, 'feed_version_not_staged'); const at = this.now(); this.s.transaction(() => { this.s.run("UPDATE feed_versions SET status='rejected',decided_by=?,decided_at=?,note=? WHERE id=?", actor, at, text(input.note, 'feed_note', 500, true), id); this.s.audit(actor, 'feed.rejected', `${v.feed}:v${v.version_no}`, {}, at); }); return this.row(this.s.get('SELECT * FROM feed_versions WHERE id=?', id)); }
  rollback(actor, feed, input) {
    object(input, ['version_no', 'reason'], 'feed_rollback'); const target = this.row(this.s.require("SELECT * FROM feed_versions WHERE feed=? AND version_no=? AND status IN ('superseded','active')", [feed, integer(input.version_no, 1, 1000000, 'feed_version_no')]));
    fail(target.status !== 'active', 409, 'feed_version_already_active'); return this.activate(actor, target, 'feed.rolled_back', text(input.reason, 'feed_rollback_reason', 500));
  }
  // Applies a version: indicators are recorded or expired (never deleted) and never create response actions.
  activate(actor, v, action, note) {
    const cur = this.active(v.feed), at = this.now(), diff = diffItems(v.kind, cur?.items || [], v.items), keep = new Set(v.items.map(x => keyOf(v.kind, x)));
    this.s.transaction(() => {
      if (v.kind === 'threat-intel') {
        for (const x of v.items) this.ti.add(actor, { type: x.type, value: x.value, source_name: v.feed, source_ref: v.source_ref, published_at: v.source_date, expires_at: x.expires_at, confidence: x.confidence, redistribution_rights: v.redistribution_rights, source_verified: v.source_verified });
        for (const x of cur?.items || []) if (!keep.has(keyOf(v.kind, x))) this.s.run('UPDATE threat_indicators SET expires_at=? WHERE source_name=? AND type=? AND value=? AND expires_at>?', at, v.feed, x.type, x.value, at);
      }
      this.s.run("UPDATE feed_versions SET status='superseded' WHERE feed=? AND status='active'", v.feed);
      this.s.run("UPDATE feed_versions SET status='active',decided_by=?,decided_at=?,note=? WHERE id=?", actor, at, note || null, v.id);
      this.s.audit(actor, action, `${v.feed}:v${v.version_no}`, { added: diff.added, removed: diff.removed, changed: diff.changed, response_actions_created: 0 }, at);
    });
    if (v.kind === 'cisa-kev' && this.domain) { this.domain.internalSource(); const ext = { external_id: 'cyberguard-feeds', hostname: 'CyberGuard feeds', os_family: 'unknown', device_type: 'unknown', addresses: [] };
      this.domain.ingest(actor, '00000000-0000-4000-8000-000000000163', { schema_version: 'cg.telemetry/1', events: [{ event_id: `feed:${v.feed}:v${v.version_no}:${at}`, kind: 'vulnerability.intel', observed_at: at, asset: ext, details: { intel_id: `${v.feed}-v${v.version_no}`, feed: 'cisa-kev', feed_version: `v${v.version_no}`, published_at: v.source_date, entries: v.items } }] }); }
    return { ...this.row(this.s.get('SELECT * FROM feed_versions WHERE id=?', v.id)), applied_diff: diff, response_actions_created: 0 };
  }
  view() {
    const rows = this.s.all('SELECT * FROM feed_versions ORDER BY feed,version_no DESC').map(r => { const x = this.row(r); delete x.items; return { ...x, item_count: JSON.parse(r.items).length }; });
    const feeds = [...new Set(rows.map(r => r.feed))].map(f => ({ feed: f, kind: rows.find(r => r.feed === f).kind, active: rows.find(r => r.feed === f && r.status === 'active') || null, versions: rows.filter(r => r.feed === f) }));
    return { feeds, mass_change: MASS,
      claim: 'Feed updates are staged with their source URL, source date and licence, and their diff against the active version is shown before anything changes. A different administrator with MFA approves them; mass changes need an explicit acknowledgement. Applying a version records or expires indicators and creates no response action, so a feed change can never cause a mass block. Any earlier version can be restored.',
      claim_ar: 'تُجهَّز تحديثات التغذية مرحليًا مع رابط مصدرها وتاريخه وترخيصه، ويُعرض الفرق عن النسخة النشطة قبل أي تغيير. ويعتمدها مسؤول آخر مع MFA، ويحتاج التغيير الجماعي إقرارًا صريحًا. وتطبيق النسخة يسجل المؤشرات أو يُنهي صلاحيتها ولا ينشئ أي إجراء استجابة، فلا يمكن أن يؤدي تغيير التغذية إلى حظر جماعي. ويمكن استعادة أي نسخة سابقة.' };
  }
}
