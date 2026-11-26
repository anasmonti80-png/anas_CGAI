// CG-144 Past-compromise check after patching. Installing the fix closes the vulnerability, not an intrusion that may
// have happened before it. When a known-exploited vulnerability (CISA KEV) that was present on an asset becomes fixed,
// and the asset received traffic from the internet while it was vulnerable, an investigation is opened over that
// window: processes, accounts, persistence and outbound connections, each with the evidence collected for the window.
// Every item needs an analyst conclusion before the investigation closes, and cases about the asset cannot be closed
// while it is open. Gaps in evidence are recorded as such, never as clean.
import { randomUUID } from 'node:crypto';
import { fail, text, choice } from './common.js';

const parse = s => JSON.parse(s), PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fc|fd|fe80)/i;
export const ITEMS = [
  { id: 'processes', title: 'Processes started on the asset while it was vulnerable', title_ar: 'العمليات التي بدأت على الأصل أثناء كونه معرّضًا', kinds: ['endpoint.process_causality'] },
  { id: 'accounts', title: 'Logons, sign-ins and remote sessions to the asset', title_ar: 'عمليات الدخول والجلسات عن بعد إلى الأصل', kinds: ['auth.failed', 'remote.attempt', 'remote.authenticated', 'remote.active', 'identity.signin_activity'] },
  { id: 'persistence', title: 'New services, scheduled tasks and protection changes', title_ar: 'الخدمات والمهام المجدولة الجديدة وتغييرات الحماية', kinds: ['endpoint.process_causality', 'endpoint.defense_tamper', 'change.sensitive'] },
  { id: 'network', title: 'Outbound connections from the asset', title_ar: 'الاتصالات الصادرة من الأصل', kinds: ['log.batch', 'endpoint.process_causality'] },
];
export const CONCLUSIONS = ['clean', 'suspicious', 'insufficient-evidence'];

export class PostPatchInvestigations {
  constructor(store, { domain, clock }) { Object.assign(this, { s: store, d: domain, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  kev() { const set = new Set(); for (const r of this.s.all("SELECT payload FROM events WHERE kind='vulnerability.intel'")) { const d = parse(r.payload).details; if (d.feed === 'cisa-kev') for (const e of d.entries) set.add(e.cve_id); } return set; }
  // Called after a software inventory for an asset: records vulnerable/fixed state and opens investigations on fixes.
  track(assetRef, observedAt) {
    const kev = this.kev(), item = this.d.softwareVulnerabilities({ limit: 5000 }).items.find(i => i.asset.external_id === assetRef); if (!item) return [];
    const now = observedAt || this.now(), current = new Map(item.matches.map(m => [m.vuln_id, m])), opened = [];
    for (const m of item.matches.filter(m => m.status === 'vulnerable')) { const row = this.s.get('SELECT * FROM vuln_observations WHERE asset_ref=? AND vuln_id=?', assetRef, m.vuln_id);
      if (!row || row.fixed_at) this.s.run('INSERT OR REPLACE INTO vuln_observations(asset_ref,vuln_id,kev,first_vulnerable_at,last_vulnerable_at,fixed_at) VALUES (?,?,?,?,?,NULL)', assetRef, m.vuln_id, m.kev || kev.has(m.vuln_id) ? 1 : 0, now, now);
      else this.s.run('UPDATE vuln_observations SET last_vulnerable_at=?,kev=? WHERE asset_ref=? AND vuln_id=?', now, m.kev || kev.has(m.vuln_id) || row.kev ? 1 : 0, assetRef, m.vuln_id); }
    for (const row of this.s.all('SELECT * FROM vuln_observations WHERE asset_ref=? AND fixed_at IS NULL', assetRef)) { const m = current.get(row.vuln_id); if (m && m.status === 'vulnerable') continue;
      this.s.run('UPDATE vuln_observations SET fixed_at=? WHERE asset_ref=? AND vuln_id=?', now, assetRef, row.vuln_id);
      if (!row.kev) continue; const exposure = this.exposure(assetRef, row.first_vulnerable_at, now); if (!exposure.length) continue;
      opened.push(this.open(assetRef, row.vuln_id, row.first_vulnerable_at, now, exposure)); }
    return opened;
  }
  assetRows(ref) { return this.s.all('SELECT id,addresses,hostname FROM assets WHERE external_id=?', ref); }
  exposure(ref, from, to) {
    const rows = this.assetRows(ref), ids = rows.map(r => r.id), addrs = new Set(rows.flatMap(r => parse(r.addresses))), out = [];
    for (const r of this.s.all(`SELECT id,asset_id,kind,observed_at,payload FROM events WHERE kind IN ('log.batch','remote.port_open','remote.attempt','remote.authenticated') AND observed_at BETWEEN ? AND ?`, from, to)) { const d = parse(r.payload).details;
      if (r.kind === 'log.batch') { for (const x of d.records || []) if (x.src_ip && !PRIVATE.test(x.src_ip) && (addrs.has(x.dst_ip) || (ids.includes(r.asset_id) && !x.dst_ip && x.category === 'web'))) { out.push({ at: x.time, source: x.src_ip, evidence_event_id: r.id }); break; } }
      else if (ids.includes(r.asset_id) && (r.kind === 'remote.port_open' || (d.source_a?.ip && !PRIVATE.test(d.source_a.ip)))) out.push({ at: r.observed_at, source: d.source_a?.ip || 'open port observed', evidence_event_id: r.id }); }
    return out.slice(0, 50);
  }
  evidence(ref, from, to) {
    const ids = this.assetRows(ref).map(r => r.id), ph = ids.map(() => '?').join(','); if (!ids.length) return {};
    return Object.fromEntries(ITEMS.map(it => { const rows = this.s.all(`SELECT id,kind,payload FROM events WHERE asset_id IN (${ph}) AND kind IN (${it.kinds.map(() => '?').join(',')}) AND observed_at BETWEEN ? AND ?`, ...ids, ...it.kinds, from, to);
      let n = 0; for (const r of rows) { const d = parse(r.payload).details;
        if (it.id === 'processes') n += r.kind === 'endpoint.process_causality' ? d.processes.length : 0;
        else if (it.id === 'persistence') n += r.kind === 'endpoint.process_causality' ? (d.service_changes.length + d.scheduled_task_changes.length) : 1;
        else if (it.id === 'network') n += r.kind === 'endpoint.process_causality' ? (d.connections || []).length : (d.records || []).filter(x => x.dst_ip && !PRIVATE.test(x.dst_ip)).length;
        else n += r.kind === 'identity.signin_activity' ? d.signins.length : 1; }
      return [it.id, { records: n, events: rows.length, event_ids: rows.slice(0, 20).map(r => r.id) }]; }));
  }
  open(ref, vulnId, from, to, exposure) {
    const existing = this.s.get("SELECT id FROM post_patch_investigations WHERE asset_ref=? AND vuln_id=? AND status='open'", ref, vulnId); if (existing) return existing.id;
    const ev = this.evidence(ref, from, to), items = ITEMS.map(it => ({ id: it.id, title: it.title, title_ar: it.title_ar, evidence: ev[it.id] || { records: 0, events: 0, event_ids: [] }, conclusion: null, note: null, by: null, at: null })), id = randomUUID();
    this.s.run('INSERT INTO post_patch_investigations(id,asset_ref,vuln_id,vulnerable_from,patched_at,exposure_json,items_json,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)', id, ref, vulnId, from, to, JSON.stringify(exposure), JSON.stringify(items), 'open', this.now());
    this.s.audit('system', 'post_patch.investigation_opened', id, { asset_ref: ref, vuln_id: vulnId }, this.now()); return id;
  }
  get(id) { const r = this.s.get('SELECT * FROM post_patch_investigations WHERE id=?', id); fail(r, 404, 'post_patch_investigation_not_found'); return { ...r, exposure: parse(r.exposure_json), items: parse(r.items_json), exposure_json: undefined, items_json: undefined }; }
  list() { return this.s.all('SELECT id FROM post_patch_investigations ORDER BY created_at DESC LIMIT 200').map(r => this.get(r.id)); }
  conclude(actor, id, input) {
    const inv = this.get(id); fail(inv.status === 'open', 409, 'post_patch_investigation_closed');
    const item = inv.items.find(i => i.id === choice(input?.item, ITEMS.map(i => i.id), 'post_patch_item')); const conclusion = choice(input.conclusion, CONCLUSIONS, 'post_patch_conclusion'), note = text(input.note, 'post_patch_note', 2000);
    Object.assign(item, { conclusion, note, by: actor, at: this.now() });
    this.s.transaction(() => { this.s.run('UPDATE post_patch_investigations SET items_json=? WHERE id=?', JSON.stringify(inv.items), id); this.s.audit(actor, 'post_patch.item_concluded', id, { item: item.id, conclusion }, this.now()); });
    return this.get(id);
  }
  close(actor, id, input = {}) {
    const inv = this.get(id); fail(inv.status === 'open', 409, 'post_patch_investigation_closed');
    fail(inv.items.every(i => i.conclusion), 409, 'post_patch_items_need_conclusions');
    const suspicious = inv.items.some(i => i.conclusion === 'suspicious'), gaps = inv.items.filter(i => i.conclusion === 'insufficient-evidence');
    const reason = gaps.length ? text(input.gaps_reason, 'post_patch_gaps_reason', 2000) : null;
    const status = suspicious ? 'escalated' : gaps.length ? 'closed-with-gaps' : 'closed-clean';
    this.s.transaction(() => { this.s.run('UPDATE post_patch_investigations SET status=?,closed_at=?,closed_by=?,gaps_reason=? WHERE id=?', status, this.now(), actor, reason, id); this.s.audit(actor, 'post_patch.investigation_closed', id, { status, gaps: gaps.map(g => g.id) }, this.now()); });
    return this.get(id);
  }
  openForAssetIds(assetIds) { if (!assetIds.length) return []; const refs = this.s.all(`SELECT DISTINCT external_id FROM assets WHERE id IN (${assetIds.map(() => '?').join(',')})`, ...assetIds).map(r => r.external_id); return refs.length ? this.s.all(`SELECT id,asset_ref,vuln_id FROM post_patch_investigations WHERE status='open' AND asset_ref IN (${refs.map(() => '?').join(',')})`, ...refs) : []; }
}
