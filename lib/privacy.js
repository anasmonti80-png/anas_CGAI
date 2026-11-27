// CG-167 Telemetry minimization and privacy.
//  - Minimization rules run at ingest, before an event is stored, indexed or shown to any analyst or AI: per evidence kind
//    (or every kind) and optionally per source type, a field path (with * over array items) is dropped, masked (last
//    four characters kept), pseudonymised with a keyed HMAC (equal values stay equal, so correlation still works) or
//    encrypted with AES-256-GCM under an installation key kept in the data directory. Built-in detectors always mask
//    payment card numbers (Luhn-valid) and Saudi IBANs found in any text field.
//  - Encrypted values are read back only by an administrator with recent MFA, one field of one event at a time, with a
//    reason, and the read is audited.
//  - Retention per source, source type or evidence kind, with the legal or contractual basis; a legal minimum is never
//    undercut by a shorter rule. Evidence of unresolved alerts and of open cases is never purged.
import fs from 'node:fs';
import path from 'node:path';
import { createCipheriv, createDecipheriv, createHmac, randomBytes, createHash } from 'node:crypto';
import { fail, object, text, choice, integer } from './common.js';

export const ACTIONS = ['drop', 'mask', 'hash', 'encrypt'];
const FIELD = /^(\*|[a-z_][a-z0-9_]*)(\.(\*|[a-z_][a-z0-9_]*)){0,5}$/i;
const luhn = d => { let s = 0; for (let i = 0; i < d.length; i++) { let n = +d[d.length - 1 - i]; if (i % 2) { n *= 2; if (n > 9) n -= 9; } s += n; } return s % 10 === 0; };
export const DETECTORS = [
  // Card numbers start with 3 to 6 (so epoch-millisecond timestamps, which start with 1, are never touched).
  { id: 'payment-card', re: /\b[3-6]\d{3}(?:[ -]?\d{4}){2,3}(?:[ -]?\d{1,3})?\b/g, test: m => { const d = m.replace(/\D/g, ''); return d.length >= 13 && d.length <= 19 && luhn(d); }, label: 'Payment card number (Luhn)', label_ar: 'رقم بطاقة دفع (Luhn)' },
  { id: 'saudi-iban', re: /\bSA\d{2}[ ]?(?:\d{4}[ ]?){5}\b/gi, test: () => true, label: 'Saudi IBAN', label_ar: 'آيبان سعودي' },
];
const mask = v => { const s = String(v); return s.length <= 4 ? '****' : `${'*'.repeat(Math.min(12, s.length - 4))}${s.slice(-4)}`; };

export class Privacy {
  constructor(store, { clock, dataDir } = {}) { Object.assign(this, { s: store, clock: clock || (() => Date.now()), dataDir }); }
  now() { return new Date(this.clock()).toISOString(); }
  key() {
    if (this.k) return this.k; fail(this.dataDir, 500, 'privacy_key_location_missing');
    const f = path.join(this.dataDir, 'field-protection.key');
    if (!fs.existsSync(f)) fs.writeFileSync(f, randomBytes(64).toString('base64'), { mode: 0o600, flag: 'wx' });
    const raw = Buffer.from(fs.readFileSync(f, 'utf8'), 'base64'); return (this.k = { enc: raw.subarray(0, 32), mac: raw.subarray(32), fingerprint: createHash('sha256').update(raw).digest('hex').slice(0, 16) });
  }
  encrypt(v) { const iv = randomBytes(12), c = createCipheriv('aes-256-gcm', this.key().enc, iv), ct = Buffer.concat([c.update(JSON.stringify(v), 'utf8'), c.final()]); return `enc:v1:${iv.toString('base64')}:${c.getAuthTag().toString('base64')}:${ct.toString('base64')}`; }
  decryptValue(s) { const [, , iv, tag, ct] = String(s).split(':'); const d = createDecipheriv('aes-256-gcm', this.key().enc, Buffer.from(iv, 'base64')); d.setAuthTag(Buffer.from(tag, 'base64')); return JSON.parse(Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8')); }
  hash(v) { return `hmac:${createHmac('sha256', this.key().mac).update(String(v).toLowerCase()).digest('hex').slice(0, 32)}`; }
  rules() { return this.s.all('SELECT * FROM privacy_rules WHERE disabled_at IS NULL ORDER BY id'); }
  addRule(actor, input) {
    object(input, ['kind', 'field', 'action', 'source_type', 'reason'], 'privacy_rule');
    const kind = text(input.kind, 'privacy_kind', 80), field = text(input.field, 'privacy_field', 200); fail(FIELD.test(field), 400, 'invalid_privacy_field');
    fail(!/^(event_id|kind|observed_at)$/.test(field), 400, 'privacy_field_is_structural');
    const action = choice(input.action, ACTIONS, 'privacy_action'), source_type = input.source_type ? text(input.source_type, 'privacy_source_type', 60) : null, at = this.now();
    const id = this.s.transaction(() => { const r = this.s.run('INSERT INTO privacy_rules(kind,field,action,source_type,reason,created_by,created_at) VALUES (?,?,?,?,?,?,?)', kind, field, action, source_type, text(input.reason, 'privacy_reason', 500), actor, at); this.s.audit(actor, 'privacy.rule_added', String(r.lastInsertRowid), { kind, field, action, source_type }, at); return Number(r.lastInsertRowid); });
    return this.s.get('SELECT * FROM privacy_rules WHERE id=?', id);
  }
  disableRule(actor, id) { const r = this.s.require('SELECT * FROM privacy_rules WHERE id=?', [id]); fail(!r.disabled_at, 409, 'privacy_rule_already_disabled'); const at = this.now(); this.s.transaction(() => { this.s.run('UPDATE privacy_rules SET disabled_at=?,disabled_by=? WHERE id=?', at, actor, id); this.s.audit(actor, 'privacy.rule_disabled', String(id), {}, at); }); return this.s.get('SELECT * FROM privacy_rules WHERE id=?', id); }
  // Applied to one validated event before it is stored. Returns the minimized event and what was done.
  minimize(e, sourceType = null) {
    const applied = [], details = structuredClone(e.details || {});
    const apply = (obj, parts, action, label) => {
      if (!obj || typeof obj !== 'object') return; const [head, ...rest] = parts;
      const keys = head === '*' ? (Array.isArray(obj) ? obj.map((_, i) => i) : Object.keys(obj)) : [head];
      for (const k of keys) { if (!(k in obj)) continue; if (rest.length) { apply(obj[k], rest, action, label); continue; }
        const v = obj[k]; if (v === null || v === undefined || v === '') continue;
        if (action === 'drop') delete obj[k]; else if (action === 'mask') obj[k] = mask(v); else if (action === 'hash') obj[k] = this.hash(v); else obj[k] = this.encrypt(v);
        applied.push({ field: label, action }); }
    };
    for (const r of this.rules()) if ((r.kind === '*' || r.kind === e.kind) && (!r.source_type || r.source_type === sourceType)) apply(details, r.field.split('.'), r.action, r.field);
    const scan = v => typeof v === 'string' && !v.startsWith('enc:v1:') ? DETECTORS.reduce((s, d) => s.replace(d.re, m => { if (!d.test(m)) return m; applied.push({ field: d.id, action: 'mask' }); return mask(m.replace(/\s/g, '')); }), v) : Array.isArray(v) ? v.map(scan) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scan(x)])) : v;
    const out = scan(details);
    return { event: applied.length ? { ...e, details: out, privacy: { minimized: [...new Map(applied.map(a => [`${a.field}|${a.action}`, a])).values()], profile: 'cg.privacy/1' } } : e, applied };
  }
  decrypt(actor, input) {
    object(input, ['event_id', 'field', 'reason'], 'privacy_decrypt'); const reason = text(input.reason, 'privacy_decrypt_reason', 500), field = text(input.field, 'privacy_field', 200);
    const ev = this.s.require('SELECT id,payload FROM events WHERE id=?', [text(input.event_id, 'privacy_event_id', 64)]), v = field.split('.').reduce((o, k) => (o && typeof o === 'object' ? o[k] : undefined), JSON.parse(ev.payload).details);
    fail(typeof v === 'string' && v.startsWith('enc:v1:'), 404, 'field_not_encrypted');
    const plain = this.decryptValue(v); this.s.audit(actor, 'privacy.field_decrypted', ev.id, { field, reason }, this.now());
    return { event_id: ev.id, field, value: plain };
  }
  // Retention: the most specific rule (source, then source type, then evidence kind) sets the days; a legal minimum from
  // any matching rule is never undercut.
  addRetention(actor, input) {
    object(input, ['scope', 'match', 'days', 'legal_basis', 'legal_minimum_days'], 'retention_rule');
    const scope = choice(input.scope, ['source', 'source-type', 'event-kind'], 'retention_scope'), match = text(input.match, 'retention_match', 100), days = integer(input.days, 1, 3650, 'retention_days');
    const legal_minimum_days = input.legal_minimum_days === undefined || input.legal_minimum_days === null ? null : integer(input.legal_minimum_days, 1, 3650, 'legal_minimum_days');
    const basis = text(input.legal_basis, 'retention_legal_basis', 300); fail(legal_minimum_days === null || days >= legal_minimum_days, 400, 'retention_below_legal_minimum');
    const at = this.now(); this.s.transaction(() => { this.s.run('INSERT INTO retention_rules(scope,match,days,legal_basis,legal_minimum_days,created_by,created_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(scope,match) DO UPDATE SET days=excluded.days,legal_basis=excluded.legal_basis,legal_minimum_days=excluded.legal_minimum_days,created_by=excluded.created_by,created_at=excluded.created_at', scope, match, days, basis, legal_minimum_days, actor, at); this.s.audit(actor, 'privacy.retention_set', `${scope}:${match}`, { days, legal_minimum_days, legal_basis: basis }, at); });
    return this.s.get('SELECT * FROM retention_rules WHERE scope=? AND match=?', scope, match);
  }
  effective(event, source, rules = this.s.all('SELECT * FROM retention_rules')) {
    const m = rules.filter(r => (r.scope === 'source' && r.match === source.id) || (r.scope === 'source-type' && r.match === source.kind) || (r.scope === 'event-kind' && r.match === event.kind));
    if (!m.length) return null; const pick = ['source', 'source-type', 'event-kind'].map(s => m.find(r => r.scope === s)).find(Boolean), floor = Math.max(0, ...m.map(r => r.legal_minimum_days || 0));
    return { days: Math.max(pick.days, floor), rule: `${pick.scope}:${pick.match}`, legal_floor: floor || null };
  }
  retentionPlan(apply = false, actor = 'retention-service') {
    const rules = this.s.all('SELECT * FROM retention_rules'), sources = new Map(this.s.all('SELECT id,kind FROM sources').map(s => [s.id, s]));
    const held = new Set([...this.s.all("SELECT j.value id FROM alerts a, json_each(a.evidence_ids) j WHERE a.status!='resolved'"), ...this.s.all("SELECT j2.value id FROM cases c, json_each(c.alert_ids) j, alerts a, json_each(a.evidence_ids) j2 WHERE c.status!='closed' AND a.id=j.value")].map(r => r.id));
    const now = this.clock(), by = {}, purge = [];
    for (const e of this.s.all('SELECT id,kind,source_id,received_at FROM events')) { const eff = this.effective(e, sources.get(e.source_id) || { id: e.source_id, kind: null }, rules); if (!eff) continue;
      const b = by[eff.rule] ||= { rule: eff.rule, days: eff.days, legal_floor: eff.legal_floor, events: 0, expired: 0, held: 0 }; b.events++;
      if (Date.parse(e.received_at) < now - eff.days * 86400000) { if (held.has(e.id)) b.held++; else { b.expired++; purge.push(e.id); } } }
    if (apply && purge.length) this.s.transaction(() => { for (const id of purge) this.s.run('DELETE FROM events WHERE id=?', id); this.s.audit(actor, 'privacy.retention_applied', 'events', { deleted: purge.length, rules: Object.values(by).map(b => ({ rule: b.rule, deleted: b.expired, held: b.held })) }, this.now()); });
    return { rules: Object.values(by), deleted: apply ? purge.length : 0, would_delete: purge.length };
  }
  view() {
    return { rules: this.s.all('SELECT * FROM privacy_rules ORDER BY id'), detectors: DETECTORS.map(({ id, label, label_ar }) => ({ id, label, label_ar, action: 'mask' })), actions: ACTIONS,
      retention: this.s.all('SELECT * FROM retention_rules ORDER BY scope,match'), plan: this.retentionPlan(false), key_fingerprint: this.dataDir ? this.key().fingerprint : null,
      minimized_events: this.s.get("SELECT COUNT(*) n FROM events WHERE json_extract(payload,'$.privacy.profile')='cg.privacy/1'").n,
      claim: 'Sensitive fields are minimized at ingest, before storage, indexing or any AI analysis: dropped, masked, pseudonymised with a keyed HMAC that keeps correlation, or encrypted with AES-256-GCM; payment cards and Saudi IBANs are always masked. Encrypted values are read only by an administrator with MFA and a reason, audited. Retention follows the source, source type or evidence kind with its legal basis, never below a legal minimum, and never purges evidence of open alerts or cases.',
      claim_ar: 'تُقلَّل الحقول الحساسة عند الاستيعاب، قبل التخزين والفهرسة وأي تحليل بالذكاء الاصطناعي: تُحذف، أو تُخفى جزئيًا، أو تُموَّه بـ HMAC بمفتاح يحفظ قابلية الربط، أو تُشفَّر بـ AES-256-GCM؛ وتُخفى أرقام بطاقات الدفع والآيبان السعودي دائمًا. ولا يقرأ القيم المشفرة إلا مسؤول مع MFA وسبب، ويُدقق ذلك. ويتبع الاحتفاظ المصدر أو نوعه أو نوع الدليل مع أساسه القانوني، ولا ينزل عن الحد الأدنى القانوني، ولا يحذف أدلة تنبيهات أو قضايا مفتوحة.' };
  }
}
