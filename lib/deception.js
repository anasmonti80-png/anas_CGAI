// CG-164 High-signal deception (MITRE D3FEND Deceive: Decoy User Credential D3-DUC, Decoy File D3-DF, Decoy Session
// Token D3-DST, Decoy Network Resource D3-DNR). A decoy is something no legitimate user or process should ever touch, so
// any observed use is a high-confidence signal. Safety rules:
//  - explicit approval: a decoy is proposed with an authorization reference and owner, and becomes active only when a
//    different administrator with recent MFA approves it; it expires (at most 365 days) and can be retired;
//  - no real credentials: CyberGuard never accepts or stores a password, key or token for a decoy. Honeytokens are random
//    markers CyberGuard generates (shown once, stored as a SHA-256 hash and a short prefix) that authenticate nowhere;
//  - safe isolation: the owner attests the isolation controls (a decoy account has no privileges and cannot log on, a
//    decoy file or share is read-only and outside production data paths); deployment itself is done by the owner.
// Detection reads stored evidence only: a decoy account name in authentication, sign-in or remote-access evidence, a decoy
// file path or share in file, process or log evidence, or a honeytoken marker anywhere in an event.
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { fail, object, text, choice, integer } from './common.js';

export const TYPES = {
  'decoy-account': { d3fend: 'D3-DUC', title: 'Decoy user account', title_ar: 'حساب مستخدم طُعم', required: ['no-privileges', 'logon-denied-or-disabled', 'monitored-sign-in'], fields: ['account', 'principal_ref', 'source_a.account', 'target_b.account', 'actor_ref', 'user', 'username'] },
  'decoy-file': { d3fend: 'D3-DF', title: 'Decoy file', title_ar: 'ملف طُعم', required: ['read-only', 'outside-production-data', 'object-access-audit'], fields: null },
  'decoy-share': { d3fend: 'D3-DNR', title: 'Decoy network share or resource', title_ar: 'مشاركة أو مورد شبكي طُعم', required: ['read-only', 'outside-production-data', 'object-access-audit'], fields: null },
  honeytoken: { d3fend: 'D3-DST', title: 'Honeytoken marker', title_ar: 'رمز طُعم (Honeytoken)', required: ['authenticates-nowhere'], fields: null },
};
export const REFERENCES = [
  { id: 'MITRE D3FEND Deceive', url: 'https://d3fend.mitre.org/tactic/d3f:Deceive/' },
  { id: 'Defender for Identity honeytoken tag', url: 'https://learn.microsoft.com/en-us/defender-for-identity/entity-tags' },
  { id: 'Windows event 4663 (SACL object access)', url: 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663' },
];
const SECRET_LIKE = /(password|passwd|secret|api[_-]?key|private[_-]?key|token)\s*[:=]|-----BEGIN|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\./i;
const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const get = (o, p) => p.split('.').reduce((v, k) => (v && typeof v === 'object' ? v[k] : undefined), o);
const sha = v => createHash('sha256').update(v).digest('hex');

export class Deception {
  constructor(store, { clock } = {}) { Object.assign(this, { s: store, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  row(r) { return r && { ...r, isolation: JSON.parse(r.isolation), ...TYPES[r.type] && { d3fend: TYPES[r.type].d3fend } }; }
  propose(actor, input) {
    object(input, ['type', 'ref', 'placement', 'owner', 'authorization_ref', 'isolation', 'expires_days', 'note'], 'decoy');
    const type = choice(input.type, Object.keys(TYPES), 'decoy_type'), t = TYPES[type];
    fail(Array.isArray(input.isolation) && t.required.every(x => input.isolation.includes(x)), 400, 'decoy_isolation_attestation_required');
    let ref, marker = null;
    if (type === 'honeytoken') { fail(input.ref === undefined || input.ref === null, 400, 'honeytoken_marker_is_generated'); marker = `CGDECOY-${randomBytes(18).toString('base64url')}`; ref = marker; }
    else { ref = text(input.ref, 'decoy_ref', 300); fail(ref.length >= 8, 400, 'decoy_ref_too_generic'); fail(!SECRET_LIKE.test(ref), 400, 'decoy_must_not_contain_credentials'); }
    const note = text(input.note, 'decoy_note', 500, true) || null; fail(!note || !SECRET_LIKE.test(note), 400, 'decoy_must_not_contain_credentials');
    const id = randomUUID(), at = this.now(), days = integer(input.expires_days ?? 90, 1, 365, 'decoy_expires_days');
    const stored = type === 'honeytoken' ? { ref_hash: sha(marker), ref_display: `${marker.slice(0, 12)}…` } : { ref_hash: sha(ref.toLowerCase()), ref_display: ref };
    this.s.transaction(() => {
      this.s.run("INSERT INTO decoys(id,type,ref_display,ref_hash,match_ref,placement,owner,authorization_ref,isolation,status,proposed_by,proposed_at,expires_days,note) VALUES (?,?,?,?,?,?,?,?,?,'proposed',?,?,?,?)", id, type, stored.ref_display, stored.ref_hash, type === 'honeytoken' ? null : ref.toLowerCase(),
        text(input.placement, 'decoy_placement', 300), text(input.owner, 'decoy_owner', 200), text(input.authorization_ref, 'decoy_authorization_ref', 200), JSON.stringify(input.isolation.map(x => text(String(x), 'decoy_isolation', 60))), actor, at, days, note);
      this.s.audit(actor, 'deception.proposed', id, { type, ref: stored.ref_display, authorization_ref: input.authorization_ref }, at);
    });
    return { ...this.row(this.s.get('SELECT * FROM decoys WHERE id=?', id)), ...(marker ? { marker, marker_note: 'Shown once. Plant it where only an intruder would read it; it authenticates nowhere.' } : {}) };
  }
  approve(actor, id) {
    const d = this.s.require('SELECT * FROM decoys WHERE id=?', [id]); fail(d.status === 'proposed', 409, 'decoy_not_proposed'); fail(d.proposed_by !== actor, 409, 'decoy_needs_second_approver');
    const at = this.now(), expires = new Date(this.clock() + d.expires_days * 86400000).toISOString();
    this.s.transaction(() => { this.s.run("UPDATE decoys SET status='active',approved_by=?,approved_at=?,expires_at=? WHERE id=?", actor, at, expires, id); this.s.audit(actor, 'deception.approved', id, { expires_at: expires }, at); });
    return this.row(this.s.get('SELECT * FROM decoys WHERE id=?', id));
  }
  retire(actor, id) {
    const d = this.s.require('SELECT * FROM decoys WHERE id=?', [id]); fail(d.status !== 'retired', 409, 'decoy_already_retired');
    const at = this.now(); this.s.transaction(() => { this.s.run("UPDATE decoys SET status='retired',retired_at=? WHERE id=?", at, id); this.s.audit(actor, 'deception.retired', id, {}, at); });
    return this.row(this.s.get('SELECT * FROM decoys WHERE id=?', id));
  }
  active(at = this.now()) { return this.s.all("SELECT * FROM decoys WHERE status='active' AND expires_at>? AND approved_at<=?", at, at); }
  // Hits of active decoys in one stored event; deployment evidence carrying the decoy's own authorization is not a hit.
  hits(e) {
    if (e.kind === 'visibility.loss') return [];
    const details = e.details || {}, blob = JSON.stringify(details), lower = blob.toLowerCase(), out = [];
    for (const d of this.active(e.observed_at > this.now() ? this.now() : e.observed_at)) {
      if (details.authorization_ref && details.authorization_ref === d.authorization_ref) continue;
      if (d.type === 'honeytoken') { const m = blob.match(/CGDECOY-[A-Za-z0-9_-]{24}/g) || []; if (m.some(x => sha(x) === d.ref_hash)) out.push({ decoy: d, where: 'marker in event' }); continue; }
      const re = new RegExp(`(^|[^a-z0-9_.$-])${esc(d.match_ref)}($|[^a-z0-9_.$-])`, 'i');
      if (d.type === 'decoy-account') {
        const vals = [...TYPES['decoy-account'].fields.map(f => get(details, f)), ...(Array.isArray(details.signins) ? details.signins.map(x => x.principal_ref) : [])].filter(v => typeof v === 'string');
        const hit = vals.find(v => v.toLowerCase() === d.match_ref || v.toLowerCase().endsWith(`\\${d.match_ref}`) || v.toLowerCase().startsWith(`${d.match_ref}@`));
        if (hit) out.push({ decoy: d, where: `account ${hit}` });
      } else if (re.test(lower) || lower.includes(d.match_ref.replace(/\\/g, '\\\\'))) out.push({ decoy: d, where: 'path in event' });
    }
    return out;
  }
  view() {
    const decoys = this.s.all('SELECT * FROM decoys ORDER BY proposed_at DESC').map(r => { const d = this.row(r), now = this.now();
      return { ...d, state: d.status === 'active' && d.expires_at <= now ? 'expired' : d.status, triggers: this.s.get("SELECT COUNT(*) n, MAX(last_seen) last FROM alerts WHERE rule_id='CG-DECOY-TRIGGER-164' AND dedup_key LIKE ?", `CG-DECOY-TRIGGER-164:${d.id}:%`) }; });
    return { decoys, types: Object.fromEntries(Object.entries(TYPES).map(([k, v]) => [k, { d3fend: v.d3fend, title: v.title, title_ar: v.title_ar, required: v.required }])), references: REFERENCES,
      claim: 'Decoys (D3FEND Deceive) are things no legitimate user or process should touch, so any use is a high-confidence signal. A decoy runs only after a second administrator with MFA approves it, it expires, CyberGuard never stores a real credential (honeytokens are generated markers that authenticate nowhere) and the owner attests its isolation. Detection reads stored evidence only.',
      claim_ar: 'الطُعم (D3FEND Deceive) شيء لا يلمسه مستخدم أو عملية مشروعة، فأي استخدام له إشارة عالية الثقة. ولا يعمل الطُعم إلا بعد اعتماد مسؤول ثانٍ مع MFA، وله تاريخ انتهاء، ولا يخزن CyberGuard أي بيانات اعتماد حقيقية (رموز الطُعم علامات مولّدة لا تصادق في أي مكان)، ويشهد المالك على عزله. والكشف يقرأ الأدلة المخزنة فقط.' };
  }
}
