// CG-122 Evidence-grounded AI answers. Every source an answer cites is captured as a dated, hashed snapshot (the stored
// event, the matched rule, an advisory, the asset record), so an answer always points at the exact version it relied on,
// even if the source later changes. Answers are stored append-only. What a reader sees is redacted for their role:
// secrets are always hidden; viewers do not see personal data; analysts see accounts and addresses but not phone or
// national identity numbers. Each claim carries its uncertainty: missing, stale, single-source or silent-source evidence.
import { createHash, randomUUID } from 'node:crypto';
import { canonical } from './rule-signing.js';

const sha = v => createHash('sha256').update(typeof v === 'string' ? v : canonical(v)).digest('hex');
const SECRET = [/\bAKIA[0-9A-Z]{16}\b/g, /\b(?:ghp|gho|github_pat)_[A-Za-z0-9_]{20,}\b/g, /\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*/gi, /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, /\b(password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*\S+/gi, /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g];
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, PHONE = /(?<![0-9A-Za-z])(?:\+?966|00966|0)?5\d{8}(?![0-9A-Za-z])/g, NATIONAL_ID = /(?<![0-9A-Za-z])[12]\d{9}(?![0-9A-Za-z])/g, PRIVATE_IP = /\b(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b|\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b/g;
// Hashes, identifiers and routes are never redacted: they carry no personal data and must stay verifiable.
const VERBATIM_KEYS = /(^|_)(sha256|id|ids|hash)$|^(route|snapshot_id|source_id|event_id|answer_id|captured_at|observed_at|generated_at)$/i;
const PERSON_KEYS = /^(account|user|user_ref|username|principal_ref|requester|actor_ref|owner|display_name|contact|email|target_account)$/i;
export const ROLE_POLICY = {
  admin: { secrets: 'hidden', accounts: 'shown', email: 'shown', phone_and_national_id: 'masked', internal_addresses: 'shown' },
  analyst: { secrets: 'hidden', accounts: 'shown', email: 'masked', phone_and_national_id: 'hidden', internal_addresses: 'shown' },
  viewer: { secrets: 'hidden', accounts: 'hidden', email: 'hidden', phone_and_national_id: 'hidden', internal_addresses: 'hidden' },
};
function redactString(s, role) {
  let out = String(s), n = 0; const count = r => (...a) => { n++; return typeof r === 'function' ? r(...a) : r; };
  for (const re of SECRET) out = out.replace(re, count('[secret]'));
  out = out.replace(NATIONAL_ID, count(role === 'admin' ? m => `${m.slice(0, 2)}******${m.slice(-2)}` : '[national-id]')).replace(PHONE, count(role === 'admin' ? m => `${m.slice(0, 3)}*****${m.slice(-2)}` : '[phone]'));
  if (role !== 'admin') out = out.replace(EMAIL, count(role === 'analyst' ? m => `${m[0]}***@${m.split('@')[1]}` : '[email]'));
  if (role === 'viewer') out = out.replace(PRIVATE_IP, count('[internal-address]'));
  return { value: out, redactions: n };
}
export function redactForRole(value, role, key = '') {
  let total = 0; const walk = (v, k) => {
    if (typeof v === 'string') { if (VERBATIM_KEYS.test(k)) return v; if (role === 'viewer' && PERSON_KEYS.test(k) && v) { total++; return '[person]'; } const r = redactString(v, role); total += r.redactions; return r.value; }
    if (Array.isArray(v)) return v.map(x => walk(x, k));
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([kk, x]) => [kk, walk(x, kk)]));
    return v;
  };
  return { value: walk(value, key), redactions: total };
}

export class EvidenceRag {
  constructor(store, { clock }) { Object.assign(this, { s: store, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  snapshot(source_type, ref, content, observed_at = null) {
    const hash = sha(content), found = this.s.get('SELECT id,captured_at FROM ai_source_snapshots WHERE ref=? AND sha256=?', ref, hash); if (found) return { id: found.id, sha256: hash, captured_at: found.captured_at, ref, source_type, reused: true };
    const id = randomUUID(), at = this.now(); this.s.run('INSERT INTO ai_source_snapshots(id,source_type,ref,sha256,captured_at,observed_at,content) VALUES (?,?,?,?,?,?,?)', id, source_type, ref, hash, at, observed_at, JSON.stringify(content));
    return { id, sha256: hash, captured_at: at, ref, source_type, reused: false };
  }
  // Ground a deterministic analysis: snapshot every cited source, compute per-claim uncertainty, store, redact for the reader.
  ground(user, analysis) {
    const now = this.clock(), snaps = {}, events = new Map();
    for (const e of analysis.evidence) { const row = this.s.get('SELECT id,source_id,kind,observed_at,sanitized_sha256,payload FROM events WHERE id=?', e.event_id); if (!row) continue; events.set(`log:${row.id}`, row); snaps[`log:${row.id}`] = this.snapshot('event', `event:${row.id}`, JSON.parse(row.payload), row.observed_at); }
    snaps['alert:record'] = this.snapshot('alert', `alert:${analysis.alert.id}`, analysis.alert);
    const rule = analysis.grounding.sources.find(x => x.id === 'rule:matched'); if (rule) snaps['rule:matched'] = this.snapshot('rule', `rule:${rule.label}`, { label: rule.label, description: rule.description || null });
    for (const a of analysis.grounding.sources.filter(x => x.type === 'advisory')) snaps[a.id] = this.snapshot('advisory', `advisory:${a.label}`, { label: a.label, published_at: a.published_at, sha256: a.sha256 }, a.published_at);
    if (analysis.asset) snaps['asset:record'] = this.snapshot('asset', `asset:${analysis.asset.id}`, analysis.asset);
    const pb = analysis.grounding.sources.find(x => x.id === 'reference:playbook'); if (pb) snaps['reference:playbook'] = this.snapshot('playbook', `playbook:${pb.label}`, { label: pb.label });
    const claims = analysis.grounding.claims.map(c => {
      const logs = c.source_ids.filter(id => id.startsWith('log:')), reasons = [], add = (id, en, ar) => reasons.push({ id, en, ar });
      if (analysis.missing_evidence_ids.length) add('missing-evidence', `${analysis.missing_evidence_ids.length} linked evidence record(s) are missing`, `${analysis.missing_evidence_ids.length} من سجلات الدليل المرتبطة مفقودة`);
      const ages = logs.map(id => events.get(id)).filter(Boolean).map(r => (now - Date.parse(r.observed_at)) / 86400000); if (ages.length && Math.min(...ages) > 7) add('stale-evidence', `the newest supporting evidence is ${Math.floor(Math.min(...ages))} days old`, `أحدث دليل داعم عمره ${Math.floor(Math.min(...ages))} يومًا`);
      const silent = [...new Set(logs.map(id => events.get(id)?.source_id).filter(Boolean))].filter(sid => { const src = this.s.get('SELECT last_received,stale_seconds,revoked FROM sources WHERE id=?', sid); return !src || src.revoked || !src.last_received || now - Date.parse(src.last_received) > src.stale_seconds * 1000; });
      if (silent.length) add('silent-source', 'a source behind this claim is not currently reporting or was revoked', 'مصدر خلف هذا الادعاء لا يبلغ حاليًا أو أُلغي');
      if (['what_happened', 'why_suspicious'].includes(c.section) && logs.length === 1) add('single-source', 'supported by a single evidence record', 'مدعوم بسجل دليل واحد');
      if (['what_happened', 'why_suspicious'].includes(c.section) && !logs.length) add('no-evidence-record', 'no evidence record supports this claim; it rests on the alert and rule only', 'لا يدعم هذا الادعاء سجل دليل؛ يعتمد على التنبيه والقاعدة فقط');
      const level = reasons.some(r => ['missing-evidence', 'no-evidence-record', 'silent-source'].includes(r.id)) ? 'high' : reasons.length ? 'medium' : 'low';
      return { id: c.id, section: c.section, ar: c.ar, en: c.en, citations: c.source_ids.map(id => snaps[id] ? { source_id: id, snapshot_id: snaps[id].id, sha256: snaps[id].sha256, captured_at: snaps[id].captured_at } : { source_id: id, snapshot_id: null }), uncertainty: { level, reasons } };
    });
    const answer = { alert_id: analysis.alert.id, generated_at: this.now(), method: analysis.mode, claims, confidence: analysis.confidence, limitations: analysis.limitations }, id = randomUUID();
    this.s.run('INSERT INTO ai_answers(id,alert_id,generated_at,generated_for,role,answer,answer_sha256) VALUES (?,?,?,?,?,?,?)', id, answer.alert_id, answer.generated_at, user.id, user.role, JSON.stringify(answer), sha(answer));
    return this.present(user, { id, ...answer }, analysis);
  }
  present(user, answer, analysis = null) {
    const r = redactForRole({ answer, analysis }, user.role);
    const { claims, ...meta } = r.value.answer;
    return { ...(r.value.analysis || {}), answer_id: answer.id, answer_generated_at: meta.generated_at, answer_alert_id: meta.alert_id, answer_confidence: meta.confidence, answer_limitations: meta.limitations, grounded_claims: claims, uncertain_claims: answer.claims.filter(c => c.uncertainty.level !== 'low').map(c => c.id), redaction: { role: user.role, policy: ROLE_POLICY[user.role], redacted_values: r.redactions },
      grounding_claim: 'Every cited source is a dated, hashed snapshot; answers are stored unchanged; secrets are always hidden and personal data is hidden by role; each claim shows its uncertainty.', grounding_claim_ar: 'كل مصدر مستشهد به نسخة مؤرخة ببصمة؛ تُحفظ الإجابات دون تغيير؛ تُخفى الأسرار دائمًا والبيانات الشخصية حسب الدور؛ ولكل ادعاء درجة عدم يقين ظاهرة.' };
  }
  // A stored answer, verified against its snapshots, redacted for the current reader.
  get(user, id) {
    const row = this.s.get('SELECT * FROM ai_answers WHERE id=?', id); if (!row) return null; const answer = JSON.parse(row.answer);
    const check = answer.claims.flatMap(c => c.citations).filter(c => c.snapshot_id).map(c => { const s = this.s.get('SELECT sha256,content FROM ai_source_snapshots WHERE id=?', c.snapshot_id); return s && s.sha256 === c.sha256 && sha(JSON.parse(s.content)) === s.sha256; });
    return { ...this.present(user, { id, ...answer }), answer_intact: sha(answer) === row.answer_sha256, snapshots_intact: check.every(Boolean), generated_for_role: row.role };
  }
  snapshotFor(user, id) { const s = this.s.get('SELECT * FROM ai_source_snapshots WHERE id=?', id); if (!s) return null; return { ...s, content: redactForRole(JSON.parse(s.content), user.role).value }; }
  recent(user) { return this.s.all('SELECT id,alert_id,generated_at,role FROM ai_answers ORDER BY generated_at DESC LIMIT 50').map(r => ({ ...r, ...(() => { const a = JSON.parse(this.s.get('SELECT answer FROM ai_answers WHERE id=?', r.id).answer); return { claims: a.claims.length, uncertain: a.claims.filter(c => c.uncertainty.level !== 'low').length, citations: a.claims.reduce((n, c) => n + c.citations.length, 0) }; })() })); }
}
