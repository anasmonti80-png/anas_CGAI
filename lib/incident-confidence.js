// CG-166 Incident confidence separation. Four levels are kept apart and only people move a case up:
//  observed-event              a stored event: something a source reported;
//  suspicious-indicator        an alert: a rule matched evidence; it may be benign;
//  verified-security-incident  an analyst verified a case: at least one of its alerts dispositioned true-positive, with
//                              a rationale and the events that prove it;
//  confirmed-compromise        a different administrator with recent MFA confirmed a compromise type (account takeover,
//                              malware execution, attacker access, data exfiltration, destructive action) with forensic
//                              evidence references, only on a verified incident.
// AI output never raises a level: certainty wording ("confirmed", "compromised", «مؤكد», «تم اختراق») in an AI text is
// withheld unless a person has confirmed the compromise, and the analysis carries the case's level.
import { fail, object, text, choice } from './common.js';

export const LEVELS = ['observed-event', 'suspicious-indicator', 'verified-security-incident', 'confirmed-compromise'];
export const LEVEL_TEXT = {
  'observed-event': { en: 'Observed event: a source reported it; nothing is implied.', ar: 'حدث مرصود: أبلغ عنه مصدر؛ ولا يعني شيئًا بذاته.' },
  'suspicious-indicator': { en: 'Suspicious indicator: a rule matched evidence; it may be benign until a person verifies it.', ar: 'مؤشر مريب: طابقت قاعدة أدلة؛ وقد يكون سليمًا حتى يتحقق منه شخص.' },
  'verified-security-incident': { en: 'Verified security incident: an analyst verified it with evidence; compromise is not confirmed.', ar: 'حادث أمني متحقق منه: تحقق منه محلل بأدلة؛ والاختراق غير مؤكد.' },
  'confirmed-compromise': { en: 'Confirmed compromise: a second administrator confirmed it with forensic evidence.', ar: 'اختراق مؤكد: أكده مسؤول ثانٍ بأدلة جنائية.' },
};
export const COMPROMISE_TYPES = ['account-takeover', 'malware-execution', 'attacker-access', 'data-exfiltration', 'destructive-action'];
// Negated forms (not confirmed, unconfirmed, غير مؤكد) are left alone: they state the opposite of certainty.
const CERTAINTY = [/(?<!\bnot )\b(confirmed|definitely|certainly|undoubtedly|without doubt)\b/gi, /\b(was|were|has been|have been|is) (compromised|breached|hacked)\b/gi, /(?<!غير )(مؤكدة|مؤكد|بالتأكيد|بلا شك|تم اختراقه|تم اختراق|اختُرق)/g];

export function enforceConfidence(value, level) {
  const withheld = [];
  if (level === 'confirmed-compromise') return { value, withheld };
  const walk = v => typeof v === 'string' ? CERTAINTY.reduce((s, re) => s.replace(re, m => { withheld.push(m); return `[withheld: ${level}]`; }), v) : Array.isArray(v) ? v.map(walk) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)])) : v;
  return { value: walk(value), withheld: [...new Set(withheld)] };
}

export class IncidentConfidence {
  constructor(store, { clock } = {}) { Object.assign(this, { s: store, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  record(caseId) { const r = this.s.get('SELECT * FROM case_confidence WHERE case_id=?', caseId); return r ? { ...r, evidence_event_ids: JSON.parse(r.evidence_event_ids), compromise_evidence_refs: r.compromise_evidence_refs ? JSON.parse(r.compromise_evidence_refs) : [] } : null; }
  levelOfCase(caseId) { return this.record(caseId)?.level || 'suspicious-indicator'; }
  levelOfAlert(alertId) {
    const c = this.s.all('SELECT c.id FROM cases c, json_each(c.alert_ids) j WHERE j.value=?', alertId).map(r => this.levelOfCase(r.id));
    return c.sort((a, b) => LEVELS.indexOf(b) - LEVELS.indexOf(a))[0] || 'suspicious-indicator';
  }
  human(actor) { const u = this.s.get('SELECT id,role FROM users WHERE id=?', actor); fail(u, 403, 'confidence_requires_a_person'); return u; }
  verify(actor, caseId, input) {
    object(input, ['rationale', 'evidence_event_ids'], 'incident_verification'); this.human(actor);
    const c = this.s.require('SELECT * FROM cases WHERE id=?', [caseId]), alerts = JSON.parse(c.alert_ids);
    fail(LEVELS.indexOf(this.levelOfCase(caseId)) < 2, 409, 'case_already_verified');
    fail(this.s.get(`SELECT COUNT(*) n FROM alert_dispositions WHERE disposition='true-positive' AND alert_id IN (SELECT value FROM json_each(?))`, JSON.stringify(alerts)).n > 0, 409, 'verification_requires_true_positive_alert');
    fail(Array.isArray(input.evidence_event_ids) && input.evidence_event_ids.length >= 1 && input.evidence_event_ids.length <= 100, 400, 'verification_requires_evidence_events');
    const linked = new Set(alerts.flatMap(a => JSON.parse(this.s.get('SELECT evidence_ids FROM alerts WHERE id=?', a)?.evidence_ids || '[]')));
    fail(input.evidence_event_ids.every(e => linked.has(e)), 400, 'verification_evidence_must_belong_to_case_alerts');
    const at = this.now(), rationale = text(input.rationale, 'verification_rationale', 2000);
    this.s.transaction(() => { this.s.run("INSERT INTO case_confidence(case_id,level,verified_by,verified_at,verification_rationale,evidence_event_ids) VALUES (?,'verified-security-incident',?,?,?,?) ON CONFLICT(case_id) DO UPDATE SET level='verified-security-incident',verified_by=excluded.verified_by,verified_at=excluded.verified_at,verification_rationale=excluded.verification_rationale,evidence_event_ids=excluded.evidence_event_ids", caseId, actor, at, rationale, JSON.stringify(input.evidence_event_ids));
      this.s.audit(actor, 'incident.verified', caseId, { evidence_events: input.evidence_event_ids.length }, at); });
    return this.view().cases.find(x => x.id === caseId);
  }
  confirm(actor, caseId, input) {
    object(input, ['compromise_type', 'evidence_refs', 'rationale'], 'compromise_confirmation'); const u = this.human(actor); fail(u.role === 'admin', 403, 'compromise_confirmation_requires_admin');
    const r = this.record(caseId); fail(r?.level === 'verified-security-incident', 409, 'compromise_requires_verified_incident'); fail(r.verified_by !== actor, 409, 'compromise_needs_second_person');
    fail(Array.isArray(input.evidence_refs) && input.evidence_refs.length >= 1 && input.evidence_refs.length <= 50, 400, 'compromise_requires_forensic_evidence');
    const type = choice(input.compromise_type, COMPROMISE_TYPES, 'compromise_type'), refs = input.evidence_refs.map((x, i) => text(String(x), `compromise_evidence_${i}`, 300)), at = this.now();
    this.s.transaction(() => { this.s.run("UPDATE case_confidence SET level='confirmed-compromise',compromise_type=?,compromise_evidence_refs=?,confirmation_rationale=?,confirmed_by=?,confirmed_at=? WHERE case_id=?", type, JSON.stringify(refs), text(input.rationale, 'confirmation_rationale', 2000), actor, at, caseId);
      this.s.audit(actor, 'incident.compromise_confirmed', caseId, { compromise_type: type, evidence_refs: refs.length }, at); });
    return this.view().cases.find(x => x.id === caseId);
  }
  downgrade(actor, caseId, input) {
    object(input, ['level', 'reason'], 'confidence_downgrade'); const u = this.human(actor); fail(u.role === 'admin', 403, 'confidence_downgrade_requires_admin');
    const cur = this.levelOfCase(caseId), to = choice(input.level, ['suspicious-indicator', 'verified-security-incident'], 'confidence_level'); fail(LEVELS.indexOf(to) < LEVELS.indexOf(cur), 409, 'confidence_can_only_go_down_here');
    const at = this.now(), reason = text(input.reason, 'downgrade_reason', 1000);
    this.s.transaction(() => { if (to === 'suspicious-indicator') this.s.run('DELETE FROM case_confidence WHERE case_id=?', caseId); else this.s.run("UPDATE case_confidence SET level=?,compromise_type=NULL,compromise_evidence_refs=NULL,confirmation_rationale=NULL,confirmed_by=NULL,confirmed_at=NULL WHERE case_id=?", to, caseId);
      this.s.audit(actor, 'incident.confidence_downgraded', caseId, { from: cur, to, reason }, at); });
    return this.view().cases.find(x => x.id === caseId);
  }
  view() {
    const cases = this.s.all('SELECT id,title,status,alert_ids,created_at FROM cases ORDER BY updated_at DESC LIMIT 500').map(c => { const r = this.record(c.id);
      return { id: c.id, title: c.title, status: c.status, alerts: JSON.parse(c.alert_ids).length, level: r?.level || 'suspicious-indicator', verified_by: r?.verified_by || null, verified_at: r?.verified_at || null, verification_rationale: r?.verification_rationale || null, evidence_events: r?.evidence_event_ids.length || 0, compromise_type: r?.compromise_type || null, confirmed_by: r?.confirmed_by || null, confirmed_at: r?.confirmed_at || null, compromise_evidence_refs: r?.compromise_evidence_refs || [] }; });
    const counts = { 'observed-event': this.s.get('SELECT COUNT(*) n FROM events').n, 'suspicious-indicator': this.s.get("SELECT COUNT(*) n FROM alerts WHERE status!='resolved'").n, 'verified-security-incident': cases.filter(c => c.level === 'verified-security-incident').length, 'confirmed-compromise': cases.filter(c => c.level === 'confirmed-compromise').length };
    return { levels: LEVELS.map(l => ({ id: l, ...LEVEL_TEXT[l], count: counts[l] })), cases, compromise_types: COMPROMISE_TYPES,
      claim: 'Observed events, suspicious indicators, verified security incidents and confirmed compromises are kept apart. Only people move a case up: an analyst verifies it with a true-positive alert and the proving events; a different administrator with MFA confirms a compromise type with forensic evidence. AI analysis carries the level and never states certainty that a person has not confirmed.',
      claim_ar: 'تُفصل الأحداث المرصودة والمؤشرات المريبة والحوادث الأمنية المتحقق منها والاختراقات المؤكدة. ولا يرفع مستوى القضية إلا البشر: يتحقق منها محلل بتنبيه إيجابي صحيح وبالأحداث التي تثبتها، ويؤكد مسؤول آخر مع MFA نوع الاختراق بأدلة جنائية. ويحمل تحليل الذكاء الاصطناعي المستوى، ولا يصرّح بيقين لم يؤكده شخص.' };
  }
}
