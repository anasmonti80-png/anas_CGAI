// CG-173 Evidence-backed action ledger. One entry per response command joins what is otherwise spread across tables:
// who requested, approved and executed it and why; the ticket or authorization reference; the trigger (an AI proposal or
// playbook run on an alert, or a manual request) and the evidence events behind it with their hashes; the preflight
// (dry-run hash, before state, management and service preflights); the connector's API result; the independent outcome
// verification (CG-118); and any rollback. Every string passes through the secret redactor and an extra password scan,
// so no password, token or key reaches the ledger. Entries are hash-chained in request order, and the export can be
// verified offline: changing any entry breaks the chain from that point.
import { createHash } from 'node:crypto';
import { redact } from './common.js';
import { ControlOutcomes } from './control-outcome.js';

const parse = s => { try { return JSON.parse(s); } catch { return null; } };
const sha = v => createHash('sha256').update(typeof v === 'string' ? v : JSON.stringify(v)).digest('hex');
const EXTRA = /\b(pass(word)?|passwd|pwd|passphrase|pin)\b\s*(is|:|=)\s*\S+/gi;
export function scrub(v) {
  const r = redact(v);
  return typeof r === 'string' ? r.replace(EXTRA, (m, k) => `${k}=[REDACTED]`) : Array.isArray(r) ? r.map(scrub) : r && typeof r === 'object' ? Object.fromEntries(Object.entries(r).map(([k, x]) => [k, scrub(x)])) : r;
}

export function ledger(store, domain, { clock } = {}) {
  const co = new ControlOutcomes(store, { domain, clock }), user = id => id ? store.get('SELECT username FROM users WHERE id=?', id)?.username || id : null;
  // Connectors act as "source:<id>"; show the connector name instead of the id.
  const party = id => !id ? null : id.startsWith('source:') ? `connector ${store.get('SELECT name FROM sources WHERE id=?', id.slice(7))?.name || id.slice(7)}` : user(id);
  const entries = []; let prev = '0'.repeat(64);
  for (const a of store.all('SELECT * FROM actions ORDER BY requested_at,id')) {
    const job = store.get('SELECT * FROM response_jobs WHERE action_id=?', a.id), req = job ? parse(job.request_json) : null, done = job?.completion_json ? parse(job.completion_json) : null;
    const audit = store.all("SELECT seq,at,actor,action,hash FROM audit WHERE target=? AND action LIKE 'action.%' ORDER BY seq", a.id);
    const ai = store.get('SELECT id,alert_id,origin,rationale FROM ai_action_proposals WHERE action_id=?', a.id), alert = ai ? store.get('SELECT id,rule_id,title,evidence_ids FROM alerts WHERE id=?', ai.alert_id) : null;
    const evidence = alert ? JSON.parse(alert.evidence_ids).map(id => store.get('SELECT id,kind,observed_at,sanitized_sha256 FROM events WHERE id=?', id)).filter(Boolean) : [];
    const safety = store.get('SELECT approved_by,approved_at,recovery_plan_hash FROM action_safety_approvals WHERE action_id=?', a.id), outcome = co.outcome(a.id), before = parse(a.before_value);
    const actor = name => audit.find(x => x.action === name)?.actor || null;
    const entry = scrub({
      action_id: a.id, type: a.type, asset_id: a.asset_id, status: a.status,
      who: { requested_by: user(a.requested_by), approved_by: user(a.approved_by), safety_approved_by: user(safety?.approved_by), dispatched_by: user(actor('action.dispatched')), executed_by: party(actor('action.executed')) },
      why: { reason: a.reason, trigger: ai ? { kind: 'ai-proposal', proposal_id: ai.id, origin: ai.origin, rationale: ai.rationale } : { kind: 'manual-request' }, alert: alert ? { id: alert.id, rule_id: alert.rule_id, title: alert.title } : null },
      ticket: req?.authorization_ref || null, change_id: a.change_id || null, provider_request_id: job?.provider_request_id || null, restore_method: a.restore_method || null, supersedes: a.supersedes || null,
      evidence: evidence.map(e => ({ event_id: e.id, kind: e.kind, observed_at: e.observed_at, sha256: e.sanitized_sha256 })),
      preflight: { dry_run_hash: a.preflight_hash, before, recovery_plan_hash: safety?.recovery_plan_hash || null },
      api: job ? { connector_id: job.connector_id, request_sha256: sha(job.request_json), status: job.status, phase: job.phase, queued_at: job.queued_at, completed_at: job.completed_at, result: done } : null,
      outcome: outcome ? { state: outcome.state, expected_state: outcome.expected_state, rollback: outcome.rollback } : null,
      rollback: audit.filter(x => /^action\.rollback/.test(x.action)).map(x => ({ at: x.at, action: x.action, actor: x.actor })),
      timeline: audit.map(x => ({ seq: x.seq, at: x.at, action: x.action, actor: x.actor, audit_hash: x.hash })),
    });
    const entry_sha256 = sha(prev + JSON.stringify(entry)); entries.push({ ...entry, previous_sha256: prev, entry_sha256 }); prev = entry_sha256;
  }
  return { schema_version: 'cg.action-ledger/1', entries, head_sha256: prev, generated_at: new Date((clock || Date.now)()).toISOString(),
    claim: 'Every response command is one ledger entry: who requested, approved and executed it and why, the ticket, the alert and evidence behind it, the preflight, the API result, the independent outcome and any rollback. Secrets and passwords are redacted, and entries are hash-chained so a changed entry is detected.',
    claim_ar: 'كل أمر استجابة قيد واحد في السجل: من طلبه واعتمده ونفذه ولماذا، والتذكرة، والتنبيه والأدلة التي استند إليها، والفحص المسبق، ونتيجة الواجهة البرمجية، والتحقق المستقل، وأي تراجع. وتُحجب الأسرار وكلمات المرور، وتتسلسل القيود ببصماتها فيُكتشف أي قيد معدّل.' };
}

export function verifyLedger(doc) {
  let prev = '0'.repeat(64);
  for (const [i, e] of doc.entries.entries()) { const { previous_sha256, entry_sha256, ...body } = e; if (previous_sha256 !== prev || sha(prev + JSON.stringify(body)) !== entry_sha256) return { valid: false, broken_at: i }; prev = entry_sha256; }
  return { valid: prev === doc.head_sha256, broken_at: prev === doc.head_sha256 ? null : doc.entries.length };
}
