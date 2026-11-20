// CG-093 Detonation in an isolated lab, never automatic. CyberGuard does not execute files. It governs jobs for an
// external sandbox (for example CAPE on a separate Linux host) registered by an administrator with recent MFA:
// - a job names a quarantined file by SHA-256 (CG-092) and is requested by a person, then approved by a different
//   administrator with recent MFA; no rule, hypothesis or AI path can create one;
// - the sandbox fetches jobs with its own source token only while its latest isolation self-check (no internet, no
//   production reach) is passing and at most 24 hours old;
// - the behavioural report must match the job hash; any network attempt that was not blocked suspends the sandbox and
//   raises a critical alert.
import { fail, object, text, choice } from './common.js';

const MAX_ISOLATION_AGE = 24 * 3600000;
export class Sandbox {
  constructor(store, { clock, domain }) { Object.assign(this, { s: store, clock: clock || (() => Date.now()), domain }); }
  now() { return new Date(this.clock()).toISOString(); }
  sandbox(id) { const r = this.s.get('SELECT * FROM sandboxes WHERE id=?', id); fail(r, 404, 'sandbox_not_found'); return { ...r, last_isolation: r.last_isolation ? JSON.parse(r.last_isolation) : null }; }
  isolationState(sb) { const c = sb.last_isolation; if (sb.status !== 'active') return sb.status; if (!c) return 'no-isolation-check'; if (!c.passed) return 'isolation-failed'; return this.clock() - Date.parse(c.checked_at) > MAX_ISOLATION_AGE ? 'isolation-check-stale' : 'isolated'; }
  register(actor, input) {
    object(input, ['name', 'source_id', 'isolation_ref', 'egress'], 'sandbox');
    const src = this.s.get('SELECT id,kind,revoked FROM sources WHERE id=?', text(input.source_id, 'sandbox_source_id', 40)); fail(src && src.kind === 'sandbox-connector' && !src.revoked, 400, 'sandbox_requires_sandbox_connector_source');
    const id = `sbx-${Date.parse(this.now()).toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
    this.s.transaction(() => { this.s.run("INSERT INTO sandboxes(id,name,source_id,isolation_ref,egress,registered_by,registered_at,status) VALUES (?,?,?,?,?,?,?,'active')", id, text(input.name, 'sandbox_name', 100), src.id, text(input.isolation_ref, 'sandbox_isolation_ref', 300), choice(input.egress, ['none', 'simulated-internet'], 'sandbox_egress'), actor, this.now()); this.s.audit(actor, 'sandbox.registered', id, { source_id: src.id }, this.now()); });
    return this.sandbox(id);
  }
  bySource(sourceId) { const r = this.s.get("SELECT id FROM sandboxes WHERE source_id=? AND status!='retired'", sourceId); fail(r, 403, 'source_is_not_a_registered_sandbox'); return this.sandbox(r.id); }
  suspend(sb, reason, detail) {
    this.s.run("UPDATE sandboxes SET status='suspended' WHERE id=?", sb.id); this.s.run("UPDATE detonation_jobs SET status='expired' WHERE sandbox_id=? AND status IN ('approved','running')", sb.id);
    this.s.audit(`source:${sb.source_id}`, 'sandbox.suspended', sb.id, { reason }, this.now());
    this.domain.alert({ key: `CG-SANDBOX-ISOLATION-093:${sb.id}:${this.now().slice(0, 13)}`, sourceId: sb.source_id, rule: 'CG-SANDBOX-ISOLATION-093', severity: 'critical', title: `Sandbox isolation broken; sandbox suspended / كُسر عزل بيئة التفجير وأُوقفت: ${sb.name} (${detail})` });
  }
  isolationCheck(sourceId, input) {
    object(input, ['checked_at', 'internet_reachable', 'production_reachable', 'evidence_ref', 'probes'], 'sandbox_isolation');
    const sb = this.bySource(sourceId); fail(typeof input.internet_reachable === 'boolean' && typeof input.production_reachable === 'boolean', 400, 'invalid_sandbox_isolation_flags');
    const at = new Date(Date.parse(input.checked_at)); fail(!Number.isNaN(at.getTime()) && at.getTime() <= this.clock() + 300000, 400, 'invalid_sandbox_checked_at');
    const probes = Array.isArray(input.probes) ? input.probes.slice(0, 20).map((p, i) => { object(p, ['target', 'reachable'], `sandbox_probe_${i}`); return { target: text(p.target, `sandbox_probe_target_${i}`, 200), reachable: p.reachable === true }; }) : [];
    const check = { checked_at: at.toISOString(), internet_reachable: input.internet_reachable, production_reachable: input.production_reachable, evidence_ref: text(input.evidence_ref, 'sandbox_isolation_evidence', 300), probes, passed: !input.internet_reachable && !input.production_reachable && probes.every(p => !p.reachable) };
    this.s.run('UPDATE sandboxes SET last_isolation=? WHERE id=?', JSON.stringify(check), sb.id); this.s.audit(`source:${sourceId}`, 'sandbox.isolation_checked', sb.id, { passed: check.passed }, this.now());
    if (!check.passed && sb.status === 'active') this.suspend(sb, 'isolation self-check failed', input.production_reachable ? 'production reachable' : 'internet reachable');
    return { sandbox_id: sb.id, ...check, state: this.isolationState(this.sandbox(sb.id)) };
  }
  request(actor, input) {
    object(input, ['sandbox_id', 'sha256', 'reason'], 'detonation');
    const sb = this.sandbox(text(input.sandbox_id, 'sandbox_id', 40)); fail(sb.status === 'active', 409, 'sandbox_not_active');
    const sha256 = String(input.sha256 || '').toLowerCase(); fail(/^[a-f0-9]{64}$/.test(sha256), 400, 'invalid_detonation_sha256');
    const ev = this.s.all("SELECT payload FROM events WHERE kind='file.triage' ORDER BY observed_at DESC").map(r => JSON.parse(r.payload).details).find(d => d.sha256 === sha256 && d.quarantine.state === 'quarantined');
    fail(ev, 409, 'detonation_requires_quarantined_file');
    const r = this.s.transaction(() => { const res = this.s.run("INSERT INTO detonation_jobs(sandbox_id,sha256,file_name,custody_id,reason,requested_by,requested_at,status) VALUES (?,?,?,?,?,?,?,'pending-approval')", sb.id, sha256, ev.name, ev.quarantine.custody_id, text(input.reason, 'detonation_reason', 1000), actor, this.now()); this.s.audit(actor, 'detonation.requested', String(res.lastInsertRowid), { sandbox_id: sb.id, sha256 }, this.now()); return Number(res.lastInsertRowid); });
    return this.job(r);
  }
  job(id) { const r = this.s.get('SELECT * FROM detonation_jobs WHERE id=?', id); fail(r, 404, 'not_found'); return { ...r, report: r.report_json ? JSON.parse(r.report_json) : null, report_json: undefined }; }
  decide(actor, id, decision) {
    choice(decision, ['approve', 'reject'], 'detonation_decision'); const j = this.job(id); fail(j.status === 'pending-approval', 409, 'detonation_not_pending'); fail(j.requested_by !== actor, 403, 'independent_detonation_approver_required');
    this.s.transaction(() => { this.s.run('UPDATE detonation_jobs SET status=?,approved_by=?,approved_at=? WHERE id=?', decision === 'approve' ? 'approved' : 'rejected', actor, this.now(), id); this.s.audit(actor, `detonation.${decision === 'approve' ? 'approved' : 'rejected'}`, String(id), { sha256: j.sha256 }, this.now()); });
    return this.job(id);
  }
  jobsFor(sourceId) {
    const sb = this.bySource(sourceId), state = this.isolationState(sb);
    if (state !== 'isolated') return { items: [], isolation_state: state, claim: 'Jobs are released only while the latest isolation self-check passed within 24 hours.' };
    const items = this.s.all("SELECT * FROM detonation_jobs WHERE sandbox_id=? AND status='approved' ORDER BY id", sb.id);
    for (const j of items) this.s.run("UPDATE detonation_jobs SET status='running',started_at=? WHERE id=?", this.now(), j.id);
    return { items: items.map(j => ({ job_id: j.id, sha256: j.sha256, file_name: j.file_name, custody_id: j.custody_id })), isolation_state: state, claim: 'Only the hash and custody reference are released; the file comes from quarantine through the lab custody procedure.' };
  }
  report(sourceId, id, input) {
    object(input, ['sha256', 'verdict', 'duration_seconds', 'processes', 'network_attempts', 'files_written', 'registry_changes', 'signatures', 'evidence_ref'], 'detonation_report');
    const sb = this.bySource(sourceId), j = this.job(id); fail(j.sandbox_id === sb.id && j.status === 'running', 409, 'detonation_job_not_running'); fail(String(input.sha256).toLowerCase() === j.sha256, 409, 'detonation_report_hash_mismatch');
    const list = (v, n, max, fn) => { fail(Array.isArray(v) && v.length <= max, 400, `invalid_detonation_${n}`); return v.map(fn); };
    const rep = { verdict: choice(input.verdict, ['malicious', 'suspicious', 'clean', 'inconclusive'], 'detonation_verdict'), duration_seconds: Number.isInteger(input.duration_seconds) && input.duration_seconds >= 0 && input.duration_seconds <= 86400 ? input.duration_seconds : fail(false, 400, 'invalid_detonation_duration'),
      processes: list(input.processes, 'processes', 500, (p, i) => text(p, `detonation_process_${i}`, 300)), network_attempts: list(input.network_attempts, 'network', 500, (a, i) => { object(a, ['destination', 'port', 'blocked'], `detonation_net_${i}`); fail(typeof a.blocked === 'boolean', 400, `invalid_detonation_net_blocked_${i}`); return { destination: text(a.destination, `detonation_dest_${i}`, 253), port: Number.isInteger(a.port) ? a.port : null, blocked: a.blocked }; }),
      files_written: list(input.files_written, 'files', 500, (f, i) => text(f, `detonation_file_${i}`, 400)), registry_changes: list(input.registry_changes || [], 'registry', 500, (f, i) => text(f, `detonation_registry_${i}`, 400)), signatures: list(input.signatures || [], 'signatures', 200, (f, i) => text(f, `detonation_signature_${i}`, 200)), evidence_ref: text(input.evidence_ref, 'detonation_evidence_ref', 300) };
    const leaked = rep.network_attempts.filter(a => !a.blocked);
    this.s.transaction(() => { this.s.run("UPDATE detonation_jobs SET status='completed',completed_at=?,report_json=? WHERE id=?", this.now(), JSON.stringify(rep), id); this.s.audit(`source:${sourceId}`, 'detonation.reported', String(id), { verdict: rep.verdict, network_attempts: rep.network_attempts.length, unblocked: leaked.length }, this.now()); });
    if (leaked.length) this.suspend(sb, 'unblocked network attempt during detonation', leaked.map(a => a.destination).slice(0, 3).join(', '));
    if (['malicious', 'suspicious'].includes(rep.verdict)) this.domain.alert({ key: `CG-SANDBOX-VERDICT-093:${j.sha256}`, sourceId, rule: 'CG-SANDBOX-VERDICT-093', severity: rep.verdict === 'malicious' ? 'high' : 'medium', title: `Isolated detonation verdict ${rep.verdict}: ${j.file_name} / نتيجة التفجير المعزول: ${rep.verdict === 'malicious' ? 'خبيث' : 'مشبوه'} ${j.file_name}` });
    return this.job(id);
  }
  overview() {
    const sandboxes = this.s.all('SELECT * FROM sandboxes ORDER BY registered_at DESC').map(r => { const sb = { ...r, last_isolation: r.last_isolation ? JSON.parse(r.last_isolation) : null }; return { ...sb, isolation_state: this.isolationState(sb) }; });
    return { sandboxes, jobs: this.s.all('SELECT * FROM detonation_jobs ORDER BY id DESC LIMIT 200').map(r => ({ ...r, report: r.report_json ? JSON.parse(r.report_json) : null, report_json: undefined })), enabled: sandboxes.some(s => s.status === 'active'),
      claim: 'Detonation runs only in a separate, registered sandbox, never on CyberGuard or production hosts and never automatically: each job is requested by a person for a quarantined file and approved by a different administrator with recent MFA; the sandbox receives jobs only while its isolation self-check passed within 24 hours, and any unblocked network attempt suspends it.',
      claim_ar: 'لا يتم التفجير إلا في بيئة معزولة منفصلة ومسجلة، لا على CyberGuard ولا على أجهزة الإنتاج، ولا تلقائيًا أبدًا: كل مهمة يطلبها شخص لملف معزول ويعتمدها مسؤول آخر بتحقق MFA حديث؛ ولا تستلم البيئة المهام إلا إذا نجح فحص العزل الذاتي خلال 24 ساعة، وأي محاولة اتصال غير محظورة توقفها فورًا.' };
  }
}
