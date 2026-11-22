// CG-116 Hunt workbench. Time-bounded, declarative hunts over stored evidence (no free-form SQL): accounts, processes,
// connections, movement between hosts and changes. Hunts are saved with their query, notes keep the analyst reasoning
// with references to the rows they discuss, and a report freezes the result (with its SHA-256) and the notes.
import { randomUUID } from 'node:crypto';
import { fail, text, choice, timestamp, digest } from './common.js';

export const ENTITIES = ['account', 'process', 'connection', 'movement', 'change'];
const ADMIN_PORTS = new Set([22, 135, 445, 3389, 5985, 5986]);
const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fc|fd|fe80)/i;
const KINDS = {
  account: ['auth.failed', 'identity.signin_activity', 'log.batch', 'remote.attempt', 'remote.authenticated', 'remote.active'],
  process: ['endpoint.process_causality'],
  connection: ['log.batch', 'endpoint.process_causality'],
  movement: ['log.batch', 'remote.attempt', 'remote.authenticated', 'remote.active', 'remote.ended'],
  change: ['change.sensitive', 'network.device_config', 'firewall.ruleset', 'identity.idp_change', 'linux.security_posture', 'endpoint.process_causality', 'email.forwarding_change'],
};

export function validateSpec(input, now = Date.now()) {
  const entity = choice(input?.entity, ENTITIES, 'hunt_entity'), from = timestamp(input.from, 'hunt_from', now), to = timestamp(input.to, 'hunt_to', now);
  fail(from < to && Date.parse(to) - Date.parse(from) <= 90 * 86400000, 400, 'hunt_window_must_be_positive_and_at_most_90_days');
  const f = input.filters || {}, opt = (k, max = 200) => (f[k] === undefined || f[k] === null || f[k] === '' ? null : text(String(f[k]), `hunt_filter_${k}`, max));
  const filters = { account: opt('account'), host: opt('host'), ip: opt('ip', 64), port: f.port === undefined || f.port === null || f.port === '' ? null : Number(f.port), process: opt('process'), contains: opt('contains') };
  fail(filters.port === null || (Number.isInteger(filters.port) && filters.port >= 0 && filters.port <= 65535), 400, 'invalid_hunt_filter_port');
  for (const k of Object.keys(f)) fail(k in filters, 400, `unknown_hunt_filter_${k}`);
  return { entity, from, to, filters, limit: Math.min(Math.max(Number(input.limit) || 500, 1), 5000) };
}
const has = (v, needle) => !needle || String(v ?? '').toLowerCase().includes(needle.toLowerCase());
function rowsFor(entity, ev) {
  const d = ev.details, host = ev.hostname, base = (time, summary, extra = {}) => ({ time, host, asset_id: ev.asset_id, event_id: ev.id, kind: ev.kind, summary, ...extra });
  const out = [];
  if (entity === 'account') {
    if (ev.kind === 'auth.failed') out.push(base(ev.observed_at, `failed ${d.protocol || 'logon'} for ${d.account} from ${d.source_ip || '?'}`, { account: d.account, ip: d.source_ip, outcome: 'failure' }));
    if (ev.kind === 'identity.signin_activity') for (const s of d.signins) out.push(base(s.at, `${s.result} sign-in for ${s.principal_ref} from ${s.source_ip || '?'}${s.country ? ` (${s.country})` : ''}`, { account: s.principal_ref, ip: s.source_ip, outcome: s.result }));
    if (ev.kind === 'log.batch') for (const r of d.records.filter(r => r.user)) out.push(base(r.time || ev.observed_at, `${r.category} ${r.action || ''} ${r.outcome || ''} for ${r.user} from ${r.src_ip || '?'}`.replace(/\s+/g, ' '), { account: r.user, ip: r.src_ip, outcome: r.outcome }));
    if (ev.kind.startsWith('remote.') && d.target_b?.account) out.push(base(ev.observed_at, `${ev.kind.slice(7)} ${d.protocol} as ${d.target_b.account} from ${d.source_a?.ip || '?'}`, { account: d.target_b.account, ip: d.source_a?.ip }));
  } else if (entity === 'process' && ev.kind === 'endpoint.process_causality') {
    for (const p of d.processes) out.push(base(p.started_at || ev.observed_at, `${p.image_path} ${p.command_line || ''}`.trim().slice(0, 400), { process: p.image_path, command: p.command_line, account: p.user_ref, signer: p.signer?.status, parent: p.parent_process_id }));
  } else if (entity === 'connection') {
    if (ev.kind === 'log.batch') for (const r of d.records.filter(r => r.src_ip || r.dst_ip)) out.push(base(r.time || ev.observed_at, `${r.category} ${r.src_ip || '?'} → ${r.dst_ip || r.query || '?'}${r.dst_port ? `:${r.dst_port}` : ''} ${r.action || ''}`.trim(), { ip: r.src_ip, dst_ip: r.dst_ip, port: r.dst_port, bytes: r.bytes, query: r.query }));
    if (ev.kind === 'endpoint.process_causality') for (const c of d.connections || []) { const p = d.processes.find(x => x.process_id === c.process_id); out.push(base(c.occurred_at || ev.observed_at, `${p?.image_path || c.process_id} ${c.direction} ${c.remote_address}:${c.remote_port}`, { process: p?.image_path, dst_ip: c.remote_address, port: c.remote_port })); }
  } else if (entity === 'movement') {
    if (ev.kind === 'log.batch') for (const r of d.records.filter(r => r.src_ip && r.dst_ip && PRIVATE.test(r.src_ip) && PRIVATE.test(r.dst_ip) && ADMIN_PORTS.has(r.dst_port))) out.push(base(r.time || ev.observed_at, `${r.src_ip} → ${r.dst_ip}:${r.dst_port}`, { ip: r.src_ip, dst_ip: r.dst_ip, port: r.dst_port }));
    if (ev.kind.startsWith('remote.')) out.push(base(ev.observed_at, `${ev.kind.slice(7)} ${d.protocol} ${d.source_a?.ip || '?'} → ${d.target_b?.ip || host}`, { ip: d.source_a?.ip, dst_ip: d.target_b?.ip, account: d.target_b?.account }));
  } else if (entity === 'change') {
    if (ev.kind === 'change.sensitive') out.push(base(d.detected_at || ev.observed_at, `${d.category} ${d.action}: ${d.object_ref}`, { account: d.actor_ref, change: d.category }));
    if (ev.kind === 'network.device_config') out.push(base(ev.observed_at, `device configuration snapshot ${d.snapshot_id} for ${d.device_ref} (firmware ${d.firmware_version})`, { change: 'device-config' }));
    if (ev.kind === 'firewall.ruleset') out.push(base(ev.observed_at, `firewall ruleset ${d.ruleset_id} on ${d.device_ref}: ${d.rules.length} rules`, { change: 'firewall' }));
    if (ev.kind === 'identity.idp_change') out.push(base(ev.observed_at, `identity provider change ${d.change_type || d.operation || ''}`.trim(), { change: 'idp', account: d.actor_ref }));
    if (ev.kind === 'linux.security_posture') for (const c of d.changes || []) out.push(base(ev.observed_at, `linux ${c.type || c.kind || 'change'}: ${c.path || c.name || ''}`.trim(), { change: 'linux' }));
    if (ev.kind === 'endpoint.process_causality') for (const c of [...d.service_changes.map(x => ({ ...x, what: `service ${x.service_name}` })), ...d.scheduled_task_changes.map(x => ({ ...x, what: `task ${x.task_name}` }))]) out.push(base(c.occurred_at || ev.observed_at, `${c.what} ${c.action}`, { change: 'persistence', process: d.processes.find(p => p.process_id === c.process_id)?.image_path }));
    if (ev.kind === 'email.forwarding_change') for (const c of d.changes) out.push(base(c.time || ev.observed_at, `${c.operation} by ${c.user} to ${c.external_domains.join(', ')}`, { account: c.user, change: 'mail-forwarding' }));
  }
  return out;
}

export class HuntWorkbench {
  constructor(store, { clock }) { Object.assign(this, { s: store, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  run(input) {
    const spec = validateSpec(input, this.clock()), f = spec.filters, kinds = KINDS[spec.entity], pad = 86400000;
    // Events are selected by observation time with a day of margin (records inside a batch carry their own time), then each row is filtered by its own time.
    const events = this.s.all(`SELECT e.id,e.kind,e.asset_id,e.observed_at,e.payload,a.hostname FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.kind IN (${kinds.map(() => '?').join(',')}) AND e.observed_at BETWEEN ? AND ? ORDER BY e.observed_at LIMIT 20000`, ...kinds, new Date(Date.parse(spec.from) - pad).toISOString(), new Date(Date.parse(spec.to) + pad).toISOString());
    let rows = events.flatMap(r => rowsFor(spec.entity, { ...r, details: JSON.parse(r.payload).details }))
      .filter(r => r.time >= spec.from && r.time <= spec.to && has(r.account, f.account) && has(r.host, f.host) && (!f.ip || r.ip === f.ip || r.dst_ip === f.ip) && (f.port === null || r.port === f.port) && has(r.process, f.process) && has(r.summary, f.contains))
      .sort((a, b) => a.time.localeCompare(b.time));
    const total = rows.length; rows = rows.slice(0, spec.limit);
    const buckets = new Map(); for (const r of rows) { const k = r.time.slice(0, 13) + ':00:00.000Z'; buckets.set(k, (buckets.get(k) || 0) + 1); }
    const top = key => [...rows.reduce((m, r) => (r[key] ? m.set(r[key], (m.get(r[key]) || 0) + 1) : m), new Map())].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([value, count]) => ({ value, count }));
    return { spec, total, truncated: total > rows.length, rows, timeline: [...buckets].map(([hour, count]) => ({ hour, count })), top: { host: top('host'), account: top('account'), ip: top('ip'), dst_ip: top('dst_ip') }, result_sha256: digest(rows.map(r => [r.time, r.event_id, r.summary])) };
  }
  save(actor, input) {
    const name = text(input.name, 'hunt_name', 200), hypothesis = text(input.hypothesis, 'hunt_hypothesis', 1000, true), spec = validateSpec(input.query, this.clock()), id = randomUUID(), at = this.now();
    this.s.run('INSERT INTO hunts(id,name,hypothesis,query,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?)', id, name, hypothesis, JSON.stringify(spec), actor, at, at);
    this.s.audit(actor, 'hunt.saved', id, { name, entity: spec.entity }, at); return this.get(id);
  }
  get(id) {
    const h = this.s.get('SELECT * FROM hunts WHERE id=?', id); fail(h, 404, 'hunt_not_found');
    return { ...h, query: JSON.parse(h.query), notes: this.s.all('SELECT id,at,actor,text,event_refs FROM hunt_notes WHERE hunt_id=? ORDER BY at', id).map(n => ({ ...n, event_refs: JSON.parse(n.event_refs) })), reports: this.s.all('SELECT id,at,actor,result_sha256,rows_total FROM hunt_reports WHERE hunt_id=? ORDER BY at DESC', id) };
  }
  list() { return this.s.all('SELECT h.*,(SELECT COUNT(*) FROM hunt_notes n WHERE n.hunt_id=h.id) notes,(SELECT COUNT(*) FROM hunt_reports r WHERE r.hunt_id=h.id) reports FROM hunts h ORDER BY updated_at DESC LIMIT 200').map(h => ({ ...h, query: JSON.parse(h.query) })); }
  note(actor, id, input) {
    this.get(id); const t = text(input.text, 'hunt_note', 4000), refs = Array.isArray(input.event_refs) ? input.event_refs.slice(0, 50).map(r => text(r, 'hunt_note_event_ref', 64)) : [];
    for (const r of refs) fail(this.s.get('SELECT id FROM events WHERE id=?', r), 400, 'hunt_note_references_unknown_event');
    const at = this.now(); this.s.run('INSERT INTO hunt_notes(id,hunt_id,at,actor,text,event_refs) VALUES (?,?,?,?,?,?)', randomUUID(), id, at, actor, t, JSON.stringify(refs)); this.s.run('UPDATE hunts SET updated_at=? WHERE id=?', at, id);
    this.s.audit(actor, 'hunt.note', id, { event_refs: refs.length }, at); return this.get(id);
  }
  report(actor, id, { conclusion } = {}) {
    const h = this.get(id), result = this.run(h.query), at = this.now(), c = text(conclusion, 'hunt_conclusion', 4000, true);
    const report = { schema_version: 'cg.hunt-report/1', generated_at: at, generated_by: actor, hunt: { id: h.id, name: h.name, hypothesis: h.hypothesis, query: h.query }, conclusion: c, result: { total: result.total, truncated: result.truncated, result_sha256: result.result_sha256, timeline: result.timeline, top: result.top, rows: result.rows.slice(0, 500) }, notes: h.notes };
    const rid = randomUUID(); this.s.run('INSERT INTO hunt_reports(id,hunt_id,at,actor,result_sha256,rows_total,report) VALUES (?,?,?,?,?,?,?)', rid, id, at, actor, result.result_sha256, result.total, JSON.stringify(report));
    this.s.run('UPDATE hunts SET updated_at=? WHERE id=?', at, id); this.s.audit(actor, 'hunt.report', id, { report_id: rid, result_sha256: result.result_sha256 }, at); return { report_id: rid, ...report };
  }
  getReport(rid) { const r = this.s.get('SELECT report FROM hunt_reports WHERE id=?', rid); fail(r, 404, 'hunt_report_not_found'); return JSON.parse(r.report); }
}
