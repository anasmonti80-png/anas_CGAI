// CG-118 Control outcome verification. A connector saying "done" is not proof. For every response action this module
// states whether the control was independently verified (an outcome check from a source other than the executing
// connector, or the absence of traffic the control should stop), how long it has been in force, and any failure,
// contradiction or failed rollback, shown as such rather than folded into a generic status.
export const EXPECTED = {
  'network.block-ip': 'blocked', 'network.block-port': 'blocked', 'endpoint.block-app': 'blocked', 'dns.block-domain': 'sinkholed', 'endpoint.quarantine-file': 'quarantined',
  'endpoint.isolate-device': 'isolated', 'network.switch-port-admin-down': 'isolated', 'network.nac-quarantine-endpoint': 'quarantined',
  'endpoint.stop-service': 'stopped', 'endpoint.disable-service': 'stopped', 'endpoint.shutdown-host': 'powered-off',
  'network.allow-ip': 'reachable', 'network.allow-port': 'reachable', 'endpoint.allow-app': 'running', 'dns.allow-domain': 'resolving', 'endpoint.reconnect-device': 'connected', 'network.switch-port-admin-up': 'connected', 'network.nac-release-endpoint': 'released',
};
export const OUTCOME_STATES = ['blocked', 'reachable', 'isolated', 'connected', 'stopped', 'running', 'powered-off', 'powered-on', 'sinkholed', 'resolving', 'quarantined', 'released', 'unknown'];
export const CHECK_TYPES = ['connectivity-probe', 'service-state', 'power-state', 'firewall-rule-present', 'dns-resolution', 'nac-session', 'edr-isolation-state', 'file-presence'];
const parse = s => JSON.parse(s);

export class ControlOutcomes {
  constructor(store, { domain, clock }) { Object.assign(this, { s: store, d: domain, clock: clock || (() => Date.now()) }); }
  timeline(id) { return this.s.all("SELECT at,actor,action FROM audit WHERE target=? AND action LIKE 'action.%' ORDER BY seq", id); }
  checks(id) { return this.s.all("SELECT e.id,e.source_id,e.observed_at,e.payload,s.name source_name FROM events e JOIN sources s ON s.id=e.source_id WHERE e.kind='response.outcome_check' ORDER BY e.observed_at").map(r => ({ event_id: r.id, source_id: r.source_id, source_name: r.source_name, ...parse(r.payload).details })).filter(c => c.action_id === id); }
  // Traffic the control should have stopped, seen in flow logs after it was enforced.
  leaks(action, asset, request, from, to) {
    const t = action.type, ip = request?.target?.ip, addrs = asset ? parse(asset.addresses) : [];
    const watch = t === 'network.block-ip' ? r => r.src_ip === ip || r.dst_ip === ip : ['endpoint.isolate-device', 'network.switch-port-admin-down', 'network.nac-quarantine-endpoint', 'endpoint.shutdown-host'].includes(t) ? r => addrs.includes(r.src_ip) : null;
    if (!watch) return null;
    const out = []; for (const row of this.s.all("SELECT payload FROM events WHERE kind='log.batch' AND observed_at>=? LIMIT 5000", from)) for (const r of parse(row.payload).details.records || []) if ((r.category === 'flow' || r.category === 'firewall') && r.time >= from && (!to || r.time <= to) && r.action !== 'blocked' && r.action !== 'deny' && watch(r)) out.push({ time: r.time, src_ip: r.src_ip, dst_ip: r.dst_ip, dst_port: r.dst_port });
    return out.slice(0, 50);
  }
  outcome(id) {
    const a = this.s.get('SELECT * FROM actions WHERE id=?', id); if (!a) return null;
    const job = this.s.get('SELECT * FROM response_jobs WHERE action_id=?', id), request = job ? parse(job.request_json) : null, asset = this.s.get('SELECT * FROM assets WHERE id=?', a.asset_id), tl = this.timeline(id), when = name => tl.filter(x => x.action === name).map(x => x.at).pop() || null;
    const enforcedAt = when('action.verified') || when('action.executed'), executionFailedAt = when('action.execution.failed'), rollbackAt = when('action.rollback.verified'), rollbackFailedAt = when('action.rollback.failed'), now = new Date(this.clock()).toISOString();
    const expected = EXPECTED[a.type] || null, checks = this.checks(id), connectorSource = job?.source_id || null;
    const during = checks.filter(c => enforcedAt && c.checked_at >= enforcedAt && (!rollbackAt || c.checked_at <= rollbackAt) && c.expected_state === expected);
    const independent = during.filter(c => c.source_id !== connectorSource), confirming = independent.filter(c => c.observed_state === expected), contradicting = during.filter(c => c.observed_state !== expected && c.observed_state !== 'unknown');
    const leaks = enforcedAt ? this.leaks(a, asset, request, enforcedAt, rollbackAt) : null;
    let state, state_ar;
    if (executionFailedAt) [state, state_ar] = ['execution-failed', 'فشل التنفيذ'];
    else if (!enforcedAt) [state, state_ar] = [a.status === 'expired' ? 'expired-before-execution' : 'not-executed', a.status === 'expired' ? 'انتهت صلاحيته قبل التنفيذ' : 'لم يُنفذ بعد'];
    else if (contradicting.length || leaks?.length) [state, state_ar] = ['ineffective', 'غير فعال: الدليل يناقض نجاحه'];
    else if (confirming.length) [state, state_ar] = ['verified-effective', 'فعال ومتحقق بشكل مستقل'];
    else [state, state_ar] = ['connector-reported-only', 'مُبلغ من الموصل فقط دون تحقق مستقل'];
    const rollback = rollbackFailedAt && (!rollbackAt || rollbackFailedAt > rollbackAt) ? { state: 'rollback-failed', state_ar: 'فشل التراجع: الإجراء ما زال مطبقًا', at: rollbackFailedAt, error: a.result } : rollbackAt ? { state: 'rolled-back', state_ar: 'تم التراجع', at: rollbackAt } : null;
    const end = (rollback?.state === 'rolled-back' ? rollbackAt : null) || (state === 'execution-failed' ? enforcedAt : null), inForce = Boolean(enforcedAt) && rollback?.state !== 'rolled-back' && state !== 'execution-failed';
    return { action_id: id, type: a.type, asset: asset ? { id: asset.id, hostname: asset.hostname, external_id: asset.external_id } : null, expected_state: expected, state, state_ar,
      error: executionFailedAt ? a.result : null, rollback, enforced_at: enforcedAt, ended_at: end, in_force: inForce, duration_seconds: enforcedAt ? Math.round((Date.parse(end || now) - Date.parse(enforcedAt)) / 1000) : null,
      connector_report: job?.completion_json ? parse(job.completion_json) : null, checks: during.map(c => ({ ...c, independent: c.source_id !== connectorSource })), traffic_after_enforcement: leaks, timeline: tl };
  }
  list() {
    const items = this.s.all("SELECT id FROM actions WHERE type<>'asset.set-criticality' ORDER BY requested_at DESC LIMIT 200").map(r => this.outcome(r.id));
    for (const i of items.filter(i => i.traffic_after_enforcement?.length)) this.d?.alert({ key: `CG-CONTROL-INEFFECTIVE-118:${i.action_id}:traffic`, assetId: i.asset?.id || null, rule: 'CG-CONTROL-INEFFECTIVE-118', severity: 'critical', title: `Traffic continued after ${i.type} was enforced: ${i.traffic_after_enforcement.length} flow(s) / استمرت الحركة بعد تطبيق الإجراء` });
    const count = s => items.filter(i => i.state === s).length;
    return { items, summary: { total: items.length, verified_effective: count('verified-effective'), connector_reported_only: count('connector-reported-only'), ineffective: count('ineffective'), execution_failed: count('execution-failed'), rollback_failed: items.filter(i => i.rollback?.state === 'rollback-failed').length, in_force: items.filter(i => i.in_force).length },
      claim: 'Each response action shows whether its effect was verified independently of the connector that ran it (outcome checks from another source, and no traffic the control should stop), how long it has been in force, and any execution error, contradicting evidence or failed rollback as it is.',
      claim_ar: 'كل إجراء استجابة يبين هل تحقق أثره بشكل مستقل عن الموصل الذي نفذه (فحوص نتيجة من مصدر آخر، وغياب الحركة التي يجب أن يوقفها)، ومدة تطبيقه، وأي خطأ تنفيذ أو دليل مناقض أو تراجع فاشل كما هو دون تجميل.' };
  }
}
