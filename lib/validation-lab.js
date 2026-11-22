// CG-115 Detection validation lab. Safe, authorized defensive test patterns: each scenario is synthetic telemetry
// (documentation addresses, no command is executed on any host and nothing leaves the process) that is ingested into an
// isolated in-memory CyberGuard instance with the same rules, and the alerts it raises are compared with the expected
// ones. Stored events (for example from a lab source) can be replayed the same way after a rule change: the alerts the
// production instance raised for them are the expectation. Production data and alerts are never touched by a run,
// except that a missed expected detection raises CG-VALIDATION-MISS-115 in production.
import { randomUUID } from 'node:crypto';
import { Store } from './store.js';
import { fail, digest } from './common.js';

const iso = (now, s = 0) => new Date(now + s * 1000).toISOString();
const flow = (t, src, dst, port, bytes = 10) => JSON.stringify({ TimeFlowStart: Math.floor(t / 1000), SrcAddr: src, DstAddr: dst, SrcPort: 50000, DstPort: port, Proto: 6, Bytes: bytes, Packets: 1 });
const bindQ = (t, name, type = 'A') => { const d = new Date(t), m = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][d.getUTCMonth()]; return `${String(d.getUTCDate()).padStart(2, '0')}-${m}-${d.getUTCFullYear()} ${d.toISOString().slice(11, 19)}.000 client @0x1 10.0.0.7#53000 (${name}): query: ${name} IN ${type} + (10.0.0.53)`; };
const host = (o = {}) => ({ external_id: 'lab-ws-01', hostname: 'LAB-WS-01', os_family: 'windows', device_type: 'workstation', addresses: ['10.0.0.20'], ...o });
const router = { external_id: 'lab-rtr-01', hostname: 'LAB-RTR-01', os_family: 'network', device_type: 'router', addresses: ['10.0.0.1'] };
const snap = (id, peer) => ({ snapshot_id: id, device_ref: 'lab:rtr-01', device_type: 'router', vendor: 'cisco', model: 'ISR4331/K9', firmware_version: '17.3.4a', dns_servers: ['10.0.0.53'], ntp_servers: [], vpn_profiles: [{ name: 'branch', peer, protocol: 'ipsec' }], management: [{ protocol: 'ssh', enabled: true, exposed_to: 'internal', restricted_sources: true }], config_sha256: digest(id) });
const fwRule = (rule_id, position, extra = {}) => ({ rule_id, name: rule_id, position, enabled: true, direction: 'in', action: 'allow', protocol: 'tcp', src: ['10.0.0.0/24'], dst: ['10.0.1.0/24'], src_ports: ['any'], dst_ports: ['443'], application: null, profile: null, last_hit_at: null, hit_count: null, expires_at: null, owner: null, created_at: null, ...extra });

// Each scenario returns events as [offset seconds, event] so time-window rules see realistic spacing.
export const SCENARIOS = [
  { id: 'brute-force-rdp', title: ['Repeated failed RDP logons', 'محاولات دخول RDP فاشلة متكررة'], techniques: ['T1110'], expected: ['CG-AUTH-FAILURES-5-IN-5M'],
    events: () => Array.from({ length: 5 }, (_, i) => [i * 20, { kind: 'auth.failed', asset: host(), details: { account: 'lab-user', source_ip: '192.0.2.20', protocol: 'rdp' } }]) },
  { id: 'smb-lateral-fanout', title: ['SMB fan-out from one workstation', 'انتشار SMB من جهاز واحد'], techniques: ['T1021.002'], expected: ['CG-NET-LATERAL-015'],
    events: now => [[0, { kind: 'log.batch', asset: host(), details: { batch_id: 'LAB-LATERAL', source_name: 'lab flows', format: 'goflow-json', lines: Array.from({ length: 5 }, (_, i) => flow(now - 60000, '10.0.0.50', `10.0.2.${i + 1}`, 445)) } }]] },
  { id: 'rdp-exposed-internet', title: ['RDP reached from the Internet', 'الوصول إلى RDP من الإنترنت'], techniques: ['T1133'], expected: ['CG-NET-EXPOSE-016'],
    events: now => [[0, { kind: 'log.batch', asset: host(), details: { batch_id: 'LAB-EXPOSE', source_name: 'lab flows', format: 'goflow-json', lines: [flow(now - 60000, '203.0.113.9', '10.0.0.20', 3389)] } }]] },
  { id: 'dns-tunnel', title: ['DNS tunnelling pattern', 'نمط نفق DNS'], techniques: ['T1071.004'], expected: ['CG-NET-DNS-017'],
    events: now => [[0, { kind: 'log.batch', asset: host(), details: { batch_id: 'LAB-DNS', source_name: 'lab resolver', format: 'bind-query', lines: [bindQ(now - 60000, 'x9q7z2kd8w4m1p0r6t3y5vbn.tunnel.example.net', 'TXT')] } }]] },
  { id: 'firewall-any-any', title: ['Any-any allow rule added', 'إضافة قاعدة تسمح بالكل'], techniques: ['T1562.004'], expected: ['CG-FW-ANYANY-018'],
    events: () => [[0, { kind: 'firewall.ruleset', asset: router, details: { ruleset_id: 'LAB-FW-1', device_ref: 'lab:fw-01', vendor: 'pfsense', evaluation: 'first-match', rules: [fwRule('web', 1), fwRule('any-any', 2, { protocol: 'any', src: ['any'], dst: ['any'], dst_ports: ['any'] })] } }]] },
  { id: 'vpn-peer-change', title: ['Router VPN peer changed', 'تغيير نظير VPN في الموجه'], techniques: ['T1600'], expected: ['CG-NETDEV-VPN-024'],
    events: () => [[0, { kind: 'network.device_config', asset: router, details: snap('LAB-S1', '198.51.100.1') }], [60, { kind: 'network.device_config', asset: router, details: snap('LAB-S2', '203.0.113.200') }]] },
  { id: 'suspicious-macro-file', title: ['Suspicious macro document', 'مستند ماكرو مشبوه'], techniques: ['T1204.002'], expected: ['CG-FILE-SUSPICIOUS-092'],
    events: () => [[0, { kind: 'file.triage', asset: host(), details: { name: 'invoice.docm', directory_ref: 'a'.repeat(16), size: 2048, type: 'ole-document', sha256: 'b'.repeat(64), sha1: 'c'.repeat(40), md5: 'd'.repeat(32), signature: { status: 'not-applicable', signer: null, issuer: null, reason: null }, yara: [{ rule: 'office_macro_autoopen', tags: ['macro'], severity: 'medium', engine: 'built-in' }], reputation: 'unknown', verdict: 'suspicious', rules_engine: 'built-in', quarantine: { state: 'not-quarantined', custody_id: null, record_hash: null, location: null } } }]] },
  { id: 'remote-port-open', title: ['Remote access port open', 'منفذ وصول عن بعد مفتوح'], techniques: ['T1133'], expected: ['CG-REMOTE-EXPOSURE'],
    events: () => [[0, { kind: 'remote.port_open', asset: host(), details: { session_id: 'lab-p1', protocol: 'rdp', source_a: { ip: '10.0.0.40', account: null }, target_b: { ip: '10.0.0.20', account: null }, evidence_type: 'port_observation' } }]] },
  { id: 'benign-baseline', title: ['Benign activity (false positive check)', 'نشاط سليم (فحص الإنذارات الكاذبة)'], techniques: [], expected: [],
    events: now => [...['alice', 'bob', 'carol'].map((a, i) => [i * 10, { kind: 'auth.failed', asset: host(), details: { account: a, source_ip: '10.0.0.30', protocol: 'rdp' } }]),
      [40, { kind: 'log.batch', asset: host(), details: { batch_id: 'LAB-BENIGN', source_name: 'lab mixed', format: 'goflow-json', lines: [flow(now - 60000, '10.0.0.20', '10.0.1.10', 443), flow(now - 60000, '10.0.0.20', '198.51.100.20', 443, 50000)] } }],
      [50, { kind: 'log.batch', asset: host(), details: { batch_id: 'LAB-BENIGN-DNS', source_name: 'lab resolver', format: 'bind-query', lines: [bindQ(now - 60000, 'www.example.org'), bindQ(now - 60000, 'mail.example.org', 'MX')] } }]] },
];

export class ValidationLab {
  constructor(store, { clock, domain, Domain }) { Object.assign(this, { s: store, clock: clock || (() => Date.now()), domain, Domain }); }
  now() { return new Date(this.clock()).toISOString(); }
  // A fresh in-memory CyberGuard with the same rules; nothing it does reaches the production store.
  isolated(clockMs) {
    const s = new Store(':memory:'); let now = clockMs; const d = new this.Domain(s, { clock: () => now });
    s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'validation-lab', 'validation-lab', 'not-a-login-account', 'admin', iso(clockMs));
    const src = d.createSource('validation-lab', { name: 'Validation lab', stale_seconds: 86400 });
    return { s, d, src, set: t => { now = t; } };
  }
  compare(expected, observedRows) {
    const observed = [...new Set(observedRows)].sort(), exp = [...new Set(expected)].sort();
    return { expected: exp, observed, missing: exp.filter(r => !observed.includes(r)), unexpected: observed.filter(r => !exp.includes(r)) };
  }
  record(actor, kind, ref, title, cmp, details) {
    const passed = !cmp.missing.length && !cmp.unexpected.length, id = randomUUID(), at = this.now();
    this.s.run('INSERT INTO validation_lab_runs(id,kind,ref,title,actor,at,expected,observed,missing,unexpected,passed,details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', id, kind, ref, title, actor, at, JSON.stringify(cmp.expected), JSON.stringify(cmp.observed), JSON.stringify(cmp.missing), JSON.stringify(cmp.unexpected), passed ? 1 : 0, JSON.stringify(details));
    this.s.audit(actor, `validation_lab.${kind}`, ref, { passed, missing: cmp.missing, unexpected: cmp.unexpected }, at);
    for (const r of cmp.missing) this.domain.alert({ key: `CG-VALIDATION-MISS-115:${kind}:${ref}:${r}`, rule: 'CG-VALIDATION-MISS-115', severity: 'high', title: `Validation lab: expected detection ${r} did not fire for ${kind} ${ref} / مختبر التحقق: لم يُطلق الكشف المتوقع ${r}` });
    return { run_id: id, kind, ref, title, at, passed, ...cmp, details };
  }
  runScenario(actor, id) {
    const sc = SCENARIOS.find(x => x.id === id); fail(sc, 404, 'validation_scenario_not_found');
    const start = this.clock(), lab = this.isolated(start), events = sc.events(start); let n = 0;
    for (const [offset, e] of events) { lab.set(start + offset * 1000); lab.d.ingest('validation-lab', lab.src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: `${sc.id}-${n++}`, observed_at: iso(start, offset), ...e }] }); }
    const rows = lab.s.all('SELECT rule_id FROM alerts').map(r => r.rule_id); lab.s.close();
    return this.record(actor, 'scenario', sc.id, sc.title[0], this.compare(sc.expected, rows), { events: events.length, techniques: sc.techniques, isolated: true });
  }
  runAll(actor) { const results = SCENARIOS.map(s => this.runScenario(actor, s.id)); return { results, passed: results.filter(r => r.passed).length, total: results.length }; }
  // Replay stored events through the current rules in isolation; expectation = what production raised for them.
  replay(actor, { source_id, since, until, limit = 2000 }) {
    fail(this.s.get('SELECT id FROM sources WHERE id=?', source_id), 404, 'source_not_found'); const from = since || '2000-01-01T00:00:00.000Z', to = until || new Date(this.clock() + 300000).toISOString();
    const rows = this.s.all('SELECT id,source_id,kind,observed_at,payload FROM events WHERE source_id=? AND observed_at BETWEEN ? AND ? ORDER BY observed_at,received_at LIMIT ?', source_id, from, to, Math.min(Math.max(1, Number(limit) || 2000), 5000));
    fail(rows.length, 400, 'no_events_to_replay'); const ids = new Set(rows.map(r => r.id));
    const expected = this.s.all('SELECT rule_id,evidence_ids FROM alerts').filter(a => JSON.parse(a.evidence_ids).some(id => ids.has(id))).map(a => a.rule_id);
    const lab = this.isolated(Date.parse(rows[0].observed_at)), map = new Map();
    for (const r of rows) {
      const e = JSON.parse(r.payload); lab.set(Date.parse(r.observed_at) + 1000);
      const asset = lab.d.observe(lab.src.id, e.asset, e.observed_at), id = randomUUID(), payload = JSON.stringify(e); map.set(id, r.id);
      lab.s.run('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', id, lab.src.id, e.event_id, asset.id, e.kind, e.observed_at, lab.d.now(), 'cg.telemetry/1', 'replay/1', digest(payload), digest(payload), payload);
      lab.d.correlate({ id, source_id: lab.src.id, asset_id: asset.id, ...e });
    }
    const observed = lab.s.all('SELECT rule_id FROM alerts').map(a => a.rule_id); lab.s.close();
    return this.record(actor, 'replay', source_id, `Replay of ${rows.length} stored events`, this.compare(expected, observed), { events: rows.length, since: from, until: to, isolated: true });
  }
  history(limit = 100) { return this.s.all('SELECT * FROM validation_lab_runs ORDER BY at DESC LIMIT ?', limit).map(r => ({ ...r, passed: Boolean(r.passed), expected: JSON.parse(r.expected), observed: JSON.parse(r.observed), missing: JSON.parse(r.missing), unexpected: JSON.parse(r.unexpected), details: JSON.parse(r.details) })); }
  view() {
    const runs = this.history(200), latest = new Map(); for (const r of [...runs].reverse()) latest.set(`${r.kind}:${r.ref}`, r);
    return { scenarios: SCENARIOS.map(s => ({ id: s.id, title: s.title[0], title_ar: s.title[1], techniques: s.techniques, expected: s.expected, last_run: latest.get(`scenario:${s.id}`) || null })), runs: runs.slice(0, 50),
      claim: 'Safe, authorized test patterns are synthetic telemetry run in an isolated in-memory instance with the current rules; stored events can be replayed the same way. Expected and observed alerts are compared, misses raise an alert and false positives are shown.',
      claim_ar: 'أنماط الاختبار الآمنة المصرح بها هي بيانات اصطناعية تُشغَّل في نسخة معزولة في الذاكرة بالقواعد الحالية، ويمكن إعادة تشغيل الأحداث المخزنة بالطريقة نفسها. تُقارن التنبيهات المتوقعة بالفعلية، ويُرفع تنبيه عند فشل الكشف وتُعرض الإنذارات الكاذبة.' };
  }
}
