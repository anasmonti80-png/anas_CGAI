import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeLogLines } from '../lib/log-normalizer.js';
import { toOcsf, exportOcsf, OCSF_VERSION } from '../lib/ocsf.js';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const t0 = Date.now() - 600000, iso = s => new Date(t0 + s * 1000).toISOString(), ts = s => ((t0 + s * 1000) / 1000).toFixed(3);
const day = new Date(t0), mon = day.toLocaleString('en-US', { month: 'short', timeZone: 'UTC' }), wd = day.toLocaleString('en-US', { weekday: 'short', timeZone: 'UTC' });
const stamp = `${wd} ${mon} ${String(day.getUTCDate()).padStart(2, ' ')} ${String(day.getUTCHours()).padStart(2, '0')}:00:00 ${day.getUTCFullYear()}`;
const LOGS = {
  'suricata-eve': [JSON.stringify({ timestamp: iso(0), event_type: 'alert', src_ip: '10.0.5.23', src_port: 50411, dest_ip: '203.0.113.80', dest_port: 443, proto: 'TCP', alert: { action: 'allowed', signature: 'ET MALWARE Synthetic beacon', category: 'Trojan', severity: 1 } }), JSON.stringify({ timestamp: iso(1), event_type: 'dns', src_ip: '10.0.5.23', dest_ip: '10.0.0.53', proto: 'UDP', dns: { type: 'query', rrname: 'example.org', rrtype: 'A' } })],
  'squid-access': [`${ts(2)}    120 10.0.5.23 TCP_MISS/200 5120 GET http://portal.example.org/login?user=alice - HIER_DIRECT/203.0.113.9 text/html`],
  freeradius: [`${stamp} : Auth: (11) Login OK: [alice/<via Auth-Type = eap>] (from client sw-hq-01 port 10 cli 00-11-22-33-44-55)`],
  'zeek-conn': ['#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state', `${ts(3)}\tC1\t10.0.5.23\t50411\t203.0.113.80\t443\ttcp\tssl\t60\t4096\t81920\tSF`],
  syslog: [`<13>1 ${iso(4)} host01 app 123 ID1 - Service restarted`],
};
const batches = () => Object.entries(LOGS).map(([format, lines]) => ({ format, source_name: `sensor ${format}`, product: 'Synthetic sensors', records: normalizeLogLines(format, lines).records }));

test('normalized records map to OCSF classes with version, source, missing fields and meaning lost (CG-103)', () => {
  const out = exportOcsf(batches()), cls = Object.fromEntries(out.quality.filter(q => q.class_name !== 'DNS Activity').map(q => [q.format, q.class_name]));
  assert.equal(out.ocsf_version, OCSF_VERSION); assert.deepEqual(cls, { 'suricata-eve': 'Detection Finding', 'squid-access': 'HTTP Activity', freeradius: 'Authentication', 'zeek-conn': 'Network Activity', syslog: 'Base Event' });
  const finding = out.events.find(e => e.class_uid === 2004); assert.deepEqual([finding.category_uid, finding.type_uid, finding.severity_id, finding.metadata.version, finding.metadata.vendor_name ?? finding.metadata.product.vendor_name], [2, 200401, 4, '1.3.0', 'suricata-eve']);
  assert.match(finding.unmapped.cyberguard_mapping.meaning_lost[0], /severity 1 mapped to OCSF severity_id 4/);
  const auth = out.events.find(e => e.class_uid === 3002); assert.deepEqual([auth.user.name, auth.status_id, auth.src_endpoint.mac], ['alice', 1, '00:11:22:33:44:55']);
  const http = out.events.find(e => e.class_uid === 4002); assert.equal(http.http_request.url.hostname, 'portal.example.org'); assert.equal(http.activity_id, 3); assert.ok(!JSON.stringify(http).includes('user=alice'));
  const net = out.events.find(e => e.class_uid === 4001); assert.equal(net.traffic.bytes, 86016);
  assert.deepEqual(out.quality.filter(q => q.format === 'suricata-eve').map(q => [q.class_name, q.records]), [['Detection Finding', 1], ['DNS Activity', 1]], 'one Suricata format yields two OCSF classes, reported separately');
  const syslog = out.quality.find(q => q.format === 'syslog'); assert.equal(syslog.lossy, 1);
  const dnsOnly = toOcsf({ category: 'dns', time: iso(5), src_ip: '10.0.5.23', query: null, severity: null }, { format: 'bind-query', source_name: 'dns' }); assert.deepEqual(dnsOnly.mapping.missing_fields, ['query'], 'a DNS record without a query is reported as incomplete');
});

test('the OCSF export runs over stored logs and reports per-format quality (CG-103)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, { clock: () => Date.now() });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = d.createSource('admin-a', { name: 'Synthetic sensors', stale_seconds: 86400 }), asset = { external_id: 'sensor', hostname: 'SENSOR', os_family: 'linux', device_type: 'server', addresses: [] };
  Object.entries(LOGS).forEach(([format, lines], i) => d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: `lb${i}`, kind: 'log.batch', observed_at: new Date().toISOString(), asset, details: { batch_id: `b${i}`, source_name: `sensor ${format}`, format, lines } }] }));
  const r = d.ocsfExport({ hours: 24 }); assert.equal(r.events.length, 6); assert.equal(r.quality.length, 6); assert.ok(r.events.every(e => e.metadata.product.name === 'Synthetic sensors' && e.metadata.version === '1.3.0'));
  assert.equal(d.ocsfExport({ hours: 24, limit: 2 }).events.length, 2); assert.throws(() => d.ocsfExport({ hours: 0 }), /invalid_ocsf_hours/); assert.ok(r.claim_ar.includes('OCSF'));
});
