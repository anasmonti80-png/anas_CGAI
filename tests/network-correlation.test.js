import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { normalizeLogLines } from '../lib/log-normalizer.js';
import { correlate, algorithmLike } from '../lib/network-correlation.js';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), t0 = Date.now() - 20 * 60000, iso = s => new Date(t0 + s * 1000).toISOString(), ts = s => ((t0 + s * 1000) / 1000).toFixed(3);
const DOMAIN = 'x7k2q9vzt4m1pl8.example', HOST = '10.0.5.23', C2 = '203.0.113.80';
const logs = {
  'suricata-eve': [JSON.stringify({ timestamp: iso(0), event_type: 'dns', src_ip: HOST, src_port: 53122, dest_ip: '10.0.0.53', dest_port: 53, proto: 'UDP', dns: { type: 'query', rrname: DOMAIN, rrtype: 'A' } }),
    JSON.stringify({ timestamp: iso(5), event_type: 'alert', src_ip: HOST, src_port: 50411, dest_ip: C2, dest_port: 443, proto: 'TCP', alert: { action: 'allowed', signature: 'ET MALWARE Synthetic beacon', category: 'A Network Trojan was detected', severity: 1 } }),
    JSON.stringify({ timestamp: iso(30), event_type: 'alert', src_ip: '10.0.9.9', src_port: 40000, dest_ip: '198.51.100.44', dest_port: 80, proto: 'TCP', alert: { action: 'allowed', signature: 'ET POLICY lone alert', category: 'Policy', severity: 2 } })],
  'zeek-ssl': ['#separator \\x09', '#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\tresumed\tlast_alert\tnext_protocol\testablished', `${ts(4)}\tCx1\t${HOST}\t50411\t${C2}\t443\tTLSv13\tTLS_AES_128_GCM_SHA256\tx25519\t${DOMAIN}\tF\t-\th2\tT`],
  'squid-access': [`${ts(6)}    120 ${HOST} TCP_TUNNEL/200 5120 CONNECT ${DOMAIN}:443 - HIER_DIRECT/${C2} -`, `${ts(7)}     15 ${HOST} TCP_DENIED/403 3900 GET http://blocked.example/path/secret?token=abc123 - HIER_NONE/- text/html`],
  'zeek-conn': ['#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state', `${ts(4)}\tCx1\t${HOST}\t50411\t${C2}\t443\ttcp\tssl\t60.1\t4096\t81920\tSF`],
};

test('TLS metadata and proxy logs are parsed with privacy: no path, no query string (CG-099)', () => {
  const tls = normalizeLogLines('zeek-ssl', logs['zeek-ssl']).records[0]; assert.deepEqual([tls.category, tls.query, tls.signature, tls.outcome, tls.dst_ip], ['tls', DOMAIN, 'TLSv13', 'established', C2]);
  const px = normalizeLogLines('squid-access', logs['squid-access']).records; assert.deepEqual(px.map(r => [r.query, r.action, r.outcome]), [[DOMAIN, 'allowed', '200'], ['blocked.example', 'blocked', '403']]);
  assert.ok(!JSON.stringify(px).includes('secret') && !JSON.stringify(px).includes('abc123'), 'paths and query strings are dropped');
  assert.equal(algorithmLike(DOMAIN), true); assert.equal(algorithmLike('mail.google.com'), false); assert.equal(algorithmLike('xn--mgbh0fb.example'), false);
});

test('an anchor is raised only when another independent source confirms it, with stated encryption limits (CG-099)', () => {
  const records = Object.entries(logs).flatMap(([f, lines]) => normalizeLogLines(f, lines).records), r = correlate(records);
  const ids = r.findings.find(f => f.anchor === 'ids-alert'), dga = r.findings.find(f => f.anchor === 'algorithm-like-domain');
  assert.deepEqual(ids.sources, ['flow', 'ids', 'proxy', 'tls']); assert.equal(ids.severity, 'high'); assert.equal(ids.confidence, 'high'); assert.equal(ids.bytes, 86016);
  assert.deepEqual(dga.sources, ['dns', 'flow', 'ids', 'proxy', 'tls']); assert.equal(dga.severity, 'high'); assert.deepEqual(dga.dst_ips, [C2]);
  assert.ok(!r.findings.some(f => f.src_ip === '10.0.9.9'), 'a lone alert without a second source is not a correlated finding');
  assert.ok(!r.findings.some(f => f.anchor === 'proxy-blocked'), 'a proxy block nothing else confirms stays uncorrelated');
  assert.ok(r.limits.some(l => /Encrypted Client Hello/.test(l.en) && /Encrypted Client Hello/.test(l.ar)));
});

test('correlation runs over ingested logs from every source and raises alerts (CG-099)', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg099-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, { clock: () => Date.now() });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = d.createSource('admin-a', { name: 'Network sensors', stale_seconds: 86400 });
  for (const [format, lines] of Object.entries(logs)) { const input = path.join(dir, `${format}.log`), out = path.join(dir, `${format}.json`); fs.writeFileSync(input, lines.join('\n') + '\n');
    execFileSync(process.execPath, [path.join(ROOT, 'scripts/logs-to-telemetry.js'), format, input, out, `sensor ${format}`], { stdio: 'pipe' }); d.ingest('admin-a', src.id, JSON.parse(fs.readFileSync(out, 'utf8'))); }
  const v = d.networkCorrelation(); assert.equal(v.findings.length >= 2, true); assert.ok(v.sources_present.every(x => x.present)); assert.ok(v.claim_ar.includes('حدود التشفير'));
  const alerts = s.all("SELECT severity,title FROM alerts WHERE rule_id='CG-NETCORR-099'"); assert.equal(alerts.length, 2); assert.ok(alerts.every(a => a.severity === 'high' && a.title.includes(HOST)));
  d.networkCorrelation(); assert.equal(s.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-NETCORR-099'").n, 2, 'repeated evaluation does not duplicate alerts');
});
