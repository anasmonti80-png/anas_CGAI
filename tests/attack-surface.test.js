import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateScope, collect, toTelemetry, findingsFor, parseNmapXml, tcpConnect } from '../lib/easm.js';
import { selfSignedCertificate } from '../lib/selfsigned.js';
import { remediationAdvice } from '../lib/remediation.js';
import { createApp } from '../server.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), future = new Date(Date.now() + 86400000).toISOString();
const listen = server => new Promise(r => server.listen(0, '127.0.0.1', () => r(server.address().port)));

test('the attack surface scope must be authorized, current, owned and narrow (CG-072)', () => {
  const ok = { authorization_ref: 'CHG-EASM-072', owner: 'IT security', window_end: future, networks: ['203.0.113.0/28'] };
  assert.equal(validateScope(ok).ports.length > 10, true);
  assert.throws(() => validateScope({ ...ok, authorization_ref: '' }), /authorization_ref required/);
  assert.throws(() => validateScope({ ...ok, window_end: '2020-01-01T00:00:00Z' }), /window has ended/);
  assert.throws(() => validateScope({ ...ok, networks: ['10.0.0.0/8'] }), /too wide/);
  assert.throws(() => validateScope({ ...ok, networks: [], domains: [{ name: 'example.org', verification: 'declared' }] }), /without an ownership reference/);
  assert.throws(() => validateScope({ ...ok, networks: [] }), /no targets/);
  assert.throws(() => validateScope({ ...ok, ports: [443], tls_ports: [8443] }), /tls_ports must be listed/);
});

test('a real TLS service and DNS records are checked; names resolving outside the authorized ranges are never contacted (CG-072)', async t => {
  const cert = selfSignedCertificate({ commonName: 'portal.example.org', hosts: ['portal.example.org'], days: 10 });
  const tlsServer = tls.createServer({ cert: cert.cert, key: cert.key, minVersion: 'TLSv1.2' }, s => s.on('data', () => s.end('HTTP/1.1 200 OK\r\nServer: synthetic\r\nContent-Length: 0\r\n\r\n')));
  // Port 1 (tcpmux) has no listener on developer machines or CI runners; a just-released ephemeral port could be reused by a parallel test.
  const tlsPort = await listen(tlsServer), closedPort = 1;
  t.after(() => tlsServer.close());
  const contacted = [], connect = (ip, port) => { contacted.push(ip); return tcpConnect(ip, port); };
  const records = { 'example.org': { A: ['127.0.0.1', '198.51.100.7'], TXT: [['cyberguard-verify=tok-123'], ['v=other']], MX: [{ exchange: 'mail.example.org' }] }, 'other.example.org': { A: ['127.0.0.1'], TXT: [['cyberguard-verify=wrong']] } };
  const resolver = { resolveTxt: async n => n.startsWith('_dmarc.') ? [] : records[n]?.TXT || [], resolve4: async n => records[n]?.A || [], resolve6: async () => [], resolveMx: async n => records[n]?.MX || [], resolveCaa: async () => [] };
  const scope = { authorization_ref: 'CHG-EASM-072', owner: 'IT security', window_end: future, networks: ['127.0.0.1/32'], ports: [tlsPort, closedPort], tls_ports: [tlsPort], rate_per_second: 100,
    domains: [{ name: 'example.org', verification: 'dns-txt', token: 'tok-123' }, { name: 'other.example.org', verification: 'dns-txt', token: 'tok-123' }] };
  const result = await collect(scope, { resolver, connect });
  assert.ok(!contacted.includes('198.51.100.7'), 'an address outside the authorized ranges is never contacted');
  const dom = result.observations.find(o => o.target === 'example.org');
  assert.equal(dom.ownership, 'verified-dns-txt'); assert.deepEqual(dom.not_probed, [{ address: '198.51.100.7', reason: 'outside-authorized-networks' }]);
  assert.deepEqual(dom.services.map(s => s.port), [tlsPort], 'the open TLS port is found and the closed one is not');
  const c = dom.tls[0]; assert.equal(c.self_signed, true); assert.equal(c.name_match, false, 'the certificate does not cover example.org'); assert.match(c.protocol, /^TLSv1\.[23]$/);
  const ids = dom.findings.map(f => f.id.split(':')[0]).sort(); assert.deepEqual(ids, ['dns-no-caa', 'http-no-hsts', 'mail-no-dmarc', 'mail-no-spf', 'tls-expiring', 'tls-name-mismatch', 'tls-self-signed']);
  const other = result.observations.find(o => o.target === 'other.example.org'); assert.equal(other.ownership, 'unverified'); assert.deepEqual(other.not_probed, [{ address: 'other.example.org', reason: 'ownership-not-verified' }]);
  assert.ok(result.observations.some(o => o.target === '127.0.0.1' && o.target_type === 'address'));
  // Into CyberGuard: alerts per finding, the attack surface view and exposure remediation.
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg072-')); const app = createApp({ dataDir, setupToken: 'easm-setup-token-000001', remoteAccess: {} });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  app.store.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = app.domain.createSource('admin-a', { name: 'EASM collector', stale_seconds: 86400 }), telemetry = toTelemetry(result);
  assert.equal(app.domain.ingest('admin-a', src.id, telemetry).accepted, telemetry.events.length);
  const alerts = app.store.all("SELECT severity,title FROM alerts WHERE rule_id='CG-EASM-072'"); assert.ok(alerts.some(a => a.severity === 'high' && /does not cover example.org/.test(a.title)));
  const view = app.domain.attackSurface(); assert.equal(view.summary.not_probed, 2); assert.ok(view.summary.certificates_expiring_30d >= 1); assert.ok(view.claim_ar.includes('لا يُستغل شيء'));
  assert.equal(remediationAdvice({ alert: { id: 'x', rule_id: 'CG-EASM-072' }, asset: null }).family, 'exposure');
});

test('exposed admin services and legacy TLS are findings, nmap XML is parsed, and the CLI refuses an expired authorization (CG-072)', () => {
  const f = findingsFor({ target: '203.0.113.5', services: [{ port: 3389 }, { port: 23 }, { port: 443 }], tls: [{ port: 443, valid_to: '2020-01-01T00:00:00.000Z', self_signed: false, name_match: true, protocol: 'TLSv1' }], http: [{ port: 443, hsts: true }] });
  assert.deepEqual(f.map(x => [x.id, x.severity]), [['tls-expired:443', 'high'], ['tls-legacy:443', 'medium'], ['exposed-admin:3389', 'high'], ['exposed-admin:23', 'critical']]); assert.ok(f.every(x => x.title_ar));
  const xml = '<?xml version="1.0"?><nmaprun><host><ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6p1" method="probed" conf="10"/></port><port protocol="tcp" portid="25"><state state="closed"/><service name="smtp"/></port><port protocol="tcp" portid="443"><state state="open"/><service name="https" tunnel="ssl"/></port></ports></host></nmaprun>';
  assert.deepEqual(parseNmapXml(xml), [{ port: 22, transport: 'tcp', state: 'open', service: 'ssh', product: 'OpenSSH', version: '9.6p1', via: 'nmap' }, { port: 443, transport: 'tcp', state: 'open', service: 'https', product: null, version: null, via: 'nmap' }]);
  const script = path.join(ROOT, 'scripts', 'attack-surface.js');
  assert.match(execFileSync(process.execPath, [script, 'token'], { encoding: 'utf8' }), /^cyberguard-verify=[A-Za-z0-9_-]{24}\n$/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg072-cli-')), scope = path.join(dir, 'scope.json'); fs.writeFileSync(scope, JSON.stringify({ authorization_ref: 'CHG-EASM-072', owner: 'IT', window_end: '2020-01-01T00:00:00Z', networks: ['127.0.0.1/32'] }));
  const r = spawnSync(process.execPath, [script, 'scan', '--scope', scope, '--output', path.join(dir, 'out.json')], { encoding: 'utf8' }); assert.equal(r.status, 1); assert.match(r.stderr, /Refused: authorization window has ended/); assert.equal(fs.existsSync(path.join(dir, 'out.json')), false);
  fs.rmSync(dir, { recursive: true, force: true });
});
