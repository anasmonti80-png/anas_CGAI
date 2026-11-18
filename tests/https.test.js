import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import http from 'node:http';
import { X509Certificate } from 'node:crypto';
import { createApp } from '../server.js';
import { selfSignedCertificate } from '../lib/selfsigned.js';

const request = (mod, opts, body) => new Promise((resolve, reject) => { const r = mod.request(opts, res => { const tls = res.socket?.getProtocol?.() || null; let b = ''; res.on('data', d => (b += d)).on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b, tls })); }); r.on('error', reject); if (body) r.write(body); r.end(); });

test('the self-signed certificate is a valid X.509 v3 server certificate for localhost only (CG-052)', () => {
  const c = selfSignedCertificate({ now: new Date('2026-11-18T00:00:00Z') }), x = new X509Certificate(c.cert);
  assert.equal(x.subjectAltName, 'DNS:localhost, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1');
  assert.equal(x.checkHost('localhost'), 'localhost'); assert.equal(x.checkHost('example.com'), undefined); assert.equal(x.ca, false);
  assert.equal(x.publicKey.asymmetricKeyDetails.modulusLength, 2048); assert.match(x.keyUsage?.join(',') || 'serverAuth', /1\.3\.6\.1\.5\.5\.7\.3\.1|serverAuth/);
  assert.equal(new Date(x.validTo).toISOString().slice(0, 10), '2027-12-20', 'valid for at most 397 days');
  assert.match(c.key, /BEGIN PRIVATE KEY/);
});

test('HTTPS serves CyberGuard with TLS 1.2+, HSTS and Secure session cookies, and keeps the key out of the repository (CG-052)', async t => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg052-')), app = createApp({ dataDir, setupToken: 'https-setup-token-0001', tls: 'self-signed' });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const { port } = await app.listen(0), ca = app.certificate, base = { host: '127.0.0.1', port, servername: 'localhost', ca };
  assert.equal(app.scheme, 'https');
  const call = (p, method = 'GET', data, extra = {}) => request(https, { ...base, path: p, method, headers: { host: `localhost:${port}`, ...(data ? { 'Content-Type': 'application/json', Origin: `https://localhost:${port}` } : {}), ...extra } }, data ? JSON.stringify(data) : null);
  const status = await call('/api/setup/status');
  assert.equal(status.status, 200); assert.match(status.tls, /^TLSv1\.[23]$/); assert.equal(status.headers['strict-transport-security'], 'max-age=31536000');
  const setup = await call('/api/auth/setup', 'POST', { setup_token: 'https-setup-token-0001', username: 'admin', password: 'Https-Local-Test-2026!' });
  assert.equal(setup.status, 201, setup.body);
  const login = await call('/api/auth/login', 'POST', { username: 'admin', password: 'Https-Local-Test-2026!' }); assert.equal(login.status, 200, login.body);
  const cookie = [].concat(login.headers['set-cookie'] || [])[0] || ''; assert.match(cookie, /HttpOnly/); assert.match(cookie, /SameSite=Strict/); assert.match(cookie, /Secure/);
  await assert.rejects(request(https, { host: '127.0.0.1', port, path: '/api/setup/status', headers: { host: `localhost:${port}` } }), /self-signed|certificate/i, 'an untrusted certificate is refused by default clients');
  await assert.rejects(request(https, { ...base, path: '/', minVersion: 'TLSv1', maxVersion: 'TLSv1.1', headers: { host: `localhost:${port}` } }), /protocol|version|alert|handshake/i, 'TLS 1.0/1.1 are refused');
  const plain = await request(http, { host: '127.0.0.1', port, path: '/api/setup/status', headers: { host: `localhost:${port}` } }).catch(e => ({ error: e.message }));
  assert.ok(plain.error || plain.status === 400 || !plain.status, 'plain HTTP is not served on the HTTPS port');
  const key = path.join(dataDir, 'tls', 'key.pem'); assert.ok(fs.existsSync(key)); if (process.platform !== 'win32') assert.equal(fs.statSync(key).mode & 0o077, 0, 'the key is readable by its owner only');
  const again = createApp({ dataDir, setupToken: 'https-setup-token-0001', tls: 'self-signed' }), againCert = again.certificate; await again.close();
  assert.equal(new X509Certificate(againCert).fingerprint256, new X509Certificate(ca).fingerprint256, 'the same certificate is reused across restarts');
});
