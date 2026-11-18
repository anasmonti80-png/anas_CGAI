import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import http from 'node:http';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createApp } from '../server.js';
import { remoteAccessConfig, RemoteAccessGate } from '../lib/remote-access.js';
import { selfSignedCertificate } from '../lib/selfsigned.js';

const ZTNA = { CG_REMOTE_ACCESS: 'ztna', CG_PUBLIC_HOSTS: 'soc.acme.example', CG_ZTNA_ISSUER: 'https://acme.cloudflareaccess.com', CG_ZTNA_AUDIENCE: 'aud-cyberguard', CG_ZTNA_JWKS_URL: 'https://acme.cloudflareaccess.com/cdn-cgi/access/certs', CG_ZTNA_DEVICE_CLAIM: 'device_posture.compliant', CG_ZTNA_DEVICE_VALUE: 'true' };

test('remote access is loopback by default and ZTNA or VPN must be configured completely (CG-053)', () => {
  assert.equal(remoteAccessConfig({}).mode, 'loopback');
  assert.throws(() => remoteAccessConfig({ CG_REMOTE_ACCESS: 'ztna', CG_ZTNA_ISSUER: 'https://x', CG_ZTNA_AUDIENCE: 'a', CG_ZTNA_JWKS_URL: 'https://x/certs' }), /ztna_requires_public_hosts/);
  assert.throws(() => remoteAccessConfig({ ...ZTNA, CG_ZTNA_JWKS_URL: 'http://gateway.example/certs' }), /sso_issuer_must_use_https/, 'a remote JWKS must use HTTPS');
  assert.throws(() => remoteAccessConfig({ CG_REMOTE_ACCESS: 'vpn', CG_LISTEN_HOST: '10.8.0.1', CG_VPN_CIDRS: '10.8.0.0/24' }), /vpn_access_requires_tls/);
  assert.throws(() => remoteAccessConfig({ CG_REMOTE_ACCESS: 'vpn', CG_LISTEN_HOST: '203.0.113.10', CG_VPN_CIDRS: '10.8.0.0/24' }, { tls: true }), /vpn_listen_host_must_be_a_private_vpn_address/, 'never listen on a public address');
  assert.throws(() => remoteAccessConfig({ CG_REMOTE_ACCESS: 'open' }), /invalid_remote_access_mode/);
});

test('VPN mode accepts only TLS clients from the VPN pools and, with a device CA, only certificate-holding devices (CG-053)', async () => {
  const gate = new RemoteAccessGate(remoteAccessConfig({ CG_REMOTE_ACCESS: 'vpn', CG_LISTEN_HOST: '10.8.0.1', CG_VPN_CIDRS: '10.8.0.0/24,100.64.0.0/10' }, { tls: true, clientCa: true }));
  const req = (remote, host = '10.8.0.1:4310', authorized = true, cn = 'laptop-0042') => ({ headers: { host }, socket: { remoteAddress: remote, authorized, getPeerCertificate: () => ({ subject: { CN: cn } }) } });
  assert.deepEqual(await gate.check(req('::ffff:10.8.0.15'), 4310), { via: 'vpn', identity: null, device: 'laptop-0042' });
  assert.equal((await gate.check(req('100.101.3.4'), 4310)).via, 'vpn');
  await assert.rejects(gate.check(req('198.51.100.20'), 4310), /source_outside_vpn_pool/);
  await assert.rejects(gate.check(req('10.8.0.15', '10.8.0.1:4310', false), 4310), /device_certificate_required/);
  await assert.rejects(gate.check(req('10.8.0.15', 'evil.example:4310'), 4310), /host_not_allowed/);
  await assert.rejects(gate.check(req('10.8.0.15', '127.0.0.1:4310'), 4310), /loopback_host_from_remote_address/, 'a remote client cannot pose as loopback');
});

test('mutual TLS refuses devices without a certificate from the organisation device CA (CG-053)', async t => {
  const ca = selfSignedCertificate({ commonName: 'Acme Device CA', usage: 'ca', days: 3650 }), device = selfSignedCertificate({ commonName: 'laptop-0042', usage: 'client', issuer: { ...ca } }), rogueCa = selfSignedCertificate({ commonName: 'Rogue CA', usage: 'ca' }), rogue = selfSignedCertificate({ commonName: 'unmanaged', usage: 'client', issuer: { ...rogueCa } });
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg053mtls-')), app = createApp({ dataDir, setupToken: 'mtls-setup-token-000001', tls: 'self-signed', clientCa: ca.cert, remoteAccess: {} });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const { port } = await app.listen(0), get = extra => new Promise((resolve, reject) => { https.get({ host: '127.0.0.1', port, servername: 'localhost', ca: app.certificate, path: '/api/setup/status', headers: { host: `localhost:${port}` }, ...extra }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); }).on('error', reject); });
  assert.equal(await get({ cert: device.cert, key: device.key }), 200, 'a managed device connects');
  await assert.rejects(get({}), /certificate|alert|socket|ECONNRESET|hang up/i, 'no device certificate, no connection');
  await assert.rejects(get({ cert: rogue.cert, key: rogue.key }), /certificate|alert|socket|ECONNRESET|hang up/i, 'a certificate from another CA is refused');
});

test('behind a Zero Trust gateway only signed, unexpired assertions for this audience from compliant devices get through (CG-053)', async t => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 }), other = generateKeyPairSync('rsa', { modulusLength: 2048 }), jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'cf1' };
  let fetches = 0; const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg053ztna-')), app = createApp({ dataDir, setupToken: 'ztna-setup-token-000001', remoteAccess: ZTNA, jwksFetcher: async url => { fetches++; assert.equal(url, ZTNA.CG_ZTNA_JWKS_URL); return [jwk]; } });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const { port } = await app.listen(0), now = Math.floor(Date.now() / 1000);
  const jwt = (claims, key = privateKey) => { const h = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'cf1' })).toString('base64url'), p = Buffer.from(JSON.stringify({ iss: ZTNA.CG_ZTNA_ISSUER, aud: [ZTNA.CG_ZTNA_AUDIENCE], email: 'sara@acme.example', sub: 'u1', iat: now, exp: now + 300, device_posture: { compliant: true }, ...claims })).toString('base64url'); return `${h}.${p}.${sign('sha256', Buffer.from(`${h}.${p}`), key).toString('base64url')}`; };
  const raw = (p, headers, method = 'GET', body = null) => new Promise((resolve, reject) => { const r = http.request({ host: '127.0.0.1', port, path: p, method, headers }, res => { let b = ''; res.on('data', d => (b += d)).on('end', () => { let j = null; try { j = JSON.parse(b); } catch {} resolve({ status: res.statusCode, body: j, cookie: [].concat(res.headers['set-cookie'] || [])[0] || null }); }); }); r.on('error', reject); if (body) r.write(body); r.end(); });
  const call = (p, { host = 'soc.acme.example', assertion, method = 'GET', data } = {}) => raw(p, { host, ...(assertion ? { 'cf-access-jwt-assertion': assertion } : {}), ...(data ? { 'Content-Type': 'application/json', Origin: `https://${host}` } : {}) }, method, data ? JSON.stringify(data) : null);
  assert.equal((await call('/api/setup/status', { assertion: jwt({}) })).status, 200);
  for (const [why, assertion, host] of [['ztna_assertion_required'], ['device_not_compliant', jwt({ device_posture: { compliant: false } })], ['ztna_audience_mismatch', jwt({ aud: ['another-app'] })], ['ztna_assertion_expired', jwt({ exp: now - 3600 })], ['ztna_invalid_signature', jwt({}, other.privateKey)], ['ztna_issuer_mismatch', jwt({ iss: 'https://evil.cloudflareaccess.com' })], ['host_not_allowed', jwt({}), 'other.acme.example']]) {
    const r = await call('/api/setup/status', { assertion, host }); assert.deepEqual([r.status, r.body?.error], [403, why], why);
  }
  assert.equal(fetches, 1, 'the gateway keys are cached');
  assert.equal((await call('/api/auth/setup', { assertion: jwt({}), method: 'POST', data: { setup_token: 'ztna-setup-token-000001', username: 'admin', password: 'Ztna-Local-Test-2026!x' } })).status, 201, 'the browser origin is the HTTPS gateway host');
  const login = await call('/api/auth/login', { assertion: jwt({}), method: 'POST', data: { username: 'admin', password: 'Ztna-Local-Test-2026!x' } });
  assert.equal(login.status, 200); assert.match(login.cookie, /Secure/, 'the session cookie is Secure behind the HTTPS gateway');
  const audit = app.store.all("SELECT details FROM audit WHERE action='access.path'").map(r => JSON.parse(r.details)); assert.deepEqual(audit.at(-1), { via: 'ztna', identity: 'sara@acme.example', device: true });
  const me = (await raw('/api/remote-access', { host: 'soc.acme.example', 'cf-access-jwt-assertion': jwt({}), cookie: login.cookie.split(';')[0] })).body;
  assert.equal(me.mode, 'ztna'); assert.deepEqual(me.this_request, { via: 'ztna', identity: 'sara@acme.example', device: true }); assert.equal(me.ztna.device_claim, 'device_posture.compliant');
  assert.equal((await raw('/api/setup/status', { host: `localhost:${port}` })).status, 200, 'the local console still works on the machine itself');
});

test('the app installs on Windows desktop, tablets and phones as a standalone web app (CG-053)', async t => {
  const m = JSON.parse(fs.readFileSync(new URL('../public/manifest.webmanifest', import.meta.url), 'utf8')), html = fs.readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.deepEqual([m.display, m.start_url, m.scope, m.icons[0].src], ['standalone', '/', '/', '/icon.svg']); assert.match(html, /<link rel="manifest" href="\/manifest.webmanifest">/); assert.match(html, /width=device-width/);
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg053pwa-')), app = createApp({ dataDir, setupToken: 'pwa-setup-token-0000001', remoteAccess: {} }); t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const { port } = await app.listen(0), r = await fetch(`http://127.0.0.1:${port}/manifest.webmanifest`);
  assert.equal(r.status, 200); assert.match(r.headers.get('content-type'), /application\/manifest\+json/); assert.match(r.headers.get('content-security-policy'), /manifest-src 'self'/);
});
