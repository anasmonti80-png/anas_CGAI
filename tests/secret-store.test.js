import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../server.js';
import { totpCode } from '../lib/auth.js';

const VALUE = 'cg055-synthetic-connector-token-7f3a9b';

test('connector secrets are encrypted at rest, write-only, released only to delegated sources and rotated on schedule (CG-055)', async t => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg055-')); let now = Date.now();
  const app = createApp({ dataDir, setupToken: 'secret-setup-token-00001', clock: () => now, remoteAccess: {} });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const { port } = await app.listen(0), base = `http://127.0.0.1:${port}`, password = 'Secret-Local-Test-2026!x';
  const req = async (p, { method = 'GET', data, user, bearer } = {}) => { const r = await fetch(base + p, { method, headers: { ...(data ? { 'Content-Type': 'application/json', Origin: base } : {}), ...(user ? { Cookie: user.cookie, 'X-CSRF-Token': user.csrf } : {}), ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}) }, body: data ? JSON.stringify(data) : undefined }); let j = null; try { j = await r.json(); } catch {} return { status: r.status, data: j }; };
  const login = async u => { const r = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ username: u, password }) }); assert.equal(r.status, 200); return { cookie: r.headers.get('set-cookie').split(';')[0], csrf: (await r.json()).csrf }; };
  await req('/api/auth/setup', { method: 'POST', data: { setup_token: 'secret-setup-token-00001', username: 'admin', password } });
  const admin = await login('admin'), adminId = app.store.get("SELECT id FROM users WHERE username='admin'").id;
  const seed = (await req('/api/auth/mfa/enroll', { method: 'POST', data: {}, user: admin })).data.seed; await req('/api/auth/mfa/confirm', { method: 'POST', data: { code: totpCode(seed, now) }, user: admin });
  await app.auth.createUser(adminId, { username: 'analyst', password, role: 'analyst' }); const analyst = await login('analyst');
  const connector = app.domain.createSource(adminId, { name: 'Cisco response connector', stale_seconds: 3600, source_type: 'response-connector' }), reader = app.domain.createSource(adminId, { name: 'Syslog reader', stale_seconds: 3600, source_type: 'network-collector' });
  // Store: admin with recent MFA; the response never contains the value.
  const body = { ref: 'cisco-ise-ers', kind: 'api-token', value: VALUE, purpose: 'ISE ANC quarantine jobs (CG-041)', rotation_days: 30, delegated_sources: [connector.id] };
  assert.equal((await req('/api/secrets', { method: 'POST', data: body, user: analyst })).status, 403, 'analysts cannot manage secrets');
  const put = await req('/api/secrets', { method: 'POST', data: body, user: admin }); assert.equal(put.status, 201, JSON.stringify(put.data));
  assert.ok(!JSON.stringify(put.data).includes(VALUE)); assert.equal(put.data.status, 'current'); assert.deepEqual(put.data.delegated_sources.map(s => s.name), ['Cisco response connector']);
  const listed = await req('/api/secrets', { user: admin }); assert.ok(!JSON.stringify(listed.data).includes(VALUE)); assert.equal(listed.data.items[0].version, 1);
  assert.equal((await req('/api/secrets', { user: analyst })).status, 403);
  // At rest: neither the database nor the audit chain holds the value; the key lives in its own owner-only file.
  const row = app.store.get("SELECT * FROM secrets WHERE ref='cisco-ise-ers'"); assert.ok(!row.cipher.includes(VALUE) && !Buffer.from(row.cipher, 'base64url').toString('latin1').includes(VALUE));
  assert.ok(!app.store.all('SELECT details FROM audit').some(r => r.details.includes(VALUE)), 'the audit chain never contains a secret');
  const keyFile = path.join(dataDir, 'cyberguard.db.secret-key'), dbFiles = fs.readdirSync(dataDir); assert.ok(dbFiles.some(f => f.endsWith('.secret-key')), dbFiles.join(','));
  for (const f of dbFiles.filter(f => !f.endsWith('-key'))) assert.ok(!fs.readFileSync(path.join(dataDir, f)).includes(Buffer.from(VALUE)), `${f} holds no plaintext`);
  // Release: only to the delegated source, with its own token and a purpose; audited without the value.
  const ok = await req(`/api/sources/${connector.id}/secrets/cisco-ise-ers`, { method: 'POST', data: { purpose: 'fetch approved ANC job' }, bearer: connector.token });
  assert.equal(ok.status, 200); assert.equal(ok.data.value, VALUE);
  assert.equal((await req(`/api/sources/${reader.id}/secrets/cisco-ise-ers`, { method: 'POST', data: { purpose: 'curious' }, bearer: reader.token })).data.error, 'secret_not_delegated_to_this_source');
  assert.equal((await req(`/api/sources/${connector.id}/secrets/cisco-ise-ers`, { method: 'POST', data: { purpose: 'x' }, bearer: 'not-the-token' })).status, 401);
  const released = app.store.all("SELECT actor,details FROM audit WHERE action='secret.released'"); assert.equal(released.length, 1); assert.equal(released[0].actor, `source:${connector.id}`); assert.match(released[0].details, /fetch approved ANC job/);
  // Tampering with the ciphertext is detected (authenticated encryption).
  const tampered = row.cipher.slice(0, -4) + (row.cipher.endsWith('AAAA') ? 'BBBB' : 'AAAA'); app.store.run("UPDATE secrets SET cipher=? WHERE ref='cisco-ise-ers'", tampered);
  assert.throws(() => app.secrets.release(connector.id, 'cisco-ise-ers', 'x'), /unable to authenticate|Unsupported state/); app.store.run("UPDATE secrets SET cipher=? WHERE ref='cisco-ise-ers'", row.cipher);
  // Rotation: overdue after 30 days raises an alert; rotating creates version 2 and clears it.
  now += 31 * 86400000; assert.equal(app.secrets.meta('cisco-ise-ers').status, 'rotation-overdue'); app.checkSecretRotation();
  assert.equal(app.store.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-SECRET-ROTATION-055'").n, 1);
  const r2 = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ username: 'admin', password, mfa_code: totpCode(seed, now) }) }); assert.equal(r2.status, 200, 'sessions do not survive a month; sign in again with MFA');
  const admin2 = { cookie: r2.headers.get('set-cookie').split(';')[0], csrf: (await r2.json()).csrf };
  const rotated = await req('/api/secrets', { method: 'POST', data: { ...body, value: `${VALUE}-v2` }, user: admin2 }); assert.deepEqual([rotated.data.version, rotated.data.status], [2, 'current']);
  assert.equal((await req(`/api/sources/${connector.id}/secrets/cisco-ise-ers`, { method: 'POST', data: { purpose: 'after rotation' }, bearer: connector.token })).data.value, `${VALUE}-v2`);
  // Revocation erases the material and every delegation.
  assert.equal((await req('/api/secrets/cisco-ise-ers/revoke', { method: 'POST', data: {}, user: admin2 })).data.status, 'revoked');
  assert.equal((await req(`/api/sources/${connector.id}/secrets/cisco-ise-ers`, { method: 'POST', data: { purpose: 'after revoke' }, bearer: connector.token })).status, 404);
  assert.deepEqual({ ...app.store.get("SELECT cipher,wrapped_key FROM secrets WHERE ref='cisco-ise-ers'") }, { cipher: '', wrapped_key: '' });
  assert.equal((await req('/api/secrets', { method: 'POST', data: { ...body, ref: 'Bad Ref!' }, user: admin2 })).data.error, 'invalid_secret_ref');
  assert.equal((await req('/api/secrets', { method: 'POST', data: { ...body, ref: 'no-delegation', delegated_sources: [] }, user: admin2 })).data.error, 'secret_requires_delegated_sources');
});
