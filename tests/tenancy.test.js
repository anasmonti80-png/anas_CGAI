import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createApp } from '../server.js';
import { totpCode } from '../lib/auth.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), TENANTS = path.join(ROOT, 'scripts', 'tenants.js');
// Both ports are held open together before release, so the operating system cannot hand out the same port twice.
const freePorts = async n => { const servers = await Promise.all(Array.from({ length: n }, () => new Promise(r => { const s = net.createServer().listen(0, '127.0.0.1', () => r(s)); }))), ports = servers.map(s => s.address().port); await Promise.all(servers.map(s => new Promise(r => s.close(r)))); return ports; };
const asset = { external_id: 'tenant-host-01', hostname: 'TENANT-01', os_family: 'linux', device_type: 'server', addresses: ['192.0.2.30'] };

test('each tenant is a separate instance with its own data, keys, audit chain and identities (CG-059)', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cg059-tenants-')), [pa, pb] = await freePorts(2);
  const cli = (...a) => execFileSync(process.execPath, [TENANTS, ...a, '--root', root], { encoding: 'utf8', stdio: 'pipe' });
  cli('add', 'acme-bank', '--port', String(pa)); cli('add', 'north-clinic', '--port', String(pb));
  assert.throws(() => cli('add', 'acme-bank', '--port', '45999'), /already exists/); assert.throws(() => cli('add', 'other-co', '--port', String(pa)), /already used by acme-bank/); assert.throws(() => cli('add', 'Bad_ID', '--port', '45998'), /tenant id/);
  assert.deepEqual(JSON.parse(cli('list')).map(x => x.tenant), ['acme-bank', 'north-clinic']);
  const child = spawn(process.execPath, [TENANTS, 'run', '--root', root], { stdio: 'pipe' }); let log = ''; child.stdout.on('data', d => { log += d; });
  t.after(async () => { child.kill('SIGTERM'); await new Promise(r => { if (child.exitCode !== null) r(); else { child.once('exit', r); setTimeout(r, 3000); } }); fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); });
  const health = async port => { for (let i = 0; i < 60; i++) { try { const r = await fetch(`http://127.0.0.1:${port}/api/health`); if (r.ok) return r.json(); } catch {} await new Promise(r => setTimeout(r, 250)); } throw new Error(`tenant on ${port} did not start: ${log}`); };
  await health(pa); await health(pb);
  // Separate data directories: own database, setup token; a user set up in one tenant does not exist in the other.
  const tokenA = fs.readFileSync(path.join(root, 'acme-bank', 'setup-token'), 'utf8').trim(), tokenB = fs.readFileSync(path.join(root, 'north-clinic', 'setup-token'), 'utf8').trim();
  assert.notEqual(tokenA, tokenB);
  const post = (port, p, data) => fetch(`http://127.0.0.1:${port}${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: `http://127.0.0.1:${port}` }, body: JSON.stringify(data) });
  assert.equal((await post(pa, '/api/auth/setup', { setup_token: tokenB, username: 'admin', password: 'Tenant-A-Local-2026!x' })).status, 403, "another tenant's setup token is refused");
  assert.equal((await post(pa, '/api/auth/setup', { setup_token: tokenA, username: 'admin', password: 'Tenant-A-Local-2026!x' })).status, 201);
  assert.equal((await post(pb, '/api/auth/login', { username: 'admin', password: 'Tenant-A-Local-2026!x' })).status, 401, 'tenant A identities do not exist in tenant B');
  assert.equal((await (await fetch(`http://127.0.0.1:${pb}/api/setup/status`)).json()).setup_required, true);
  assert.ok(fs.existsSync(path.join(root, 'acme-bank', 'cyberguard.sqlite')) && fs.existsSync(path.join(root, 'north-clinic', 'cyberguard.sqlite')));
  assert.ok(log.includes('[acme-bank]') && log.includes('[north-clinic]'));
});

test('tenant limits refuse telemetry with an alert, retention ages out activity only, both admin with MFA (CG-059)', async t => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg059-')); let now = Date.now();
  const app = createApp({ dataDir, setupToken: 'tenant-setup-token-00001', clock: () => now, remoteAccess: {}, tenant: 'acme-bank' });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const { port } = await app.listen(0), base = `http://127.0.0.1:${port}`, password = 'Tenant-Local-Test-2026!x';
  const req = async (p, { method = 'GET', data, user } = {}) => { const r = await fetch(base + p, { method, headers: { ...(data ? { 'Content-Type': 'application/json', Origin: base } : {}), ...(user ? { Cookie: user.cookie, 'X-CSRF-Token': user.csrf } : {}) }, body: data ? JSON.stringify(data) : undefined }); return { status: r.status, data: await r.json() }; };
  const login = async (u, extra = {}) => { const r = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ username: u, password, ...extra }) }); assert.equal(r.status, 200); return { cookie: r.headers.get('set-cookie').split(';')[0], csrf: (await r.json()).csrf }; };
  await req('/api/auth/setup', { method: 'POST', data: { setup_token: 'tenant-setup-token-00001', username: 'admin', password } });
  let admin = await login('admin'); const adminId = app.store.get("SELECT id FROM users WHERE username='admin'").id;
  // Defaults before any change; analysts cannot read or change the tenant policy.
  let st = (await req('/api/tenant-policy', { user: admin })).data; assert.equal(st.policy.tenant, 'acme-bank'); assert.equal(st.policy.source, 'default'); assert.equal(st.policy.retention_days, 365); assert.ok(st.claim_ar.includes('مستأجر'));
  await app.auth.createUser(adminId, { username: 'analyst', password, role: 'analyst' }); const analyst = await login('analyst');
  assert.equal((await req('/api/tenant-policy', { user: analyst })).status, 403);
  assert.equal((await req('/api/tenant-policy', { method: 'POST', data: { max_events_per_day: 100 }, user: admin })).status, 403, 'changing limits needs recent MFA');
  const seed = (await req('/api/auth/mfa/enroll', { method: 'POST', data: {}, user: admin })).data.seed; await req('/api/auth/mfa/confirm', { method: 'POST', data: { code: totpCode(seed, now) }, user: admin });
  assert.equal((await req('/api/tenant-policy', { method: 'POST', data: { max_events_per_day: 5 }, user: admin })).data.error, 'invalid_max_events_per_day');
  assert.equal((await req('/api/tenant-policy', { method: 'POST', data: { tenant: 'other' }, user: admin })).data.error, 'unknown_tenant_policy_field', 'the tenant id cannot be changed from inside an instance');
  const set = await req('/api/tenant-policy', { method: 'POST', data: { max_events_per_day: 100, max_sources: 1, retention_days: 30 }, user: admin });
  assert.equal(set.status, 200, JSON.stringify(set.data)); assert.deepEqual([set.data.max_events_per_day, set.data.max_sources, set.data.retention_days, set.data.source], [100, 1, 30, 'administrator']);
  assert.equal(app.store.all("SELECT * FROM audit WHERE action='tenant.policy_changed'").length, 1);
  // Source limit.
  const source = app.domain.createSource(adminId, { name: 'Syslog', stale_seconds: 86400 });
  assert.throws(() => app.domain.createSource(adminId, { name: 'Second', stale_seconds: 86400 }), /tenant_source_limit_exceeded/);
  assert.equal((await req('/api/tenant-policy', { method: 'POST', data: { max_sources: 1, max_assets: 1 }, user: admin })).status, 200);
  // Daily event quota: a batch that crosses it is refused whole (nothing half-stored) and raises a tenant alert.
  const ev = (id, kind, details, observed = now) => ({ event_id: id, kind, observed_at: new Date(observed).toISOString(), asset, details });
  const failed = i => ev(`fail-${i}`, 'auth.failed', { account: 'svc-backup', source_ip: '198.51.100.7', protocol: 'ssh' });
  const ingest = events => app.domain.ingest(adminId, source.id, { schema_version: 'cg.telemetry/1', events });
  assert.equal(ingest([1, 2, 3, 4, 5].map(failed)).accepted, 5, 'five failures raise the brute-force alert whose evidence must be kept');
  assert.equal(ingest(Array.from({ length: 90 }, (_, i) => ev(`log-${i}`, 'auth.failed', { account: `user-${i}`, source_ip: '198.51.100.8', protocol: 'web' }))).accepted, 90);
  const before = app.store.get('SELECT COUNT(*) n FROM events').n;
  assert.throws(() => ingest(Array.from({ length: 10 }, (_, i) => ev(`over-${i}`, 'auth.failed', { account: `over-${i}`, source_ip: '198.51.100.9', protocol: 'web' }))), e => e.code === 'tenant_event_quota_exceeded' && e.status === 429);
  assert.equal(app.store.get('SELECT COUNT(*) n FROM events').n, before, 'the refused batch is rolled back');
  assert.equal(app.store.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-TENANT-LIMIT-059'").n, 1);
  assert.equal(app.store.all("SELECT * FROM audit WHERE action='tenant.limit_reached'").length, 1);
  // Asset limit (1): a new asset is refused.
  now += 86400000; admin = await login('admin', { mfa_code: totpCode(seed, now) });
  assert.throws(() => ingest([{ ...ev('new-asset', 'asset.observed', {}), asset: { ...asset, external_id: 'tenant-host-02', hostname: 'TENANT-02', addresses: ['192.0.2.31'] } }]), /tenant_asset_limit_exceeded/);
  st = (await req('/api/tenant-policy', { user: admin })).data; assert.equal(st.usage.assets, 1); assert.equal(st.utilisation.assets, 100); assert.equal(st.usage.events_today, 0);
  // Retention after 40 days (policy 30): activity aged out, alert evidence and state records kept, and audited.
  ingest([ev('state', 'asset.observed', {})]);
  now += 40 * 86400000; admin = await login('admin', { mfa_code: totpCode(seed, now) });
  const evidence = new Set(JSON.parse(app.store.get("SELECT evidence_ids FROM alerts WHERE rule_id='CG-AUTH-FAILURES-5-IN-5M'").evidence_ids));
  const r = await req('/api/tenant-policy/retention', { method: 'POST', data: {}, user: admin }); assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(r.data.deleted_events, 95 - evidence.size, 'every activity event except the evidence of the open alert is removed');
  const left = app.store.all('SELECT id,kind FROM events'); assert.ok([...evidence].every(id => left.some(e => e.id === id)), 'evidence of the open alert is kept');
  assert.ok(left.some(e => e.kind === 'asset.observed'), 'state records are kept');
  assert.equal(app.store.all("SELECT * FROM audit WHERE action='retention.applied'").length, 1); assert.equal(app.store.verifyAudit().valid, true);
  assert.equal((await req('/api/tenant-policy/retention', { method: 'POST', data: {}, user: analyst })).status, 401);
});
