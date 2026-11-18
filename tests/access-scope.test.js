import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../server.js';
import { totpCode } from '../lib/auth.js';
import { pathDomain, siteScopedPath } from '../lib/access-scope.js';

test('paths map to functional domains and only investigation paths are open to site-limited users (CG-052)', () => {
  assert.deepEqual(['/api/cloud-posture', '/api/nsg-flow-migration', '/api/network-topology', '/api/identity-directories', '/api/actions/preview', '/api/vulnerability-risk', '/api/alerts'].map(pathDomain), ['cloud', 'cloud', 'network', 'identity', 'response', 'vulnerability', null]);
  assert.deepEqual(['/api/alerts', '/api/alerts/0f8fad5b-d9cb-469f-a165-70867728950e', '/api/cases', '/api/dashboard', '/api/audit', '/api/risk-register'].map(siteScopedPath), [true, true, true, false, false, false]);
});

test('tenant, site and domain scope are enforced on every API call on top of roles (CG-052)', async t => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg052abac-')), app = createApp({ dataDir, setupToken: 'abac-setup-token-00001', tenant: 'acme' });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const { port } = await app.listen(0), base = `http://localhost:${port}`, password = 'Abac-Local-Test-2026!x';
  const req = async (p, { method = 'GET', data, user } = {}) => { const r = await fetch(base + p, { method, headers: { ...(data ? { 'Content-Type': 'application/json', Origin: base } : {}), ...(user ? { Cookie: user.cookie, 'X-CSRF-Token': user.csrf } : {}) }, body: data ? JSON.stringify(data) : undefined }); let json = null; try { json = await r.json(); } catch {} return { status: r.status, data: json }; };
  const login = async username => { const r = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ username, password }) }); assert.equal(r.status, 200, username); return { cookie: r.headers.get('set-cookie').split(';')[0], csrf: (await r.json()).csrf }; };
  assert.equal((await req('/api/auth/setup', { method: 'POST', data: { setup_token: 'abac-setup-token-00001', username: 'admin', password } })).status, 201);
  const admin = await login('admin'), adminId = app.store.get("SELECT id FROM users WHERE username='admin'").id;
  const seed = (await req('/api/auth/mfa/enroll', { method: 'POST', data: {}, user: admin })).data.seed; await req('/api/auth/mfa/confirm', { method: 'POST', data: { code: totpCode(seed) }, user: admin });
  for (const u of ['riyadh-analyst', 'identity-analyst', 'other-tenant']) await app.auth.createUser(adminId, { username: u, password, role: 'analyst' });
  const id = name => app.store.get('SELECT id FROM users WHERE username=?', name).id;
  // Evidence: three hosts, two sites and one unassigned, each with a high finding that raises an alert.
  const src = app.domain.createSource(adminId, { name: 'Sites', stale_seconds: 86400 }), at = new Date().toISOString();
  const host = (ext, site) => ({ external_id: ext, hostname: ext.toUpperCase(), os_family: 'windows', device_type: 'server', addresses: [] });
  const ctx = (ext, site) => ({ event_id: `ctx-${ext}`, kind: 'asset.context', observed_at: at, asset: host(ext), details: { owner: { owner_id: 'it', display_name: 'IT', contact: null }, business_service: 'ERP', service_name: null, site, data_sensitivity: 'internal', maintenance_windows: [], service_criticality: 'medium' } });
  const finding = ext => ({ event_id: `f-${ext}`, kind: 'security.finding', observed_at: at, asset: host(ext), details: { title: `Finding on ${ext}`, severity: 'high', description: 'synthetic' } });
  app.domain.ingest(adminId, src.id, { schema_version: 'cg.telemetry/1', events: [ctx('ryd-1', 'riyadh'), ctx('jed-1', 'jeddah'), finding('ryd-1'), finding('jed-1'), finding('nosite-1')] });
  const alertOf = ext => app.store.get("SELECT a.id FROM alerts a JOIN assets s ON s.id=a.asset_id WHERE s.external_id=? AND a.rule_id='CG-REPORTED-FINDING'", ext).id;
  // Only an all-sites administrator with recent MFA may set scopes, and never their own.
  const set = (user, body) => req('/api/user-scopes', { method: 'POST', data: body, user });
  assert.equal((await set(admin, { user_id: adminId, tenant: 'acme', sites: ['riyadh'], domains: ['*'] })).data.error, 'cannot_change_own_scope');
  assert.equal((await set(admin, { user_id: id('riyadh-analyst'), tenant: 'acme', sites: ['riyadh'], domains: ['teleport'] })).data.error, 'invalid_scope_domains');
  for (const [u, body] of [['riyadh-analyst', { tenant: 'acme', sites: ['riyadh'], domains: ['response'] }], ['identity-analyst', { tenant: 'acme', sites: ['*'], domains: ['identity'] }], ['other-tenant', { tenant: 'globex', sites: ['*'], domains: ['*'] }]]) assert.equal((await set(admin, { user_id: id(u), ...body })).status, 200, u);
  // Site scope: lists and details filtered to Riyadh; organisation-wide views refused.
  const ryd = await login('riyadh-analyst');
  assert.deepEqual((await req('/api/assets', { user: ryd })).data.items.map(a => a.external_id), ['ryd-1']);
  const alerts = (await req('/api/alerts', { user: ryd })).data; assert.equal(alerts.total, 1); assert.equal(alerts.items[0].id, alertOf('ryd-1'));
  assert.ok((await req('/api/events', { user: ryd })).data.items.every(e => e.asset_id === app.store.get("SELECT id FROM assets WHERE external_id='ryd-1'").id));
  assert.equal((await req(`/api/alerts/${alertOf('jed-1')}`, { user: ryd })).status, 404, 'an alert at another site does not exist for this user');
  assert.equal((await req(`/api/alerts/${alertOf('nosite-1')}`, { user: ryd })).status, 404, 'unassigned assets are outside every limited scope');
  for (const p of ['/api/dashboard', '/api/audit', '/api/risk-register', '/api/cloud-posture']) assert.equal((await req(p, { user: ryd })).status, 403, p);
  assert.equal((await req('/api/cases', { method: 'POST', data: { title: 'Mixed sites', alert_ids: [alertOf('ryd-1'), alertOf('jed-1')] }, user: ryd })).data.error, 'outside_site_scope');
  const ov = (await req('/api/scoped-overview', { user: ryd })).data; assert.deepEqual([ov.assets, ov.open_alerts, ov.sites], [1, 1, ['riyadh']]);
  assert.deepEqual((await req('/api/auth/me', { user: ryd })).data.user.scope, { tenant: 'acme', sites: ['riyadh'], domains: ['response'], source: 'admin', restricted: true });
  assert.equal((await set(ryd, { user_id: id('identity-analyst'), tenant: 'acme', sites: ['*'], domains: ['*'] })).status, 403, 'analysts cannot change scopes');
  // Domain scope: identity analyst sees identity areas but not cloud.
  const idn = await login('identity-analyst');
  assert.equal((await req('/api/cloud-posture', { user: idn })).data.error, 'domain_out_of_scope'); assert.equal((await req('/api/identity-directories', { user: idn })).status, 200);
  assert.equal((await req('/api/alerts', { user: idn })).data.total, 3, 'all sites');
  // Tenant scope: a user of another tenant is refused everywhere.
  const other = await login('other-tenant'); assert.equal((await req('/api/auth/me', { user: other })).data.error, 'tenant_scope_mismatch');
  const audit = app.store.all("SELECT details FROM audit WHERE action='user.scope.set'").map(r => JSON.parse(r.details)); assert.equal(audit.length, 3);
});
