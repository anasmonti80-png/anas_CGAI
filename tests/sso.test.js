import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { createApp } from '../server.js';
import { totpCode } from '../lib/auth.js';
import { verifyIdToken } from '../lib/oidc.js';

// A local OpenID provider: discovery, JWKS, and a token endpoint that enforces PKCE S256 like a real provider.
async function mockIdp(t) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 }), other = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig', alg: 'RS256' }, codes = new Map(), seen = { tokenRequests: [] };
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x'), iss = `http://127.0.0.1:${server.address().port}`, json = (s, v) => { res.writeHead(s, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(v)); };
    if (url.pathname === '/.well-known/openid-configuration') return json(200, { issuer: iss, authorization_endpoint: `${iss}/authorize`, token_endpoint: `${iss}/token`, jwks_uri: `${iss}/jwks`, code_challenge_methods_supported: ['S256'] });
    if (url.pathname === '/jwks') return json(200, { keys: [jwk] });
    if (url.pathname === '/token' && req.method === 'POST') { let b = ''; for await (const c of req) b += c; const f = new URLSearchParams(b), entry = codes.get(f.get('code')); seen.tokenRequests.push(Object.fromEntries(f));
      if (!entry || createHash('sha256').update(f.get('code_verifier') || '').digest('base64url') !== entry.challenge || f.get('redirect_uri') !== entry.redirect) return json(400, { error: 'invalid_grant' });
      codes.delete(f.get('code')); return json(200, { token_type: 'Bearer', id_token: entry.idToken }); }
    json(404, {});
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r)); t.after(() => server.close());
  const issuer = `http://127.0.0.1:${server.address().port}`;
  const idToken = (claims, key = privateKey, kid = 'k1') => { const h = Buffer.from(JSON.stringify({ alg: 'RS256', kid, typ: 'JWT' })).toString('base64url'), p = Buffer.from(JSON.stringify(claims)).toString('base64url'); return `${h}.${p}.${sign('sha256', Buffer.from(`${h}.${p}`), key).toString('base64url')}`; };
  // Plays the browser + provider: follows /api/sso/start, "authenticates" with the given claims and returns the callback URL.
  const authorize = (startLocation, claimsFn, opts = {}) => { const u = new URL(startLocation), code = `code-${Math.random().toString(36).slice(2)}`, now = Math.floor(Date.now() / 1000);
    codes.set(code, { challenge: opts.challenge ?? u.searchParams.get('code_challenge'), redirect: u.searchParams.get('redirect_uri'), idToken: idToken({ iss: issuer, aud: u.searchParams.get('client_id'), iat: now, exp: now + 300, auth_time: now, nonce: u.searchParams.get('nonce'), ...claimsFn(u) }, opts.key, opts.kid) });
    return `${u.searchParams.get('redirect_uri')}?code=${code}&state=${encodeURIComponent(opts.state ?? u.searchParams.get('state'))}`; };
  return { issuer, authorize, idToken, other, seen, privateKey };
}

test('OIDC SSO signs users in only with a verified, MFA-backed ID token and maps IdP groups to the least role and site scope (CG-052)', async t => {
  const idp = await mockIdp(t), dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg052sso-')), app = createApp({ dataDir, setupToken: 'sso-setup-token-0000001', tenant: 'tenant-a' });
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const { port } = await app.listen(0), base = `http://localhost:${port}`;
  const req = async (p, { method = 'GET', data, cookie, csrf } = {}) => { const r = await fetch(base + p, { method, redirect: 'manual', headers: { ...(data ? { 'Content-Type': 'application/json', Origin: base } : {}), ...(cookie ? { Cookie: cookie, 'X-CSRF-Token': csrf } : {}) }, body: data ? JSON.stringify(data) : undefined }); const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch {} return { status: r.status, headers: r.headers, data: json }; };
  const password = 'Sso-Local-Admin-2026!x';
  assert.equal((await req('/api/auth/setup', { method: 'POST', data: { setup_token: 'sso-setup-token-0000001', username: 'admin', password } })).status, 201);
  let r = await req('/api/auth/login', { method: 'POST', data: { username: 'admin', password } }); const admin = { cookie: r.headers.get('set-cookie').split(';')[0], csrf: r.data.csrf };
  const seed = (await req('/api/auth/mfa/enroll', { method: 'POST', data: {}, ...admin })).data.seed; assert.equal((await req('/api/auth/mfa/confirm', { method: 'POST', data: { code: totpCode(seed) }, ...admin })).status, 200);
  assert.equal((await req('/api/sso/status')).data.enabled, false); assert.equal((await req('/api/sso/start')).status, 404);
  const config = { issuer: idp.issuer, client_id: 'cyberguard-local', client_secret_env: 'CG_SSO_CLIENT_SECRET', tenant: 'tenant-a', role_map: [{ group: 'soc-analysts-riyadh', role: 'analyst', tenant: 'tenant-a', sites: ['riyadh'] }, { group: 'soc-viewers', role: 'viewer', tenant: 'tenant-a', sites: ['*'] }, { group: 'soc-admins', role: 'admin', tenant: 'tenant-a', sites: ['*'] }] };
  assert.equal((await req('/api/sso/config', { method: 'POST', data: { ...config, client_secret_env: 'not a name' }, ...admin })).status, 400, 'only the name of an environment variable is stored, never a secret');
  assert.equal((await req('/api/sso/config', { method: 'POST', data: { ...config, issuer: 'http://idp.example.com' }, ...admin })).status, 400, 'a remote provider must use HTTPS');
  assert.equal((await req('/api/sso/config', { method: 'POST', data: { ...config, role_map: [{ group: 'x', role: 'viewer', tenant: 'tenant-b' }] }, ...admin })).data.error, 'sso_role_map_0_tenant_is_not_this_installation', 'a group cannot grant access to another tenant');
  r = await req('/api/sso/config', { method: 'POST', data: config, ...admin }); assert.equal(r.status, 200, JSON.stringify(r.data)); assert.equal(r.data.enabled, true);
  const login = async (claimsFn, opts) => { const start = await req('/api/sso/start'); assert.equal(start.status, 302); const loc = start.headers.get('location'), u = new URL(loc);
    assert.deepEqual([u.searchParams.get('code_challenge_method'), u.searchParams.get('response_type'), u.searchParams.get('scope')], ['S256', 'code', 'openid profile email']); assert.ok(u.searchParams.get('nonce') && u.searchParams.get('state'));
    const cb = await fetch(idp.authorize(loc, claimsFn, opts).replace(/^http:\/\/localhost:\d+/, base), { redirect: 'manual' }); return { status: cb.status, location: cb.headers.get('location'), cookie: cb.headers.get('set-cookie')?.split(';')[0] || null, startUrl: loc }; };
  // A good login: MFA claim present, group mapped to analyst scoped to one site.
  const good = await login(() => ({ sub: 'user-1', preferred_username: 'sara@tenant-a.example', tid: 'tenant-a', amr: ['pwd', 'mfa'], groups: ['soc-analysts-riyadh', 'soc-viewers'] }));
  assert.equal(good.location, '/'); assert.ok(good.cookie);
  const me = await req('/api/auth/me', { cookie: good.cookie }); assert.equal(me.data.user.role, 'analyst', 'the highest mapped role, not admin'); assert.equal(me.data.user.mfa.recent, true, 'the provider MFA counts as a recent second factor');
  assert.ok(!idp.seen.tokenRequests.at(-1).client_secret, 'no secret is sent when the environment variable is not set');
  assert.equal((await req('/api/auth/login', { method: 'POST', data: { username: 'sara@tenant-a.example', password: 'anything-at-all-123' } })).status, 401, 'SSO users cannot use a local password');
  const scope = app.store.get('SELECT * FROM user_scopes WHERE user_id=?', me.data.user.id); assert.deepEqual([scope.tenant, JSON.parse(scope.sites), scope.source], ['tenant-a', ['riyadh'], 'sso']);
  // Every rejection reason, each ending at the login page with an error and no session.
  const reasons = {
    sso_mfa_required: [() => ({ sub: 'user-2', tid: 'tenant-a', amr: ['pwd'], groups: ['soc-viewers'] })],
    sso_tenant_mismatch: [() => ({ sub: 'user-3', tid: 'tenant-b', amr: ['mfa'], groups: ['soc-viewers'] })],
    sso_no_role_mapping: [() => ({ sub: 'user-4', tid: 'tenant-a', amr: ['mfa'], groups: ['marketing'] })],
    sso_invalid_signature: [() => ({ sub: 'user-5', tid: 'tenant-a', amr: ['mfa'], groups: ['soc-viewers'] }), { key: idp.other.privateKey }],
    sso_nonce_mismatch: [() => ({ sub: 'user-6', tid: 'tenant-a', amr: ['mfa'], groups: ['soc-viewers'], nonce: 'replayed-nonce' })],
    sso_audience_mismatch: [() => ({ sub: 'user-7', tid: 'tenant-a', amr: ['mfa'], groups: ['soc-viewers'], aud: 'another-app' })],
    sso_token_expired: [() => ({ sub: 'user-8', tid: 'tenant-a', amr: ['mfa'], groups: ['soc-viewers'], exp: Math.floor(Date.now() / 1000) - 3600 })],
    sso_provider_http_400: [() => ({ sub: 'user-9', tid: 'tenant-a', amr: ['mfa'], groups: ['soc-viewers'] }), { challenge: 'not-the-real-challenge' }],
    sso_state_invalid_or_expired: [() => ({ sub: 'user-10', tid: 'tenant-a', amr: ['mfa'], groups: ['soc-viewers'] }), { state: 'forged-state' }] };
  for (const [reason, [fn, opts]] of Object.entries(reasons)) { const x = await login(fn, opts); assert.equal(x.location, `/#sso_error=${reason}`, reason); assert.equal(x.cookie, null, reason); }
  // State is single use: replaying a good callback fails.
  const start = await req('/api/sso/start'), cbUrl = idp.authorize(start.headers.get('location'), () => ({ sub: 'user-1', tid: 'tenant-a', amr: ['mfa'], groups: ['soc-viewers'] })).replace(/^http:\/\/localhost:\d+/, base);
  assert.equal((await fetch(cbUrl, { redirect: 'manual' })).headers.get('location'), '/'); assert.equal((await fetch(cbUrl, { redirect: 'manual' })).headers.get('location'), '/#sso_error=sso_state_invalid_or_expired');
  const denied = app.store.all("SELECT details FROM audit WHERE action='sso.denied'").map(x => JSON.parse(x.details).reason); for (const reason of ['sso_mfa_required', 'sso_tenant_mismatch', 'sso_no_role_mapping', 'sso_invalid_signature']) assert.ok(denied.includes(reason), `audited ${reason}`);
});

test('ID token verification also accepts the acr route to MFA and rejects unsupported algorithms (CG-052)', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 }), jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'a' }, now = Date.now(), s = Math.floor(now / 1000);
  const tok = (claims, alg = 'RS256') => { const h = Buffer.from(JSON.stringify({ alg, kid: 'a' })).toString('base64url'), p = Buffer.from(JSON.stringify(claims)).toString('base64url'); return `${h}.${p}.${sign('sha256', Buffer.from(`${h}.${p}`), privateKey).toString('base64url')}`; };
  const claims = { iss: 'https://idp', aud: 'c', sub: 'x', exp: s + 60, iat: s, nonce: 'n', acr: 'urn:example:mfa' }, opts = { keys: [jwk], issuer: 'https://idp', clientId: 'c', nonce: 'n', now, mfaAmr: ['mfa'], mfaAcr: ['urn:example:mfa'] };
  assert.equal(verifyIdToken(tok(claims), opts).sub, 'x');
  assert.throws(() => verifyIdToken(tok(claims, 'none'), opts), /sso_unsupported_algorithm/); assert.throws(() => verifyIdToken(tok(claims, 'HS256'), opts), /sso_unsupported_algorithm/);
  assert.throws(() => verifyIdToken(tok({ ...claims, aud: ['c', 'd'] }), opts), /sso_audience_mismatch/, 'multiple audiences need azp');
});
