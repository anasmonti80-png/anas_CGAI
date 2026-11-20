import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { validateWebScope, checkScope } from '../lib/web-check.js';
import { createApp } from '../server.js';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), future = new Date(Date.now() + 3600000).toISOString();
const listen = s => new Promise(r => s.listen(0, '127.0.0.1', () => r(s.address().port)));

test('the web check scope is authorized, current, URL-listed and refuses rate probes on production (CG-107)', () => {
  const ok = { authorization_ref: 'CHG-WEB-107', owner: 'App team', window_end: future, environment: 'staging', targets: [{ url: 'https://staging.example.org/api/orders', rate_limit_probe: true }] };
  assert.equal(validateWebScope(ok).probe_requests, 20);
  assert.throws(() => validateWebScope({ ...ok, environment: 'production' }), /rate limit probes are refused on production/);
  assert.throws(() => validateWebScope({ ...ok, window_end: '2020-01-01T00:00:00Z' }), /window has ended/);
  assert.throws(() => validateWebScope({ ...ok, targets: [{ url: 'ftp://x.example' }] }), /only http and https/);
});

test('a weak API is found out and CyberGuard itself passes; evidence keeps no query strings and raises alerts (CG-107)', async t => {
  let hits = 0;
  const weak = http.createServer((req, res) => { hits++; res.setHeader('Server', 'nginx/1.18.0'); if (req.headers.origin) { res.setHeader('Access-Control-Allow-Origin', req.headers.origin); res.setHeader('Access-Control-Allow-Credentials', 'true'); } res.setHeader('Set-Cookie', 'session=abc; Path=/'); res.setHeader('Content-Type', 'application/json'); res.end('{"orders":[1,2,3]}'); });
  const limited = http.createServer((req, res) => { hits++; if (hits > 30) { res.statusCode = 429; res.setHeader('Retry-After', '1'); } res.setHeader('X-Content-Type-Options', 'nosniff'); res.end('ok'); });
  const wp = await listen(weak), lp = await listen(limited); t.after(() => { for (const s of [weak, limited]) { s.closeAllConnections(); s.close(); } });
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg107-')), app = createApp({ dataDir, setupToken: 'web-check-setup-token-01', remoteAccess: {} }); const { port: cp } = await app.listen(0);
  t.after(async () => { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); });
  const scope = { authorization_ref: 'CHG-WEB-107', owner: 'App team', window_end: future, environment: 'test', rate_per_second: 20, probe_requests: 10, targets: [
    { url: `http://127.0.0.1:${wp}/api/orders?api_key=SECRET123`, requires_auth: true, rate_limit_probe: true },
    { url: `http://127.0.0.1:${lp}/api/ping`, rate_limit_probe: true },
    { url: `http://127.0.0.1:${cp}/api/alerts`, requires_auth: true }, { url: `http://127.0.0.1:${cp}/` }] };
  const { results } = await checkScope(scope), [w, l, cgApi, cgPage] = results;
  assert.deepEqual(w.findings.map(f => f.id).sort(), ['api-key-in-url', 'cookie-flags:session', 'cors-reflects-origin', 'missing-authentication', 'no-nosniff', 'no-rate-limit', 'server-version-disclosed']);
  assert.equal(w.findings.find(f => f.id === 'cors-reflects-origin').severity, 'high'); assert.equal(w.url, `http://127.0.0.1:${wp}/api/orders`, 'the query string (and its key) is not kept');
  hits = 25; const again = (await checkScope({ ...scope, targets: [scope.targets[1]] })).results[0]; assert.equal(again.rate_limit_probe.limited, true); assert.ok(!again.findings.some(f => f.id === 'no-rate-limit'));
  assert.equal(cgApi.status, 401); assert.deepEqual(cgApi.findings, [], 'CyberGuard API requires authentication and sends no permissive CORS');
  assert.deepEqual(cgPage.findings, [], 'CyberGuard pages send CSP, nosniff and frame protection');
  // CyberGuard rate limits unauthenticated API requests: it advertises the limit and refuses the 121st request in a minute.
  const cgHealth = (await checkScope({ ...scope, targets: [{ url: `http://127.0.0.1:${cp}/api/health`, rate_limit_probe: true }] })).results[0]; assert.equal(cgHealth.rate_limit_probe.limited, true);
  const codes = []; for (let i = 0; i < 125; i++) codes.push((await fetch(`http://127.0.0.1:${cp}/api/setup/status`)).status); assert.ok(codes.includes(429), 'an unauthenticated flood is refused'); assert.ok(codes.slice(0, 100).every(c => c === 200));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg107-cli-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dir, 'scope.json'), JSON.stringify({ ...scope, targets: [scope.targets[0]] })); const out = path.join(dir, 'web.json');
  // Asynchronous: the target server runs in this process, so a synchronous child would deadlock it.
  await promisify(execFile)(process.execPath, [path.join(ROOT, 'scripts/web-check.js'), 'scan', '--scope', path.join(dir, 'scope.json'), '--output', out], { timeout: 60000 }); assert.ok(!fs.readFileSync(out, 'utf8').includes('SECRET123'));
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, { clock: () => Date.now() });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  d.ingest('admin-a', d.createSource('admin-a', { name: 'Web checks', stale_seconds: 86400 }).id, JSON.parse(fs.readFileSync(out, 'utf8')));
  assert.equal(s.get("SELECT COUNT(*) n FROM alerts WHERE rule_id='CG-WEB-107'").n, 5, 'medium and higher findings alert');
  const v = d.webSecurity(); assert.equal(v.targets.length, 1); assert.ok(v.claim_ar.includes('لا زحف'));
});
