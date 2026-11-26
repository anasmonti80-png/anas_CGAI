// Operational smoke check: start CyberGuard in a disposable data directory, sign in with MFA, load data through every
// connector with its documented sample inputs, then call every page and read API and fail on any error.
// node scripts/smoke.js            (prints a JSON report; exit code 1 when anything does not work)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createApp } from '../server.js';
import { totpCode } from '../lib/auth.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), FX = p => path.join(ROOT, 'tests', 'fixtures', p), started = Date.now();
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-smoke-')), work = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-smoke-files-'));
const app = createApp({ dataDir, setupToken: 'smoke-setup-token-000000001', remoteAccess: {} }), report = { platform: `${process.platform}-${process.arch}`, node: process.version, checks: [], failures: [] };
const check = (name, ok, detail = null) => { report.checks.push({ name, ok }); if (!ok) report.failures.push({ name, detail }); };
try {
  const { port } = await app.listen(0), base = `http://127.0.0.1:${port}`, password = 'Smoke-Local-Check-2026!x';
  let cookie = null, csrf = null;
  const req = async (p, { method = 'GET', data } = {}) => { const r = await fetch(base + p, { method, redirect: 'manual', headers: { ...(data ? { 'Content-Type': 'application/json', Origin: base } : {}), ...(cookie ? { Cookie: cookie, 'X-CSRF-Token': csrf } : {}) }, body: data ? JSON.stringify(data) : undefined }); const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch {} return { status: r.status, json, text, type: r.headers.get('content-type') || '', attachment: /attachment/i.test(r.headers.get('content-disposition') || '') }; };
  check('health', (await req('/api/health')).status === 200);
  for (const p of ['/', '/app.js', '/dashboard.js', '/styles.css', '/soc.css', '/icon.svg', '/manifest.webmanifest']) { const r = await req(p); check(`static ${p}`, r.status === 200 && r.text.length > 50, r.status); }
  check('setup', (await req('/api/auth/setup', { method: 'POST', data: { setup_token: 'smoke-setup-token-000000001', username: 'admin', password } })).status === 201);
  const login = await fetch(`${base}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ username: 'admin', password }) });
  check('login', login.status === 200); cookie = login.headers.get('set-cookie').split(';')[0]; csrf = (await login.json()).csrf;
  const seed = (await req('/api/auth/mfa/enroll', { method: 'POST', data: {} })).json?.seed; check('mfa enroll', Boolean(seed));
  check('mfa confirm', (await req('/api/auth/mfa/confirm', { method: 'POST', data: { code: totpCode(seed) } })).status === 200);
  // Data through every connector, using each one's documented sample inputs.
  const admin = app.store.get("SELECT id FROM users WHERE username='admin'").id, source = app.domain.createSource(admin, { name: 'Smoke check sources', stale_seconds: 86400 });
  const run = (script, args) => { const out = path.join(work, `${script}-${report.checks.length}-${Math.random().toString(36).slice(2)}.json`); execFileSync(process.execPath, [path.join(ROOT, 'scripts', `${script}.js`), ...args, ...(script === 'firewall-policy-to-telemetry' ? [] : ['--output', out])], { stdio: 'pipe' }); return out; };
  const runs = [
    ['aws-connector', ['inventory', '--input', FX('aws/list-accounts.json'), '--services', FX('aws/services.json'), '--access', FX('aws/access.json')]], ['aws-connector', ['findings-asff', '--input', FX('aws/securityhub-findings.json')]], ['aws-connector', ['security-groups', '--input', FX('aws/security-groups.json'), '--device-ref', 'aws:444455556666:vpc']], ['aws-connector', ['cloudtrail', '--input', FX('aws/cloudtrail.json')]], ['aws-connector', ['vpc-flow', '--input', FX('aws/vpc-flow.txt')]], ['aws-connector', ['resources', '--input', FX('cloud-inventory/aws-resources.json')]],
    ['azure-connector', ['inventory', '--input', FX('azure/subscriptions.json'), '--graph', FX('azure/resource-graph.json'), '--access', FX('azure/access.json')]], ['azure-connector', ['defender-alerts', '--input', FX('azure/defender-alerts.json')]], ['azure-connector', ['nsg', '--input', FX('azure/nsg.json'), '--device-ref', 'azure:prod:web-nsg']], ['azure-connector', ['entra-signins', '--input', FX('azure/entra-signins.json'), '--directory-ref', 'entra:smoke']],
    ['gcp-connector', ['inventory', '--input', FX('gcp/projects.json'), '--subnets', FX('gcp/subnets.json'), '--access', FX('gcp/access.json'), '--scc', 'enabled']], ['gcp-connector', ['scc-findings', '--input', FX('gcp/scc-findings.json')]], ['gcp-connector', ['firewall-rules', '--input', FX('gcp/firewall-rules.json'), '--device-ref', 'gcp:example-prod-1234:default']], ['gcp-connector', ['iam', '--input', FX('gcp/iam-policy.json'), '--project', 'example-prod-1234']],
    ['cloud-access-review', ['aws-root', '--summary', FX('cloud-access/aws-account-summary.json'), '--account', '444455556666']]];
  for (const [script, args] of runs) { try { const file = run(script, args); const r = app.domain.ingest(admin, source.id, JSON.parse(fs.readFileSync(file, 'utf8'))); check(`connector ${script} ${args[0]}`, (r.accepted ?? r.events ?? 1) !== 0); } catch (e) { check(`connector ${script} ${args[0]}`, false, String(e.stderr || e.message).slice(0, 300)); } }
  // Every read API and every list must answer 200 with JSON.
  const routes = [...fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8').matchAll(/p==='(\/api\/[a-z0-9/-]+)'&&method==='GET'/g)].map(m => m[1]).filter(p => !p.startsWith('/api/sso/'));
  for (const p of [...new Set([...routes, '/api/assets', '/api/events', '/api/alerts', '/api/remote-sessions', '/api/cases', '/api/actions', '/api/audit', '/api/sso/status', '/api/cloud-posture?provider=azure', '/api/cloud-posture?provider=gcp'])]) { const r = await req(p), ndjsonOk = r.type.includes('ndjson') ? r.text.trim().split('\n').every(l => { try { JSON.parse(l); return true; } catch { return false; } }) : true; check(`GET ${p}`, r.status === 200 && (r.json !== null || (r.attachment && r.text.length > 0 && ndjsonOk)), r.status === 200 ? (r.attachment ? 'empty or malformed download' : 'not JSON') : `${r.status} ${r.text.slice(0, 120)}`); }
  const alerts = (await req('/api/alerts?limit=100')).json; check('alerts raised from connector data', alerts.total >= 10, alerts.total);
  const first = alerts.items[0]; check('alert detail', (await req(`/api/alerts/${first.id}`)).status === 200); check('AI analysis of an alert', (await req(`/api/ai-analysis/${first.id}`)).status === 200);
  check('analyst disposition of an alert', (await req(`/api/alerts/${first.id}/disposition`, { method: 'POST', data: { disposition: 'true-positive' } })).status === 200); check('quality metrics measured after triage', (await req('/api/quality-metrics')).json?.detection_quality?.precision === 1);
  check('audit chain intact', (await req('/api/audit/verify')).json?.valid === true);
  report.counts = { alerts: alerts.total, assets: (await req('/api/assets')).json.total, events: (await req('/api/events')).json.total };
} catch (e) { check('smoke run', false, e.stack?.slice(0, 500)); }
finally { await app.close(); fs.rmSync(dataDir, { recursive: true, force: true }); fs.rmSync(work, { recursive: true, force: true }); }
report.passed = report.failures.length === 0; report.total = report.checks.length; report.seconds = Math.round((Date.now() - started) / 100) / 10; delete report.checks;
console.log(JSON.stringify(report, null, 2)); process.exit(report.passed ? 0 : 1);
