// CG-107 API and web security check of authorized application URLs.
//   node scripts/web-check.js scan --scope web-scope.json --output web.json
// web-scope.json: { "authorization_ref": "CHG-1234", "owner": "App team", "window_end": "2026-12-31T00:00:00Z",
//   "environment": "staging", "rate_per_second": 5, "probe_requests": 20,
//   "targets": [ { "url": "https://staging.example.org/api/orders", "requires_auth": true, "rate_limit_probe": true } ] }
// Only the listed URLs are requested; rate-limit probes are refused on production.
import fs from 'node:fs';
import { checkScope } from '../lib/web-check.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
if (args[0] !== 'scan' || !flag('--scope') || !flag('--output')) { console.error('usage: web-check.js scan --scope web-scope.json --output web.json'); process.exit(2); }
if (fs.existsSync(flag('--output'))) { console.error('Output already exists. Choose a new private file path.'); process.exit(2); }
try {
  const { scope, results } = await checkScope(JSON.parse(fs.readFileSync(flag('--scope'), 'utf8'))), at = new Date().toISOString();
  fs.writeFileSync(flag('--output'), JSON.stringify({ schema_version: 'cg.telemetry/1', events: [{ event_id: `webcheck:${scope.authorization_ref}:${at}`, kind: 'web.security_check', observed_at: at, asset: { external_id: `web:${new URL(scope.targets[0].url).host}`, hostname: new URL(scope.targets[0].url).host, os_family: 'unknown', device_type: 'server', addresses: [] }, details: { authorization_ref: scope.authorization_ref, owner: scope.owner, environment: scope.environment, results } }] }, null, 2), { mode: 0o600, flag: 'wx' });
  console.log(JSON.stringify({ targets: results.length, findings: results.reduce((n, r) => n + r.findings.length, 0), errors: results.filter(r => r.error).length }));
  process.exit(0);
} catch (e) { console.error(`Refused: ${e.message}`); process.exit(1); }
