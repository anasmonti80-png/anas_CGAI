// CG-072 External attack surface check of YOUR registered and authorized assets (Linux, Windows or macOS).
//   node scripts/attack-surface.js token                         -> a random value to publish as a DNS TXT record:
//                                                                   cyberguard-verify=<value>   (proves domain ownership)
//   node scripts/attack-surface.js scan --scope scope.json --output easm.json [--nmap]
// scope.json: { "authorization_ref": "CHG-1234", "owner": "IT security", "window_end": "2026-12-31T00:00:00Z",
//   "domains": [ { "name": "example.org", "verification": "dns-txt", "token": "<value>" } ],
//   "networks": [ "203.0.113.0/28" ], "ports": [22, 443, 3389], "rate_per_second": 20 }
// Only addresses inside "networks" are contacted. With --nmap (Linux: apt install nmap) service versions come from nmap
// service detection, run only against those in-scope addresses at the configured rate. Nothing is exploited and no
// credentials are tried. The output is a cg.telemetry/1 file to ingest into CyberGuard (or send with scripts/forwarder.js).
import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import { collect, toTelemetry, runNmap, nmapAvailable } from '../lib/easm.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const [command] = args;
if (command === 'token') { console.log(`cyberguard-verify=${randomBytes(18).toString('base64url')}`); process.exit(0); }
if (command !== 'scan') { console.error('usage: attack-surface.js token | scan --scope scope.json --output easm.json [--nmap]'); process.exit(2); }
const scopeFile = flag('--scope'), output = flag('--output');
if (!scopeFile || !output) { console.error('--scope and --output are required'); process.exit(2); }
if (fs.existsSync(output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(2); }
let nmap = null, tool = 'tcp-connect';
if (args.includes('--nmap')) { const v = await nmapAvailable(); if (!v) { console.error('nmap is not installed (Linux: sudo apt install nmap). Run without --nmap to use TCP connect checks.'); process.exit(1); } nmap = runNmap; tool = 'nmap'; console.error(`Using nmap ${v} service detection on in-scope addresses only.`); }
try {
  const scope = JSON.parse(fs.readFileSync(scopeFile, 'utf8'));
  // CG-100 --ot-exclusions <file>: the exclusions list from GET /api/ot-safety (OT addresses are never probed).
  if (flag('--ot-exclusions')) { const ex = JSON.parse(fs.readFileSync(flag('--ot-exclusions'), 'utf8')); scope.exclusions = [...(scope.exclusions || []), ...(Array.isArray(ex) ? ex : ex.exclusions || [])]; }
  const result = await collect(scope, { nmap, log: m => console.error(`checking ${m}`) });
  fs.writeFileSync(output, JSON.stringify(toTelemetry(result, { tool }), null, 2), { mode: 0o600, flag: 'wx' });
  const findings = result.observations.flatMap(o => o.findings), notProbed = result.observations.flatMap(o => o.not_probed);
  console.log(JSON.stringify({ targets: result.observations.length, open_services: result.observations.reduce((n, o) => n + o.services.length, 0), findings: findings.length, high_or_critical: findings.filter(f => ['high', 'critical'].includes(f.severity)).length, not_probed: notProbed.length, tool, output }, null, 2));
} catch (e) { console.error(`Refused: ${e.message}`); process.exit(1); }
