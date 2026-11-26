// CG-147 Google Workspace baseline import. CyberGuard does not sign in to the domain. The owner runs CISA ScubaGoggles
// (Super Admin; see docs/OPERATIONS_AR.md for its scopes) and imports the ScubaResults JSON of the run directory:
//   scubagoggles gws --outputpath <dir>
//   node scripts/gws-baseline.js --scubagoggles <dir>/.../ScubaResults.json --domain-ref <ref> --authorization-ref <ref>
//        --edition enterprise-plus|enterprise-standard|business-plus|...|unknown --output gws.json
import fs from 'node:fs';
import { parseScubaGoggles, EDITIONS, PRODUCTS } from '../lib/gws-baseline.js';
import { summarize } from '../lib/m365-baseline.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const file = flag('--scubagoggles'), domain = flag('--domain-ref'), auth = flag('--authorization-ref'), out = flag('--output'), edition = flag('--edition') || 'unknown';
if (!file || !domain || !auth || !out) { console.error('usage: gws-baseline.js --scubagoggles ScubaResults.json --domain-ref <ref> --authorization-ref <ref> [--edition <edition>] --output gws.json'); process.exit(2); }
if (!EDITIONS.includes(edition)) { console.error(`Unknown edition. Use one of: ${EDITIONS.join(', ')}`); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
let r; try { r = parseScubaGoggles(fs.readFileSync(file, 'utf8').replace(/^﻿/, ''), { edition }); } catch (e) { console.error(`Not a ScubaGoggles results file: ${e.code || e.message}`); process.exit(2); }
if (r.controls.length > 2000) { console.error('Too many controls in one file.'); process.exit(2); }
const at = new Date().toISOString(), details = { domain_ref: domain, authorization_ref: auth, ...r };
const event = { event_id: `gws-baseline:${domain}:${r.report_uuid || at}`, kind: 'identity.gws_baseline', observed_at: r.assessed_at && !Number.isNaN(Date.parse(r.assessed_at)) ? new Date(r.assessed_at).toISOString() : at,
  asset: { external_id: `gws:${domain}`, hostname: `Google Workspace ${domain}`, os_family: 'unknown', device_type: 'unknown', addresses: [] }, details };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
const s = summarize(r.controls, r.products_assessed, PRODUCTS);
console.log(JSON.stringify({ domain, edition: r.edition, tool_version: r.tool_version, controls: r.controls.length, shall_deviations: s.shall_deviations, license_dependent: s.license_dependent, no_log_events: s.no_log_events, output: out }));
