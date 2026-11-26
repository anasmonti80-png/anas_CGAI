// CG-146 Microsoft 365 baseline assessment import. CyberGuard does not sign in to the tenant. The owner runs CISA
// ScubaGear with read-only roles where they exist (Global Reader; see docs/OPERATIONS_AR.md) and imports its JSON:
//   Invoke-SCuBA -ProductNames * -OutPath <dir>
//   node scripts/m365-baseline.js --scuba <dir>/ScubaResults_<uuid>.json --tenant-ref <ref> --authorization-ref <ref> --output m365.json
import fs from 'node:fs';
import { parseScubaResults, summarize } from '../lib/m365-baseline.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const file = flag('--scuba'), tenant = flag('--tenant-ref'), auth = flag('--authorization-ref'), out = flag('--output');
if (!file || !tenant || !auth || !out) { console.error('usage: m365-baseline.js --scuba ScubaResults_<uuid>.json --tenant-ref <ref> --authorization-ref <ref> --output m365.json'); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
let r; try { r = parseScubaResults(fs.readFileSync(file, 'utf8').replace(/^﻿/, '')); } catch (e) { console.error(`Not a ScubaGear results file: ${e.code || e.message}`); process.exit(2); }
if (r.controls.length > 2000) { console.error('Too many controls in one file.'); process.exit(2); }
const at = new Date().toISOString(), details = { tenant_ref: tenant, authorization_ref: auth, ...r };
const event = { event_id: `m365-baseline:${tenant}:${r.report_uuid || at}`, kind: 'identity.m365_baseline', observed_at: r.assessed_at && !Number.isNaN(Date.parse(r.assessed_at)) ? new Date(r.assessed_at).toISOString() : at,
  asset: { external_id: `m365:${tenant}`, hostname: `Microsoft 365 ${tenant}`, os_family: 'unknown', device_type: 'unknown', addresses: [] }, details };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
const s = summarize(r.controls, r.products_assessed);
console.log(JSON.stringify({ tenant, tool_version: r.tool_version, controls: r.controls.length, shall_deviations: s.shall_deviations, should_deviations: s.should_deviations, products_not_assessed: s.products_not_assessed, output: out }));
