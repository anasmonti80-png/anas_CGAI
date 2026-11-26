// CG-154 GCP attack exposure import from Security Command Center findings exported by the owner
// (role roles/securitycenter.findingsViewer; nothing is changed):
//   gcloud scc findings list <organization-id> --location=global --filter='state="ACTIVE"' --format=json > scc.json
//   node scripts/gcp-attack-exposure.js --organization-id <id> --authorization-ref <ref> --tier premium|enterprise|standard|unknown
//        --activation organization|project|unknown --high-value-set yes|no --findings scc.json --output gcp.json
import fs from 'node:fs';
import { parseSccFindings, assessGcpExposure, TIERS, ACTIVATIONS } from '../lib/gcp-attack-exposure.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const org = flag('--organization-id'), auth = flag('--authorization-ref'), out = flag('--output'), tier = flag('--tier') || 'unknown', activation = flag('--activation') || 'unknown', hv = flag('--high-value-set') || 'no';
if (!org || !/^\d{6,20}$/.test(org) || !auth || !out || !flag('--findings') || !TIERS.includes(tier) || !ACTIVATIONS.includes(activation) || !['yes', 'no'].includes(hv)) { console.error('usage: gcp-attack-exposure.js --organization-id <digits> --authorization-ref <ref> --tier premium|enterprise|standard|unknown --activation organization|project|unknown --high-value-set yes|no --findings scc.json --output gcp.json'); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
let findings; try { findings = parseSccFindings(JSON.parse(fs.readFileSync(flag('--findings'), 'utf8').replace(/^﻿/, ''))); } catch (e) { console.error(`Not an SCC findings export: ${e.code || e.message}`); process.exit(2); }
const at = new Date().toISOString(), details = { organization_id: org, authorization_ref: auth, tier, activation, high_value_set: hv === 'yes', findings };
const event = { event_id: `gcp-exposure:${org}:${at}`, kind: 'cloud.gcp_attack_exposure', observed_at: at, asset: { external_id: `gcp:${org}`, hostname: `GCP organization ${org}`, os_family: 'unknown', device_type: 'unknown', addresses: [] }, details };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
const a = assessGcpExposure(details);
console.log(JSON.stringify({ organization: org, available: a.availability.available, counts: a.counts, notes: a.notes.length, output: out }));
