// CG-155 AWS multi-account and multi-Region completeness import (read-only exports by the owner; nothing is enabled):
//   aws account list-regions --account-id <id> > regions-<id>.json            (one per account; organization with all features)
//   hubs.json (owner): [{ "account_id", "region", "enabled_at" }] Security Hub CSPM enablement per account and Region
//   aggregation.json (owner): { "home_region": "us-east-1", "linked_regions": ["eu-west-1"] }
//   node scripts/aws-region-completeness.js --organization-ref <ref> --authorization-ref <ref> --regions <id>=regions-<id>.json [...]
//        [--hubs hubs.json] [--aggregation aggregation.json] --output regions.json
// Service status per account and Region comes from the AWS account inventory (scripts/aws-connector.js, CG-046).
import fs from 'node:fs';
import { parseListRegions } from '../lib/aws-completeness.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; }, all = n => args.flatMap((a, i) => a === n ? [args[i + 1]] : []);
const org = flag('--organization-ref'), auth = flag('--authorization-ref'), out = flag('--output');
if (!org || !auth || !out || !all('--regions').length) { console.error('usage: aws-region-completeness.js --organization-ref <ref> --authorization-ref <ref> --regions <account-id>=list-regions.json [...] [--hubs f] [--aggregation f] --output f'); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
const read = f => JSON.parse(fs.readFileSync(f, 'utf8').replace(/^﻿/, ''));
let accounts_regions, hubs = [], aggregation = null;
try {
  accounts_regions = all('--regions').map(spec => { const [id, file] = spec.split('='); return parseListRegions(read(file), id); });
  if (flag('--hubs')) { hubs = read(flag('--hubs')); if (!Array.isArray(hubs) || hubs.some(h => !/^\d{12}$/.test(String(h.account_id)) || !h.region || Number.isNaN(Date.parse(h.enabled_at)))) throw Object.assign(new Error('hubs'), { code: 'invalid_hubs' }); }
  if (flag('--aggregation')) { aggregation = read(flag('--aggregation')); if (!aggregation.home_region || !Array.isArray(aggregation.linked_regions)) throw Object.assign(new Error('agg'), { code: 'invalid_aggregation' }); }
} catch (e) { console.error(`Invalid export: ${e.code || e.message}`); process.exit(2); }
const at = new Date().toISOString(), details = { organization_ref: org, authorization_ref: auth, accounts_regions, hubs: hubs.map(h => ({ account_id: String(h.account_id), region: String(h.region), enabled_at: new Date(h.enabled_at).toISOString() })), aggregation: aggregation && { home_region: String(aggregation.home_region), linked_regions: aggregation.linked_regions.map(String) } };
const event = { event_id: `aws-regions:${org}:${at}`, kind: 'cloud.aws_region_status', observed_at: at, asset: { external_id: `aws-org:${org}`, hostname: `AWS organization ${org}`, os_family: 'unknown', device_type: 'unknown', addresses: [] }, details };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ organization: org, accounts: accounts_regions.length, enabled_regions: accounts_regions.reduce((n, a) => n + a.regions.filter(r => r.opt === 'ENABLED' || r.opt === 'ENABLED_BY_DEFAULT').length, 0), output: out }));
