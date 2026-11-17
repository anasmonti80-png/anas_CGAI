// CG-041 Cisco connector. Converts Catalyst Center, Secure Firewall FMC and IOS XE RESTCONF responses into
// cg.telemetry/1 files, either from a saved API response (--input) or live (--url) with credentials taken only from
// environment variables. Live reads use GET only. The ise-anc-jobs mode applies ISE ANC policies only for jobs that
// CyberGuard has approved for this connector source, and reports the result back. Nothing is uploaded except job results.
//
// node scripts/cisco-connector.js catalyst-inventory|catalyst-topology|catalyst-health|fmc-rules|iosxe-native
//      (--input <saved.json> | --url <https://host/api-path>) --output <file.json> [--device-ref <ref>] [--policy-name <n>] [--model <platform>]
//   live auth: CG_CISCO_TOKEN (Catalyst Center X-Auth-Token / FMC X-auth-access-token) or CG_CISCO_USER + CG_CISCO_PASSWORD (Basic)
// node scripts/cisco-connector.js ise-anc-jobs --cyberguard <https://cg> --source-id <uuid> --ise <https://ise:9060> [--dry-run]
//   auth: CG_SOURCE_TOKEN (CyberGuard connector source), CG_ISE_USER + CG_ISE_PASSWORD (ISE ERS)
import fs from 'node:fs';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { catalystInventory, catalystTopology, catalystHealth, fmcAccessRules, iosxeNative, iseAncRequest } from '../lib/connectors/cisco.js';

const [mode, ...rest] = process.argv.slice(2);
const args = Object.fromEntries(rest.reduce((pairs, v, i, all) => (v.startsWith('--') ? [...pairs, [v.slice(2), all[i + 1] && !all[i + 1].startsWith('--') ? all[i + 1] : true]] : pairs), []));
const modes = ['catalyst-inventory', 'catalyst-topology', 'catalyst-health', 'fmc-rules', 'iosxe-native', 'ise-anc-jobs'];
if (!modes.includes(mode)) { console.error(`Usage: node scripts/cisco-connector.js <${modes.join('|')}> ... (see the header of this file)`); process.exit(2); }
const authHeaders = () => (process.env.CG_CISCO_TOKEN ? { 'X-Auth-Token': process.env.CG_CISCO_TOKEN, 'X-auth-access-token': process.env.CG_CISCO_TOKEN } : process.env.CG_CISCO_USER ? { Authorization: `Basic ${Buffer.from(`${process.env.CG_CISCO_USER}:${process.env.CG_CISCO_PASSWORD || ''}`).toString('base64')}` } : {});
async function readSource() {
  if (args.input) return fs.readFileSync(args.input, 'utf8').replace(/^﻿/, '');
  if (!args.url || !/^https:\/\//.test(args.url)) throw new Error('Give --input <saved response> or an https --url.');
  const response = await fetch(args.url, { method: 'GET', headers: { Accept: mode === 'iosxe-native' ? 'application/yang-data+json' : 'application/json', ...authHeaders() } });
  if (!response.ok) throw new Error(`${new URL(args.url).host} answered HTTP ${response.status}`);
  return response.text();
}
const collector = { external_id: `cisco-connector-${os.hostname().toLowerCase()}`, hostname: os.hostname(), os_family: { win32: 'windows', linux: 'linux', darwin: 'macos' }[process.platform] || 'unknown', device_type: 'server', addresses: [] };
const now = new Date().toISOString(), event = (kind, asset, details) => ({ event_id: `cisco-${randomUUID()}`, kind, observed_at: now, asset, details });

if (mode === 'ise-anc-jobs') {
  for (const key of ['cyberguard', 'source-id', 'ise']) if (!args[key]) { console.error(`Missing --${key}`); process.exit(2); }
  const cg = { Authorization: `Bearer ${process.env.CG_SOURCE_TOKEN || ''}`, 'Content-Type': 'application/json' };
  const listed = await fetch(`${args.cyberguard}/api/sources/${args['source-id']}/response-jobs`, { headers: cg });
  // A rejected token or source must stop the connector loudly, never look like an empty queue.
  if (!listed.ok) { console.error(`CyberGuard refused the job request: HTTP ${listed.status}. Check CG_SOURCE_TOKEN and --source-id.`); process.exit(1); }
  const jobs = await listed.json();
  const mine = (jobs.items || []).filter(j => ['network.nac-quarantine-endpoint', 'network.nac-release-endpoint'].includes(j.request.action_type));
  console.log(`${mine.length} approved ISE ANC job(s) for this connector.`);
  for (const job of mine) {
    // The job carries the action to perform (CyberGuard sends the inverse type on rollback): quarantine applies ANC, release clears it.
    const req = iseAncRequest(job.request.action_type === 'network.nac-quarantine-endpoint' ? 'execute' : 'rollback', job.request.target);
    if (args['dry-run']) { console.log(`DRY RUN ${job.action_id}: ${req.method} ${req.path} ${JSON.stringify(req.body)}`); continue; }
    const ise = await fetch(`${args.ise}${req.path}`, { method: req.method, headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Basic ${Buffer.from(`${process.env.CG_ISE_USER}:${process.env.CG_ISE_PASSWORD}`).toString('base64')}` }, body: JSON.stringify(req.body) });
    const outcome = ise.status === 204 || ise.ok ? 'succeeded' : 'failed';
    await fetch(`${args.cyberguard}/api/sources/${args['source-id']}/response-jobs/${job.action_id}/result`, { method: 'POST', headers: cg, body: JSON.stringify({ phase: job.phase, outcome, observed_state: `ISE ANC ${req.path.endsWith('apply') ? 'applied' : 'cleared'} for ${job.request.target.mac}: HTTP ${ise.status}`, evidence_ref: `ise-ers:${new URL(args.ise).host}`, rollback_supported: true }) });
    console.log(`${job.action_id}: ${outcome} (ISE HTTP ${ise.status})`);
  }
  process.exit(0);
}

if (!args.output) { console.error('Missing --output'); process.exit(2); }
if (fs.existsSync(args.output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(1); }
const raw = await readSource(), events = [];
if (mode === 'catalyst-inventory') { const devices = catalystInventory(raw); for (const d of devices) events.push(event('asset.observed', d.asset, {})); console.log(`Catalyst Center inventory: ${devices.length} device(s).`); }
if (mode === 'catalyst-topology') { const t = catalystTopology(raw); events.push(event('network.topology', collector, { topology_id: 'cisco-catalyst-physical', source: 'cisco-catalyst-center', nodes: t.nodes, links: t.links })); console.log(`Catalyst Center topology: ${t.nodes.length} node(s), ${t.links.length} link(s)${t.dropped_links ? `, ${t.dropped_links} link(s) to unknown nodes dropped` : ''}.`); }
if (mode === 'catalyst-health') { const devices = catalystHealth(raw); events.push(event('network.device_health', collector, { snapshot_id: 'cisco-catalyst-health', source: 'cisco-catalyst-center', devices })); console.log(`Catalyst Center device health: ${devices.length} device(s), ${devices.filter(d => d.reachability === 'unreachable').length} unreachable.`); }
if (mode === 'fmc-rules') { const r = fmcAccessRules(raw, { policyName: args['policy-name'] || 'fmc-access-policy' }); events.push(event('firewall.ruleset', collector, { ruleset_id: `cisco-fmc:${args['policy-name'] || 'access-policy'}`, device_ref: args['device-ref'] || 'cisco-fmc', vendor: 'cisco-fmc', evaluation: 'first-match', rules: r.rules })); console.log(`FMC access rules: ${r.rules.length} rule(s), ${r.unreadable} with unresolved objects (not evaluated), ${r.monitor_only} monitor-only.`); }
if (mode === 'iosxe-native') { const c = iosxeNative(raw), ref = args['device-ref'] || `cisco-iosxe:${c.hostname || 'device'}`; events.push(event('network.device_config', { external_id: ref, hostname: c.hostname, os_family: 'network', device_type: 'router', addresses: [] }, { snapshot_id: `${ref}:${now}`, device_ref: ref, device_type: 'router', vendor: 'cisco', model: args.model || 'unknown', firmware_version: c.firmware_version, dns_servers: c.dns_servers, ntp_servers: c.ntp_servers, vpn_profiles: [], management: c.management, config_sha256: null })); console.log(`IOS XE RESTCONF: ${c.hostname || 'device'} version ${c.firmware_version || 'unknown'}, management ${c.management.map(m => m.protocol + (m.restricted_sources ? ' (restricted)' : '')).join(', ') || 'none found'}.`); }
fs.writeFileSync(args.output, JSON.stringify({ schema_version: 'cg.telemetry/1', events }));
console.log('Wrote the requested private file. No upload performed.');
