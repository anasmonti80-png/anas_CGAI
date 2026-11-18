// CG-042 Huawei connector: iMaster NCE-Campus device query and VRP device output into cg.telemetry/1 files.
// node scripts/huawei-connector.js nce-devices (--input <saved.json> | --url <https://nce/controller/campus/v3/devices>) --output <file>
//   live auth: CG_HUAWEI_TOKEN (X-ACCESS-TOKEN from the NCE token API); GET only
// node scripts/huawei-connector.js vrp-config --version <display-version.txt> --config <current-configuration.txt> --device-ref <ref> --output <file>
// node scripts/huawei-connector.js vrp-lldp --input <lldp-neighbor-brief.txt> --device <local sysname> --output <file>
// Read-only: nothing is configured on any device and nothing is uploaded. Configuration secrets are not copied.
import fs from 'node:fs';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { nceDevices, parseHuaweiVrp, vrpLldp } from '../lib/connectors/huawei.js';

const [mode, ...rest] = process.argv.slice(2);
const args = Object.fromEntries(rest.reduce((pairs, v, i, all) => (v.startsWith('--') ? [...pairs, [v.slice(2), all[i + 1] && !all[i + 1].startsWith('--') ? all[i + 1] : true]] : pairs), []));
if (!['nce-devices', 'vrp-config', 'vrp-lldp'].includes(mode) || !args.output) { console.error('Usage: see the header of scripts/huawei-connector.js'); process.exit(2); }
if (fs.existsSync(args.output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(1); }
const read = f => fs.readFileSync(f, 'utf8').replace(/^﻿/, '');
const collector = { external_id: `huawei-connector-${os.hostname().toLowerCase()}`, hostname: os.hostname(), os_family: { win32: 'windows', linux: 'linux', darwin: 'macos' }[process.platform] || 'unknown', device_type: 'server', addresses: [] };
const now = new Date().toISOString(), event = (kind, asset, details) => ({ event_id: `huawei-${randomUUID()}`, kind, observed_at: now, asset, details }), events = [];
if (mode === 'nce-devices') {
  let raw;
  if (args.input) raw = read(args.input);
  else { if (!args.url || !/^https:\/\//.test(args.url)) { console.error('Give --input or an https --url.'); process.exit(2); } const r = await fetch(args.url, { method: 'GET', headers: { Accept: 'application/json', 'X-ACCESS-TOKEN': process.env.CG_HUAWEI_TOKEN || '' } }); if (!r.ok) { console.error(`${new URL(args.url).host} answered HTTP ${r.status}`); process.exit(1); } raw = await r.text(); }
  const devices = nceDevices(raw);
  for (const d of devices) events.push(event('asset.observed', d.asset, {}));
  if (devices.length) events.push(event('network.device_health', collector, { snapshot_id: 'huawei-nce-device-status', source: 'huawei-imaster-nce', devices: devices.map(d => d.health) }));
  console.log(`NCE-Campus: ${devices.length} device(s), ${devices.filter(d => d.health.reachability === 'unreachable').length} offline, ${devices.filter(d => d.facts.status === 'alarm').length} with alarms.`);
}
if (mode === 'vrp-config') {
  if (!args.version || !args.config || !args['device-ref']) { console.error('vrp-config needs --version, --config and --device-ref'); process.exit(2); }
  const c = parseHuaweiVrp(read(args.version), read(args.config)), ref = args['device-ref'];
  events.push(event('network.device_config', { external_id: ref, hostname: c.hostname, os_family: 'network', device_type: 'switch', addresses: [] }, { snapshot_id: `${ref}:${now}`, device_ref: ref, device_type: 'switch', vendor: 'huawei', model: c.model || 'unknown', firmware_version: c.firmware_version || 'unknown', dns_servers: c.dns_servers, ntp_servers: c.ntp_servers, vpn_profiles: c.vpn_profiles, management: c.management, config_sha256: null }));
  console.log(`VRP ${c.hostname || ref}: ${c.model || 'model unknown'} ${c.firmware_version || 'version unknown'}; management enabled: ${c.management.filter(m => m.enabled).map(m => m.protocol).join(', ') || 'none'}. Secrets were not copied.`);
}
if (mode === 'vrp-lldp') {
  if (!args.input || !args.device) { console.error('vrp-lldp needs --input and --device'); process.exit(2); }
  const t = vrpLldp(read(args.input), args.device);
  events.push(event('network.topology', collector, { topology_id: `huawei-lldp:${String(args.device).toLowerCase()}`, source: 'device-lldp', nodes: t.nodes, links: t.links }));
  console.log(`VRP LLDP on ${args.device}: ${t.links.length} neighbor link(s).`);
}
fs.writeFileSync(args.output, JSON.stringify({ schema_version: 'cg.telemetry/1', events }));
console.log('Wrote the requested private file. No upload performed.');
