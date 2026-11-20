// CG-096 Network posture from an authorized, read-only configuration export ("show running-config" text).
//   node scripts/network-posture.js <running-config.txt> --device-ref <ref> --authorization-ref <ref> --output <out.json>
//        [--sections ipv4,ipv6,wifi,dns,dhcp,vpn,vlan,trunks,acl,nat,routing]   (only the sections you actually exported)
// Areas not listed in --sections are reported as not collected; an export with authorization errors is not readable.
import fs from 'node:fs';
import { analyseNetworkPosture, AREAS } from '../lib/network-posture.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const [input] = args, device = flag('--device-ref'), auth = flag('--authorization-ref'), output = flag('--output');
if (!input || !device || !auth || !output) { console.error('usage: network-posture.js <running-config.txt> --device-ref <ref> --authorization-ref <ref> --output <out.json> [--sections a,b]'); process.exit(2); }
if (fs.existsSync(output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(2); }
const sections = flag('--sections') ? flag('--sections').split(',').map(s => s.trim()) : AREAS;
if (!sections.every(s => AREAS.includes(s))) { console.error(`--sections must be from: ${AREAS.join(',')}`); process.exit(2); }
const r = analyseNetworkPosture(fs.readFileSync(input, 'utf8'), { collected: sections }), at = new Date().toISOString();
const batch = { schema_version: 'cg.telemetry/1', events: [{ event_id: `netposture:${device}:${at}`, kind: 'network.posture', observed_at: at, asset: { external_id: device, hostname: r.hostname || device, os_family: 'network', device_type: 'router', addresses: [] }, details: { device_ref: device, authorization_ref: auth, readable: r.readable, areas: r.areas } }] };
fs.writeFileSync(output, JSON.stringify(batch, null, 2), { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ device, readable: r.readable, assessed: r.areas.filter(a => a.state === 'assessed').length, findings: r.areas.reduce((n, a) => n + a.findings.length, 0), output }));
