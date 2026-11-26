// CG-140 Telecom / Salt Typhoon hardening and technique checks from an authorized, read-only configuration export.
// Only the organisation's own devices, or carrier devices with the carrier's written authorization; nothing is scanned.
//   node scripts/telecom-hardening.js --config config.txt --device-ref <ref> --authorization-ref <ref>
//        [--scope customer-owned|carrier-managed-authorized] [--declared declared.json] --output telecom.json
//   declared.json (optional): { "mirroring": ["monitor session 1"], "tunnels": ["Tunnel10"], "ssh_ports": [2222], "guest_shell": false }
import fs from 'node:fs';
import { parseTelecomConfig, SCOPES } from '../lib/telecom-hardening.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const device = flag('--device-ref'), auth = flag('--authorization-ref'), out = flag('--output'), scope = flag('--scope') || 'customer-owned';
if (!flag('--config') || !device || !auth || !out) { console.error('usage: telecom-hardening.js --config config.txt --device-ref <ref> --authorization-ref <ref> [--scope customer-owned|carrier-managed-authorized] [--declared declared.json] --output telecom.json'); process.exit(2); }
if (!SCOPES.includes(scope)) { console.error(`--scope must be one of ${SCOPES.join(', ')}; carrier equipment needs the carrier's written authorization`); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
const cfg = parseTelecomConfig(fs.readFileSync(flag('--config'), 'utf8')), declared = flag('--declared') ? JSON.parse(fs.readFileSync(flag('--declared'), 'utf8')) : {}, at = new Date().toISOString();
const event = { event_id: `telecom:${device}:${at}`, kind: 'network.telecom_hardening', observed_at: at, asset: { external_id: device, hostname: cfg.hostname || device, os_family: 'network', device_type: 'router', addresses: [] }, details: { device_ref: device, authorization_ref: auth, scope, declared: { mirroring: declared.mirroring || [], tunnels: declared.tunnels || [], ssh_ports: declared.ssh_ports || [], guest_shell: declared.guest_shell === true }, config: cfg } };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ device, scope, tunnels: cfg.tunnels.length, mirroring: cfg.mirroring.length, acl: cfg.acl.length, output: out }));
