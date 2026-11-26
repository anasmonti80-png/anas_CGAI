// CG-132 NetBox source-of-truth export to CyberGuard telemetry (read-only; nothing is written to NetBox).
//   curl -H "Authorization: Token $NETBOX_TOKEN" https://netbox.example/api/dcim/devices/?limit=1000 > devices.json
//   curl -H "Authorization: Token $NETBOX_TOKEN" https://netbox.example/api/dcim/interfaces/?limit=5000 > interfaces.json
//   node scripts/netbox-to-telemetry.js --devices devices.json --interfaces interfaces.json --output intended.json
import fs from 'node:fs';
import { parseNetbox } from '../lib/intended-state.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; }, out = flag('--output');
if (!flag('--devices') || !out) { console.error('usage: netbox-to-telemetry.js --devices devices.json [--interfaces interfaces.json] --output intended.json'); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
const devices = parseNetbox({ devices: JSON.parse(fs.readFileSync(flag('--devices'), 'utf8')), interfaces: flag('--interfaces') ? JSON.parse(fs.readFileSync(flag('--interfaces'), 'utf8')) : { results: [] } }), at = new Date().toISOString();
const event = { event_id: `netbox-intended:${at}`, kind: 'inventory.intended', observed_at: at, asset: { external_id: 'source-of-truth:netbox', hostname: 'NetBox', os_family: 'unknown', device_type: 'server', addresses: [] }, details: { source: 'netbox', exported_at: at, devices } };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ devices: devices.length, interfaces: devices.reduce((n, d) => n + d.interfaces.length, 0), output: out }));
