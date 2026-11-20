// CG-101 Build switch port evidence from the text a Cisco IOS / IOS-XE switch prints (read-only show commands):
//   node scripts/port-map.js --switch-ref <ref> --authorization-ref <ref> --output <out.json>
//        --mac-table "show mac address-table".txt --switchport "show interfaces switchport".txt
//        [--arp "show ip arp".txt] [--lldp "show lldp neighbors detail".txt]
import fs from 'node:fs';
import { parseArp, parseMacTable, parseSwitchport, parseLldp } from '../lib/port-map.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; }, read = n => flag(n) ? fs.readFileSync(flag(n), 'utf8') : '';
const sw = flag('--switch-ref'), auth = flag('--authorization-ref'), output = flag('--output');
if (!sw || !auth || !output || !flag('--mac-table') || !flag('--switchport')) { console.error('usage: port-map.js --switch-ref <ref> --authorization-ref <ref> --output <out.json> --mac-table <file> --switchport <file> [--arp <file>] [--lldp <file>]'); process.exit(2); }
if (fs.existsSync(output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(2); }
const details = { switch_ref: sw, authorization_ref: auth, arp: parseArp(read('--arp')), mac_table: parseMacTable(read('--mac-table')), switchports: parseSwitchport(read('--switchport')), lldp: parseLldp(read('--lldp')) }, at = new Date().toISOString();
fs.writeFileSync(output, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [{ event_id: `portmap:${sw}:${at}`, kind: 'network.port_map', observed_at: at, asset: { external_id: sw, hostname: sw, os_family: 'network', device_type: 'switch', addresses: [] }, details }] }, null, 2), { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ switch: sw, arp: details.arp.length, mac_entries: details.mac_table.length, ports: details.switchports.length, lldp_neighbors: details.lldp.length, output }));
