// CG-043 Convert a saved firewall policy read-out into a cg.telemetry/1 firewall.ruleset file (read only; no upload).
// node scripts/firewall-policy-to-telemetry.js <panos|fortios|mikrotik|opnsense|junos|iptables> <input> <output> <device-ref>
//   panos     PAN-OS REST  GET /restapi/v10.x/Policies/SecurityRules?location=vsys&vsys=vsys1 (JSON)
//   fortios   FortiOS REST GET /api/v2/cmdb/firewall/policy (JSON)
//   mikrotik  RouterOS v7  GET /rest/ip/firewall/filter (JSON)
//   opnsense  OPNsense     GET /api/firewall/filter/searchRule (JSON)
//   junos     Junos        show configuration security policies | display set (text)
//   iptables  Linux        iptables-save (text)
import fs from 'node:fs';
import { randomUUID } from 'node:crypto';
import { panosRules, fortiosPolicies, mikrotikFilter, opnsenseRules, junosSetPolicies, iptablesSave } from '../lib/connectors/firewall-vendors.js';

const converters = { panos: panosRules, fortios: fortiosPolicies, mikrotik: mikrotikFilter, opnsense: opnsenseRules, junos: junosSetPolicies, iptables: iptablesSave };
const [kind, input, output, deviceRef] = process.argv.slice(2);
if (!converters[kind] || !input || !output || !deviceRef) { console.error(`Usage: node scripts/firewall-policy-to-telemetry.js <${Object.keys(converters).join('|')}> <input> <output> <device-ref>`); process.exit(2); }
if (fs.existsSync(output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(1); }
const raw = fs.readFileSync(input, 'utf8').replace(/^﻿/, ''), result = converters[kind](['junos', 'iptables'].includes(kind) ? raw : JSON.parse(raw));
const asset = { external_id: `firewall-${deviceRef}`.slice(0, 200), hostname: deviceRef, os_family: 'network', device_type: kind === 'iptables' ? 'server' : 'firewall', addresses: [] };
const event = { event_id: `fwpolicy-${randomUUID()}`, kind: 'firewall.ruleset', observed_at: new Date().toISOString(), asset, details: { ruleset_id: `${result.vendor}:${deviceRef}`, device_ref: deviceRef, vendor: result.vendor, evaluation: 'first-match', rules: result.rules } };
fs.writeFileSync(output, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }));
console.log(`${result.vendor}: ${result.rules.length} rule(s), ${result.unreadable} with unresolved objects (not evaluated). Wrote the requested private file; no upload performed.`);
