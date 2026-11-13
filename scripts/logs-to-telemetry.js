// Convert a raw log file into a cg.telemetry/1 log.batch file (read only; no upload).
// Usage: node scripts/logs-to-telemetry.js <format> <input.log> <output.json> [source-name]
// Formats: syslog, journal, nfdump-csv, goflow-json, suricata-eve, bind-query, isc-dhcpd, openvpn,
//          iptables, windows-firewall, pfsense-filterlog, modsecurity-json, aws-waf-json, dnsmasq,
//          zeek-conn, freeradius, cloudflare-access-json
import fs from 'node:fs';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { logFormats } from '../lib/log-normalizer.js';

const [format, input, output, sourceName = `${os.hostname()} ${format}`] = process.argv.slice(2);
if (!logFormats[format] || !input || !output) { console.error(`Usage: node scripts/logs-to-telemetry.js <${Object.keys(logFormats).join('|')}> <input> <output> [source-name]`); process.exit(2); }
if (fs.existsSync(output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(1); }
const lines = fs.readFileSync(input, 'utf8').replace(/^﻿/, '').split(/\r?\n/).map(line => line.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '').slice(0, 4000)).filter(line => line.trim()).slice(-5000);
const now = new Date().toISOString();
const batch = { schema_version: 'cg.telemetry/1', events: [{ event_id: `logs-${randomUUID()}`, kind: 'log.batch', observed_at: now, asset: { external_id: `log-collector-${os.hostname().toLowerCase()}`, hostname: os.hostname(), os_family: { win32: 'windows', linux: 'linux', darwin: 'macos' }[process.platform] || 'unknown', device_type: 'server', addresses: [] }, details: { batch_id: `logs-${randomUUID()}`, source_name: sourceName.slice(0, 200), format, lines } }] };
fs.writeFileSync(output, JSON.stringify(batch));
console.log(`Wrote ${lines.length} ${format} lines to the requested private file. No upload performed.`);
