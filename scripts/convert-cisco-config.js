// Convert saved Cisco IOS/IOS-XE "show version" and "show running-config" outputs into a
// cg.telemetry/1 network.device_config event. Secrets in the config (SNMP communities, keys,
// passwords) are never copied: only versions, DNS/NTP servers, VPN peers and management flags.
// Usage: node scripts/convert-cisco-config.js <show-version.txt> <running-config.txt> <out.json> <device-ref> [unknown|internal|external|any]
import fs from 'node:fs';
import { randomUUID, createHash } from 'node:crypto';
import { parseCiscoIos } from '../lib/device-config.js';

const [versionFile, configFile, output, deviceRef, exposure = 'unknown'] = process.argv.slice(2);
if (!versionFile || !configFile || !output || !deviceRef || !['unknown', 'internal', 'external', 'any'].includes(exposure)) { console.error('Usage: node scripts/convert-cisco-config.js <show-version.txt> <running-config.txt> <out.json> <device-ref> [unknown|internal|external|any]'); process.exit(2); }
if (fs.existsSync(output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(1); }
const config = fs.readFileSync(configFile, 'utf8'), parsed = parseCiscoIos(fs.readFileSync(versionFile, 'utf8'), config);
const now = new Date().toISOString();
const details = { snapshot_id: `cisco-${randomUUID()}`, device_ref: deviceRef, device_type: 'router', vendor: parsed.vendor, model: parsed.model || 'unknown', firmware_version: parsed.firmware_version || 'unknown', dns_servers: parsed.dns_servers, ntp_servers: parsed.ntp_servers, vpn_profiles: parsed.vpn_profiles, management: parsed.management.map(m => ({ ...m, exposed_to: m.enabled ? exposure : 'unknown' })), config_sha256: createHash('sha256').update(config).digest('hex') };
fs.writeFileSync(output, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [{ event_id: `devcfg-${randomUUID()}`, kind: 'network.device_config', observed_at: now, asset: { external_id: `netdev-${deviceRef}`.slice(0, 200), hostname: parsed.hostname, os_family: 'network', device_type: 'router', addresses: [] }, details }] }));
console.log(`Converted ${deviceRef}: ${parsed.vendor} ${parsed.model || ''} ${parsed.firmware_version || ''}. Secrets were not copied. No upload performed.`);
