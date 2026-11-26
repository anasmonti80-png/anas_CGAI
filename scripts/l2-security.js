// CG-134 Layer-2 security posture from an authorized, read-only switch export (nothing is changed on the device).
//   show running-config > config.txt ; show logging > syslog.txt
//   node scripts/l2-security.js --config config.txt [--syslog syslog.txt] --device-ref <ref> --authorization-ref <ref>
//        [--authorized-dhcp 10.0.0.10,10.0.0.11] [--unsupported dai,ip-source-guard] --output l2.json
// ip helper-address targets in the configuration are added to the authorized DHCP servers.
import fs from 'node:fs';
import { parseL2Config, assessL2Posture, parseL2Syslog, FEATURES } from '../lib/l2-security.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; }, list = n => (flag(n) || '').split(',').map(s => s.trim()).filter(Boolean);
const device = flag('--device-ref'), auth = flag('--authorization-ref'), out = flag('--output');
if (!device || !auth || !out) { console.error('usage: l2-security.js --config config.txt [--syslog syslog.txt] --device-ref <ref> --authorization-ref <ref> [--authorized-dhcp a,b] [--unsupported f1,f2] --output l2.json'); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
const unsupported = list('--unsupported'); if (!unsupported.every(f => FEATURES.includes(f))) { console.error(`--unsupported must be from: ${FEATURES.join(',')}`); process.exit(2); }
const cfg = flag('--config') ? parseL2Config(fs.readFileSync(flag('--config'), 'utf8')) : null, signals = flag('--syslog') ? parseL2Syslog(fs.readFileSync(flag('--syslog'), 'utf8')) : [];
const features = assessL2Posture(cfg || { ports: [], snoopingVlans: [], dai: [], helpers: [] }, { unsupported, collected: !!cfg }), at = new Date().toISOString();
const authorized_dhcp = [...new Set([...list('--authorized-dhcp'), ...(cfg?.helpers || [])])];
const event = { event_id: `l2-security:${device}:${at}`, kind: 'network.l2_security', observed_at: at, asset: { external_id: device, hostname: cfg?.hostname || device, os_family: 'network', device_type: 'switch', addresses: [] }, details: { device_ref: device, authorization_ref: auth, hostname: cfg?.hostname || null, features, authorized_dhcp, signals } };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ device, features: features.map(f => `${f.feature}:${f.state}`), signals: signals.length, output: out }));
