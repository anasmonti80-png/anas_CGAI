// CG-136 Wireless and guest network assurance from an authorized, read-only wireless controller export. Nothing is
// transmitted over the air and nothing is changed on the controller.
//   show running-config > wlc.txt   (Cisco Catalyst 9800)
//   rogues.json: [{ bssid, ssid, rssi, channel, clients, detected_by: [ap], last_heard }]  (converted from the controller rogue list)
//   aps.json:    [{ name, site, mode, rogue_detection }]
//   node scripts/wireless-assurance.js --config wlc.txt [--rogues rogues.json] [--aps aps.json] --controller-ref <ref> --authorization-ref <ref> --output wifi.json
import fs from 'node:fs';
import { parseWlcConfig, assessWlans } from '../lib/wireless.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const ref = flag('--controller-ref'), auth = flag('--authorization-ref'), out = flag('--output');
if (!flag('--config') || !ref || !auth || !out) { console.error('usage: wireless-assurance.js --config wlc.txt [--rogues rogues.json] [--aps aps.json] --controller-ref <ref> --authorization-ref <ref> --output wifi.json'); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
const cfg = parseWlcConfig(fs.readFileSync(flag('--config'), 'utf8')), { ssids, findings } = assessWlans(cfg), json = n => flag(n) ? JSON.parse(fs.readFileSync(flag(n), 'utf8')) : [];
const rogues = json('--rogues').map(r => ({ bssid: r.bssid, ssid: r.ssid ?? null, rssi: r.rssi ?? null, channel: r.channel ?? null, clients: r.clients ?? 0, detected_by: r.detected_by || [], last_heard: r.last_heard || null }));
const aps = json('--aps').map(a => ({ name: a.name, site: a.site || null, mode: a.mode || 'local', rogue_detection: a.rogue_detection !== false })), at = new Date().toISOString();
const event = { event_id: `wireless:${ref}:${at}`, kind: 'wireless.assurance', observed_at: at, asset: { external_id: ref, hostname: cfg.hostname || ref, os_family: 'network', device_type: 'access-point', addresses: [] }, details: { controller_ref: ref, authorization_ref: auth, hostname: cfg.hostname, ssids, findings, rogues, aps } };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ controller: ref, ssids: ssids.map(s => `${s.ssid}:${s.security}`), findings: findings.map(f => f.id), rogues: rogues.length, aps: aps.length, output: out }));
