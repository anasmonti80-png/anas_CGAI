// CG-137 Infrastructure management-plane audit from an authorized, read-only configuration export (nothing is changed).
//   show running-config > config.txt
//   node scripts/mgmt-plane-audit.js --config config.txt --device-ref <ref> --authorization-ref <ref>
//        [--vendor cisco] [--version 17.9] [--org org.json] --output mgmt.json
//   org.json (optional): { "ntp_servers": [...], "syslog_hosts": [...], "aaa_servers": [...], "backup": "external" }
import fs from 'node:fs';
import { parseMgmtConfig, auditMgmtPlane } from '../lib/mgmt-plane.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const device = flag('--device-ref'), auth = flag('--authorization-ref'), out = flag('--output'), vendor = (flag('--vendor') || 'cisco').toLowerCase();
if (!flag('--config') || !device || !auth || !out) { console.error('usage: mgmt-plane-audit.js --config config.txt --device-ref <ref> --authorization-ref <ref> [--vendor cisco] [--version v] [--org org.json] --output mgmt.json'); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
const cfg = parseMgmtConfig(fs.readFileSync(flag('--config'), 'utf8')), org = flag('--org') ? JSON.parse(fs.readFileSync(flag('--org'), 'utf8')) : {};
const r = auditMgmtPlane(cfg, { vendor, version: flag('--version'), org }), at = new Date().toISOString();
const details = { device_ref: device, authorization_ref: auth, hostname: cfg.hostname, vendor, version: r.version || null, baseline: r.baseline, reason: r.reason || null, reason_ar: r.reason_ar || null, controls: r.controls, score: r.score };
const event = { event_id: `mgmt-plane:${device}:${at}`, kind: 'network.mgmt_plane', observed_at: at, asset: { external_id: device, hostname: cfg.hostname || device, os_family: 'network', device_type: 'switch', addresses: [] }, details };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ device, baseline: r.baseline, score: r.score, failed: r.controls.filter(c => c.status === 'fail').map(c => c.id), output: out }));
