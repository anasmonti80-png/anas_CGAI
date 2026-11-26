// CG-135 BGP routing security from an authorized, read-only router export (nothing is changed on the router).
//   show running-config > config.txt ; show ip bgp > bgp.txt ; show ip bgp neighbors <ip> advertised-routes > adv-<ip>.txt
//   routinator vrps --format json > vrps.json   (or rpki-client JSON output)
//   node scripts/routing-security.js --config config.txt [--bgp-table bgp.txt] [--advertised <ip>=adv.txt ...]
//        [--vrps vrps.json] [--own-prefixes 203.0.113.0/24,...] --device-ref <ref> --authorization-ref <ref> --output rs.json
// A configuration without "router bgp" is reported as not applicable.
import fs from 'node:fs';
import { parseBgpConfig, parseBgpTable, parseVrps, assessRouting } from '../lib/routing-security.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; }, all = n => args.flatMap((a, i) => a === n ? [args[i + 1]] : []);
const device = flag('--device-ref'), auth = flag('--authorization-ref'), out = flag('--output');
if (!flag('--config') || !device || !auth || !out) { console.error('usage: routing-security.js --config config.txt [--bgp-table bgp.txt] [--advertised ip=file] [--vrps vrps.json] [--own-prefixes a,b] --device-ref <ref> --authorization-ref <ref> --output rs.json'); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
const config = parseBgpConfig(fs.readFileSync(flag('--config'), 'utf8')), table = flag('--bgp-table') ? parseBgpTable(fs.readFileSync(flag('--bgp-table'), 'utf8')) : [];
const advertised = Object.fromEntries(all('--advertised').map(x => { const [ip, file] = x.split(/=(.*)/s); return [ip, parseBgpTable(fs.readFileSync(file, 'utf8'))]; }));
const vrps = flag('--vrps') ? parseVrps(JSON.parse(fs.readFileSync(flag('--vrps'), 'utf8'))) : [], ownPrefixes = (flag('--own-prefixes') || '').split(',').map(s => s.trim()).filter(Boolean);
const r = assessRouting({ config, table, advertised, vrps, ownPrefixes }), at = new Date().toISOString();
const details = { device_ref: device, authorization_ref: auth, hostname: config.hostname, applicable: r.applicable, reason: r.reason || null, reason_ar: r.reason_ar || null, asn: r.asn ?? null, ebgp_neighbors: r.ebgp_neighbors || [], rov: r.rov || null, own: r.own, announcements: r.announcements, findings: r.findings, vrps: r.vrps ?? 0 };
const event = { event_id: `routing-security:${device}:${at}`, kind: 'network.routing_security', observed_at: at, asset: { external_id: device, hostname: config.hostname || device, os_family: 'network', device_type: 'router', addresses: [] }, details };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ device, applicable: r.applicable, asn: r.asn ?? null, findings: r.findings.map(f => f.id), output: out }));
