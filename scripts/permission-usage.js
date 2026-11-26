// CG-152 Permission usage import for reduction recommendations. Read-only exports made by the owner:
//   AWS: aws accessanalyzer get-finding-v2 --analyzer-arn <unused-access analyzer> --id <id>   (one per finding, as a JSON array)
//   other platforms: usage.json [{ "principal", "kind": "permission|role|access-key|password|grant", "permission", "service", "last_used", "owner", "seasonal", "break_glass" }]
//   owners.json: { "<principal>": "<accountable owner>" }
//   node scripts/permission-usage.js --source-ref <ref> --authorization-ref <ref> --window-days <days observed>
//        (--aws-findings findings.json | --usage usage.json) [--owners owners.json] [--break-glass p1,p2] [--seasonal service1,service2] --output usage-event.json
// Nothing is changed anywhere: the recommendations and dry-run report are computed by CyberGuard from this import.
import fs from 'node:fs';
import { fromAccessAnalyzer, decide } from '../lib/permission-reduction.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; }, list = n => (flag(n) || '').split(',').map(x => x.trim()).filter(Boolean);
const ref = flag('--source-ref'), auth = flag('--authorization-ref'), out = flag('--output'), win = Number(flag('--window-days'));
if (!ref || !auth || !out || !(win > 0) || !(flag('--aws-findings') || flag('--usage'))) { console.error('usage: permission-usage.js --source-ref <ref> --authorization-ref <ref> --window-days <n> (--aws-findings f | --usage f) [--owners f] [--break-glass a,b] [--seasonal s1,s2] --output f'); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
const read = f => JSON.parse(fs.readFileSync(f, 'utf8').replace(/^﻿/, ''));
const owners = flag('--owners') ? read(flag('--owners')) : {}, breakGlass = list('--break-glass'), seasonal = list('--seasonal');
let entries;
try {
  if (flag('--aws-findings')) entries = fromAccessAnalyzer(read(flag('--aws-findings')), { windowDays: win, owners, breakGlass, seasonal });
  else { const u = read(flag('--usage')); if (!Array.isArray(u)) throw Object.assign(new Error('usage'), { code: 'not_usage_list' });
    entries = u.map((x, i) => { if (!x.principal || !['permission', 'role', 'access-key', 'password', 'grant'].includes(x.kind) || !x.permission) throw Object.assign(new Error('entry'), { code: `invalid_usage_entry_${i}` });
      return { source: 'declared', principal: String(x.principal), kind: x.kind, permission: String(x.permission), service: x.service || null, last_used: x.last_used || null, owner: x.owner || owners[x.principal] || null, window_days: win, break_glass: x.break_glass === true || breakGlass.includes(x.principal), seasonal: x.seasonal === true || seasonal.includes(x.service) }; }); }
} catch (e) { console.error(`Invalid usage export: ${e.code || e.message}`); process.exit(2); }
if (entries.length > 20000) { console.error('Too many entries in one import.'); process.exit(2); }
const at = new Date().toISOString(), details = { source_ref: ref, authorization_ref: auth, window_days: win, entries };
const event = { event_id: `permission-usage:${ref}:${at}`, kind: 'identity.permission_usage', observed_at: at, asset: { external_id: `permissions:${ref}`, hostname: `Permissions ${ref}`, os_family: 'unknown', device_type: 'unknown', addresses: [] }, details };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
const counts = {}; for (const e of entries) { const d = decide(e).decision; counts[d] = (counts[d] || 0) + 1; }
console.log(JSON.stringify({ source: ref, window_days: win, entries: entries.length, decisions: counts, output: out }));
