// CG-108 Email security evidence from authorized mail sources.
//   node scripts/email-security.js domain --domain example.org [--selectors selector1,selector2] --output out.json
//   node scripts/email-security.js eml --input msg1.eml [--input msg2.eml ...] --internal-domains example.org --output out.json
//   node scripts/email-security.js audit --input m365-unified-audit.json --internal-domains example.org --output out.json
// .eml files are exported by the mailbox owner or the mail administrator; bodies are never stored.
import fs from 'node:fs';
import dns from 'node:dns/promises';
import { domainPosture, analyseEml, forwardingChanges } from '../lib/email-security.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; }, all = n => args.flatMap((a, i) => a === n ? [args[i + 1]] : []), [mode] = args;
const output = flag('--output'), internal = (flag('--internal-domains') || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
if (!['domain', 'eml', 'audit'].includes(mode) || !output) { console.error('usage: email-security.js domain|eml|audit ... --output out.json'); process.exit(2); }
if (fs.existsSync(output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(2); }
const at = new Date().toISOString(), asset = name => ({ external_id: `mail:${name}`, hostname: name, os_family: 'unknown', device_type: 'server', addresses: [] });
let events;
try {
  if (mode === 'domain') { const d = flag('--domain'); if (!/^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(d || '')) throw new Error('--domain required'); const r = await domainPosture(d.toLowerCase(), dns, (flag('--selectors') || '').split(',').filter(Boolean)); events = [{ event_id: `mailposture:${d}:${at}`, kind: 'email.domain_posture', observed_at: at, asset: asset(d), details: r }]; }
  else if (mode === 'eml') { const files = all('--input'); if (!files.length) throw new Error('--input required'); events = files.map((f, i) => { const r = analyseEml(fs.readFileSync(f, 'latin1'), { internalDomains: internal }); return { event_id: `mailmsg:${r.message_id || i}:${at}`.slice(0, 200), kind: 'email.message_analysis', observed_at: at, asset: asset(internal[0] || 'mailbox'), details: r }; }); }
  else { const recs = JSON.parse(fs.readFileSync(flag('--input'), 'utf8')), changes = forwardingChanges(Array.isArray(recs) ? recs : recs.value || [], internal); events = [{ event_id: `mailfwd:${at}`, kind: 'email.forwarding_change', observed_at: at, asset: asset(internal[0] || 'tenant'), details: { records_checked: (Array.isArray(recs) ? recs : recs.value || []).length, changes: changes.slice(0, 500) } }]; }
} catch (e) { console.error(`Refused: ${e.message}`); process.exit(1); }
fs.writeFileSync(output, JSON.stringify({ schema_version: 'cg.telemetry/1', events }, null, 2), { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ mode, events: events.length, findings: events.reduce((n, e) => n + (e.details.findings || e.details.changes || []).length, 0), output }));
