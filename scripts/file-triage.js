// CG-092 Triage suspicious files without executing them (Linux, Windows, macOS).
//   node scripts/file-triage.js scan <file>... --rules rules.yar --output triage.json [--yara]
//        [--known-bad bad-sha256.txt] [--known-good good-sha256.txt] [--quarantine <dir> --reason "<text>" [--case IR-123]]
//   node scripts/file-triage.js verify-custody --quarantine <dir>
// --yara uses the installed yara tool (Linux: sudo apt install yara) for full rule syntax; without it a built-in subset
// is used. Only files named on the command line are read. With --quarantine, files judged malicious are moved unchanged
// into the quarantine directory under their SHA-256 name, made read-only, and recorded in a hash-chained custody log.
import fs from 'node:fs';
import os from 'node:os';
import { triage, parseYaraLite, yaraAvailable, loadHashList, quarantine, verifyCustody } from '../lib/file-triage.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const valued = new Set(['--rules', '--output', '--known-bad', '--known-good', '--quarantine', '--reason', '--case']);
const [command] = args, files = args.slice(1).filter((a, i, all) => !a.startsWith('--') && !valued.has(all[i - 1]));
if (command === 'verify-custody') { const r = verifyCustody(flag('--quarantine')); console.log(JSON.stringify(r)); process.exit(r.valid ? 0 : 1); }
if (command !== 'scan' || !files.length || !flag('--output')) { console.error('usage: file-triage.js scan <file>... --rules rules.yar --output triage.json [--yara] [--known-bad f] [--known-good f] [--quarantine dir --reason text] | verify-custody --quarantine dir'); process.exit(2); }
const output = flag('--output'); if (fs.existsSync(output)) { console.error('Output already exists. Choose a new private file path.'); process.exit(2); }
const rulesFile = flag('--rules'), useYara = args.includes('--yara'), qdir = flag('--quarantine'), reason = flag('--reason');
if (qdir && !(reason && reason.length >= 6)) { console.error('--quarantine needs --reason (at least 6 characters)'); process.exit(2); }
let rules = null, ruleMeta = {};
try {
  if (rulesFile) { const src = fs.readFileSync(rulesFile, 'utf8'); if (useYara) { if (!(await yaraAvailable())) throw new Error('yara is not installed (Linux: sudo apt install yara); run without --yara to use the built-in subset'); for (const m of src.matchAll(/rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*([A-Za-z0-9_ ]+))?\s*\{[\s\S]*?severity\s*=\s*"(low|medium|high|critical)"/g)) ruleMeta[m[1]] = { tags: (m[2] || '').trim().split(/\s+/).filter(Boolean), severity: m[3] }; } else rules = parseYaraLite(src); }
  const knownBad = loadHashList(flag('--known-bad')), knownGood = loadHashList(flag('--known-good')), at = new Date().toISOString(), events = [];
  for (const file of files) {
    const r = await triage(file, { rules, rulesFile, useYara, ruleMeta, knownBad, knownGood });
    const custody = qdir && r.verdict === 'malicious' ? quarantine(file, qdir, { sha256: r.sha256, reason, case_ref: flag('--case') }) : null;
    events.push({ event_id: `triage:${r.sha256}:${at}`, kind: 'file.triage', observed_at: at, asset: { external_id: `host:${os.hostname().toLowerCase()}`, hostname: os.hostname(), os_family: { win32: 'windows', darwin: 'macos', linux: 'linux' }[process.platform] || 'unknown', device_type: 'unknown', addresses: [] },
      details: { ...r, rules_engine: useYara ? 'yara' : rules ? 'built-in' : 'none', quarantine: custody ? { state: 'quarantined', custody_id: custody.custody_id, record_hash: custody.record_hash, location: custody.location } : { state: 'not-quarantined', custody_id: null, record_hash: null, location: null } } });
    console.error(`${r.verdict.padEnd(10)} ${r.sha256} ${r.name}${custody ? ' -> quarantined' : ''}`);
  }
  fs.writeFileSync(output, JSON.stringify({ schema_version: 'cg.telemetry/1', events }, null, 2), { mode: 0o600, flag: 'wx' });
  console.log(JSON.stringify({ files: events.length, malicious: events.filter(e => e.details.verdict === 'malicious').length, suspicious: events.filter(e => e.details.verdict === 'suspicious').length, quarantined: events.filter(e => e.details.quarantine.state === 'quarantined').length, output }));
} catch (e) { console.error(`Refused: ${e.message}`); process.exit(1); }
