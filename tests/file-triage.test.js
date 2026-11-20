import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseYaraLite, matchYaraLite, triage, quarantine, verifyCustody, hashes } from '../lib/file-triage.js';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), SCRIPT = path.join(ROOT, 'scripts', 'file-triage.js');
// A harmless synthetic marker (not real malware) so antivirus on developer machines leaves the test alone.
const MARKER = 'CG-SYNTHETIC-TRIAGE-MARKER-092', RULES = `rule Synthetic_Marker : test synthetic {
  meta:
    severity = "high"
  strings:
    $a = "${MARKER}" nocase
    $b = { 43 47 2D 53 59 4E }
  condition:
    any of them
}
rule Two_Words {
  strings:
    $x = "alpha"
    $y = "omega"
  condition:
    all of them
}`;

test('the built-in YARA subset matches text, hex and nocase strings and refuses syntax it cannot evaluate (CG-092)', () => {
  const rules = parseYaraLite(RULES); assert.deepEqual(rules.map(r => [r.name, r.need, r.tags]), [['Synthetic_Marker', 1, ['test', 'synthetic']], ['Two_Words', 2, []]]);
  assert.deepEqual(matchYaraLite(rules, Buffer.from(`xx ${MARKER.toLowerCase()} yy`)).map(m => [m.rule, m.severity, m.engine]), [['Synthetic_Marker', 'high', 'built-in']]);
  assert.deepEqual(matchYaraLite(rules, Buffer.from('alpha only')), []); assert.deepEqual(matchYaraLite(rules, Buffer.from('alpha and omega')).map(m => m.rule), ['Two_Words']);
  assert.throws(() => parseYaraLite('rule W { strings: $a = "x" wide\n condition: any of them\n}'), /wide strings are not supported/);
  assert.throws(() => parseYaraLite('rule R { strings: $a = /re/\n condition: any of them\n}'), /unsupported string/);
  assert.throws(() => parseYaraLite('rule C { strings: $a = "x"\n condition: $a at 0\n}'), /unsupported condition/);
});

test('files are judged without execution, quarantined unchanged with a verifiable chain of custody, and raise alerts (CG-092)', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg092-')); t.after(() => { for (const f of fs.readdirSync(path.join(dir, 'q'), { withFileTypes: true }).filter(f => f.isFile())) fs.chmodSync(path.join(dir, 'q', f.name), 0o600); fs.rmSync(dir, { recursive: true, force: true }); });
  const w = (n, c) => { const p = path.join(dir, n); fs.writeFileSync(p, c); return p; };
  const bad = w('invoice.txt', `hello ${MARKER} bye`), benign = w('notes.txt', 'meeting notes'), known = w('tool.bin', Buffer.from([0, 1, 2, 3, 255])), pe = w('fake.exe', Buffer.concat([Buffer.from('MZ'), Buffer.alloc(64)]));
  const rules = parseYaraLite(RULES), knownBad = new Set([hashes(fs.readFileSync(known)).sha256]);
  const r1 = await triage(bad, { rules }); assert.deepEqual([r1.verdict, r1.type, r1.yara[0].rule], ['malicious', 'text', 'Synthetic_Marker']); assert.equal(r1.sha256, hashes(Buffer.from(`hello ${MARKER} bye`)).sha256);
  assert.equal((await triage(benign, { rules })).verdict, 'unknown'); assert.equal((await triage(known, { rules, knownBad })).verdict, 'malicious'); assert.equal((await triage(known, { rules, knownGood: knownBad })).verdict, 'trusted');
  const r4 = await triage(pe, { rules }); assert.equal(r4.type, 'pe-executable');
  assert.ok(process.platform === 'win32' ? ['unsigned', 'unknown', 'invalid'].includes(r4.signature.status) : r4.signature.status === 'not-available', r4.signature.status);
  if (process.platform === 'win32') { const sys = await triage(path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'notepad.exe'), { rules }); assert.equal(sys.signature.status, 'valid'); assert.match(sys.signature.signer, /Microsoft/); assert.equal(sys.verdict, 'trusted'); }
  // Quarantine: same bytes, SHA-256 name, original removed, read-only, custody verified; tampering is detected.
  const q = path.join(dir, 'q'), rec = quarantine(bad, q, { sha256: r1.sha256, reason: 'Matched synthetic marker in lab', case_ref: 'IR-092' });
  assert.equal(fs.existsSync(bad), false); const stored = path.join(q, `${r1.sha256}.quarantine`); assert.equal(hashes(fs.readFileSync(stored)).sha256, r1.sha256);
  if (process.platform !== 'win32') assert.equal(fs.statSync(stored).mode & 0o777, 0o400);
  assert.deepEqual(verifyCustody(q), { valid: true, records: 1 }); assert.equal(rec.hash_verified_after_move, true);
  const log = path.join(q, 'custody.jsonl'), original = fs.readFileSync(log, 'utf8'); fs.writeFileSync(log, original.replace('Matched synthetic marker', 'Edited reason')); assert.equal(verifyCustody(q).valid, false); fs.writeFileSync(log, original);
  // The command-line tool end to end, then into CyberGuard.
  const bad2 = w('dropper.txt', `${MARKER} again`), rulesFile = w('rules.yar', RULES), out = path.join(dir, 'triage.json');
  const res = spawnSync(process.execPath, [SCRIPT, 'scan', bad2, benign, '--rules', rulesFile, '--output', out, '--quarantine', q, '--reason', 'Synthetic lab triage', '--case', 'IR-092'], { encoding: 'utf8' });
  assert.equal(res.status, 0, res.stderr); assert.deepEqual(JSON.parse(res.stdout).quarantined, 1); assert.equal(fs.existsSync(bad2), false); assert.equal(fs.existsSync(benign), true, 'only malicious files are moved');
  assert.equal(JSON.parse(execFileSync(process.execPath, [SCRIPT, 'verify-custody', '--quarantine', q], { encoding: 'utf8' })).records, 2);
  assert.match(spawnSync(process.execPath, [SCRIPT, 'scan', benign, '--rules', rulesFile, '--output', path.join(dir, 'x.json'), '--quarantine', q], { encoding: 'utf8' }).stderr, /needs --reason/);
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, { clock: () => Date.now() });
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin-a', 'admin-a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = d.createSource('admin-a', { name: 'Triage', stale_seconds: 3600 }); assert.equal(d.ingest('admin-a', src.id, JSON.parse(fs.readFileSync(out, 'utf8'))).accepted, 2);
  const alert = s.get("SELECT severity,title FROM alerts WHERE rule_id='CG-FILE-MALICIOUS-092'"); assert.equal(alert.severity, 'high'); assert.match(alert.title, /YARA Synthetic_Marker/); assert.match(alert.title, /quarantined/);
  const view = d.fileTriage(); assert.deepEqual([view.summary.files, view.summary.malicious, view.summary.quarantined], [2, 1, 1]); assert.ok(view.claim_ar.includes('دون تشغيلها'));
});
