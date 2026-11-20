// CG-092 Suspicious file triage without executing anything: hashes, file type, YARA rules (the yara tool when installed,
// otherwise a built-in subset: text and hex strings, nocase, "any/all/N of them"), publisher signature (Windows
// Authenticode through PowerShell), hash reputation from approved local lists, and quarantine with a hash-chained chain
// of custody. Files are only read; quarantine moves the bytes unchanged under the SHA-256 name, removes execute
// permission and verifies the hash after the move.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';

const run = (cmd, args, opts = {}) => new Promise(resolve => execFile(cmd, args, { timeout: 60000, maxBuffer: 4 * 1024 * 1024, windowsHide: true, ...opts }, (e, stdout, stderr) => resolve({ ok: !e, code: e?.code ?? 0, stdout: String(stdout || ''), stderr: String(stderr || '') })));
export function hashes(buf) { return { sha256: createHash('sha256').update(buf).digest('hex'), sha1: createHash('sha1').update(buf).digest('hex'), md5: createHash('md5').update(buf).digest('hex') }; }
export function fileType(buf) {
  const h = buf.subarray(0, 8).toString('hex');
  if (h.startsWith('4d5a')) return 'pe-executable'; if (h.startsWith('7f454c46')) return 'elf-executable'; if (/^(cafebabe|cffaedfe|cefaedfe|feedfacf|feedface)/.test(h)) return 'mach-o-executable';
  if (h.startsWith('504b0304')) return 'zip-archive'; if (h.startsWith('25504446')) return 'pdf'; if (h.startsWith('d0cf11e0')) return 'ole-document'; if (buf.subarray(0, 2).toString() === '#!') return 'script';
  return buf.subarray(0, 512).every(b => b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127) || b >= 128) ? 'text' : 'binary';
}

// Built-in YARA subset. Unsupported syntax is refused, never silently ignored.
export function parseYaraLite(src) {
  const rules = [], body = String(src).replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
  const re = /rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*([A-Za-z0-9_ ]+))?\s*\{([\s\S]*?)\n\s*\}/g; let m;
  while ((m = re.exec(body))) {
    const [, name, tags, inner] = m, strings = [], meta = {};
    const metaSec = /meta:\s*([\s\S]*?)(?=strings:|condition:)/.exec(inner)?.[1] || '';
    for (const mm of metaSec.matchAll(/([A-Za-z_]+)\s*=\s*"([^"]*)"/g)) meta[mm[1]] = mm[2];
    const strSec = /strings:\s*([\s\S]*?)condition:/.exec(inner)?.[1]; if (!strSec) throw new Error(`rule ${name}: strings section required`);
    for (const line of strSec.split('\n').map(l => l.trim()).filter(Boolean)) {
      let s;
      if ((s = /^\$([A-Za-z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"\s*(nocase|ascii|wide|\s)*$/.exec(line))) { if (/\bwide\b/.test(line)) throw new Error(`rule ${name}: wide strings are not supported by the built-in matcher; install yara`); strings.push({ id: s[1], bytes: Buffer.from(JSON.parse(`"${s[2]}"`), 'latin1'), nocase: /\bnocase\b/.test(line) }); }
      else if ((s = /^\$([A-Za-z0-9_]*)\s*=\s*\{([0-9A-Fa-f\s]+)\}$/.exec(line))) strings.push({ id: s[1], bytes: Buffer.from(s[2].replace(/\s+/g, ''), 'hex'), nocase: false });
      else throw new Error(`rule ${name}: unsupported string "${line.slice(0, 60)}"; install yara for full syntax`);
    }
    const cond = /condition:\s*([\s\S]*)$/.exec(inner)[1].trim(); let need;
    if (cond === 'any of them') need = 1; else if (cond === 'all of them') need = strings.length; else if (/^\d+ of them$/.test(cond)) need = Number(cond.split(' ')[0]); else throw new Error(`rule ${name}: unsupported condition "${cond}"; install yara`);
    rules.push({ name, tags: (tags || '').trim().split(/\s+/).filter(Boolean), meta, strings, need });
  }
  if (!rules.length) throw new Error('no rules found');
  return rules;
}
export function matchYaraLite(rules, buf) {
  const lower = Buffer.from(buf.toString('latin1').toLowerCase(), 'latin1');
  return rules.filter(r => r.strings.filter(s => (s.nocase ? lower.includes(Buffer.from(s.bytes.toString('latin1').toLowerCase(), 'latin1')) : buf.includes(s.bytes))).length >= r.need).map(r => ({ rule: r.name, tags: r.tags, severity: ['low', 'medium', 'high', 'critical'].includes(r.meta.severity) ? r.meta.severity : 'high', engine: 'built-in' }));
}
export async function yaraAvailable() { const r = await run('yara', ['--version']); return r.ok ? r.stdout.trim() : null; }
export async function matchYara(rulesFile, file, ruleMeta = {}) {
  const r = await run('yara', ['-w', rulesFile, file]); if (!r.ok && r.code !== 0 && r.code !== 1) throw new Error(`yara failed: ${r.stderr.slice(0, 200)}`);
  return r.stdout.split('\n').filter(Boolean).map(l => l.split(' ')[0]).map(rule => ({ rule, tags: ruleMeta[rule]?.tags || [], severity: ruleMeta[rule]?.severity || 'high', engine: 'yara' }));
}
// Windows Authenticode through PowerShell; elsewhere the publisher check is reported as not available.
export async function signature(file) {
  if (process.platform !== 'win32') return { status: 'not-available', signer: null, issuer: null, reason: 'Authenticode verification runs on Windows' };
  const ps = `$s=Get-AuthenticodeSignature -LiteralPath $env:CG_FILE; [pscustomobject]@{status=[string]$s.Status;signer=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{$null};issuer=if($s.SignerCertificate){$s.SignerCertificate.Issuer}else{$null}}|ConvertTo-Json -Compress`;
  const r = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], { env: { ...process.env, CG_FILE: file } });
  try { const j = JSON.parse(r.stdout.trim()); const map = { Valid: 'valid', NotSigned: 'unsigned', HashMismatch: 'invalid', NotTrusted: 'untrusted', UnknownError: 'unknown', NotSupportedFileFormat: 'not-applicable', Incompatible: 'unknown' }; return { status: map[j.status] || 'unknown', signer: j.signer, issuer: j.issuer, reason: null }; }
  catch { return { status: 'unknown', signer: null, issuer: null, reason: 'PowerShell signature check failed' }; }
}
export function loadHashList(file) { if (!file) return new Set(); return new Set(fs.readFileSync(file, 'utf8').split(/\r?\n/).map(l => l.trim().toLowerCase()).filter(l => /^[a-f0-9]{64}$/.test(l))); }

// Quarantine: move unchanged, name by SHA-256, read-only, verify hash, append a hash-chained custody record.
export function quarantine(file, dir, { sha256, actor = os.userInfo().username, reason, case_ref = null, now = new Date() }) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const target = path.join(dir, `${sha256}.quarantine`);
  if (!fs.existsSync(target)) { try { fs.renameSync(file, target); } catch { fs.copyFileSync(file, target); fs.unlinkSync(file); } } else fs.unlinkSync(file);
  fs.chmodSync(target, 0o400);
  const after = createHash('sha256').update(fs.readFileSync(target)).digest('hex'); if (after !== sha256) throw new Error('hash changed during quarantine');
  const log = path.join(dir, 'custody.jsonl'), lines = fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean) : [];
  const previous = lines.length ? JSON.parse(lines.at(-1)).record_hash : '0'.repeat(64);
  const record = { custody_id: randomUUID(), at: now.toISOString(), actor, host: os.hostname(), action: 'quarantined', sha256, original_name: path.basename(file), reason, case_ref, location: path.basename(target), hash_verified_after_move: true, previous_hash: previous };
  record.record_hash = createHash('sha256').update(JSON.stringify(record)).digest('hex'); fs.appendFileSync(log, JSON.stringify(record) + '\n', { mode: 0o600 });
  return record;
}
export function verifyCustody(dir) {
  const log = path.join(dir, 'custody.jsonl'); if (!fs.existsSync(log)) return { valid: true, records: 0 }; let previous = '0'.repeat(64), n = 0;
  for (const line of fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean)) { const r = JSON.parse(line), { record_hash, ...rest } = r; if (r.previous_hash !== previous || createHash('sha256').update(JSON.stringify(rest)).digest('hex') !== record_hash) return { valid: false, records: n }; const f = path.join(dir, r.location); if (fs.existsSync(f) && createHash('sha256').update(fs.readFileSync(f)).digest('hex') !== r.sha256) return { valid: false, records: n, reason: `quarantined file ${r.location} changed` }; previous = record_hash; n++; }
  return { valid: true, records: n };
}

export async function triage(file, { rules = null, rulesFile = null, useYara = false, ruleMeta = {}, knownBad = new Set(), knownGood = new Set() } = {}) {
  const stat = fs.statSync(file); if (!stat.isFile()) throw new Error('not a regular file'); if (stat.size > 256 * 1024 * 1024) throw new Error('file larger than 256 MB');
  const buf = fs.readFileSync(file), h = hashes(buf), type = fileType(buf);
  const yara = useYara && rulesFile ? await matchYara(rulesFile, file, ruleMeta) : rules ? matchYaraLite(rules, buf) : [];
  const sig = ['pe-executable', 'ole-document', 'script'].includes(type) || path.extname(file).match(/\.(exe|dll|sys|msi|ps1|cab|cat)$/i) ? await signature(file) : { status: 'not-applicable', signer: null, issuer: null, reason: 'file type is not signed' };
  const reputation = knownBad.has(h.sha256) ? 'known-bad' : knownGood.has(h.sha256) ? 'known-good' : 'unknown';
  const verdict = reputation === 'known-bad' || yara.some(m => ['high', 'critical'].includes(m.severity)) ? 'malicious' : yara.length || sig.status === 'invalid' ? 'suspicious' : reputation === 'known-good' || sig.status === 'valid' ? 'trusted' : 'unknown';
  return { name: path.basename(file), directory_ref: createHash('sha256').update(path.dirname(path.resolve(file))).digest('hex').slice(0, 16), size: stat.size, type, ...h, signature: sig, yara, reputation, verdict };
}
