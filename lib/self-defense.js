// CG-128 Product self-defense. CyberGuard is itself a high-value target, so it checks its own posture: administrator
// accounts (MFA, count, staleness), the leftover setup token, key-file permissions, where its data lives, how it is
// reached (loopback, VPN, TLS), its audit chain, the integrity of its own code against a signed release manifest,
// its software supply chain (runtime dependencies) and whether a recent encrypted platform backup was restore-tested.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, createPublicKey, createPrivateKey, sign, verify, randomBytes, scryptSync, createCipheriv, createDecipheriv } from 'node:crypto';

const sha = b => createHash('sha256').update(b).digest('hex');
export const RELEASE_ENTRIES = ['lib', 'public', 'scripts', 'server.js', 'package.json'];
export function releaseFiles(root) {
  const out = {}; const visit = rel => { const abs = path.join(root, rel); if (!fs.existsSync(abs)) return; if (fs.statSync(abs).isDirectory()) { for (const n of fs.readdirSync(abs).sort()) visit(`${rel}/${n}`); } else out[rel] = sha(fs.readFileSync(abs, 'utf8').replace(/\r\n/g, '\n')); };
  for (const e of RELEASE_ENTRIES) visit(e); return out;
}
const canonical = files => JSON.stringify(Object.keys(files).sort().map(k => [k, files[k]]));
export function signRelease(root, privateKeyPem, version) {
  const files = releaseFiles(root), body = canonical(files), key = createPrivateKey(privateKeyPem), pub = createPublicKey(key).export({ type: 'spki', format: 'pem' });
  return { schema_version: 'cg.release-manifest/1', version, created_at: new Date().toISOString(), files, signer_fingerprint: sha(createPublicKey(pub).export({ type: 'spki', format: 'der' })), signature: sign(null, Buffer.from(body), key).toString('base64') };
}
export function verifyRelease(root, manifest, publicKeyPem) {
  if (!manifest) return { state: 'unsigned', changed: [], missing: [], added: [] };
  const key = createPublicKey(publicKeyPem), okSig = verify(null, Buffer.from(canonical(manifest.files)), key, Buffer.from(manifest.signature, 'base64')), now = releaseFiles(root);
  const changed = Object.keys(manifest.files).filter(f => now[f] && now[f] !== manifest.files[f]), missing = Object.keys(manifest.files).filter(f => !now[f]), added = Object.keys(now).filter(f => !manifest.files[f]);
  return { state: !okSig ? 'signature-invalid' : changed.length || missing.length || added.length ? 'modified' : 'verified', version: manifest.version, changed, missing, added };
}
// Encrypted platform backup: a consistent database copy plus the key files, sealed with AES-256-GCM under a passphrase.
export function createBackup({ store, dbFile, dataDir, passphrase, outDir }) {
  if (!passphrase || passphrase.length < 16) throw Object.assign(new Error('backup_passphrase_must_have_16_characters'), { code: 'backup_passphrase_must_have_16_characters', status: 400 });
  fs.mkdirSync(outDir, { recursive: true, mode: 0o700 }); const tmp = path.join(outDir, `.snapshot-${Date.now()}.sqlite`); store.db.exec(`VACUUM INTO '${tmp.replace(/'/g, "''")}'`);
  const files = { 'cyberguard.sqlite': fs.readFileSync(tmp) }; fs.rmSync(tmp);
  for (const k of [`${path.basename(dbFile)}.secret-key`, `${path.basename(dbFile)}.mfa-key`, 'rule-signing-key.pem']) { const f = path.join(dataDir, k); if (fs.existsSync(f)) files[k] = fs.readFileSync(f); }
  const plain = Buffer.from(JSON.stringify(Object.fromEntries(Object.entries(files).map(([k, v]) => [k, v.toString('base64')])))), salt = randomBytes(16), iv = randomBytes(12), key = scryptSync(passphrase, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  const c = createCipheriv('aes-256-gcm', key, iv), enc = Buffer.concat([c.update(plain), c.final()]), out = Buffer.concat([Buffer.from('CGBK1'), salt, iv, c.getAuthTag(), enc]), name = `cyberguard-${new Date().toISOString().replace(/[:.]/g, '-')}.cgbak`;
  fs.writeFileSync(path.join(outDir, name), out, { mode: 0o600, flag: 'wx' }); return { file: path.join(outDir, name), sha256: sha(out), bytes: out.length, contents: Object.keys(files) };
}
export function restoreTest({ file, passphrase, workDir, Store }) {
  const buf = fs.readFileSync(file); if (buf.subarray(0, 5).toString() !== 'CGBK1') throw new Error('not_a_cyberguard_backup');
  const salt = buf.subarray(5, 21), iv = buf.subarray(21, 33), tag = buf.subarray(33, 49), enc = buf.subarray(49), key = scryptSync(passphrase, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  const d = createDecipheriv('aes-256-gcm', key, iv); d.setAuthTag(tag); let plain; try { plain = Buffer.concat([d.update(enc), d.final()]); } catch { throw new Error('backup_decryption_failed'); }
  const files = JSON.parse(plain.toString()); fs.mkdirSync(workDir, { recursive: true, mode: 0o700 }); const dbPath = path.join(workDir, 'cyberguard.sqlite'); fs.writeFileSync(dbPath, Buffer.from(files['cyberguard.sqlite'], 'base64'));
  const s = new Store(dbPath); try { const audit = s.verifyAudit(), counts = Object.fromEntries(['users', 'assets', 'events', 'alerts', 'cases'].map(t => [t, s.get(`SELECT COUNT(*) n FROM ${t}`).n])); return { restored: true, audit_chain_valid: audit.valid, counts, keys: Object.keys(files).filter(k => k !== 'cyberguard.sqlite'), sha256: sha(buf) }; } finally { s.close(); fs.rmSync(workDir, { recursive: true, force: true }); }
}

export class SelfDefense {
  constructor(store, { clock, root, dataDir, dbFile, tls, accessMode, releasePublicKeyPem, domain }) { Object.assign(this, { s: store, clock: clock || (() => Date.now()), root, dataDir, dbFile, tls, accessMode, releasePublicKeyPem, domain }); }
  now() { return new Date(this.clock()).toISOString(); }
  recordBackup(actor, result) { this.s.run('INSERT INTO platform_backups(at,actor,sha256,bytes,restore_tested,audit_chain_valid,detail) VALUES (?,?,?,?,?,?,?)', this.now(), actor, result.sha256, result.bytes || 0, result.restored ? 1 : 0, result.audit_chain_valid ? 1 : 0, JSON.stringify(result)); this.s.audit(actor, 'platform.backup.recorded', 'platform', { sha256: result.sha256, restore_tested: Boolean(result.restored) }, this.now()); }
  release() { const f = path.join(this.root, 'release-manifest.json'); const m = fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : null; return m && this.releasePublicKeyPem ? verifyRelease(this.root, m, this.releasePublicKeyPem) : { state: 'unsigned', changed: [], missing: [], added: [] }; }
  posture() {
    const checks = [], add = (id, state, en, ar) => checks.push({ id, state, detail: en, detail_ar: ar }), now = this.clock();
    const admins = this.s.all("SELECT u.id,u.username,u.created_at,m.enabled_at FROM users u LEFT JOIN user_mfa m ON m.user_id=u.id WHERE u.role='admin'"), noMfa = admins.filter(a => !a.enabled_at);
    add('admin-mfa', noMfa.length ? 'fail' : 'pass', noMfa.length ? `${noMfa.length} administrator(s) without MFA: ${noMfa.map(a => a.username).join(', ')}` : 'Every administrator has MFA', noMfa.length ? `${noMfa.length} مسؤول دون تحقق متعدد: ${noMfa.map(a => a.username).join('، ')}` : 'كل المسؤولين لديهم تحقق متعدد');
    add('admin-count', !admins.length ? 'fail' : admins.length > 5 ? 'warn' : 'pass', `${admins.length} administrator account(s)`, `${admins.length} حساب مسؤول`);
    const stale = admins.filter(a => { const last = this.s.get('SELECT MAX(last_seen) t FROM sessions WHERE user_id=?', a.id)?.t; return now - Date.parse(a.created_at) > 90 * 86400000 && (!last || now - last > 90 * 86400000); });
    add('stale-admins', stale.length ? 'warn' : 'pass', stale.length ? `Administrators unused for 90 days: ${stale.map(a => a.username).join(', ')}` : 'No unused administrator accounts', stale.length ? `مسؤولون غير مستخدمين منذ 90 يومًا: ${stale.map(a => a.username).join('، ')}` : 'لا حسابات مسؤول غير مستخدمة');
    const setupLeft = fs.existsSync(path.join(this.dataDir, 'setup-token')) && this.s.get('SELECT COUNT(*) n FROM users').n > 0;
    add('setup-token', setupLeft ? 'fail' : 'pass', setupLeft ? 'The first-run setup token still exists after setup' : 'No setup token left behind', setupLeft ? 'رمز التهيئة الأولى ما زال موجودًا بعد التهيئة' : 'لا يوجد رمز تهيئة متبقٍ');
    const keyFiles = [`${this.dbFile}.secret-key`, `${this.dbFile}.mfa-key`, path.join(this.dataDir, 'rule-signing-key.pem')].filter(f => fs.existsSync(f));
    if (process.platform === 'win32') add('key-permissions', 'pass', `${keyFiles.length} key file(s) in the owner-only data folder (Windows ACLs)`, `${keyFiles.length} ملف مفاتيح في مجلد البيانات الخاص بالمالك (صلاحيات Windows)`);
    else { const open = keyFiles.filter(f => fs.statSync(f).mode & 0o077); add('key-permissions', open.length ? 'fail' : 'pass', open.length ? `Key files readable by others: ${open.map(f => path.basename(f)).join(', ')}` : `${keyFiles.length} key file(s) are owner-only`, open.length ? `ملفات مفاتيح يقرؤها غير المالك: ${open.map(f => path.basename(f)).join('، ')}` : `${keyFiles.length} ملف مفاتيح للمالك فقط`); }
    const inSource = path.resolve(this.dataDir).startsWith(path.resolve(this.root) + path.sep);
    add('data-location', inSource ? 'warn' : 'pass', inSource ? 'The data folder is inside the source tree; keep it out of copies and archives of the code' : 'The data folder is outside the source tree', inSource ? 'مجلد البيانات داخل شجرة الكود؛ أبقِه خارج نسخ الكود وأرشيفاته' : 'مجلد البيانات خارج شجرة الكود');
    add('transport', this.accessMode === 'vpn' && !this.tls ? 'fail' : 'pass', this.accessMode === 'vpn' ? (this.tls ? 'Reachable over the VPN with TLS' : 'Reachable over the VPN without TLS') : 'Bound to loopback only; remote access is refused unless VPN mode is configured', this.accessMode === 'vpn' ? (this.tls ? 'متاح عبر VPN مع TLS' : 'متاح عبر VPN دون TLS') : 'مربوط بالعنوان المحلي فقط؛ ويُرفض الوصول البعيد ما لم يُضبط وضع VPN');
    const audit = this.s.verifyAudit(); add('audit-chain', audit.valid ? 'pass' : 'fail', audit.valid ? `Audit chain intact (${audit.checked} records)` : 'Audit chain broken', audit.valid ? `سلسلة التدقيق سليمة (${audit.checked} سجل)` : 'سلسلة التدقيق مكسورة');
    const rel = this.release();
    add('release-integrity', rel.state === 'verified' ? 'pass' : rel.state === 'unsigned' ? 'warn' : 'fail', rel.state === 'verified' ? `Code matches signed release ${rel.version}` : rel.state === 'unsigned' ? 'Development build: no signed release manifest' : `Code differs from the signed release (${rel.state}: ${[...rel.changed, ...rel.missing, ...rel.added].slice(0, 5).join(', ')})`, rel.state === 'verified' ? `الكود يطابق الإصدار الموقع ${rel.version}` : rel.state === 'unsigned' ? 'نسخة تطوير: لا يوجد بيان إصدار موقع' : 'الكود يختلف عن الإصدار الموقع');
    if (['modified', 'signature-invalid'].includes(rel.state)) this.domain?.alert({ key: `CG-SELF-TAMPER-128:${rel.state}:${sha([...rel.changed, ...rel.missing, ...rel.added].join(','))}`, rule: 'CG-SELF-TAMPER-128', severity: 'critical', title: `CyberGuard code differs from its signed release: ${[...rel.changed, ...rel.missing, ...rel.added].slice(0, 3).join(', ')} / كود CyberGuard يختلف عن إصداره الموقع` });
    let deps = {}; try { const pkg = JSON.parse(fs.readFileSync(path.join(this.root, 'package.json'), 'utf8')); deps = { ...pkg.dependencies, ...pkg.optionalDependencies }; } catch { }
    add('supply-chain', Object.keys(deps).length ? 'warn' : 'pass', Object.keys(deps).length ? `${Object.keys(deps).length} runtime dependencies to keep verified` : 'No third-party runtime dependencies (Node.js built-ins only)', Object.keys(deps).length ? `${Object.keys(deps).length} اعتماديات تشغيل يجب التحقق منها` : 'لا اعتماديات تشغيل من أطراف ثالثة (مكتبات Node.js المدمجة فقط)');
    const b = this.s.get('SELECT at,restore_tested,audit_chain_valid FROM platform_backups ORDER BY at DESC LIMIT 1'), age = b ? (now - Date.parse(b.at)) / 86400000 : null;
    add('platform-backup', !b ? 'fail' : !b.restore_tested || !b.audit_chain_valid ? 'fail' : age > 7 ? 'warn' : 'pass', !b ? 'No encrypted platform backup recorded' : `Last backup ${Math.floor(age)} day(s) ago, restore ${b.restore_tested ? 'tested' : 'not tested'}`, !b ? 'لا توجد نسخة احتياطية مشفرة للمنصة' : `آخر نسخة قبل ${Math.floor(age)} يوم، والاستعادة ${b.restore_tested ? 'مختبرة' : 'غير مختبرة'}`);
    return { checks, score: { pass: checks.filter(c => c.state === 'pass').length, warn: checks.filter(c => c.state === 'warn').length, fail: checks.filter(c => c.state === 'fail').length }, release: rel,
      claim: 'CyberGuard checks its own defenses: administrator MFA and accounts, setup token, key permissions, data location, transport, audit chain, code integrity against a signed release, runtime dependencies and restore-tested encrypted backups.',
      claim_ar: 'يفحص CyberGuard دفاعاته الذاتية: التحقق المتعدد للمسؤولين وحساباتهم، ورمز التهيئة، وصلاحيات المفاتيح، ومكان البيانات، وطريقة الوصول، وسلسلة التدقيق، وسلامة الكود مقابل إصدار موقع، واعتماديات التشغيل، ونسخًا احتياطية مشفرة مختبرة الاستعادة.' };
  }
}
