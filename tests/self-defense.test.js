import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { SelfDefense, signRelease, verifyRelease, createBackup, restoreTest } from '../lib/self-defense.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), tmp = (t, p) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), p)); process.once('exit', () => fs.rmSync(d, { recursive: true, force: true })); return d; };
const keys = () => { const { privateKey, publicKey } = generateKeyPairSync('ed25519'); return { priv: privateKey.export({ type: 'pkcs8', format: 'pem' }), pub: publicKey.export({ type: 'spki', format: 'pem' }) }; };

test('the platform checks its own administrators, setup token, transport, audit chain, dependencies and backups (CG-128)', t => {
  const dir = tmp(t, 'cg128-'), dbFile = path.join(dir, 'cyberguard.sqlite'), s = new Store(dbFile); t.after(() => s.close());
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'root', 'root-admin', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); fs.writeFileSync(path.join(dir, 'setup-token'), 'left-behind');
  const sd = new SelfDefense(s, { root: ROOT, dataDir: dir, dbFile, tls: false, accessMode: 'local' }), by = p => Object.fromEntries(p.checks.map(c => [c.id, c.state]));
  let p = by(sd.posture()); assert.equal(p['admin-mfa'], 'fail'); assert.equal(p['setup-token'], 'fail'); assert.equal(p['platform-backup'], 'fail'); assert.equal(p['audit-chain'], 'pass'); assert.equal(p.transport, 'pass'); assert.equal(p['supply-chain'], 'pass', 'no third-party runtime dependencies'); assert.equal(p['release-integrity'], 'warn', 'unsigned development build');
  s.run('INSERT INTO user_mfa(user_id,seed_cipher,enrolled_at,enabled_at) VALUES (?,?,?,?)', 'root', 'x', new Date().toISOString(), new Date().toISOString()); fs.rmSync(path.join(dir, 'setup-token'));
  p = by(sd.posture()); assert.equal(p['admin-mfa'], 'pass'); assert.equal(p['setup-token'], 'pass');
  assert.equal(by(new SelfDefense(s, { root: ROOT, dataDir: dir, dbFile, tls: false, accessMode: 'vpn' }).posture()).transport, 'fail', 'VPN access without TLS');
  if (process.platform !== 'win32') { fs.writeFileSync(`${dbFile}.secret-key`, Buffer.alloc(32), { mode: 0o644 }); assert.equal(by(sd.posture())['key-permissions'], 'fail'); }
});

test('code changes against a signed release are detected and raise CG-SELF-TAMPER-128 (CG-128)', t => {
  const root = tmp(t, 'cg128-rel-'), k = keys(), other = keys();
  fs.mkdirSync(path.join(root, 'lib')); fs.writeFileSync(path.join(root, 'lib', 'a.js'), 'export const a = 1;\n'); fs.writeFileSync(path.join(root, 'server.js'), 'console.log(1)\n'); fs.writeFileSync(path.join(root, 'package.json'), '{"name":"x"}\n');
  const m = signRelease(root, k.priv, '1.4.0'); assert.equal(Object.keys(m.files).length, 3);
  assert.equal(verifyRelease(root, m, k.pub).state, 'verified'); assert.equal(verifyRelease(root, m, other.pub).state, 'signature-invalid');
  fs.writeFileSync(path.join(root, 'lib', 'a.js'), 'export const a = 2; // backdoor\n'); fs.writeFileSync(path.join(root, 'lib', 'b.js'), 'x');
  const r = verifyRelease(root, m, k.pub); assert.equal(r.state, 'modified'); assert.deepEqual(r.changed, ['lib/a.js']); assert.deepEqual(r.added, ['lib/b.js']);
  fs.writeFileSync(path.join(root, 'release-manifest.json'), JSON.stringify(m)); const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  const post = new SelfDefense(s, { root, dataDir: root, dbFile: path.join(root, 'db'), accessMode: 'local', releasePublicKeyPem: k.pub, domain: d }).posture();
  assert.equal(post.checks.find(c => c.id === 'release-integrity').state, 'fail'); assert.deepEqual(s.all("SELECT severity FROM alerts WHERE rule_id='CG-SELF-TAMPER-128'").map(x => x.severity), ['critical']);
  const keyOut = path.join(root, 'priv.pem'); assert.equal(spawnSync(process.execPath, [path.join(ROOT, 'scripts/release-sign.js'), 'keygen', '--private', path.join(ROOT, 'inside.pem')], { encoding: 'utf8' }).status, 2, 'a private key inside the repository is refused'); assert.ok(!fs.existsSync(keyOut));
});

test('encrypted platform backups are restore-tested; a wrong passphrase or a tampered file fails (CG-128)', t => {
  const dir = tmp(t, 'cg128-bk-'), dbFile = path.join(dir, 'cyberguard.sqlite'), s = new Store(dbFile); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString()); fs.writeFileSync(`${dbFile}.secret-key`, Buffer.alloc(32, 7), { mode: 0o600 });
  const src = d.createSource('a', { name: 'S', stale_seconds: 86400 }); d.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'e', kind: 'asset.observed', observed_at: new Date().toISOString(), asset: { external_id: 'h', hostname: 'H', os_family: 'windows', device_type: 'server', addresses: [] }, details: {} }] });
  const pass = 'a-long-backup-passphrase-2026', out = path.join(dir, 'backups'); assert.throws(() => createBackup({ store: s, dbFile, dataDir: dir, passphrase: 'short', outDir: out }), /backup_passphrase_must_have_16_characters/);
  const b = createBackup({ store: s, dbFile, dataDir: dir, passphrase: pass, outDir: out }); assert.ok(b.contents.includes('cyberguard.sqlite') && b.contents.includes('cyberguard.sqlite.secret-key'));
  assert.ok(!fs.readFileSync(b.file).includes(Buffer.from('fixture-not-a-password-hash')), 'the backup is encrypted');
  const r = restoreTest({ file: b.file, passphrase: pass, workDir: path.join(dir, 'restore'), Store }); assert.equal(r.audit_chain_valid, true); assert.equal(r.counts.events, 1); assert.deepEqual(r.keys, ['cyberguard.sqlite.secret-key']);
  assert.throws(() => restoreTest({ file: b.file, passphrase: 'wrong-passphrase-0000', workDir: path.join(dir, 'r2'), Store }), /backup_decryption_failed/);
  const bad = Buffer.from(fs.readFileSync(b.file)); bad[bad.length - 5] ^= 0xff; fs.writeFileSync(path.join(dir, 'bad.cgbak'), bad); assert.throws(() => restoreTest({ file: path.join(dir, 'bad.cgbak'), passphrase: pass, workDir: path.join(dir, 'r3'), Store }), /backup_decryption_failed/);
  const sd = new SelfDefense(s, { root: ROOT, dataDir: dir, dbFile, accessMode: 'local' }); sd.recordBackup('test', { ...r, bytes: b.bytes });
  assert.equal(sd.posture().checks.find(c => c.id === 'platform-backup').state, 'pass');
});

test('the backup script reads the passphrase from the environment and records a restore-tested backup (CG-128)', t => {
  const dir = tmp(t, 'cg128-cli-'), s = new Store(path.join(dir, 'cyberguard.sqlite')); s.close();
  const run = env => spawnSync(process.execPath, [path.join(ROOT, 'scripts/platform-backup.js'), 'create', '--data', dir, '--out', path.join(dir, 'bk')], { encoding: 'utf8', env: { ...process.env, ...env } });
  assert.equal(run({ CG_BACKUP_PASSPHRASE: '' }).status, 2); const r = run({ CG_BACKUP_PASSPHRASE: 'cli-backup-passphrase-2026' }); assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).restore_test.restored, true); const s2 = new Store(path.join(dir, 'cyberguard.sqlite')); t.after(() => s2.close()); assert.equal(s2.get('SELECT restore_tested FROM platform_backups').restore_tested, 1);
});
