// CG-128 Encrypted platform backup with a real restore test.
//   CG_BACKUP_PASSPHRASE=<16+ characters> node scripts/platform-backup.js create --data <data dir> --out <backup dir>
//   CG_BACKUP_PASSPHRASE=<...>            node scripts/platform-backup.js restore-test --data <data dir> --file <file.cgbak>
// The passphrase is read from the environment only (never a command-line argument). Each run is recorded in the
// platform database so the self-defense posture can show when a backup was last restore-tested.
import os from 'node:os';
import path from 'node:path';
import { Store } from '../lib/store.js';
import { createBackup, restoreTest, SelfDefense } from '../lib/self-defense.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; }, [mode] = args;
const dataDir = path.resolve(flag('--data') || process.env.CG_DATA_DIR || 'data'), dbFile = path.join(dataDir, 'cyberguard.sqlite'), passphrase = process.env.CG_BACKUP_PASSPHRASE || '';
if (!['create', 'restore-test'].includes(mode)) { console.error('usage: platform-backup.js create --data <dir> --out <dir> | restore-test --data <dir> --file <file>'); process.exit(2); }
if (passphrase.length < 16) { console.error('Set CG_BACKUP_PASSPHRASE (16 or more characters).'); process.exit(2); }
const store = new Store(dbFile), sd = new SelfDefense(store, { root: process.cwd(), dataDir, dbFile });
try {
  if (mode === 'create') {
    const out = path.resolve(flag('--out') || path.join(dataDir, 'backups')), made = createBackup({ store, dbFile, dataDir, passphrase, outDir: out });
    // Every backup is restore-tested immediately; an untested backup is not counted.
    const test = restoreTest({ file: made.file, passphrase, workDir: path.join(os.tmpdir(), `cg-restore-${process.pid}`), Store });
    sd.recordBackup('platform-backup', { ...test, bytes: made.bytes }); console.log(JSON.stringify({ file: made.file, sha256: made.sha256, bytes: made.bytes, contents: made.contents, restore_test: test }, null, 2));
  } else {
    const test = restoreTest({ file: path.resolve(flag('--file')), passphrase, workDir: path.join(os.tmpdir(), `cg-restore-${process.pid}`), Store });
    sd.recordBackup('platform-backup', test); console.log(JSON.stringify(test, null, 2));
  }
} catch (e) { console.error(`Backup failed: ${e.message}`); process.exitCode = 1; } finally { store.close(); }
