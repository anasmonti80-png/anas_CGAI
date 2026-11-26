// CG-157 AWS Backup Vault Lock review from read-only exports by the owner (nothing is locked or changed):
//   aws backup list-backup-vaults --region <r> > vaults.json
//   aws backup list-restore-jobs --region <r> --by-created-after <date> > restores.json
//   node scripts/backup-vault-lock.js --account-id <id> --region <r> --authorization-ref <ref> --vaults vaults.json [--restore-jobs restores.json] --output vl.json
import fs from 'node:fs';
import { parseVaults, parseRestoreJobs, assessVaults } from '../lib/backup-vault-lock.js';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const acct = flag('--account-id'), region = flag('--region'), auth = flag('--authorization-ref'), out = flag('--output');
if (!/^\d{12}$/.test(acct || '') || !region || !auth || !out || !flag('--vaults')) { console.error('usage: backup-vault-lock.js --account-id <12 digits> --region <r> --authorization-ref <ref> --vaults vaults.json [--restore-jobs restores.json] --output f'); process.exit(2); }
if (fs.existsSync(out)) { console.error('Output already exists. Choose a new file path.'); process.exit(2); }
const read = f => JSON.parse(fs.readFileSync(f, 'utf8').replace(/^﻿/, ''));
let vaults, restores = [];
try { vaults = parseVaults(read(flag('--vaults'))); if (flag('--restore-jobs')) restores = parseRestoreJobs(read(flag('--restore-jobs'))); } catch (e) { console.error(`Invalid export: ${e.code || e.message}`); process.exit(2); }
const at = new Date().toISOString(), details = { account_id: acct, region, authorization_ref: auth, vaults, restores: restores.slice(0, 5000) };
const event = { event_id: `vault-lock:${acct}:${region}:${at}`, kind: 'resilience.backup_vault_lock', observed_at: at, asset: { external_id: `aws:${acct}`, hostname: `AWS ${acct}`, os_family: 'unknown', device_type: 'unknown', addresses: [] }, details };
fs.writeFileSync(out, JSON.stringify({ schema_version: 'cg.telemetry/1', events: [event] }, null, 2), { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ account: acct, region, vaults: assessVaults(details).map(v => `${v.name}:${v.mode}:${v.restore}`), output: out }));
