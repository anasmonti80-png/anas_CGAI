import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { RuleSigner, verifySignature } from '../lib/rule-signing.js';
import { EvidenceVault } from '../lib/evidence-vault.js';

const sha = b => createHash('sha256').update(b).digest('hex');
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg114-')), s = new Store(':memory:');
  t.after(() => { s.close(); for (const f of fs.existsSync(path.join(dir, 'evidence')) ? fs.readdirSync(path.join(dir, 'evidence')) : []) fs.chmodSync(path.join(dir, 'evidence', f), 0o600); fs.rmSync(dir, { recursive: true, force: true }); });
  let now = Date.parse('2026-11-22T10:00:00.000Z'); const d = new Domain(s, { clock: () => now });
  for (const id of ['admin-a', 'analyst-b']) s.run('INSERT INTO users VALUES (?,?,?,?,?)', id, id, 'fixture-not-a-password-hash', id === 'admin-a' ? 'admin' : 'analyst', new Date(now).toISOString());
  const src = d.createSource('admin-a', { name: 'Synthetic lab', stale_seconds: 86400 });
  d.ingest('admin-a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'f1', kind: 'security.finding', observed_at: new Date(now).toISOString(), asset: { external_id: 'lab-01', hostname: 'LAB-01', os_family: 'windows', device_type: 'workstation', addresses: ['192.0.2.10'] }, details: { severity: 'high', title: 'SYNTHETIC finding', description: 'Synthetic only' } }] });
  const alert = s.get('SELECT id FROM alerts LIMIT 1'), kase = d.createCase('admin-a', { title: 'Synthetic case', alert_ids: [alert.id] });
  const vault = new EvidenceVault(s, { dataDir: dir, clock: () => now, signer: new RuleSigner(dir), domain: d });
  return { s, d, dir, vault, kase, advance: ms => { now += ms; } };
}
const LOG = Buffer.from('Nov 22 09:41:07 lab-01 sshd[811]: Failed password for root from 192.0.2.66 port 50111 ssh2\nNov 22 09:41:09 lab-01 sshd[811]: Failed password for root from 192.0.2.66 port 50111 ssh2\n');
const meta = { name: 'auth.log', media_type: 'text/plain', source_ref: 'lab-01:/var/log/auth.log', acquisition: 'collector-export', collected_at: '2026-11-22T09:50:00.000Z', collected_by: 'collector lab-01' };

test('original evidence is kept byte for byte with its time, source, collector and SHA-256, read-only and content-addressed (CG-114)', t => {
  const { vault, kase, dir } = fixture(t);
  assert.throws(() => vault.collect('analyst-b', kase.id, { ...meta, expected_sha256: 'f'.repeat(64) }, LOG), /evidence_hash_mismatch_with_source/);
  assert.throws(() => vault.collect('analyst-b', kase.id, { ...meta, name: '../etc/passwd' }, LOG), /evidence_name_must_not_contain_paths/);
  assert.throws(() => vault.collect('analyst-b', kase.id, { ...meta, collected_at: '2027-01-01T00:00:00.000Z' }, LOG), /invalid_evidence_collected_at/);
  assert.throws(() => vault.collect('analyst-b', 'no-case', meta, LOG), /case_not_found/);
  const item = vault.collect('analyst-b', kase.id, { ...meta, expected_sha256: sha(LOG) }, LOG);
  assert.equal(item.sha256, sha(LOG)); assert.equal(item.size, LOG.length); assert.equal(item.collected_at, meta.collected_at); assert.equal(item.received_by, 'analyst-b'); assert.equal(item.acquisition, 'collector-export');
  const file = path.join(dir, 'evidence', item.sha256); assert.deepEqual(fs.readFileSync(file), LOG, 'stored unchanged');
  if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o400, 'owner read-only');
  assert.deepEqual(item.custody.map(c => [c.action, c.actor]), [['collected', 'analyst-b']]); assert.equal(item.custody[0].details.source_hash_confirmed, true);
});

test('every access needs a purpose and is recorded; derived copies are separate items and exports are signed (CG-114)', t => {
  const { vault, kase, s, advance } = fixture(t), item = vault.collect('analyst-b', kase.id, meta, LOG);
  assert.throws(() => vault.read('admin-a', item.id, ''), /access_purpose/);
  advance(60000); const { bytes } = vault.read('admin-a', item.id, 'Confirm the brute force source for the case'); assert.deepEqual(bytes, LOG);
  advance(60000); const redacted = Buffer.from(LOG.toString().replaceAll('192.0.2.66', '[source]'));
  assert.throws(() => vault.derive('analyst-b', item.id, { name: 'auth.copy.log', transform: 'none' }, LOG), /derived_copy_is_identical_to_parent/);
  const child = vault.derive('analyst-b', item.id, { name: 'auth.redacted.log', transform: 'Source address replaced for sharing with the vendor' }, redacted);
  assert.equal(child.parent_id, item.id); assert.equal(child.acquisition, 'derived'); assert.equal(child.collected_at, meta.collected_at, 'the original collection time is kept');
  const parent = vault.item(item.id); assert.deepEqual(parent.custody.map(c => c.action), ['collected', 'accessed', 'copy-derived']); assert.equal(parent.custody[1].purpose, 'Confirm the brute force source for the case'); assert.equal(parent.custody[1].actor, 'admin-a');
  assert.equal(parent.sha256, sha(LOG), 'the original is unchanged'); assert.equal(parent.derived[0].id, child.id);
  const exp = vault.exportCustody('admin-a', item.id, 'Hand-over to legal counsel');
  assert.ok(verifySignature(exp.bundle, exp.signature, exp.public_key)); assert.equal(exp.bundle.verification.content_valid, true); assert.equal(exp.bundle.custody.at(-1).action, 'exported');
  assert.equal(vault.list(kase.id).find(x => x.id === item.id).last_access.actor, 'admin-a');
  assert.ok(s.all("SELECT action FROM audit WHERE action LIKE 'evidence.%'").length >= 5, 'mirrored into the global audit chain');
});

test('tampering with evidence bytes, custody records or stored events is detected and raises CG-EVIDENCE-TAMPER-114 (CG-114)', t => {
  const { vault, kase, s, dir } = fixture(t), item = vault.collect('analyst-b', kase.id, meta, LOG);
  assert.throws(() => s.run('UPDATE evidence_items SET sha256=? WHERE id=?', 'a'.repeat(64), item.id), /evidence_immutable/);
  assert.throws(() => s.run('DELETE FROM evidence_items WHERE id=?', item.id), /evidence_immutable/);
  assert.throws(() => s.run('UPDATE evidence_custody SET actor=? WHERE item_id=?', 'someone', item.id), /custody_append_only/);
  assert.throws(() => s.run('DELETE FROM evidence_custody WHERE item_id=?', item.id), /custody_append_only/);
  assert.throws(() => s.run("UPDATE events SET payload='{}'"), /events_immutable/);
  const ok = vault.verify('admin-a', item.id); assert.equal(ok.content_valid && ok.chain_valid, true); assert.equal(vault.item(item.id).custody.at(-1).action, 'verified');
  const file = path.join(dir, 'evidence', item.sha256); fs.chmodSync(file, 0o600); fs.writeFileSync(file, Buffer.from(LOG.toString().replace('root', 'svc1')));
  const bad = vault.verify('admin-a', item.id); assert.equal(bad.content_valid, false); assert.equal(bad.chain_valid, true);
  assert.throws(() => vault.read('admin-a', item.id, 'Review after tamper'), /evidence_integrity_failure/);
  assert.throws(() => vault.exportCustody('admin-a', item.id, 'Hand-over'), /evidence_integrity_failure/);
  const alerts = s.all("SELECT severity,title FROM alerts WHERE rule_id='CG-EVIDENCE-TAMPER-114'"); assert.equal(alerts.length, 1); assert.equal(alerts[0].severity, 'critical'); assert.match(alerts[0].title, /content hash differs/);
  // A stored event changed behind the application (trigger dropped by someone with file access) is found by its hash.
  s.db.exec('DROP TRIGGER events_no_update'); s.run("UPDATE events SET payload=replace(payload,'SYNTHETIC finding','edited')");
  const integ = vault.integrity('admin-a'); assert.equal(integ.events.tampered.length, 1); assert.equal(integ.evidence.failures.length, 1); assert.equal(integ.audit_chain.valid, true);
  assert.equal(s.all("SELECT 1 FROM alerts WHERE rule_id='CG-EVIDENCE-TAMPER-114'").length, 2); assert.ok(integ.claim_ar.includes('SHA-256'));
});
