// CG-055 Secret Store for connector secrets (API tokens, SNMPv3 keys, client secrets).
// - Envelope encryption: every secret has its own random data key (AES-256-GCM); data keys are wrapped with the store
//   key kept in the data directory (owner-only file, never in the database, never in the repository).
// - Write-only API: values are never returned to users; only metadata (owner, purpose, rotation, last use).
// - Segmented delegation: a secret is released only to the response-connector or collector sources it is delegated to,
//   for a stated purpose, and every release is audited.
// - Rotation: each secret has a rotation period; overdue secrets are reported and raise CG-SECRET-ROTATION-055.
import fs from 'node:fs';
import { randomBytes, randomUUID, createCipheriv, createDecipheriv } from 'node:crypto';
import { fail, text, digest } from './common.js';

const seal = (key, plain, aad) => { const iv = randomBytes(12), c = createCipheriv('aes-256-gcm', key, iv); c.setAAD(Buffer.from(aad)); const body = Buffer.concat([c.update(plain), c.final()]); return Buffer.concat([iv, c.getAuthTag(), body]).toString('base64url'); };
const open = (key, packed, aad) => { const b = Buffer.from(packed, 'base64url'); fail(b.length > 28, 500, 'secret_record_corrupt'); const d = createDecipheriv('aes-256-gcm', key, b.subarray(0, 12)); d.setAAD(Buffer.from(aad)); d.setAuthTag(b.subarray(12, 28)); return Buffer.concat([d.update(b.subarray(28)), d.final()]); };
export const secretKinds = ['api-token', 'client-secret', 'snmpv3-auth', 'snmpv3-priv', 'ssh-key', 'password', 'certificate-key', 'other'];

export class SecretStore {
  constructor(store, { clock = () => Date.now() } = {}) {
    this.store = store; this.clock = clock;
    if (store.filename === ':memory:') this.key = randomBytes(32);
    else { const file = `${store.filename}.secret-key`; if (fs.existsSync(file)) { this.key = fs.readFileSync(file); fail(this.key.length === 32, 500, 'invalid_secret_store_key'); } else { this.key = randomBytes(32); fs.writeFileSync(file, this.key, { mode: 0o600, flag: 'wx' }); } }
  }
  now() { return new Date(this.clock()).toISOString(); }
  put(actor, input) {
    const ref = text(input.ref, 'secret_ref', 100); fail(/^[a-z0-9][a-z0-9._-]{2,99}$/.test(ref), 400, 'invalid_secret_ref');
    const value = input.value; fail(typeof value === 'string' && value.length >= 8 && value.length <= 16384, 400, 'secret_value_must_be_8_to_16384_characters');
    const kind = text(input.kind, 'secret_kind', 40); fail(secretKinds.includes(kind), 400, 'invalid_secret_kind');
    const purpose = text(input.purpose, 'secret_purpose', 300), rotationDays = Number(input.rotation_days ?? 90); fail(Number.isInteger(rotationDays) && rotationDays >= 1 && rotationDays <= 365, 400, 'invalid_rotation_days');
    const sources = Array.isArray(input.delegated_sources) ? input.delegated_sources.map(String) : []; fail(sources.length >= 1 && sources.length <= 20, 400, 'secret_requires_delegated_sources');
    for (const s of sources) fail(this.store.get("SELECT id FROM sources WHERE id=? AND revoked=0 AND kind IN ('response-connector','network-collector','generic','log-forwarder','managed-agent')", s), 400, 'secret_delegated_source_unknown');
    const dek = randomBytes(32), at = this.now(), existing = this.store.get('SELECT * FROM secrets WHERE ref=?', ref);
    const row = { cipher: seal(dek, Buffer.from(value, 'utf8'), ref), wrapped: seal(this.key, dek, `dek:${ref}`), fingerprint: digest({ ref, value }).slice(0, 16) };
    this.store.transaction(() => {
      if (existing) { fail(existing.owner === actor.id || actor.role === 'admin', 403, 'secret_owned_by_another_user'); this.store.run('UPDATE secrets SET kind=?,purpose=?,cipher=?,wrapped_key=?,fingerprint=?,rotation_days=?,rotated_at=?,version=version+1 WHERE ref=?', kind, purpose, row.cipher, row.wrapped, row.fingerprint, rotationDays, at, ref); }
      else this.store.run('INSERT INTO secrets(ref,kind,purpose,cipher,wrapped_key,fingerprint,owner,created_at,rotated_at,rotation_days,version) VALUES (?,?,?,?,?,?,?,?,?,?,1)', ref, kind, purpose, row.cipher, row.wrapped, row.fingerprint, actor.id, at, at, rotationDays);
      this.store.run('DELETE FROM secret_delegations WHERE ref=?', ref); for (const s of [...new Set(sources)]) this.store.run('INSERT INTO secret_delegations(ref,source_id,granted_by,granted_at) VALUES (?,?,?,?)', ref, s, actor.id, at);
      this.store.audit(actor.id, existing ? 'secret.rotated' : 'secret.created', ref, { kind, rotation_days: rotationDays, delegated_sources: sources.length, fingerprint: row.fingerprint }, at);
    });
    return this.meta(ref);
  }
  // Release a secret to a delegated source for a stated purpose (the only path that decrypts).
  release(sourceId, ref, purpose) {
    const row = this.store.get('SELECT * FROM secrets WHERE ref=? AND revoked_at IS NULL', String(ref)); fail(row, 404, 'secret_not_found');
    fail(this.store.get('SELECT 1 FROM secret_delegations WHERE ref=? AND source_id=?', row.ref, sourceId), 403, 'secret_not_delegated_to_this_source');
    const why = text(purpose, 'secret_release_purpose', 200), at = this.now(), value = open(open(this.key, row.wrapped_key, `dek:${row.ref}`), row.cipher, row.ref).toString('utf8');
    this.store.transaction(() => { this.store.run('UPDATE secrets SET last_used_at=?,uses=uses+1 WHERE ref=?', at, row.ref); this.store.audit(`source:${sourceId}`, 'secret.released', row.ref, { purpose: why, version: row.version }, at); });
    return { ref: row.ref, version: row.version, value };
  }
  revoke(actor, ref) { const row = this.store.get('SELECT * FROM secrets WHERE ref=? AND revoked_at IS NULL', String(ref)); fail(row, 404, 'secret_not_found'); const at = this.now(); this.store.transaction(() => { this.store.run("UPDATE secrets SET revoked_at=?,cipher='',wrapped_key='' WHERE ref=?", at, row.ref); this.store.run('DELETE FROM secret_delegations WHERE ref=?', row.ref); this.store.audit(actor.id, 'secret.revoked', row.ref, {}, at); }); return this.meta(row.ref); }
  meta(ref) {
    const r = this.store.get('SELECT s.ref,s.kind,s.purpose,s.fingerprint,s.owner,u.username owner_name,s.created_at,s.rotated_at,s.rotation_days,s.version,s.last_used_at,s.uses,s.revoked_at FROM secrets s LEFT JOIN users u ON u.id=s.owner WHERE s.ref=?', ref); if (!r) return null;
    const due = new Date(Date.parse(r.rotated_at) + r.rotation_days * 86400000).toISOString(), delegated = this.store.all('SELECT d.source_id,src.name FROM secret_delegations d JOIN sources src ON src.id=d.source_id WHERE d.ref=?', ref);
    return { ...r, rotation_due_at: due, status: r.revoked_at ? 'revoked' : Date.parse(due) <= this.clock() ? 'rotation-overdue' : Date.parse(due) - this.clock() <= 14 * 86400000 ? 'rotation-due-soon' : 'current', delegated_sources: delegated };
  }
  list() { return this.store.all('SELECT ref FROM secrets ORDER BY ref').map(r => this.meta(r.ref)); }
}
