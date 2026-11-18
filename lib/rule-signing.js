// CG-066 Ed25519 signing of detection content. Each installation has its own rule-signing key pair, generated at runtime
// and kept owner-only in the data directory (never in the database or the repository). Approved rule versions and
// exported rule packs are signed over a canonical JSON form; packs are accepted only from trusted publisher keys.
import fs from 'node:fs';
import path from 'node:path';
import { generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify, createHash } from 'node:crypto';

export const canonical = v => Array.isArray(v) ? `[${v.map(canonical).join(',')}]` : v && typeof v === 'object' ? `{${Object.keys(v).sort().filter(k => v[k] !== undefined).map(k => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}` : JSON.stringify(v);
export const fingerprint = publicKeyPem => createHash('sha256').update(createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' })).digest('hex');
export function verifySignature(value, signature, publicKeyPem) {
  try { return verify(null, Buffer.from(canonical(value)), createPublicKey(publicKeyPem), Buffer.from(String(signature), 'base64')); } catch { return false; }
}
export class RuleSigner {
  constructor(dataDir) {
    const file = path.join(dataDir, 'rule-signing-key.pem');
    if (!fs.existsSync(file)) { const { privateKey } = generateKeyPairSync('ed25519'); fs.writeFileSync(file, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' }); }
    this.privateKey = createPrivateKey(fs.readFileSync(file, 'utf8'));
    this.publicKeyPem = createPublicKey(this.privateKey).export({ type: 'spki', format: 'pem' }); this.fingerprint = fingerprint(this.publicKeyPem);
  }
  sign(value) { return sign(null, Buffer.from(canonical(value)), this.privateKey).toString('base64'); }
  verify(value, signature) { return verifySignature(value, signature, this.publicKeyPem); }
}
