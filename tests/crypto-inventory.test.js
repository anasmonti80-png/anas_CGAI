import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { assessEndpoint, cryptoView } from '../lib/crypto-inventory.js';

test('endpoints are inventoried for legacy and quantum-vulnerable cryptography with post-quantum readiness, and nothing is forced on products that do not support it (CG-179)', t => {
  const old = assessEndpoint({ endpoint: 'vpn.lab:443', protocol: 'tls', versions: ['tls1.0', 'tls1.2'], key_exchange: ['rsa', 'dh-1024'], key: { algorithm: 'rsa', bits: 1024 }, signature_hash: 'sha1', ciphers: ['aes128-gcm', '3des-cbc'], product: 'Old VPN', pqc_support: 'not-supported' });
  assert.deepEqual(old.legacy, ['version:tls1.0', 'cipher:3des-cbc', 'signature-hash:sha1', 'rsa-key:1024', 'dh:1024']);
  assert.deepEqual([old.quantum_vulnerable, old.readiness], [['key-exchange', 'signature'], 'do-not-force']); assert.match(old.recommendation, /nothing is forced/);
  const modern = assessEndpoint({ endpoint: 'web.lab:443', protocol: 'tls', versions: ['tls1.3'], key_exchange: ['x25519'], key: { algorithm: 'ecdsa', bits: 256 }, signature_hash: 'sha256', ciphers: ['aes256-gcm'], product: 'Web proxy', pqc_support: 'supported' });
  assert.deepEqual([modern.legacy, modern.readiness], [[], 'ready-to-migrate']); assert.match(modern.recommendation, /hybrid ML-KEM \(FIPS 203\).*ML-DSA \(FIPS 204\)/);
  const hybrid = assessEndpoint({ endpoint: 'edge.lab:443', protocol: 'tls', versions: ['tls1.3'], key_exchange: ['x25519mlkem768'], key: { algorithm: 'ml-dsa', bits: null }, signature_hash: null, ciphers: ['aes256-gcm'], product: 'Edge', pqc_support: 'supported' });
  assert.deepEqual([hybrid.quantum_vulnerable, hybrid.readiness], [[], 'migrated']);
  const ssh = assessEndpoint({ endpoint: 'bastion:22', protocol: 'ssh', versions: ['ssh2'], key_exchange: ['sntrup761x25519-sha512', 'curve25519-sha256'], key: { algorithm: 'ed25519', bits: 256 }, signature_hash: null, ciphers: ['chacha20-poly1305'], product: 'OpenSSH', pqc_support: 'supported' });
  assert.deepEqual([ssh.quantum_vulnerable, ssh.readiness], [['signature'], 'ready-to-migrate'], 'a hybrid key exchange protects the session; the host key is still classical');
  assert.equal(assessEndpoint({ endpoint: 'fw', protocol: 'ipsec', versions: ['ikev2'], key_exchange: ['dh-group14'], key: null, ciphers: ['aes256-gcm'], product: 'FW', pqc_support: 'vendor-roadmap' }).readiness, 'wait-for-vendor');
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'admin', 'admin', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  const src = d.createSource('admin', { name: 'TLS scanner', stale_seconds: 86400 });
  d.ingest('admin', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'c1', kind: 'crypto.inventory', observed_at: new Date().toISOString(), asset: { external_id: 'scanner', hostname: 'SCANNER', os_family: 'linux', device_type: 'server', addresses: [] }, details: { inventory_id: 'inv-179', collected_by: 'synthetic scan', items: [
    { endpoint: 'vpn.lab:443', protocol: 'tls', versions: ['TLS1.0', 'tls1.2'], key_exchange: ['rsa'], key: { algorithm: 'RSA', bits: 2048 }, signature_hash: 'sha256', ciphers: ['aes128-gcm'], product: 'Old VPN', product_version: '9.1', pqc_support: 'not-supported' },
    { endpoint: 'edge.lab:443', protocol: 'tls', versions: ['tls1.3'], key_exchange: ['x25519mlkem768'], key: { algorithm: 'ml-dsa', bits: null }, signature_hash: null, ciphers: ['aes256-gcm'], product: 'Edge', product_version: '2.0', pqc_support: 'supported' }] } }] });
  const v = cryptoView(s); assert.deepEqual(v.summary, { endpoints: 2, legacy: 1, quantum_vulnerable: 1, ready_to_migrate: 0, do_not_force: 1, migrated: 1 });
  assert.match(s.get("SELECT title FROM alerts WHERE rule_id='CG-CRYPTO-LEGACY-179'").title, /version:tls1.0/);
  assert.equal(s.get("SELECT COUNT(*) n FROM actions").n, 0, 'the inventory never creates a change');
});
