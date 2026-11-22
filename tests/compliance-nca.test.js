import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { ECC, CCC, SOURCES, applicability, NcaCompliance } from '../lib/compliance-nca.js';

test('subdomain lists match the official NCA ECC-2:2024 and CCC-2:2024 structure (CG-124)', () => {
  assert.equal(ECC.length, 28, 'ECC-2:2024 has 28 subdomains'); assert.equal(CCC.length, 24, 'CCC-2:2024 has 24 subdomains');
  assert.deepEqual([...new Set(ECC.map(r => r[0].split('-')[0]))], ['1', '2', '3', '4']); assert.equal(ECC.filter(r => r[0].startsWith('2-')).length, 15);
  assert.deepEqual(CCC.filter(r => r[0].startsWith('2-')).map(r => r[0]).slice(-3), ['2-15', '2-16', '2-17']); assert.equal(CCC.find(r => r[0] === '2-15')[1], 'Key Management');
  assert.equal(ECC.find(r => r[0] === '4-2')[1], 'Cloud Computing and Hosting Cybersecurity'); assert.equal(ECC.find(r => r[0] === '2-15')[1], 'Web Application Security');
  for (const [, , keys] of [...ECC, ...CCC]) for (const k of keys) assert.ok(SOURCES[k], `evidence source ${k} is defined`);
});

test('applicability follows the entity profile and never becomes a compliance claim (CG-124)', () => {
  const gov = applicability({ entity_type: 'government', uses_cloud: true, has_ot: false, has_critical_systems: true, handles_classified_data: false });
  assert.deepEqual(Object.fromEntries(Object.entries(gov).map(([k, v]) => [k, v.state])), { 'ECC-2:2024': 'mandatory', 'CCC-2:2024': 'mandatory', 'OTCC-1:2022': 'not-applicable', 'CSCC-1:2019': 'mandatory', 'DCC-1:2022': 'not-applicable' });
  assert.equal(applicability({ entity_type: 'other-private' })['ECC-2:2024'].state, 'recommended');
  assert.match(applicability({ entity_type: 'cni-private', is_csp: true, serves_in_scope_tenants: true })['CCC-2:2024'].reason, /CSP controls apply/);
  assert.equal(applicability({ entity_type: 'government', uses_cloud: false })['CCC-2:2024'].state, 'not-applicable');
});

test('each subdomain shows the evidence CyberGuard actually holds and organisational subdomains are marked as such (CG-124)', t => {
  const s = new Store(':memory:'); t.after(() => s.close()); const d = new Domain(s, {}), nca = new NcaCompliance(s, {});
  s.run('INSERT INTO users VALUES (?,?,?,?,?)', 'a', 'a', 'fixture-not-a-password-hash', 'admin', new Date().toISOString());
  let v = nca.view(); assert.equal(v.applicability, null); assert.equal(v.ecc.subdomains.find(r => r.id === '2-4').state, 'no-evidence-collected');
  assert.throws(() => nca.saveProfile('a', { entity_type: 'alien' }), /invalid_entity_type/);
  nca.saveProfile('a', { entity_type: 'government', uses_cloud: false });
  const src = d.createSource('a', { name: 'S', stale_seconds: 86400 }), asset = { external_id: 'h', hostname: 'H', os_family: 'windows', device_type: 'server', addresses: ['10.0.0.9'] };
  d.ingest('a', src.id, { schema_version: 'cg.telemetry/1', events: [{ event_id: 'ds', kind: 'data.store', observed_at: new Date().toISOString(), asset, details: { store_id: 'hr', store_type: 'file-share', classification: 'restricted', owner: 'HR', location: 'sa', encryption_at_rest: 'enabled', public_access: false, contains_personal_data: true, legal_basis: 'contract', retention_days: 365, content_inspection: null, evidence_ref: 'inv' } }] });
  v = nca.view(); const row = id => v.ecc.subdomains.find(r => r.id === id);
  assert.equal(row('2-7').state, 'technical-evidence-available'); assert.equal(row('2-7').evidence[0].records, 1); assert.deepEqual(row('2-7').evidence[0].requirements, ['CG-109']);
  assert.equal(row('2-1').state, 'technical-evidence-available', 'the asset inventory holds the store host');
  for (const id of ['1-1', '1-9', '1-10', '2-14']) assert.equal(row(id).state, 'organisational-evidence-required', id);
  assert.equal(row('4-2').state, 'not-applicable', 'no cloud use declared'); assert.deepEqual(v.ccc.subdomains, [], 'CCC not applicable without cloud');
  assert.ok(!JSON.stringify(v).match(/"compliant"|fully compliant/i), 'no compliance claim'); assert.ok(v.claim_ar.includes('وليس ادعاء امتثال'));
  nca.saveProfile('a', { entity_type: 'government', uses_cloud: true }); v = nca.view(); assert.equal(v.ccc.subdomains.length, 24); assert.equal(v.ccc.role, 'CST'); assert.equal(v.ecc.subdomains.find(r => r.id === '4-2').state, 'no-evidence-collected');
});
