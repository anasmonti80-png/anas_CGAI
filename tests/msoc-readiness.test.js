import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { Store } from '../lib/store.js';
import { MsocReadiness, ITEMS } from '../lib/msoc-readiness.js';

const ksa = { storage: 'saudi-arabia', processing: 'saudi-arabia', backups: 'saudi-arabia', encryption_keys: 'saudi-arabia' };
const fixture = (t, now = Date.parse('2026-11-22T10:00:00.000Z')) => { const s = new Store(':memory:'); t.after(() => s.close()); return { s, m: new MsocReadiness(s, { clock: () => now }) }; };

test('the research is recorded with official NCA sources and every obligation is a readiness item (CG-125)', () => {
  const doc = fs.readFileSync(new URL('../docs/research/MSOC_REGULATION_AR.md', import.meta.url), 'utf8');
  for (const marker of ['NPMSOC-1:2024', 'RFMSOC-1:2024', 'cdn.nca.gov.sa', 'إقامة البيانات', 'المستوى الأول', 'التعاقد من الباطن', 'ليست استشارة قانونية']) assert.ok(doc.includes(marker), marker);
  assert.deepEqual(ITEMS.map(i => i[0]), ['licence', 'tier-fit', 'residency', 'analysts', 'subcontracting', 'ownership-notice', 'national-integration', 'pdpl']);
});

test('no external customer can be registered until licence, tier, residency and the other obligations are met (CG-125)', t => {
  const { m, s } = fixture(t);
  let r = m.readiness(); assert.equal(r.may_offer_service, false); assert.ok(r.items.filter(i => !i.passed).length >= 6);
  assert.throws(() => m.addCustomer('admin', { name: 'Ministry A', sector: 'government', pdpl_agreement_ref: 'DPA-1' }), /msoc_not_ready:licence,tier-fit,residency,analysts,subcontracting,ownership-notice,national-integration/);
  m.saveProvider('admin', { licence_number: 'MSOC-T2-0042', licence_tier: 'tier-2', licence_valid_until: '2027-06-30T00:00:00.000Z', residency: { ...ksa, backups: 'outside-saudi-arabia' }, qualified_analysts: 6, subcontracting: 'none', ownership_notice_contact: 'compliance@provider.example', national_integration_ref: 'NSOC-INT-7' });
  assert.throws(() => m.addCustomer('admin', { name: 'Retail Co', sector: 'other', pdpl_agreement_ref: 'DPA-2' }), /msoc_not_ready:residency/, 'backups outside the Kingdom');
  m.saveProvider('admin', { licence_number: 'MSOC-T2-0042', licence_tier: 'tier-2', licence_valid_until: '2027-06-30T00:00:00.000Z', residency: ksa, qualified_analysts: 6, subcontracting: 'none', ownership_notice_contact: 'compliance@provider.example', national_integration_ref: 'NSOC-INT-7' });
  assert.throws(() => m.addCustomer('admin', { name: 'Retail Co', sector: 'other' }), /msoc_not_ready:pdpl/);
  r = m.addCustomer('admin', { name: 'Retail Co', sector: 'other', pdpl_agreement_ref: 'DPA-2' }); assert.equal(r.may_offer_service, true); assert.equal(r.customers.length, 1);
  assert.throws(() => m.addCustomer('admin', { name: 'Ministry A', sector: 'government', pdpl_agreement_ref: 'DPA-1' }), /msoc_not_ready:tier-fit/, 'a Tier 2 licence cannot serve government');
  assert.equal(s.get('SELECT COUNT(*) n FROM msoc_customers').n, 1); assert.ok(s.all("SELECT 1 FROM audit WHERE action='msoc.customer.registered'").length === 1); assert.ok(r.claim_ar.includes('ليست ترخيصًا'));
});

test('an expired licence closes the service again (CG-125)', t => {
  const { m } = fixture(t, Date.parse('2027-07-01T00:00:00.000Z'));
  m.saveProvider('admin', { licence_number: 'MSOC-T1-0001', licence_tier: 'tier-1', licence_valid_until: '2027-06-30T00:00:00.000Z', residency: ksa, qualified_analysts: 10, subcontracting: 'approved-under-framework', ownership_notice_contact: 'x', national_integration_ref: 'y' });
  const r = m.readiness(); assert.equal(r.may_offer_service, false); assert.match(r.items.find(i => i.id === 'licence').reason, /expired/);
});
