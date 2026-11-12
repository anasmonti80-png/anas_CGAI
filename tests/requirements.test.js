import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { sourceInventory, classify, applyReview, applyBatchReview, applyAcceptance } from '../scripts/requirements.js';

test('all 1440 IDs, source lines, 12 chunks and embedded sources retain their original content', () => {
  const inventory = sourceInventory();
  assert.equal(inventory.requirements.length, 1440);
  assert.equal(inventory.history.length, 27);
  assert.equal(inventory.chunks.length, 12);
});
test('traceability preserves raw text and never turns inventory into verified product coverage', () => {
  const source = sourceInventory().requirements;
  const rows = classify(source);
  assert.equal(rows.length, 1440);
  rows.forEach((r,i) => {
    assert.equal(r.raw_requirement, source[i].text_verbatim);
    assert.equal(r.status, 'planned');
    assert.equal(r.test_result, 'not-run');
    assert.equal(r.review_status, 'needs-semantic-review');
  });
  assert.equal(rows[920].current_scope, 'IT-Twin');
  assert.equal(rows[925].current_scope, 'CyberGuard');
  assert.deepEqual(rows[1432].refines, ['CG-859','CG-1296']);
});

test('subset evidence does not count as full acceptance and stale evidence is not promoted',()=>{
  const source=classify(sourceInventory().requirements);
  const review={'CG-032':{reason:'Local metadata subset only',code:['lib/domain.js'],tests:['approval test'],remaining:['Real device actions not implemented']}};
  const evidence={passed:true,source:{sha256:'tested'},at:'2026-11-11T00:00:00Z',environment:{platform:'win32'}};
  const stale=applyReview(source,review,evidence,{sha256:'changed'})[31];
  assert.equal(stale.status,'partially-implemented');assert.equal(stale.test_result,'not-run-for-this-source');assert.equal(stale.last_verified,null);
  const fresh=applyReview(source,review,evidence,{sha256:'tested'})[31];
  assert.equal(fresh.test_result,'passed-for-subset');assert.equal(fresh.platform_coverage.macos,'not-tested');
  assert.equal(fresh.status,'partially-implemented');
});

test('full acceptance requires requirement-specific code, tests and a fresh passing source fingerprint',()=>{
  const source=classify(sourceInventory().requirements),entry={entries:{'CG-001':{reason:'Verified UI contract',code:['public/app.js'],tests:['tests/ui-contract.test.js'],evidence:[],restrictions:[]}}};
  const verification={passed:true,source:{sha256:'current'},at:'2026-11-12T00:00:00Z',environment:{platform:'win32'}};
  const stale=applyAcceptance(source,entry,verification,{sha256:'changed'})[0];
  assert.equal(stale.status,'implemented-unverified');assert.equal(stale.last_verified,null);
  const fresh=applyAcceptance(source,entry,verification,{sha256:'current'})[0];
  assert.equal(fresh.status,'acceptance-verified');assert.equal(fresh.test_result,'passed-acceptance');assert.equal(fresh.platform_coverage.windows,'unit-tested');
  assert.throws(()=>applyAcceptance(source,{entries:{'CG-601':entry.entries['CG-001']}},verification,{sha256:'current'}),/limited to CG-001/);
});

test('first 300 requirements receive non-acceptance semantic triage without changing their source text',()=>{
  const requirements=sourceInventory().requirements;
  const batch=JSON.parse(fs.readFileSync(new URL('../docs/engineering/REVIEW_BATCH_001_300.json',import.meta.url),'utf8'));
  const rows=applyBatchReview(classify(requirements),batch);
  assert.equal(rows.filter(r=>r.review_status==='reviewed-semantic-triage').length,300);
  assert.equal(rows[0].raw_requirement,requirements[0].text_verbatim);
  assert.equal(rows[299].raw_requirement,requirements[299].text_verbatim);
  assert.equal(rows[300].review_status,'needs-semantic-review');
  assert.equal(rows.filter(r=>r.status==='planned').length,1440);
  assert.equal(rows[0].current_scope,'CyberGuard');
  assert.equal(rows[4].current_scope,'NCC-integration');
});

test('requirements 301 through 600 receive non-acceptance semantic triage with complete non-overlapping coverage',()=>{
  const requirements=sourceInventory().requirements;
  const first=JSON.parse(fs.readFileSync(new URL('../docs/engineering/REVIEW_BATCH_001_300.json',import.meta.url),'utf8'));
  const second=JSON.parse(fs.readFileSync(new URL('../docs/engineering/REVIEW_BATCH_301_600.json',import.meta.url),'utf8'));
  const rows=applyBatchReview(applyBatchReview(classify(requirements),first),second);
  assert.equal(rows.slice(0,600).filter(r=>r.review_status==='reviewed-semantic-triage').length,600);
  assert.equal(rows[300].raw_requirement,requirements[300].text_verbatim);
  assert.equal(rows[599].raw_requirement,requirements[599].text_verbatim);
  assert.equal(rows[600].review_status,'needs-semantic-review');
  assert.equal(rows[599].current_scope,'CyberGuard');
  assert.equal(rows[572].current_scope,'CyberGuard/NCC-integration');
});
