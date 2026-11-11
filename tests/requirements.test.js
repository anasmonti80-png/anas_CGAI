import test from 'node:test';
import assert from 'node:assert/strict';
import { sourceInventory, classify, applyReview } from '../scripts/requirements.js';

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
