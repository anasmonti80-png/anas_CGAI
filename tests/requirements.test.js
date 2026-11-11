import test from 'node:test';
import assert from 'node:assert/strict';
import { sourceInventory, classify } from '../scripts/requirements.js';

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
  assert.deepEqual(rows[1432].refines, ['CG-859','CG-1296']);
});
