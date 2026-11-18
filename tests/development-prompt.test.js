import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readiness, writePrompt } from '../scripts/development-prompt.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), SCRIPT = path.join(ROOT, 'scripts', 'development-prompt.js');

test('the final development prompt is refused until every requirement is reviewed and accepted, then built only from approved text (CG-063)', () => {
  // The real repository is not finished: the generator refuses, writes nothing and names the blockers.
  const real = readiness(ROOT); assert.equal(real.ready, false); assert.ok(real.blockers.in_scope_not_accepted > 0 && real.blockers.needs_semantic_review > 0);
  const out = path.join(os.tmpdir(), `cg063-real-${process.pid}.md`), refused = spawnSync(process.execPath, [SCRIPT, '--write', '--output', out], { encoding: 'utf8' });
  assert.equal(refused.status, 3); assert.equal(JSON.parse(refused.stdout).written, false); assert.equal(fs.existsSync(out), false);
  assert.equal(fs.existsSync(path.join(ROOT, 'docs/engineering/DEVELOPMENT_PROMPT.md')), false, 'no prompt exists in the repository before approval');
  // A finished requirement set (synthetic copy): every row reviewed, every in-scope row accepted.
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'cg063-')); fs.mkdirSync(path.join(repo, 'docs/engineering'), { recursive: true });
  const row = (id, extra) => ({ id, raw_requirement: `- **${id}** مطلوب — synthetic requirement ${id}`, source_line: 1, source_sha256: 'a'.repeat(64), current_scope: 'CyberGuard', status: 'acceptance-verified', review_status: 'acceptance-verified', code_reference: [], test_id: [], restrictions: [], ...extra });
  const rows = [row('CG-001'), row('CG-002'), row('CG-063', { status: 'planned', review_status: 'reviewed-semantic-triage' }), row('CG-900', { current_scope: 'IT-Twin', status: 'planned', review_status: 'reviewed-semantic-triage' })];
  const write = list => fs.writeFileSync(path.join(repo, 'docs/engineering/TRACEABILITY.jsonl'), list.map(r => JSON.stringify(r)).join('\n') + '\n');
  fs.writeFileSync(path.join(repo, 'docs/engineering/ACCEPTANCE_001_600.json'), JSON.stringify({ entries: { 'CG-001': { reason: 'Accepted behaviour one', code: ['lib/a.js'], tests: ['tests/a.test.js: one'], restrictions: ['none known'] }, 'CG-002': { reason: 'Accepted behaviour two', code: ['lib/b.js'], tests: ['tests/b.test.js: two'], restrictions: [] } } }));
  write([...rows.slice(0, 1), row('CG-002', { review_status: 'needs-semantic-review', status: 'planned' }), ...rows.slice(2)]);
  assert.equal(writePrompt(repo).written, false, 'one unreviewed requirement still blocks');
  write(rows); const result = writePrompt(repo); assert.equal(result.written, true); assert.equal(result.requirements, 2);
  const text = fs.readFileSync(path.join(repo, 'docs/engineering/DEVELOPMENT_PROMPT.md'), 'utf8');
  assert.ok(text.includes('synthetic requirement CG-001') && text.includes('Accepted behaviour two') && text.includes('a'.repeat(64)));
  assert.ok(!text.includes('CG-900') && !text.includes('## CG-063'), 'out-of-scope and unapproved items are not included');
  assert.equal(JSON.parse(execFileSync(process.execPath, [SCRIPT, '--status', '--root', repo], { encoding: 'utf8' })).ready, true);
  fs.rmSync(repo, { recursive: true, force: true });
});
