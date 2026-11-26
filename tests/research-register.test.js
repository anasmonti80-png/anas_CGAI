import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { validateRegister, saturation, registerView } from '../lib/research-register.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), reg = () => JSON.parse(fs.readFileSync(new URL('../docs/research/register.json', import.meta.url), 'utf8'));

test('the research register is complete: source, dates, summary, applicability, risks, priority, verification and decision for every idea (CG-130)', () => {
  const v = registerView(ROOT); assert.deepEqual(v.errors, []); assert.equal(v.valid, true); assert.ok(v.summary.ideas >= 20);
  for (const e of v.entries.filter(e => e.verification === 'verified-in-code')) for (const f of e.evidence_files) assert.ok(fs.existsSync(new URL(`../${f}`, import.meta.url)), f);
  assert.ok(v.entries.some(e => e.decision === 'deferred' && e.requirements.includes('CG-131')), 'Batfish is deferred to CG-131'); assert.ok(v.claim_ar.includes('يتوقف البحث'));
});

test('invalid entries are rejected: missing source, non-https URL, accepted without a requirement, unknown dependency (CG-130)', () => {
  const r = reg(); r.entries = [{ ...r.entries[0], id: 'R-900', url: 'http://example.org', requirements: [], dependencies: ['R-999'], evidence_files: ['lib/nope.js'] }];
  const errors = validateRegister(r, ROOT); for (const m of ['url must be https', 'accepted ideas must name the requirement', 'unknown dependency R-999', 'evidence file missing: lib/nope.js']) assert.ok(errors.some(e => e.includes(m)), m);
});

test('a topic stops after enough rounds without new valuable ideas, and continues otherwise (CG-130)', () => {
  const r = { stop_rule: { min_rounds: 3, quiet_rounds: 2 }, entries: [{ topic: 'a' }, { topic: 'b' }], rounds: [
    { topic: 'a', at: '2026-01-01', new_valuable_ideas: 4 }, { topic: 'a', at: '2026-02-01', new_valuable_ideas: 0 }, { topic: 'a', at: '2026-03-01', new_valuable_ideas: 0 },
    { topic: 'b', at: '2026-01-01', new_valuable_ideas: 3 }, { topic: 'b', at: '2026-02-01', new_valuable_ideas: 0 }, { topic: 'b', at: '2026-03-01', new_valuable_ideas: 1 }] };
  const s = Object.fromEntries(saturation(r).map(x => [x.topic, x.status])); assert.deepEqual(s, { a: 'stop-research', b: 'continue-research' });
  assert.equal(saturation({ ...r, rounds: r.rounds.slice(1, 3) }).find(x => x.topic === 'a').status, 'continue-research', 'two quiet rounds alone are not enough');
});
