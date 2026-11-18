// CG-063 The final comprehensive development prompt is written only after the study is finished and the requirements
// are approved. This generator enforces that order: it refuses while any requirement still needs semantic review or any
// in-scope requirement is not acceptance-verified, and lists exactly what blocks it. Once ready it writes the prompt from
// the approved requirements only (their verbatim text, source hash, acceptance reason, code, tests and restrictions),
// so nothing is invented and nothing unapproved is included.
//   node scripts/development-prompt.js --status        (readiness JSON; exit 0 ready, 3 not ready)
//   node scripts/development-prompt.js --write [--root <repo>] [--output <file>]
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2), flag = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const root = path.resolve(flag('--root') || fileURLToPath(new URL('../', import.meta.url)));
const SELF = 'CG-063', inScope = r => String(r.current_scope || '').startsWith('CyberGuard');

export function readiness(repo = root) {
  const rows = fs.readFileSync(path.join(repo, 'docs/engineering/TRACEABILITY.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
  const needsReview = rows.filter(r => r.review_status === 'needs-semantic-review').map(r => r.id);
  const notAccepted = rows.filter(r => r.id !== SELF && inScope(r) && r.status !== 'acceptance-verified').map(r => r.id);
  return { ready: needsReview.length === 0 && notAccepted.length === 0, tracked: rows.length, in_scope: rows.filter(inScope).length, accepted: rows.filter(r => r.status === 'acceptance-verified').length,
    blockers: { needs_semantic_review: needsReview.length, in_scope_not_accepted: notAccepted.length, first_not_accepted: notAccepted.slice(0, 10), first_needing_review: needsReview.slice(0, 10) },
    rule: 'The development prompt is written only when no requirement needs semantic review and every in-scope requirement is acceptance-verified.', rows };
}

export function writePrompt(repo = root, output = path.join(repo, 'docs/engineering/DEVELOPMENT_PROMPT.md')) {
  const r = readiness(repo); if (!r.ready) return { written: false, ...r, rows: undefined };
  const acceptance = JSON.parse(fs.readFileSync(path.join(repo, 'docs/engineering/ACCEPTANCE_001_600.json'), 'utf8')).entries;
  const approved = r.rows.filter(x => inScope(x) && x.status === 'acceptance-verified');
  const lines = ['# CyberGuard AI — final development prompt (CG-063)', '', `Generated from ${approved.length} approved requirements. Every item below is verbatim from the approved requirement set with its source hash; nothing outside it is included.`, ''];
  for (const x of approved) { const a = acceptance[x.id] || {}; lines.push(`## ${x.id}`, '', x.raw_requirement, '', `- Source: line ${x.source_line}, sha256 ${x.source_sha256}`, `- Accepted behaviour: ${a.reason || 'see traceability'}`, `- Code: ${(a.code || x.code_reference || []).join(', ') || '—'}`, `- Tests: ${(a.tests || x.test_id || []).join('; ') || '—'}`, `- Restrictions: ${(a.restrictions || x.restrictions || []).join('; ') || '—'}`, ''); }
  const text = lines.join('\n'); fs.writeFileSync(output, text);
  return { written: true, output, requirements: approved.length, sha256: createHash('sha256').update(text).digest('hex') };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (args.includes('--write')) { const out = writePrompt(root, flag('--output') ? path.resolve(flag('--output')) : undefined); console.log(JSON.stringify(out, null, 2)); process.exit(out.written ? 0 : 3); }
  const r = readiness(); delete r.rows; console.log(JSON.stringify(r, null, 2)); process.exit(r.ready ? 0 : 3);
}
