// CG-130 Research evidence register. Every idea carries its official source or repository, dates, an accurate summary,
// applicability, dependencies, risks, priority, verification status and an accept/defer/reject decision with its reason.
// The register is a versioned file (docs/research/register.json) so every change is reviewed with the code. A topic stops
// being researched when it has enough review rounds and the latest ones produced no new valuable idea.
import fs from 'node:fs';
import path from 'node:path';

export const VERIFICATION = ['verified-in-code', 'verified-source', 'partially-verified', 'unverified'];
export const DECISIONS = ['accepted', 'deferred', 'rejected'];
const DATE = /^\d{4}-\d{2}-\d{2}$/;
export function validateRegister(reg, root) {
  const errors = [], ids = new Set(), err = (id, m) => errors.push(`${id}: ${m}`);
  if (reg?.schema_version !== 'cg.research-register/1') errors.push('schema_version');
  for (const e of reg?.entries || []) {
    if (!/^R-\d{3}$/.test(e.id) || ids.has(e.id)) err(e.id, 'id must be unique R-NNN'); ids.add(e.id);
    for (const k of ['topic', 'title', 'summary', 'applicability', 'risks', 'decision_reason']) if (typeof e[k] !== 'string' || e[k].trim().length < 3) err(e.id, `${k} required`);
    if (!/^https:\/\/[^\s]+$/.test(e.url || '')) err(e.id, 'url must be https');
    if (!['official', 'repository', 'vendor', 'paper'].includes(e.source_type)) err(e.id, 'source_type');
    for (const k of ['source_date', 'reviewed_at']) if (!DATE.test(e[k] || '')) err(e.id, `${k} must be YYYY-MM-DD`);
    if (!['P1', 'P2', 'P3'].includes(e.priority)) err(e.id, 'priority');
    if (!VERIFICATION.includes(e.verification)) err(e.id, 'verification'); if (!DECISIONS.includes(e.decision)) err(e.id, 'decision');
    if (!Array.isArray(e.dependencies) || !Array.isArray(e.evidence_files) || !Array.isArray(e.requirements)) err(e.id, 'lists required');
    if (e.decision === 'accepted' && !e.requirements?.length) err(e.id, 'accepted ideas must name the requirement that implements them');
    if (e.verification === 'verified-in-code' && !e.evidence_files?.length) err(e.id, 'verified-in-code needs evidence files');
    for (const f of e.evidence_files || []) if (root && !fs.existsSync(path.join(root, f))) err(e.id, `evidence file missing: ${f}`);
    for (const r of e.requirements || []) if (!/^CG-\d{3}$/.test(r)) err(e.id, `bad requirement ${r}`);
  }
  for (const e of reg?.entries || []) for (const dep of e.dependencies || []) if (!ids.has(dep)) err(e.id, `unknown dependency ${dep}`);
  return errors;
}
// Stop rule per topic: at least min_rounds review rounds and the last quiet_rounds produced no new valuable idea.
export function saturation(reg) {
  const rule = reg.stop_rule, topics = [...new Set([...reg.entries.map(e => e.topic), ...reg.rounds.map(r => r.topic)])];
  return topics.map(topic => { const rounds = reg.rounds.filter(r => r.topic === topic).sort((a, b) => a.at.localeCompare(b.at)), last = rounds.slice(-rule.quiet_rounds);
    const saturated = rounds.length >= rule.min_rounds && last.length === rule.quiet_rounds && last.every(r => r.new_valuable_ideas === 0);
    return { topic, rounds: rounds.length, ideas: reg.entries.filter(e => e.topic === topic).length, last_round: rounds.at(-1)?.at || null, new_ideas_last_round: rounds.at(-1)?.new_valuable_ideas ?? null, status: saturated ? 'stop-research' : 'continue-research' }; });
}
export function registerView(root) {
  const reg = JSON.parse(fs.readFileSync(path.join(root, 'docs', 'research', 'register.json'), 'utf8')), errors = validateRegister(reg, root), count = (k, v) => reg.entries.filter(e => e[k] === v).length;
  return { entries: reg.entries, topics: saturation(reg), stop_rule: reg.stop_rule, valid: !errors.length, errors,
    summary: { ideas: reg.entries.length, accepted: count('decision', 'accepted'), deferred: count('decision', 'deferred'), rejected: count('decision', 'rejected'), verified_in_code: count('verification', 'verified-in-code'), unverified: count('verification', 'unverified') },
    claim: 'Every researched idea records its official source or repository, dates, summary, applicability, dependencies, risks, priority, verification and decision; a topic stops when new review rounds stop producing valuable ideas.',
    claim_ar: 'كل فكرة بحثية تسجل مصدرها الرسمي أو مستودعها وتواريخها وملخصها وقابلية تطبيقها وتبعياتها ومخاطرها وأولويتها وحالة التحقق والقرار؛ ويتوقف البحث في الموضوع عندما تتوقف جولات المراجعة الجديدة عن إنتاج أفكار ذات قيمة.' };
}
