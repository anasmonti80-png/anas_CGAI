// CG-040 incident reconstruction: evidence graph (proven, from stored records only) and a probabilistic attack
// path (hypothesis, explicitly scored and contestable). Nothing in the hypothesis is presented as proof.
const tacticRules = [
  [/^CG-(VULN-KEV|VULN-RISK|NET-EXPOSE|FW-EXPOSE|REMOTE-EXPOSURE|WAF|LOG-IDS)/, 'TA0001', 'Initial Access', 'الوصول الأولي'],
  [/^CG-(AUTH-FAILURES|ACCESS-FAIL|IDENT-SIGNIN|IDENTITY)/, 'TA0006', 'Credential Access', 'الوصول إلى بيانات الاعتماد'],
  [/^CG-(IDENT-PRIVADD|IDENT-PRIVGRANT|PRIV)/, 'TA0004', 'Privilege Escalation', 'تصعيد الصلاحيات'],
  [/^CG-(PROTECTION-NOT-RUNNING|TAMPER|DEFENSE)/, 'TA0005', 'Defense Evasion', 'التهرب من الدفاعات'],
  [/^CG-(NET-LATERAL|REMOTE-SUSPICIOUS|REMOTE)/, 'TA0008', 'Lateral Movement', 'الحركة الجانبية'],
  [/^CG-NET-DNS/, 'TA0011', 'Command and Control', 'القيادة والتحكم'],
  [/^CG-(RANSOM|IMPACT)/, 'TA0040', 'Impact', 'التأثير'],
];
const killChain = ['TA0001', 'TA0006', 'TA0004', 'TA0005', 'TA0008', 'TA0011', 'TA0040'];
export function tacticOf(ruleId) {
  const hit = tacticRules.find(([re]) => re.test(ruleId || ''));
  return hit ? { id: hit[1], en: hit[2], ar: hit[3] } : { id: null, en: 'Unmapped', ar: 'غير مصنف' };
}

const isIp = v => typeof v === 'string' && /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]*$/i.test(v);
// Proven edges: only relations stated by a stored event's own fields.
export function edgesFromEvent(event, assetNode) {
  const d = event.details || {}, out = [], add = (from, to, relation) => { if (from && to && from !== to) out.push({ from, to, relation, evidence_event_id: event.id, observed_at: event.observed_at, basis: 'proven' }); };
  const ip = v => (isIp(v) ? `ip:${v}` : null), account = v => (v ? `account:${String(v).toLowerCase().slice(0, 120)}` : null);
  if (event.kind === 'auth.failed') { add(ip(d.source_ip), assetNode, 'failed-logon-to'); add(account(d.account), assetNode, 'account-targeted-on'); }
  else if (event.kind.startsWith('remote.')) { add(ip(d.source_a?.ip), assetNode, `remote-${event.kind.slice(7)}`); add(account(d.target_b?.account), assetNode, 'account-used-on'); }
  else if (event.kind === 'identity.signin_activity') { for (const s of (d.signins || []).slice(0, 20)) add(ip(s.source_ip), account(s.principal_ref), s.result === 'failure' ? 'failed-signin-as' : 'signin-as'); }
  else if (event.kind === 'log.batch') { for (const r of (d.records || []).slice(0, 25)) { if (r.src_ip && r.dst_ip) add(ip(r.src_ip), ip(r.dst_ip), `${r.category || 'flow'}${r.dst_port ? `:${r.dst_port}` : ''}`); if (r.user && r.src_ip) add(ip(r.src_ip), account(r.user), `${r.category || 'log'}-as`); } }
  out.push({ from: `event:${event.id}`, to: assetNode, relation: `observed-on (${event.kind})`, evidence_event_id: event.id, observed_at: event.observed_at, basis: 'proven' });
  return out;
}

// Hypothesis: order the case alerts in time, map them to ATT&CK tactics and score the chain transparently.
export function attackPath(steps, edges) {
  const entitiesOf = step => new Set(edges.filter(e => step.evidence_ids.includes(e.evidence_event_id)).flatMap(e => [e.from, e.to]).filter(n => !n.startsWith('event:')));
  const ordered = [...steps].sort((a, b) => a.at.localeCompare(b.at));
  const base = { critical: 0.8, high: 0.7, medium: 0.55, low: 0.4 };
  let probability = 1; const notes = [];
  const path = ordered.map((step, i) => {
    const tactic = tacticOf(step.rule_id), confidence = base[step.severity] ?? 0.4;
    probability *= confidence;
    let link = null;
    if (i < ordered.length - 1) {
      const next = ordered[i + 1], shared = [...entitiesOf(step)].filter(n => entitiesOf(next).has(n));
      const nextTactic = tacticOf(next.rule_id), backwards = tactic.id && nextTactic.id && killChain.indexOf(nextTactic.id) < killChain.indexOf(tactic.id);
      const factor = (shared.length ? 0.9 : 0.5) * (backwards ? 0.7 : 1);
      probability *= factor;
      link = { linked: shared.length > 0, shared_entities: shared.slice(0, 10), out_of_order: Boolean(backwards), factor };
      if (!shared.length) notes.push({ en: `No stored record links step ${i + 1} to step ${i + 2}; the connection is inferred from timing only.`, ar: `لا يوجد سجل مخزن يربط الخطوة ${i + 1} بالخطوة ${i + 2}؛ الربط مستنتج من التوقيت فقط.` });
      if (backwards) notes.push({ en: `Step ${i + 2} (${nextTactic.en}) usually precedes step ${i + 1} (${tactic.en}).`, ar: `الخطوة ${i + 2} (${nextTactic.ar}) تسبق عادة الخطوة ${i + 1} (${tactic.ar}).` });
    }
    if (!tactic.id) notes.push({ en: `Rule ${step.rule_id} has no ATT&CK tactic mapping.`, ar: `القاعدة ${step.rule_id} غير مربوطة بمرحلة ATT&CK.` });
    return { order: i + 1, tactic, alert_id: step.alert_id, rule_id: step.rule_id, title: step.title, severity: step.severity, asset_ref: step.asset_ref, at: step.at, confidence, supporting_evidence: step.evidence_ids.slice(0, 10), link_to_next: link, basis: 'hypothesis' };
  });
  probability = ordered.length ? Math.round(probability * 1000) / 1000 : 0;
  const covered = new Set(path.map(p => p.tactic.id).filter(Boolean));
  const missing = killChain.filter(id => !covered.has(id)).slice(0, 4).map(id => tacticRules.find(r => r[1] === id)).map(r => ({ id: r[1], en: r[2], ar: r[3] }));
  return {
    basis: 'hypothesis', probability, competing_hypothesis: { en: 'The alerts are unrelated events', ar: 'التنبيهات أحداث غير مترابطة', probability: Math.round((1 - probability) * 1000) / 1000 },
    steps: path, notes, untested_tactics: missing,
    how_to_confirm: { en: ['Find a stored record linking each unlinked step (shared IP, account or host).', 'Collect the missing tactics\' telemetry for the affected assets.', 'Review the evidence of each step before acting.'], ar: ['ابحث عن سجل مخزن يربط كل خطوة غير مربوطة (عنوان أو حساب أو جهاز مشترك).', 'اجمع بيانات المراحل الناقصة للأصول المتأثرة.', 'راجع دليل كل خطوة قبل أي إجراء.'] },
    model: 'Step confidence by alert severity (critical 0.8, high 0.7, medium 0.55, low 0.4); each link multiplies by 0.9 when a stored record shares an IP, account or host between steps, 0.5 when only timing connects them, and 0.7 more when the tactic order runs backwards in the kill chain.',
  };
}
