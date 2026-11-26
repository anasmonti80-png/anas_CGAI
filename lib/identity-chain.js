// CG-142 Identity-to-endpoint kill chain. Starting from an account with an unusual successful sign-in (new country or
// new address for that account), one incident graph collects what the same account did afterwards: OAuth consents and
// cloud tokens or keys, sign-in policy changes, processes on endpoints, their network connections and protection or
// policy changes. To avoid a false causal sequence, every link between consecutive steps says what supports it:
// "proven" when a stored record shares a concrete entity (the sign-in address reused, the connection made by that very
// process), "same-account" when only the account name is shared (correlated, not shown as cause), and steps that happened
// before the unusual sign-in are listed as preceding it, never as its consequence.
const parse = s => JSON.parse(s);
export const localPart = v => String(v || '').toLowerCase().replace(/^arn:[^ ]*\//, '').replace(/^.*\\/, '').replace(/@.*$/, '').trim();
const TOKEN = /createaccesskey|assumerole|getsessiontoken|createloginprofile|add service principal credentials|update application.*certificates|generateaccesstoken|serviceaccountkeys\.create/i;
const POLICY = /policy|roleassignments\/write|setiampolicy|attach.*policy|conditionalaccess/i;
export const STEP_AR = { 'unusual-signin': 'دخول غير معتاد', 'oauth-consent': 'موافقة OAuth', 'token-or-key': 'رمز أو مفتاح سحابي', 'policy-change': 'تغيير سياسة', 'endpoint-process': 'عملية على جهاز', 'network-connection': 'اتصال شبكي' };

export function identityChains(domain, { now = Date.now(), windowHours = 24, historyDays = 30 } = {}) {
  const s = domain.s, since = new Date(now - (historyDays + 1) * 86400000).toISOString(), rows = kind => s.all('SELECT e.id,e.observed_at,e.payload,a.external_id,a.hostname FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.kind=? AND e.observed_at>=? ORDER BY e.observed_at', kind, since);
  const signins = rows('identity.signin_activity').flatMap(r => parse(r.payload).details.signins.map(x => ({ ...x, event_id: r.id }))).sort((a, b) => a.at.localeCompare(b.at));
  const seen = new Map(), anchors = [];
  for (const x of signins.filter(x => x.result === 'success')) { const k = localPart(x.principal_ref), h = seen.get(k) || { countries: new Set(), ips: new Set(), first: x.at };
    const prior = Date.parse(x.at) - Date.parse(h.first) >= 86400000, why = [!h.countries.has(x.country) && x.country ? `new country ${x.country}` : null, !h.ips.has(x.source_ip) && x.source_ip ? `new address ${x.source_ip}` : null].filter(Boolean);
    if (prior && why.length && Date.parse(x.at) >= now - windowHours * 3600000) anchors.push({ ...x, why });
    if (x.country) h.countries.add(x.country); if (x.source_ip) h.ips.add(x.source_ip); seen.set(k, h); }
  const consents = rows('identity.oauth_consent').map(r => ({ ...parse(r.payload).details, event_id: r.id })), idp = rows('identity.idp_change').map(r => ({ ...parse(r.payload).details, event_id: r.id }));
  const audit = rows('log.batch').flatMap(r => { const d = parse(r.payload).details; return d.category === 'cloud-audit' ? (d.records || []).map(x => ({ ...x, event_id: r.id })) : []; });
  const procs = rows('endpoint.process_causality').map(r => ({ ...parse(r.payload).details, event_id: r.id, asset_ref: r.external_id, hostname: r.hostname }));
  const tamper = rows('endpoint.defense_tamper').map(r => ({ ...parse(r.payload).details, event_id: r.id, asset_ref: r.external_id }));
  return anchors.map(a => {
    const who = localPart(a.principal_ref), t0 = Date.parse(a.at), end = t0 + windowHours * 3600000, inWin = t => { const x = Date.parse(t); return x >= t0 - windowHours * 3600000 && x <= end; }, steps = [];
    const add = (step, at, detail, detail_ar, entities, eventId, extra = {}) => steps.push({ step, at, detail, detail_ar, entities, evidence_event_id: eventId, ...extra });
    add('unusual-signin', a.at, `${a.principal_ref} signed in from ${a.source_ip || 'unknown'}${a.country ? ` (${a.country})` : ''}: ${a.why.join(', ')}${a.mfa ? `; MFA ${a.mfa}` : ''}`, `${a.principal_ref} دخل من ${a.source_ip || 'غير معروف'}${a.country ? ` (${a.country})` : ''}: ${a.why.map(w => w.replace('new country', 'دولة جديدة').replace('new address', 'عنوان جديد')).join('، ')}`, { ip: a.source_ip }, a.event_id);
    for (const c of consents.filter(c => localPart(c.granted_by_ref) === who && inWin(c.granted_at))) add('oauth-consent', c.granted_at, `Consent to ${c.app_ref}${c.publisher_verified ? '' : ' (unverified publisher)'}: ${c.scopes.slice(0, 6).join(', ')}`, `موافقة للتطبيق ${c.app_ref}${c.publisher_verified ? '' : ' (ناشر غير موثّق)'}`, {}, c.event_id);
    for (const c of idp.filter(c => localPart(c.actor_ref) === who && inWin(c.at))) add('policy-change', c.at, `${c.setting} ${c.action}${c.authorization_ref ? '' : ' without an authorization reference'}`, `${c.setting}: ${c.action}${c.authorization_ref ? '' : ' دون مرجع تصريح'}`, {}, c.event_id);
    for (const r of audit.filter(r => localPart(r.user) === who && inWin(r.time))) { const name = `${r.signature || r.action || ''}`; if (TOKEN.test(name)) add('token-or-key', r.time, `${name} from ${r.src_ip || 'unknown'}`, `${name} من ${r.src_ip || 'غير معروف'}`, { ip: r.src_ip }, r.event_id); else if (POLICY.test(name)) add('policy-change', r.time, `${name} from ${r.src_ip || 'unknown'}`, `${name} من ${r.src_ip || 'غير معروف'}`, { ip: r.src_ip }, r.event_id); }
    for (const p of procs) { const byId = new Map(p.processes.map(x => [x.process_id, x]));
      for (const x of p.processes.filter(x => localPart(x.user_ref) === who && inWin(x.started_at))) { add('endpoint-process', x.started_at, `${x.image_path.split('\\').pop()} on ${p.hostname || p.asset_ref} as ${x.user_ref}`, `${x.image_path.split('\\').pop()} على ${p.hostname || p.asset_ref} باسم ${x.user_ref}`, { process: `${p.event_id}:${x.process_id}`, device: p.asset_ref }, p.event_id, { label: x.image_path.split('\\').pop() });
        for (const c of (p.connections || []).filter(c => c.process_id === x.process_id && inWin(c.occurred_at))) add('network-connection', c.occurred_at, `${x.image_path.split('\\').pop()} ${c.direction} to ${c.remote_address}:${c.remote_port}`, `${x.image_path.split('\\').pop()} اتصل ${c.direction === 'outbound' ? 'خارجيًا' : 'داخليًا'} بـ ${c.remote_address}:${c.remote_port}`, { process: `${p.event_id}:${x.process_id}`, ip: c.remote_address, device: p.asset_ref }, p.event_id, { label: x.image_path.split('\\').pop() }); } }
    for (const t of tamper.filter(t => localPart(t.change.actor_ref) === who && inWin(t.change.occurred_at))) add('policy-change', t.change.occurred_at, `${t.control.name} ${t.change.action} on ${t.asset_ref}`, `${t.control.name}: ${t.change.action} على ${t.asset_ref}`, { device: t.asset_ref }, t.event_id);
    steps.sort((x, y) => x.at.localeCompare(y.at) || (x.step === 'unusual-signin' ? -1 : 0));
    const anchorIdx = steps.findIndex(x => x.step === 'unusual-signin'), before = steps.slice(0, anchorIdx), chain = steps.slice(anchorIdx);
    const links = chain.slice(1).map((step, i) => { const prev = chain[i], shared = Object.entries(step.entities).filter(([k, v]) => v && chain.slice(0, i + 1).some(p => p.entities[k] === v)).map(([k, v]) => k === 'process' ? `process:${step.label}` : `${k}:${v}`);
      return { from: i, to: i + 1, basis: shared.length ? 'proven' : 'same-account', shared, note: shared.length ? `Shares ${shared.join(', ')} with an earlier step` : 'Only the account name is shared; correlated, not shown as cause', note_ar: shared.length ? `يشترك في ${shared.join('، ')} مع خطوة سابقة` : 'الاسم وحده مشترك؛ ترابط لا سببية' }; });
    const kinds = [...new Set(chain.map(x => x.step))], proven = links.filter(l => l.basis === 'proven').length;
    const severity = kinds.length >= 3 && (kinds.includes('token-or-key') || kinds.includes('oauth-consent') || kinds.includes('policy-change')) && (kinds.includes('endpoint-process') || kinds.includes('network-connection')) ? 'high' : kinds.length >= 2 ? 'medium' : null;
    return { principal: a.principal_ref, anchor_at: a.at, steps: chain, links, preceding: before.map(b => ({ ...b, note: 'Happened before the unusual sign-in; not its consequence', note_ar: 'حدث قبل الدخول غير المعتاد؛ وليس نتيجة له' })), kinds, proven_links: proven, same_account_links: links.length - proven, severity,
      identity_match: 'Account names are matched by their user part (DOMAIN\\user and user@domain); verify they are the same person', identity_match_ar: 'تُطابق أسماء الحسابات بالجزء الأول (DOMAIN\\user وuser@domain)؛ تحقق أنها الشخص نفسه' };
  });
}

export function identityChainView(domain) {
  return { chains: identityChains(domain), step_ar: STEP_AR,
    claim: 'One graph per unusual sign-in with what the same account did in the following 24 hours. A link is proven only by a shared address, process or device in stored records; links that share only the account name are correlation, and steps before the sign-in are never presented as its result.',
    claim_ar: 'رسم واحد لكل دخول غير معتاد مع ما فعله الحساب نفسه خلال 24 ساعة بعده. لا يُثبت الرابط إلا بعنوان أو عملية أو جهاز مشترك في السجلات المخزنة؛ والروابط التي تشترك في اسم الحساب وحده ترابط فقط، والخطوات التي سبقت الدخول لا تُعرض نتيجةً له أبدًا.' };
}
