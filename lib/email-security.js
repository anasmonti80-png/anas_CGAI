// CG-108 Email security and phishing signals from authorized mail sources: domain SPF/DKIM/DMARC posture from DNS,
// message analysis from exported .eml files (authentication results, sender spoofing, risky attachments, deceptive
// links) and mailbox forwarding rule changes from the Microsoft 365 unified audit log. Message bodies are never stored:
// only header verdicts, attachment names and hashes, and link domains.
import { createHash } from 'node:crypto';

export async function domainPosture(domain, resolver, selectors = []) {
  const txt = async n => { try { return (await resolver.resolveTxt(n)).map(r => r.join('')); } catch { return []; } };
  const spf = (await txt(domain)).filter(t => /^v=spf1\b/i.test(t)), dmarc = (await txt(`_dmarc.${domain}`)).find(t => /^v=DMARC1/i.test(t)) || null, f = [], add = (id, severity, en, ar) => f.push({ id, severity, title: en, title_ar: ar });
  if (!spf.length) add('no-spf', 'high', `${domain} publishes no SPF record`, `${domain} لا ينشر سجل SPF`);
  else if (spf.length > 1) add('multiple-spf', 'high', `${domain} publishes ${spf.length} SPF records (invalid)`, `${domain} ينشر ${spf.length} سجلات SPF (غير صالح)`);
  const s = spf[0] || '', all = (s.match(/([-~?+]?)all\b/) || [])[1];
  if (spf.length === 1 && (all === '+' || (s.match(/\ball\b/) && all === ''))) add('spf-pass-all', 'critical', `${domain} SPF allows every sender (+all)`, `SPF للنطاق ${domain} يسمح لأي مرسل (+all)`);
  else if (spf.length === 1 && all === '?') add('spf-neutral', 'medium', `${domain} SPF ends with ?all (no protection)`, `SPF للنطاق ${domain} ينتهي بـ?all (بلا حماية)`);
  else if (spf.length === 1 && !s.match(/\ball\b/) && !/redirect=/.test(s)) add('spf-no-all', 'medium', `${domain} SPF has no all mechanism`, `SPF للنطاق ${domain} بلا آلية all`);
  const lookups = (s.match(/\b(include|a|mx|ptr|exists|redirect)[:=]?/g) || []).length; if (lookups > 10) add('spf-too-many-lookups', 'medium', `${domain} SPF needs ${lookups} DNS lookups (limit 10)`, `SPF للنطاق ${domain} يحتاج ${lookups} استعلامات DNS (الحد 10)`);
  const tag = k => (dmarc?.match(new RegExp(`\\b${k}=([^;\\s]+)`, 'i')) || [])[1]?.toLowerCase() || null, p = tag('p'), pct = Number(tag('pct') ?? 100);
  if (!dmarc) add('no-dmarc', 'high', `${domain} publishes no DMARC policy`, `${domain} لا ينشر سياسة DMARC`);
  else if (p === 'none') add('dmarc-none', 'medium', `${domain} DMARC policy is p=none (monitoring only)`, `سياسة DMARC للنطاق ${domain} هي p=none (مراقبة فقط)`);
  else if (pct < 100) add('dmarc-partial', 'low', `${domain} DMARC applies to ${pct}% of mail`, `DMARC للنطاق ${domain} يطبق على ${pct}% من البريد`);
  if (dmarc && !tag('rua')) add('dmarc-no-reports', 'low', `${domain} DMARC requests no aggregate reports (rua)`, `DMARC للنطاق ${domain} لا يطلب تقارير مجمعة (rua)`);
  const dkim = []; for (const sel of selectors) dkim.push({ selector: sel, present: (await txt(`${sel}._domainkey.${domain}`)).some(t => /v=DKIM1|k=rsa|p=/i.test(t)) });
  if (selectors.length && !dkim.some(d => d.present)) add('no-dkim', 'high', `${domain} has no DKIM key for the declared selectors`, `${domain} بلا مفتاح DKIM للمحددات المعلنة`);
  return { domain, spf: s || null, dmarc, dmarc_policy: p, dkim, findings: f };
}

const unfold = h => h.replace(/\r?\n[ \t]+/g, ' ');
const RISKY_EXT = /\.(exe|scr|js|jse|vbs|vbe|wsf|hta|lnk|iso|img|vhd|cmd|bat|ps1|msi|html?|docm|xlsm|pptm|one|zip)$/i;
export function analyseEml(raw, { internalDomains = [] } = {}) {
  const text = String(raw), split = text.search(/\r?\n\r?\n/), headerText = unfold(text.slice(0, split < 0 ? text.length : split)), header = n => (headerText.match(new RegExp(`^${n}:\\s*(.*)$`, 'im')) || [])[1]?.trim() || null;
  const addr = v => (String(v || '').match(/<([^>]+)>/) || [null, String(v || '').trim()])[1].toLowerCase(), dom = a => (a.split('@')[1] || '').toLowerCase();
  const from = addr(header('From')), reply = header('Reply-To') ? addr(header('Reply-To')) : null, display = (header('From') || '').replace(/<[^>]*>/, '').replace(/"/g, '').trim(), ar = header('Authentication-Results') || '';
  const verdict = k => (ar.match(new RegExp(`\\b${k}=(\\w+)`, 'i')) || [])[1]?.toLowerCase() || 'none';
  const auth = { spf: verdict('spf'), dkim: verdict('dkim'), dmarc: verdict('dmarc') }, f = [], add = (id, severity, en, ar2) => f.push({ id, severity, title: en, title_ar: ar2 });
  if (auth.dmarc === 'fail') add('dmarc-fail', 'high', `DMARC failed for ${dom(from)}`, `فشل DMARC للنطاق ${dom(from)}`);
  else if (auth.spf === 'fail' && auth.dkim !== 'pass') add('auth-fail', 'medium', 'SPF failed and no passing DKIM signature', 'فشل SPF ولا يوجد توقيع DKIM ناجح');
  if (reply && dom(reply) !== dom(from)) add('reply-to-mismatch', 'medium', `Replies go to ${dom(reply)}, not the sender domain ${dom(from)}`, `الردود تذهب إلى ${dom(reply)} وليس نطاق المرسل ${dom(from)}`);
  if (internalDomains.length && !internalDomains.includes(dom(from)) && internalDomains.some(d => display.toLowerCase().includes(d.split('.')[0]))) add('display-name-spoof', 'high', `Display name "${display.slice(0, 60)}" imitates an internal sender from ${dom(from)}`, `اسم العرض "${display.slice(0, 60)}" ينتحل مرسلًا داخليًا من ${dom(from)}`);
  if (/^xn--|\.xn--/.test(dom(from))) add('punycode-sender', 'medium', `Sender domain ${dom(from)} uses punycode (possible lookalike)`, `نطاق المرسل ${dom(from)} يستخدم punycode (قد يكون شبيهًا)`);
  // MIME parts: attachment names and hashes only; links as domains only.
  const attachments = [], links = [];
  const boundary = (headerText.match(/boundary="?([^";]+)"?/i) || [])[1];
  const parts = boundary ? text.split(`--${boundary}`).slice(1, -1) : [text.slice(split + 1)];
  for (const part of parts) { const ps = part.search(/\r?\n\r?\n/), ph = unfold(part.slice(0, ps)), body = part.slice(ps).trim(), name = (ph.match(/filename\*?="?([^";\r\n]+)"?/i) || ph.match(/name="?([^";\r\n]+)"?/i) || [])[1];
    if (name && /attachment|filename/i.test(ph)) { const bytes = /base64/i.test(ph) ? Buffer.from(body.replace(/\s+/g, ''), 'base64') : Buffer.from(body); attachments.push({ name: name.slice(0, 200), sha256: createHash('sha256').update(bytes).digest('hex'), size: bytes.length });
      if (RISKY_EXT.test(name) || /\.(pdf|docx?|xlsx?|txt|jpg|png)\.(exe|js|scr|lnk|html?)$/i.test(name)) add(`risky-attachment:${name.slice(0, 80)}`, /\.(exe|scr|js|vbs|hta|lnk|iso|img|ps1|bat|cmd)$/i.test(name) ? 'high' : 'medium', `Risky attachment ${name}`, `مرفق خطر ${name}`); continue; }
    const html = /text\/html/i.test(ph) ? (/quoted-printable/i.test(ph) ? body.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))) : /base64/i.test(ph) ? Buffer.from(body.replace(/\s+/g, ''), 'base64').toString('utf8') : body) : '';
    for (const m of html.matchAll(/<a\b[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi)) { let hd; try { hd = new URL(m[1]).hostname.toLowerCase(); } catch { continue; } const shown = m[2].replace(/<[^>]+>/g, '').trim(), shownDomain = (shown.match(/([a-z0-9-]+\.)+[a-z]{2,}/i) || [])[0]?.toLowerCase();
      links.push(hd); if (shownDomain && !hd.endsWith(shownDomain) && !shownDomain.endsWith(hd)) add(`deceptive-link:${hd}`, 'high', `Link text shows ${shownDomain} but points to ${hd}`, `نص الرابط يظهر ${shownDomain} لكنه يشير إلى ${hd}`);
      if (/^\d+\.\d+\.\d+\.\d+$/.test(hd)) add(`ip-link:${hd}`, 'medium', `Link points to a bare IP address ${hd}`, `رابط يشير إلى عنوان IP مباشر ${hd}`); } }
  return { message_id: header('Message-ID')?.slice(0, 200) || null, date: header('Date'), from_domain: dom(from) || null, reply_to_domain: reply ? dom(reply) : null, subject_sha256: createHash('sha256').update(header('Subject') || '').digest('hex'), auth, attachments, link_domains: [...new Set(links)].slice(0, 50), findings: f };
}
// Microsoft 365 unified audit log: inbox rules and mailbox forwarding that send mail outside the organisation.
export function forwardingChanges(records, internalDomains = []) {
  const out = [], external = v => { const d = String(v || '').toLowerCase().replace(/^smtp:/, '').split('@')[1]; return d && !internalDomains.includes(d) ? d : null; };
  for (const r of records) { if (!['New-InboxRule', 'Set-InboxRule', 'Set-Mailbox', 'UpdateInboxRules'].includes(r.Operation)) continue; const params = Object.fromEntries((r.Parameters || []).map(p => [p.Name, p.Value]));
    const targets = ['ForwardTo', 'RedirectTo', 'ForwardAsAttachmentTo', 'ForwardingSmtpAddress', 'ForwardingAddress'].flatMap(k => params[k] ? String(params[k]).split(/[;,]/) : []), ext = [...new Set(targets.map(external).filter(Boolean))];
    const hides = /DeleteMessage|MoveToFolder|MarkAsRead/.test(Object.keys(params).join(' ')) && (params.DeleteMessage === 'True' || params.MarkAsRead === 'True' || /RSS|Archive|Conversation History/i.test(params.MoveToFolder || ''));
    if (ext.length || hides) out.push({ time: r.CreationTime, user: r.UserId, operation: r.Operation, rule: params.Name || null, external_domains: ext, hides_messages: hides, severity: ext.length ? 'high' : 'medium', title: ext.length ? `${r.UserId} forwards mail outside the organisation to ${ext.join(', ')} (${r.Operation})` : `${r.UserId} created a rule that hides incoming messages (${r.Operation})`, title_ar: ext.length ? `${r.UserId} يحوّل البريد خارج المؤسسة إلى ${ext.join('، ')}` : `${r.UserId} أنشأ قاعدة تخفي الرسائل الواردة` }); }
  return out;
}
