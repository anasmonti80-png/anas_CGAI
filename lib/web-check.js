// CG-107 API and web security checks of authorized application URLs only. A scope names the authorization, owner,
// window, environment and each URL to check; nothing else is requested and nothing is crawled. Single-request checks
// (CORS, authentication, API keys in URLs, security headers, cookie flags) run on any environment; the repeated-request
// rate-limit probe runs only on test or staging environments, at the scope rate, with GET and no credentials.
export function validateWebScope(scope, now = Date.now()) {
  const fail = m => { throw new Error(m); };
  if (!scope || typeof scope.authorization_ref !== 'string' || scope.authorization_ref.length < 6) fail('authorization_ref required (at least 6 characters)');
  if (!scope.owner) fail('owner required'); if (!scope.window_end || Date.parse(scope.window_end) < now) fail('authorization window has ended or is missing (window_end)');
  if (!['test', 'staging', 'production'].includes(scope.environment)) fail('environment must be test, staging or production');
  if (!Array.isArray(scope.targets) || !scope.targets.length || scope.targets.length > 100) fail('targets: 1 to 100 URLs');
  for (const t of scope.targets) { let u; try { u = new URL(t.url); } catch { fail(`invalid URL ${t.url}`); } if (!['http:', 'https:'].includes(u.protocol)) fail(`only http and https URLs: ${t.url}`); if (t.rate_limit_probe && scope.environment === 'production') fail(`rate limit probes are refused on production (${t.url}); use a test or staging environment`); }
  return { ...scope, rate_per_second: Math.min(Math.max(Number(scope.rate_per_second) || 5, 1), 20), probe_requests: Math.min(Math.max(Number(scope.probe_requests) || 20, 5), 60) };
}
const PROBE_ORIGIN = 'https://cyberguard-cors-probe.invalid';
export async function checkTarget(t, scope, { fetchImpl = fetch } = {}) {
  const f = [], add = (id, severity, en, ar) => f.push({ id, severity, title: en, title_ar: ar }), u = new URL(t.url), wait = () => new Promise(r => setTimeout(r, 1000 / scope.rate_per_second));
  const res = await fetchImpl(t.url, { method: 'GET', redirect: 'manual', headers: { Origin: PROBE_ORIGIN, 'User-Agent': 'CyberGuard-WebCheck' } }), hd = k => res.headers.get(k), status = res.status; try { await res.text(); } catch {}
  const acao = hd('access-control-allow-origin'), acac = hd('access-control-allow-credentials') === 'true';
  if (acao === PROBE_ORIGIN) add('cors-reflects-origin', acac ? 'high' : 'medium', `CORS reflects any Origin${acac ? ' with credentials' : ''}`, `CORS يعكس أي أصل${acac ? ' مع بيانات الاعتماد' : ''}`);
  else if (acao === '*' && acac) add('cors-wildcard-credentials', 'high', 'CORS allows any origin with credentials', 'CORS يسمح لأي أصل مع بيانات الاعتماد');
  else if (acao === 'null') add('cors-null-origin', 'medium', 'CORS allows the null origin', 'CORS يسمح بالأصل null');
  if (t.requires_auth && status >= 200 && status < 300) add('missing-authentication', 'high', `Returned ${status} without credentials although authentication is required`, `أعاد ${status} دون بيانات اعتماد رغم أن المصادقة مطلوبة`);
  if ([...u.searchParams.keys()].some(k => /^(api[_-]?key|apikey|key|token|access_token|secret)$/i.test(k))) add('api-key-in-url', 'medium', 'Credential passed in the URL query string (logged by proxies and browsers)', 'بيانات اعتماد ممررة في عنوان URL (تُسجل في الوكلاء والمتصفحات)');
  if (u.protocol === 'https:' && !hd('strict-transport-security')) add('no-hsts', 'low', 'No Strict-Transport-Security header', 'لا توجد ترويسة Strict-Transport-Security');
  if (u.protocol === 'http:' && !/^(localhost|127\.|\[::1\])/.test(u.hostname)) add('cleartext-http', 'high', 'Application served over cleartext HTTP', 'التطبيق يُقدَّم عبر HTTP غير مشفر');
  if (/html/.test(hd('content-type') || '') && !hd('content-security-policy')) add('no-csp', 'low', 'HTML without Content-Security-Policy', 'صفحة HTML بلا Content-Security-Policy');
  if (hd('x-content-type-options') !== 'nosniff') add('no-nosniff', 'low', 'Missing X-Content-Type-Options: nosniff', 'لا توجد X-Content-Type-Options: nosniff');
  if (/html/.test(hd('content-type') || '') && !hd('x-frame-options') && !/frame-ancestors/.test(hd('content-security-policy') || '')) add('no-framing-protection', 'low', 'Page can be framed (no X-Frame-Options or frame-ancestors)', 'يمكن تضمين الصفحة في إطار (لا X-Frame-Options ولا frame-ancestors)');
  for (const c of (res.headers.getSetCookie?.() || [])) { const name = c.split('=')[0], miss = ['Secure', 'HttpOnly', 'SameSite'].filter(a => !new RegExp(`;\\s*${a}`, 'i').test(c) && !(a === 'Secure' && u.protocol === 'http:')); if (miss.length) add(`cookie-flags:${name}`, 'medium', `Cookie ${name} lacks ${miss.join(', ')}`, `ملف تعريف الارتباط ${name} ينقصه ${miss.join('، ')}`); }
  if (hd('server') && /\d/.test(hd('server'))) add('server-version-disclosed', 'low', `Server header discloses a version (${hd('server').slice(0, 60)})`, `ترويسة Server تكشف الإصدار (${hd('server').slice(0, 60)})`);
  let probe = null;
  if (t.rate_limit_probe) { const codes = []; let limited = false; for (let i = 0; i < scope.probe_requests; i++) { await wait(); const r = await fetchImpl(t.url, { method: 'GET', redirect: 'manual', headers: { 'User-Agent': 'CyberGuard-WebCheck' } }); try { await r.text(); } catch {} codes.push(r.status); if (r.status === 429 || r.headers.get('ratelimit-remaining') === '0' || r.headers.get('x-ratelimit-remaining') === '0' || r.headers.get('ratelimit-limit') || r.headers.get('x-ratelimit-limit')) { limited = true; break; } }
    probe = { requests: codes.length, limited }; if (!limited) add('no-rate-limit', 'medium', `No rate limiting after ${codes.length} requests`, `لا يوجد تحديد للمعدل بعد ${codes.length} طلبًا`); }
  return { url: `${u.origin}${u.pathname}`, status, findings: f, rate_limit_probe: probe };
}
export async function checkScope(scopeInput, opts = {}) { const scope = validateWebScope(scopeInput); const results = []; for (const t of scope.targets) { try { results.push(await checkTarget(t, scope, opts)); } catch (e) { results.push({ url: t.url, status: null, error: String(e.cause?.code || e.message).slice(0, 120), findings: [], rate_limit_probe: null }); } } return { scope, results }; }
