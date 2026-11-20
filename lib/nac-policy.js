// CG-098 Zero Trust segmentation and NAC posture. A site declares its NAC policy (how devices and users prove who
// they are, and what happens to new, guest and unmanaged devices); CyberGuard assesses it and compares it with the
// authentications actually observed in NAC logs (FreeRADIUS), so a policy on paper is not taken as enforcement.
const MAC_USER = /^([0-9a-f]{2}[:-]?){5}[0-9a-f]{2}$/i;
export function assessNacPolicy(p, { now = Date.now(), observed = null } = {}) {
  const f = [], add = (id, severity, en, ar) => f.push({ id, severity, title: en, title_ar: ar });
  if (p.device_authentication === 'none') add('no-device-authentication', 'high', 'Devices are not authenticated before network access', 'لا يُتحقق من أصالة الأجهزة قبل الوصول للشبكة');
  else if (p.device_authentication === 'mab') add('mab-only', 'medium', 'Device identity relies on MAC address bypass, which can be spoofed', 'هوية الجهاز تعتمد على عنوان MAC (MAB) ويمكن انتحاله');
  if (p.user_authentication === 'none') add('no-user-authentication', 'high', 'Users are not authenticated at network access', 'لا يُتحقق من المستخدمين عند الوصول للشبكة');
  else if (p.user_authentication === 'peap-mschapv2') add('peap-mschapv2', 'medium', 'PEAP-MSCHAPv2 credentials can be captured by a rogue access point; prefer EAP-TLS', 'بيانات PEAP-MSCHAPv2 يمكن التقاطها بنقطة وصول مزيفة؛ يُفضل EAP-TLS');
  if (p.unknown_devices === 'allow') add('unknown-devices-allowed', 'high', 'New unknown devices get normal network access', 'الأجهزة الجديدة غير المعروفة تحصل على وصول عادي للشبكة');
  if (p.guest.network === 'shared') add('guest-not-isolated', 'high', 'Guests share the internal network instead of an isolated internet-only segment', 'الضيوف يشاركون الشبكة الداخلية بدل جزء معزول للإنترنت فقط');
  if (p.guest.network !== 'none' && !p.guest.sponsor_required && !p.guest.max_hours) add('guest-unbounded', 'low', 'Guest access has no sponsor and no time limit', 'وصول الضيوف بلا راعٍ ولا مدة محددة');
  if (p.unmanaged_devices === 'allow') add('unmanaged-allowed', 'high', 'Unmanaged devices are allowed on the corporate segments', 'الأجهزة غير المُدارة مسموحة في أجزاء المؤسسة');
  if (p.posture_check === 'none') add('no-posture-check', 'medium', 'No device health posture check before access', 'لا فحص لصحة الجهاز قبل منح الوصول');
  if (!p.reauth_hours || p.reauth_hours > 24) add('long-reauthentication', 'low', 'Sessions are not re-authenticated at least daily', 'الجلسات لا يُعاد التحقق منها يوميًا على الأقل');
  if (p.segmentation.some(s => s.to.includes('*'))) add('flat-segmentation', 'medium', `Segment(s) ${p.segmentation.filter(s => s.to.includes('*')).map(s => s.from).join(', ')} may reach every other segment`, `الأجزاء ${p.segmentation.filter(s => s.to.includes('*')).map(s => s.from).join('، ')} يمكنها الوصول لكل الأجزاء`);
  if (now - Date.parse(p.reviewed_at) > 365 * 86400000) add('policy-not-reviewed', 'low', 'NAC policy has not been reviewed for over a year', 'سياسة NAC لم تُراجع منذ أكثر من سنة');
  if (observed) {
    if (observed.total === 0) add('no-nac-evidence', 'medium', 'No NAC authentications observed in 30 days: enforcement cannot be confirmed', 'لا توجد عمليات تحقق NAC مرصودة خلال 30 يومًا: لا يمكن تأكيد التطبيق');
    else if (p.device_authentication === 'certificate' && observed.mab_success > 0) add('policy-drift-mab', 'medium', `Policy requires certificates but ${observed.mab_success} MAC-based logins succeeded`, `السياسة تتطلب شهادات لكن ${observed.mab_success} عمليات دخول بعنوان MAC نجحت`);
  }
  const weight = { high: 25, medium: 10, low: 3 }, score = Math.max(0, 100 - f.reduce((n, x) => n + (weight[x.severity] || 0), 0));
  return { findings: f, score };
}
export function observedNac(records) {
  const nac = records.filter(r => r.category === 'nac');
  const mab = r => r.user && MAC_USER.test(r.user);
  return { total: nac.length, success: nac.filter(r => r.outcome === 'success').length, failure: nac.filter(r => r.outcome === 'failure').length, mab_success: nac.filter(r => r.outcome === 'success' && mab(r)).length, dot1x_success: nac.filter(r => r.outcome === 'success' && !mab(r)).length, distinct_devices: new Set(nac.map(r => r.mac).filter(Boolean)).size };
}
