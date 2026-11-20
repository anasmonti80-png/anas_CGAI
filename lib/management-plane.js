// CG-102 Management plane protection. A management access policy names the devices it covers, the approved
// administrative sources (jump hosts or a management network), the approved protocols, whether each session needs an
// authorization reference (change or ticket), and the administrative hours. Every authenticated remote administration
// session on a covered device is checked; anything outside the approved procedure is a finding.
import { ipInCidr } from './vulnerability-intel.js';

export const MGMT_PROTOCOLS = ['ssh', 'rdp', 'winrm', 'vpn', 'snmpv3', 'https'];
const minutes = hhmm => { const [h, m] = hhmm.split(':').map(Number); return h * 60 + m; };
export function covers(policy, asset) {
  return policy.scope.asset_refs.includes(asset.external_id) || (asset.addresses || []).some(ip => policy.scope.networks.some(n => ipInCidr(ip, n)));
}
export function evaluateSession(policy, session, at) {
  const v = [], add = (id, severity, en, ar) => v.push({ id, severity, title: en, title_ar: ar }), src = session.source_a?.ip;
  if (!src) add('unknown-source', 'medium', 'Administrative session from an unknown source address', 'جلسة إدارية من عنوان مصدر غير معروف');
  else if (!policy.approved_sources.some(n => ipInCidr(src, n))) add('unapproved-source', 'high', `Administrative ${session.protocol} session from ${src}, which is not an approved jump host or management network`, `جلسة إدارة ${session.protocol} من ${src} وهو ليس مضيفًا وسيطًا أو شبكة إدارة معتمدة`);
  if (!policy.approved_protocols.includes(session.protocol)) add('unapproved-protocol', 'high', `Administrative access over ${session.protocol}, which the policy does not approve`, `وصول إداري عبر ${session.protocol} وهو غير معتمد في السياسة`);
  if (policy.reference_required && !session.authorization_ref) add('no-authorization', 'medium', 'Administrative session without a change or ticket reference', 'جلسة إدارية دون مرجع تغيير أو تذكرة');
  if (policy.admin_hours) { const d = new Date(at), mins = d.getUTCHours() * 60 + d.getUTCMinutes(), h = policy.admin_hours;
    if (!h.days.includes(d.getUTCDay()) || mins < minutes(h.start) || mins >= minutes(h.end)) if (!session.authorization_ref) add('outside-hours', 'medium', `Administrative session outside approved hours (${h.start}-${h.end} UTC) without an emergency reference`, `جلسة إدارية خارج الساعات المعتمدة (${h.start}-${h.end} UTC) دون مرجع طارئ`); }
  return v;
}
export const SECURE_GUIDANCE = [
  ['Disable Telnet, HTTP management and SNMPv1/v2c; use SSH, HTTPS and SNMPv3 with authPriv.', 'عطّل Telnet وإدارة HTTP وSNMPv1/v2c؛ واستخدم SSH وHTTPS وSNMPv3 مع authPriv.'],
  ['Restrict management to a dedicated network or jump hosts with MFA and session recording.', 'اقصر الإدارة على شبكة مخصصة أو مضيفات وسيطة مع MFA وتسجيل الجلسات.'],
  ['Require RDP Network Level Authentication and WinRM over HTTPS only.', 'اشترط مصادقة مستوى الشبكة لـRDP وWinRM عبر HTTPS فقط.'],
  ['Tie every administrative session to an approved change or a just-in-time grant.', 'اربط كل جلسة إدارية بتغيير معتمد أو تصريح مؤقت.'],
];
