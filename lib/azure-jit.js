// CG-156 Temporary Azure VM access through Microsoft Defender for Cloud just-in-time (JIT) VM access. CyberGuard
// reads, never opens ports: the owner exports the JIT policies (with their requests), the Defender pricings and the
// VM list. JIT is a Defender for Servers Plan 2 feature; it keeps deny rules on the selected ports and, for an
// approved request, allows the requester's source address for a limited time, then restores the rules (established
// connections are not interrupted). Default management ports 22, 3389, 5985 and 5986; default maximum 3 hours.
import { fail } from './common.js';

export const MGMT_PORTS = [22, 3389, 5985, 5986];
export const DEFAULT_MAX_HOURS = 3;
export const PERMISSIONS = [
  { task: 'Configure or edit a JIT policy', task_ar: 'إعداد سياسة JIT أو تعديلها', actions: ['Microsoft.Security/locations/jitNetworkAccessPolicies/write', 'Microsoft.Compute/virtualMachines/write'] },
  { task: 'Request JIT access to a VM', task_ar: 'طلب وصول JIT إلى جهاز', actions: ['Microsoft.Security/locations/jitNetworkAccessPolicies/initiate/action', 'Microsoft.Security/locations/jitNetworkAccessPolicies/*/read', 'Microsoft.Compute/virtualMachines/read', 'Microsoft.Network/networkInterfaces/*/read', 'Microsoft.Network/publicIPAddresses/read'] },
  { task: 'Read JIT policies (CyberGuard export)', task_ar: 'قراءة سياسات JIT (تصدير CyberGuard)', actions: ['Microsoft.Security/locations/jitNetworkAccessPolicies/read', 'Microsoft.Security/policies/read', 'Microsoft.Security/pricings/read', 'Microsoft.Compute/virtualMachines/read', 'Microsoft.Network/*/read'] },
];
const hoursOf = iso => { const m = /^PT(?:(\d+)H)?(?:(\d+)M)?$/i.exec(String(iso || '')); return m ? Number(m[1] || 0) + Number(m[2] || 0) / 60 : null; };
const vmKey = id => String(id || '').toLowerCase();

export function planStatus(pricings) {
  const vm = (pricings?.value || pricings || []).find?.(x => x.name === 'VirtualMachines'); const p = vm?.properties || vm || {};
  if (!vm) return { plan: 'unknown', jit: null };
  if (p.pricingTier !== 'Standard') return { plan: 'free', jit: false };
  return p.subPlan === 'P2' ? { plan: 'plan-2', jit: true } : p.subPlan === 'P1' ? { plan: 'plan-1', jit: false } : { plan: 'standard-unknown-subplan', jit: null };
}

export function parseJitPolicies(json) {
  const list = Array.isArray(json) ? json : json?.value; fail(Array.isArray(list), 400, 'not_jit_policy_export');
  const vms = [], requests = [];
  for (const p of list) { const pr = p.properties || p;
    for (const v of pr.virtualMachines || []) vms.push({ vm_id: vmKey(v.id), policy: String(p.name || p.id || ''), ports: (v.ports || []).map(x => { const src = x.allowedSourceAddressPrefixes || (x.allowedSourceAddressPrefix ? [x.allowedSourceAddressPrefix] : []); return { port: Number(x.number), protocol: String(x.protocol || '*'), sources: src.map(String), max_hours: hoursOf(x.maxRequestAccessDuration) }; }) });
    for (const r of pr.requests || []) for (const v of r.virtualMachines || []) for (const x of v.ports || []) requests.push({ vm_id: vmKey(v.id), policy: String(p.name || ''), port: Number(x.number), source: String(x.allowedSourceAddressPrefix || (x.allowedSourceAddressPrefixes || []).join(',') || ''), start: r.startTimeUtc || null, end: x.endTimeUtc || null, status: String(x.status || ''), requestor: r.requestor ? String(r.requestor).slice(0, 200) : null, justification: r.justification ? String(r.justification).slice(0, 500) : null });
  }
  return { vms, requests };
}

export function assessJit({ plans, policies, vms }) {
  const bySub = sub => plans.find(p => p.subscription === sub)?.status || { plan: 'unknown', jit: null };
  const rows = vms.map(v => { const sub = (String(v.resource_id).match(/\/subscriptions\/([^/]+)/i) || [])[1]?.toLowerCase() || v.account_id; const plan = bySub(sub), pol = policies.vms.find(x => x.vm_id === vmKey(v.resource_id)), findings = [];
    if (!pol) findings.push({ id: 'no-jit-policy', severity: plan.jit === false ? 'low' : 'medium', text: plan.jit === false ? 'No JIT: the subscription does not have Defender for Servers Plan 2.' : 'No JIT policy: management ports are not time-limited by JIT.', text_ar: plan.jit === false ? 'لا JIT: الاشتراك لا يملك Defender for Servers Plan 2.' : 'لا سياسة JIT: منافذ الإدارة غير مقيدة بالوقت.' });
    for (const p of pol?.ports || []) {
      if (!p.sources.length || p.sources.includes('*') || p.sources.includes('Internet') || p.sources.includes('0.0.0.0/0')) findings.push({ id: `any-source-${p.port}`, severity: 'medium', text: `Port ${p.port}: requests may open it to any source address.`, text_ar: `المنفذ ${p.port}: يمكن فتحه لأي عنوان مصدر عند الطلب.` });
      if (p.max_hours !== null && p.max_hours > DEFAULT_MAX_HOURS) findings.push({ id: `long-window-${p.port}`, severity: 'low', text: `Port ${p.port}: maximum request ${p.max_hours} hours, above the ${DEFAULT_MAX_HOURS}-hour default.`, text_ar: `المنفذ ${p.port}: أقصى مدة طلب ${p.max_hours} ساعات، فوق الافتراضي ${DEFAULT_MAX_HOURS} ساعات.` });
    }
    const missing = pol ? MGMT_PORTS.filter(m => !pol.ports.some(p => p.port === m)) : [];
    return { vm_id: v.resource_id, name: v.name || v.resource_id, subscription: sub, plan: plan.plan, jit_available: plan.jit, policy: pol?.policy || null, ports: pol?.ports || [], ports_not_in_policy: missing, findings }; });
  const reqs = policies.requests.map(r => ({ ...r, findings: [!r.justification ? 'no-justification' : null, !r.source || r.source === '*' ? 'any-source' : null].filter(Boolean) }));
  return { vms: rows, requests: reqs.sort((a, b) => String(b.start).localeCompare(String(a.start))), summary: { vms: rows.length, with_jit: rows.filter(r => r.policy).length, plan2_subscriptions: plans.filter(p => p.status.jit).length, requests: reqs.length, requests_flagged: reqs.filter(r => r.findings.length).length } };
}

export function jitView(store) {
  const d = store.all("SELECT observed_at,payload FROM events WHERE kind='cloud.azure_jit' ORDER BY observed_at DESC,received_at DESC LIMIT 1").map(r => ({ ...JSON.parse(r.payload).details, observed_at: r.observed_at }))[0];
  return { available: !!d, observed_at: d?.observed_at || null, ...(d ? assessJit(d) : {}), permissions: PERMISSIONS, mgmt_ports: MGMT_PORTS,
    references: [{ id: 'JIT overview', url: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/just-in-time-access-overview' }, { id: 'Enable JIT (permissions)', url: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-just-in-time-access' }],
    claim: 'Just-in-time VM access is a Defender for Servers Plan 2 feature: deny rules stay on management ports and an approved request opens them for the requester source address for a limited time. CyberGuard reads the policies and requests; it never opens or requests access itself.',
    claim_ar: 'الوصول المؤقت للأجهزة (JIT) ميزة في Defender for Servers Plan 2: تبقى قواعد المنع على منافذ الإدارة، والطلب المعتمد يفتحها لعنوان مصدر الطالب لمدة محدودة. يقرأ CyberGuard السياسات والطلبات فقط، ولا يفتح منافذ ولا يطلب وصولًا بنفسه.' };
}
