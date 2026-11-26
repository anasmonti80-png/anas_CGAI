// CG-155 AWS multi-account and multi-Region completeness. Uses the latest AWS account inventory (CG-046: accounts,
// access and per-Region service status) plus the owner's read-only exports of each account's Regions (Account
// Management ListRegions: RegionOptStatus), the Security Hub CSPM enablement date per account and Region, and the
// cross-Region aggregation home and linked Regions. It states what AWS documents: Security Hub CSPM only detects and
// consolidates findings generated after it is enabled (no history), only processes findings in Regions where it is
// enabled, needs AWS Config recording in each Region for control findings, and aggregation does not enable it.
import { fail } from './common.js';

export const OPT = ['ENABLED', 'ENABLED_BY_DEFAULT', 'ENABLING', 'DISABLING', 'DISABLED'];
export const CHECKS = ['security-hub', 'config', 'guardduty', 'cloudtrail'];
export const STATEMENTS = [
  { id: 'no-history', text: 'Security Hub CSPM only detects and consolidates findings generated after it is enabled; it does not retroactively collect earlier findings.', text_ar: 'لا يرصد Security Hub CSPM ولا يجمع إلا النتائج المتولدة بعد تفعيله؛ ولا يجمع ما قبل ذلك بأثر رجعي.' },
  { id: 'regional', text: 'It only receives and processes findings in the Regions where it is enabled in the account.', text_ar: 'لا يستقبل النتائج ولا يعالجها إلا في المناطق التي فُعّل فيها داخل الحساب.' },
  { id: 'config', text: 'AWS Config must be enabled and recording in each Region where it is enabled to produce control findings.', text_ar: 'يجب تفعيل AWS Config وتشغيل التسجيل في كل منطقة فُعّل فيها لإنتاج نتائج الضوابط.' },
  { id: 'aggregation', text: 'Cross-Region aggregation only aggregates Regions where it is enabled and does not enable it in any account.', text_ar: 'التجميع عبر المناطق لا يجمع إلا المناطق المفعّل فيها، ولا يفعّله في أي حساب.' },
];
const enabledOpt = o => o === 'ENABLED' || o === 'ENABLED_BY_DEFAULT';

export function parseListRegions(json, accountId) {
  const list = (typeof json === 'string' ? JSON.parse(json) : json)?.Regions; fail(Array.isArray(list) && /^\d{12}$/.test(String(accountId)), 400, 'not_list_regions_export');
  return { account_id: String(accountId), regions: list.map(r => ({ name: String(r.RegionName), opt: OPT.includes(r.RegionOptStatus) ? r.RegionOptStatus : 'DISABLED' })) };
}

export function assessCompleteness({ inventory, accountsRegions, hubs = [], aggregation = null }) {
  const invAccounts = inventory?.accounts || [], services = inventory?.services || [];
  const ids = [...new Set([...invAccounts.map(a => a.account_id), ...accountsRegions.map(a => a.account_id)])];
  const svc = (acct, region, name) => services.find(s => s.account_id === acct && s.service === name && String(s.region || '').toLowerCase() === region.toLowerCase())?.status || 'not-checked';
  const accounts = ids.map(id => {
    const inv = invAccounts.find(a => a.account_id === id), regs = accountsRegions.find(a => a.account_id === id);
    const access = inv?.access || 'not-attempted', assessed = !!regs && access !== 'denied';
    const enabled = regs ? regs.regions.filter(r => enabledOpt(r.opt)) : [], disabled = regs ? regs.regions.filter(r => r.opt === 'DISABLED').map(r => r.name) : [], changing = regs ? regs.regions.filter(r => r.opt === 'ENABLING' || r.opt === 'DISABLING').map(r => `${r.name} (${r.opt})`) : [];
    const regions = enabled.map(r => { const st = Object.fromEntries(CHECKS.map(c => [c, svc(id, r.name, c)])), hub = hubs.find(h => h.account_id === id && h.region === r.name);
      const gaps = CHECKS.filter(c => st[c] !== 'enabled'); const linked = !aggregation ? null : aggregation.home_region === r.name || (aggregation.linked_regions || []).includes(r.name);
      return { region: r.name, opt: r.opt, services: st, gaps, security_hub_since: hub?.enabled_at || null, aggregated: linked, notes: [st['security-hub'] === 'enabled' && st.config !== 'enabled' ? 'Security Hub CSPM without AWS Config recording produces no control findings here.' : null, aggregation && st['security-hub'] === 'enabled' && linked === false ? 'Findings stay in this Region: it is not the home Region and not linked.' : null].filter(Boolean) }; });
    return { account_id: id, name: inv?.name || null, status: inv?.status || 'unknown', access, assessed, in_inventory: !!inv, regions_listed: !!regs, regions, disabled_regions: disabled, changing_regions: changing,
      complete: assessed && regions.length > 0 && regions.every(r => !r.gaps.length) };
  });
  return { accounts, summary: { accounts: accounts.length, not_assessed: accounts.filter(a => !a.assessed).length, complete: accounts.filter(a => a.complete).length, region_gaps: accounts.reduce((n, a) => n + a.regions.filter(r => r.gaps.length).length, 0), disabled_regions: accounts.reduce((n, a) => n + a.disabled_regions.length, 0) },
    aggregation, statements: STATEMENTS };
}

export function completenessView(store) {
  const inv = store.all("SELECT payload FROM events WHERE kind='cloud.account_inventory' AND json_extract(payload,'$.details.provider')='aws' ORDER BY observed_at DESC,received_at DESC LIMIT 1").map(r => JSON.parse(r.payload).details)[0] || null;
  const st = store.all("SELECT observed_at,payload FROM events WHERE kind='cloud.aws_region_status' ORDER BY observed_at DESC,received_at DESC LIMIT 1").map(r => ({ ...JSON.parse(r.payload).details, observed_at: r.observed_at }))[0] || null;
  if (!st && !inv) return { available: false, statements: STATEMENTS };
  return { available: true, observed_at: st?.observed_at || null, ...assessCompleteness({ inventory: inv, accountsRegions: st?.accounts_regions || [], hubs: st?.hubs || [], aggregation: st?.aggregation || null }),
    claim: 'Every account in the organization and every Region enabled for it is checked for Security Hub CSPM, AWS Config, GuardDuty and CloudTrail. An account whose Regions were not listed or that denied access is not assessed, never complete.',
    claim_ar: 'يُفحص كل حساب في المنظمة وكل منطقة مفعّلة له بحثًا عن Security Hub CSPM وAWS Config وGuardDuty وCloudTrail. والحساب الذي لم تُدرج مناطقه أو رفض الوصول «غير مُقيَّم»، ولا يُعد مكتملًا أبدًا.' };
}
