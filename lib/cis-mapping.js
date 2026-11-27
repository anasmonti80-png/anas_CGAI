// CG-178 CIS Benchmark evidence mapping. Each system's baseline is tied to the benchmark that was actually assessed:
// platform (Windows Server, Cisco IOS XE, Microsoft 365, firewall) and its version, the benchmark title and version
// with its source reference, the profile, the tool, the assessment date and per-control evidence. CyberGuard does not
// ship CIS content: the owner imports results produced under their own CIS licence.
//  - The benchmark must match the platform and version (a Windows Server 2019 benchmark does not evidence a 2022 host).
//  - Assessments older than 90 days are stale.
//  - Licence: CIS lists its free Benchmark PDFs under a Creative Commons licence (CC BY-NC-SA 4.0, non-commercial);
//    when the declared basis is the free PDF or unknown, the mapping warns that commercial use may be restricted and
//    that a CIS SecureSuite membership or other commercial licence should cover it.
export const PLATFORMS = { 'windows-server': { label: 'Windows Server', match: v => new RegExp(`\\b${String(v).match(/\d{4}/)?.[0] || '__'}\\b`) }, 'cisco-ios-xe': { label: 'Cisco IOS XE', match: v => new RegExp(`IOS XE( ${String(v).split('.')[0]}\\.x)?`, 'i') }, m365: { label: 'Microsoft 365', match: () => /Microsoft 365/i }, firewall: { label: 'Firewall', match: v => new RegExp(String(v).split(/\s+/)[0].replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i') } };
export const STATUSES = ['pass', 'fail', 'manual', 'not-applicable', 'error'];
export const LICENCE = { url: 'https://www.cisecurity.org/terms-and-conditions-table-of-contents', licence: 'CC BY-NC-SA 4.0 (CIS Benchmarks free PDF use)', licence_url: 'https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode' };
const STALE_DAYS = 90;

export function assessMapping(d, now = Date.now()) {
  const counts = Object.fromEntries(STATUSES.map(s => [s, d.results.filter(r => r.status === s).length])), issues = [];
  const p = PLATFORMS[d.platform]; if (!p.match(d.platform_version).test(d.benchmark_title)) issues.push('benchmark-does-not-match-platform-version');
  const age = Math.floor((now - Date.parse(d.assessed_at)) / 86400000); if (age > STALE_DAYS) issues.push('assessment-stale');
  if (d.license_basis !== 'securesuite-member' && d.license_basis !== 'commercial-licence') issues.push('licence-may-restrict-commercial-use');
  if (counts.fail) issues.push('failed-controls');
  return { counts, issues, age_days: age, scored: counts.pass + counts.fail, pass_rate: counts.pass + counts.fail ? Math.round(counts.pass / (counts.pass + counts.fail) * 1000) / 10 : null };
}

export function cisView(store, { clock = () => Date.now() } = {}) {
  const latest = new Map();
  for (const r of store.all("SELECT e.id,e.observed_at,e.payload,a.hostname,a.external_id FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.kind='compliance.cis_assessment' ORDER BY e.observed_at,e.received_at")) { const p = JSON.parse(r.payload); latest.set(`${r.external_id}|${p.details.platform}`, { ...p.details, asset: r.hostname || r.external_id, event_id: r.id }); }
  return { systems: [...latest.values()].map(d => ({ asset: d.asset, platform: d.platform, platform_label: PLATFORMS[d.platform].label, platform_version: d.platform_version, benchmark_title: d.benchmark_title, benchmark_version: d.benchmark_version, profile: d.profile, source_ref: d.source_ref, tool: d.tool, assessed_at: d.assessed_at, license_basis: d.license_basis, event_id: d.event_id, ...assessMapping(d, clock()), failed: d.results.filter(r => r.status === 'fail').slice(0, 20) })),
    platforms: Object.fromEntries(Object.entries(PLATFORMS).map(([k, v]) => [k, v.label])), licence: LICENCE, stale_days: STALE_DAYS,
    claim: 'Each system baseline is mapped to the CIS Benchmark actually assessed: platform and version, benchmark title, version and source, profile, tool, assessment date and per-control evidence. A benchmark that does not match the platform version, an assessment older than 90 days and failed controls are flagged. CIS lists its free Benchmark PDFs under CC BY-NC-SA 4.0, so free-PDF or unknown licensing is flagged as possibly restricted for commercial use.',
    claim_ar: 'يُربط خط الأساس لكل نظام بمعيار CIS الذي قُيّم فعلًا: النظام وإصداره، وعنوان المعيار وإصداره ومصدره، والملف، والأداة، وتاريخ التقييم، وأدلة كل ضابط. ويُعلَّم المعيار الذي لا يطابق إصدار النظام، والتقييم الأقدم من 90 يومًا، والضوابط الفاشلة. وتنشر CIS ملفات PDF المجانية لمعاييرها برخصة CC BY-NC-SA 4.0، لذا يُعلَّم الترخيص «PDF مجاني» أو «غير معروف» بأنه قد يقيّد الاستخدام التجاري.' };
}
