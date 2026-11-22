import { fail } from './common.js';
// CG-124 Compliance evidence mapping for the Saudi National Cybersecurity Authority (NCA) controls. Subdomain lists are
// taken from the official NCA documents ECC-2:2024 (4 domains, 28 subdomains) and CCC-2:2024 (4 domains, 24 subdomains).
// CyberGuard maps the technical evidence it actually holds to each subdomain and states which subdomains need
// organisational evidence it cannot provide. Applicability comes from the entity profile (scope of each framework).
// It never declares compliance: compliance is determined by the entity's assessment against NCA's own tools.
export const FRAMEWORKS = {
  'ECC-2:2024': { title: 'Essential Cybersecurity Controls', title_ar: 'الضوابط الأساسية للأمن السيبراني' },
  'CCC-2:2024': { title: 'Cloud Cybersecurity Controls', title_ar: 'ضوابط الأمن السيبراني للحوسبة السحابية' },
  'OTCC-1:2022': { title: 'Operational Technology Cybersecurity Controls', title_ar: 'ضوابط الأمن السيبراني للأنظمة التشغيلية' },
  'CSCC-1:2019': { title: 'Critical Systems Cybersecurity Controls', title_ar: 'ضوابط الأمن السيبراني للأنظمة الحساسة' },
  'DCC-1:2022': { title: 'Data Cybersecurity Controls', title_ar: 'ضوابط الأمن السيبراني للبيانات' },
};
// [id, title, evidence source keys]; an empty list means organisational evidence outside the platform.
export const ECC = [
  ['1-1', 'Cybersecurity Strategy', []], ['1-2', 'Cybersecurity Management', []], ['1-3', 'Cybersecurity Policies and Procedures', []], ['1-4', 'Cybersecurity Roles and Responsibilities', ['roles']],
  ['1-5', 'Cybersecurity Risk Management', ['risk']], ['1-6', 'Cybersecurity in Information and Technology Project Management', []], ['1-7', 'Compliance with Cybersecurity Standards, Laws and Regulations', ['compliance']],
  ['1-8', 'Periodical Cybersecurity Review and Audit', ['audit']], ['1-9', 'Cybersecurity in Human Resources', []], ['1-10', 'Cybersecurity Awareness and Training Program', []],
  ['2-1', 'Asset Management', ['assets']], ['2-2', 'Identity and Access Management', ['identity']], ['2-3', 'Information Systems and Information Processing Facilities Protection', ['endpoint']],
  ['2-4', 'Email Protection', ['email']], ['2-5', 'Network Security Management', ['network']], ['2-6', 'Mobile Devices Security', ['mobile']], ['2-7', 'Data and Information Protection', ['data']],
  ['2-8', 'Cryptography', ['crypto']], ['2-9', 'Backup and Recovery Management', ['backup']], ['2-10', 'Vulnerability Management', ['vulnerability']], ['2-11', 'Penetration Testing', ['validation']],
  ['2-12', 'Cybersecurity Event Logs and Monitoring Management', ['logs']], ['2-13', 'Cybersecurity Incident and Threat Management', ['incident']], ['2-14', 'Physical Security', []], ['2-15', 'Web Application Security', ['web']],
  ['3-1', 'Cybersecurity Resilience Aspects of Business Continuity Management (BCM)', ['resilience']],
  ['4-1', 'Third-Party Cybersecurity', ['supply']], ['4-2', 'Cloud Computing and Hosting Cybersecurity', ['cloud']],
];
export const CCC = [
  ['1-1', 'Cybersecurity Roles and Responsibilities', ['roles']], ['1-2', 'Cybersecurity Risk Management', ['risk']], ['1-3', 'Compliance with Cybersecurity Standards, Laws, and Regulations', ['compliance']],
  ['1-4', 'Cybersecurity in Human Resources', []], ['1-5', 'Cybersecurity in Change Management', ['change']],
  ['2-1', 'Asset Management', ['assets', 'cloud']], ['2-2', 'Identity and Access Management', ['identity', 'cloudAccess']], ['2-3', 'Information System and Information Processing Facilities Protection', ['endpoint', 'containers']],
  ['2-4', 'Networks Security Management', ['network', 'cloud']], ['2-5', 'Mobile Devices Security', ['mobile']], ['2-6', 'Data and Information Protection', ['data']], ['2-7', 'Cryptography', ['crypto']],
  ['2-8', 'Backup and Recovery Management', ['backup']], ['2-9', 'Vulnerabilities Management', ['vulnerability', 'containers']], ['2-10', 'Penetration Testing', ['validation']],
  ['2-11', 'Cybersecurity Event Logs and Monitoring Management', ['logs', 'cloud']], ['2-12', 'Cybersecurity Incident and Threat Management', ['incident']], ['2-13', 'Physical Security', []],
  ['2-14', 'Web Application Security', ['web']], ['2-15', 'Key Management', ['keys']], ['2-16', 'System Development Security', ['devsecops']], ['2-17', 'Storage Media Security', []],
  ['3-1', 'Cybersecurity Resilience Aspects of Business Continuity Management (BCM)', ['resilience']], ['4-1', 'Supply Chain and Third-Party Cybersecurity', ['supply']],
];
const K = (...kinds) => ({ kinds }), T = (table, where = '') => ({ table, where });
// Evidence sources: stored event kinds or platform tables, with the CyberGuard requirement that produces them.
export const SOURCES = {
  roles: { label: 'User roles, scopes and just-in-time elevation', reqs: ['CG-052'], query: [T('users')] },
  risk: { label: 'Risk register and threat models', reqs: ['CG-033'], query: [K('governance.risk_record', 'governance.threat_model')] },
  compliance: { label: 'This evidence mapping and its exports', reqs: ['CG-124'], query: [T('compliance_profiles')] },
  audit: { label: 'Hash-chained audit log and evidence integrity checks', reqs: ['CG-114'], query: [T('audit')] },
  assets: { label: 'Asset inventory with ownership and criticality context', reqs: ['CG-001', 'CG-028'], query: [T('assets'), K('asset.context')] },
  identity: { label: 'Directory snapshots, account posture, sign-ins and privileged access', reqs: ['CG-007', 'CG-009'], query: [K('identity.directory_snapshot', 'identity.account_posture', 'identity.signin_activity', 'identity.privileged_access', 'identity.laps_posture')] },
  endpoint: { label: 'Endpoint protection, process causality, tamper and ransomware posture', reqs: ['CG-004', 'CG-005'], query: [K('protection.observed', 'agent.inventory_report', 'endpoint.process_causality', 'endpoint.defense_tamper', 'endpoint.ransomware_posture', 'linux.security_posture')] },
  email: { label: 'SPF, DKIM and DMARC posture, phishing analysis and forwarding rules', reqs: ['CG-108'], query: [K('email.domain_posture', 'email.message_analysis', 'email.forwarding_change')] },
  network: { label: 'Firewall rulesets, device configuration, network posture, NAC and flow analysis', reqs: ['CG-018', 'CG-096', 'CG-098'], query: [K('firewall.ruleset', 'network.device_config', 'network.posture', 'nac.policy', 'management.policy', 'network.port_map')] },
  mobile: { label: 'Mobile device management posture', reqs: ['CG-095'], query: [K('mdm.device_posture')] },
  data: { label: 'Declared data stores, classification and egress signals', reqs: ['CG-109'], query: [K('data.store')] },
  crypto: { label: 'TLS checks of web and external services', reqs: ['CG-072', 'CG-107'], query: [K('web.security_check', 'easm.observation')] },
  backup: { label: 'Backup security and restore readiness', reqs: ['CG-031'], query: [K('resilience.backup_security', 'resilience.restore_readiness')] },
  vulnerability: { label: 'Software inventory, vulnerability catalog, assessments and governance', reqs: ['CG-024', 'CG-074'], query: [K('software.inventory', 'vulnerability.catalog', 'vulnerability.assessment_scope'), T('vuln_tracking')] },
  validation: { label: 'Authorized validation runs and the detection validation lab', reqs: ['CG-026', 'CG-115'], query: [K('validation.test_run'), T('validation_lab_runs')] },
  logs: { label: 'Normalised log sources and source health', reqs: ['CG-014', 'CG-103'], query: [K('log.batch'), T('sources')] },
  incident: { label: 'Alerts, cases, playbooks and threat intelligence', reqs: ['CG-035', 'CG-112'], query: [T('alerts'), T('cases')] },
  web: { label: 'Web and API security checks and WAF logs', reqs: ['CG-107', 'CG-025'], query: [K('web.security_check')] },
  resilience: { label: 'Incident recovery and resilience controls', reqs: ['CG-031'], query: [K('resilience.incident_recovery', 'resilience.controls', 'resilience.restore_readiness')] },
  supply: { label: 'SBOM, CI review and artifact verification', reqs: ['CG-106'], query: [K('supply_chain.sbom', 'supply_chain.ci_review', 'supply_chain.artifact')] },
  cloud: { label: 'Cloud inventory, findings, audit logs and coverage', reqs: ['CG-046', 'CG-104'], query: [K('cloud.account_inventory', 'cloud.resource_inventory', 'cloud.finding')] },
  cloudAccess: { label: 'Cloud access grants and reviews', reqs: ['CG-049'], query: [K('cloud.access_grant')] },
  containers: { label: 'Kubernetes audit, RBAC and image scans', reqs: ['CG-105'], query: [K('k8s.audit_batch', 'k8s.rbac_snapshot', 'container.image_scan')] },
  change: { label: 'Sensitive change monitoring and change windows', reqs: ['CG-032', 'CG-119'], query: [K('change.sensitive'), T('change_windows')] },
  keys: { label: 'Encrypted connector secret store and rotation', reqs: ['CG-055'], query: [T('secrets')] },
  devsecops: { label: 'CI pipeline review and SBOM', reqs: ['CG-106'], query: [K('supply_chain.ci_review', 'supply_chain.sbom')] },
};

export function applicability(p) {
  const inScope = ['government', 'cni-private'].includes(p.entity_type), out = {}, set = (fw, state, en, ar) => { out[fw] = { state, reason: en, reason_ar: ar }; };
  set('ECC-2:2024', inScope ? 'mandatory' : 'recommended', inScope ? 'Government entity or private CNI owner/operator/host: ECC applies' : 'Outside the ECC scope; NCA encourages adopting it', inScope ? 'جهة حكومية أو جهة خاصة تملك أو تشغل أو تستضيف بنية تحتية وطنية حساسة: تنطبق الضوابط الأساسية' : 'خارج نطاق الضوابط الأساسية؛ وتشجع الهيئة على تطبيقها');
  if (p.is_csp) set('CCC-2:2024', p.serves_in_scope_tenants ? 'mandatory' : 'recommended', p.serves_in_scope_tenants ? 'Cloud service provider serving in-scope tenants: CSP controls apply' : 'Cloud provider without in-scope tenants', p.serves_in_scope_tenants ? 'مزود خدمة سحابية يخدم جهات ضمن النطاق: تنطبق ضوابط مزود الخدمة' : 'مزود سحابي لا يخدم جهات ضمن النطاق');
  else if (p.uses_cloud) set('CCC-2:2024', inScope ? 'mandatory' : 'recommended', inScope ? 'In-scope entity using cloud services: tenant (CST) controls apply, and ECC subdomain 4-2' : 'Uses cloud services outside the CCC scope', inScope ? 'جهة ضمن النطاق تستخدم خدمات سحابية: تنطبق ضوابط المستأجر والمكون الفرعي 4-2' : 'تستخدم خدمات سحابية خارج نطاق ضوابط الحوسبة السحابية');
  else set('CCC-2:2024', 'not-applicable', 'No cloud services used or provided', 'لا تُستخدم أو تُقدم خدمات سحابية');
  set('OTCC-1:2022', p.has_ot ? (inScope ? 'mandatory' : 'recommended') : 'not-applicable', p.has_ot ? 'Operational technology or industrial control systems are present' : 'No operational technology declared', p.has_ot ? 'توجد أنظمة تشغيلية أو أنظمة تحكم صناعي' : 'لا توجد أنظمة تشغيلية معلنة');
  set('CSCC-1:2019', p.has_critical_systems ? (inScope ? 'mandatory' : 'recommended') : 'not-applicable', p.has_critical_systems ? 'The entity has systems classified as critical' : 'No critical systems declared', p.has_critical_systems ? 'لدى الجهة أنظمة مصنفة حساسة' : 'لا توجد أنظمة حساسة معلنة');
  set('DCC-1:2022', p.handles_classified_data ? (inScope ? 'mandatory' : 'recommended') : 'not-applicable', p.handles_classified_data ? 'The entity handles classified data' : 'No classified data declared', p.handles_classified_data ? 'تتعامل الجهة مع بيانات مصنفة' : 'لا توجد بيانات مصنفة معلنة');
  return out;
}

export class NcaCompliance {
  constructor(store, { clock }) { Object.assign(this, { s: store, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  profile() { const r = this.s.get('SELECT * FROM compliance_profiles ORDER BY saved_at DESC LIMIT 1'); return r ? { ...JSON.parse(r.profile), saved_at: r.saved_at, saved_by: r.saved_by } : null; }
  saveProfile(actor, input) {
    const bool = k => input[k] === true, entity_type = ['government', 'cni-private', 'other-private'].includes(input.entity_type) ? input.entity_type : null;
    fail(entity_type, 400, 'invalid_entity_type');
    const p = { entity_type, uses_cloud: bool('uses_cloud'), is_csp: bool('is_csp'), serves_in_scope_tenants: bool('serves_in_scope_tenants'), has_ot: bool('has_ot'), has_critical_systems: bool('has_critical_systems'), handles_classified_data: bool('handles_classified_data') };
    this.s.run('INSERT INTO compliance_profiles(saved_at,saved_by,profile) VALUES (?,?,?)', this.now(), actor, JSON.stringify(p)); this.s.audit(actor, 'compliance.profile.saved', 'nca', p, this.now()); return this.profile();
  }
  evidence(key) {
    const src = SOURCES[key]; let count = 0, last = null;
    for (const q of src.query) {
      if (q.kinds) { const r = this.s.get(`SELECT COUNT(*) n, MAX(observed_at) last FROM events WHERE kind IN (${q.kinds.map(() => '?').join(',')})`, ...q.kinds); count += r.n; if (r.last && (!last || r.last > last)) last = r.last; }
      else { const r = this.s.get(`SELECT COUNT(*) n FROM ${q.table}`); count += r.n; }
    }
    return { source: key, label: src.label, requirements: src.reqs, records: count, last_observed: last };
  }
  assess(list, cloudApplies) {
    return list.map(([id, title, keys]) => {
      if (id === '4-2' && !cloudApplies) return { id, title, state: 'not-applicable', evidence: [] };
      if (!keys.length) return { id, title, state: 'organisational-evidence-required', evidence: [] };
      const ev = keys.map(k => this.evidence(k)), withData = ev.filter(e => e.records > 0);
      return { id, title, state: withData.length === ev.length ? 'technical-evidence-available' : withData.length ? 'partial-technical-evidence' : 'no-evidence-collected', evidence: ev };
    });
  }
  view() {
    const p = this.profile(), app = p ? applicability(p) : null, cloudApplies = Boolean(p?.uses_cloud || p?.is_csp);
    const summarize = rows => Object.fromEntries(['technical-evidence-available', 'partial-technical-evidence', 'no-evidence-collected', 'organisational-evidence-required', 'not-applicable'].map(s => [s, rows.filter(r => r.state === s).length]));
    const ecc = this.assess(ECC, cloudApplies), ccc = app && app['CCC-2:2024'].state !== 'not-applicable' ? this.assess(CCC, true) : [];
    return { profile: p, applicability: app, frameworks: FRAMEWORKS, ecc: { framework: 'ECC-2:2024', subdomains: ecc, summary: summarize(ecc) }, ccc: { framework: 'CCC-2:2024', subdomains: ccc, summary: summarize(ccc), role: p?.is_csp ? 'CSP' : 'CST' },
      other: ['OTCC-1:2022', 'CSCC-1:2019', 'DCC-1:2022'].map(f => ({ framework: f, ...(app ? app[f] : { state: 'profile-required' }), note: 'Applicability only: evidence for these frameworks is mapped through the ECC subdomains they extend.', note_ar: 'الانطباق فقط: تُربط أدلة هذه الأطر عبر مكونات الضوابط الأساسية التي تبني عليها.' })),
      sources: 'Subdomain lists from the official NCA documents ECC-2:2024 and CCC-2:2024 (cdn.nca.gov.sa).',
      claim: 'Evidence mapping, not a compliance claim: CyberGuard shows which technical evidence it holds for each NCA subdomain and which subdomains need organisational evidence. Compliance is determined by the entity assessment against NCA tools.',
      claim_ar: 'ربط أدلة وليس ادعاء امتثال: يبين CyberGuard الأدلة التقنية التي يملكها لكل مكون فرعي من ضوابط الهيئة الوطنية للأمن السيبراني، والمكونات التي تحتاج أدلة تنظيمية. يُحدد الامتثال بتقييم الجهة وفق أدوات الهيئة.' };
  }
}
