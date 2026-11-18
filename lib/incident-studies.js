// CG-064 Library of documented incident studies. Each study is a publicly documented incident with its official
// government advisory, broken into attack stages (MITRE ATT&CK tactic and technique IDs). For every stage it names the
// evidence kinds in which CyberGuard could see it, the CyberGuard rules that alert on it, the typed response actions
// that contain it, and the preventive controls. Facts are limited to what the cited advisory states; the library is
// reference material for analysts and for detection hypotheses (CG-065), never an automatic action.
export const incidentStudies = [
  {
    id: 'colonial-pipeline-2021', title: ['Colonial Pipeline ransomware (DarkSide)', 'هجوم الفدية على Colonial Pipeline (DarkSide)'], year: 2021, sector: 'energy',
    source: { publisher: 'CISA · FBI', ref: 'AA21-131A', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a' },
    summary: ['Ransomware on the business network led the operator to shut down pipeline operations as a precaution; DarkSide affiliates steal data before encrypting.', 'فدية على شبكة الأعمال دفعت المشغل لإيقاف تشغيل خط الأنابيب احترازيًا؛ ومنتسبو DarkSide يسرقون البيانات قبل التشفير.'],
    stages: [
      { tactic: 'initial-access', techniques: ['T1133', 'T1078'], what: ['Remote access with valid but compromised credentials', 'وصول عن بعد ببيانات اعتماد صحيحة لكنها مسروقة'], evidence: ['identity.signin_activity', 'remote.authenticated', 'log.batch'], rules: ['CG-IDENT-TRAVEL-011', 'CG-REMOTE-SUSPICIOUS'], response: ['network.block-ip'], prevention: ['MFA on every remote access path', 'Disable unused and legacy VPN accounts'] },
      { tactic: 'exfiltration', techniques: ['T1567'], what: ['Data stolen before encryption for double extortion', 'سرقة البيانات قبل التشفير للابتزاز المزدوج'], evidence: ['log.batch'], rules: ['CG-LOG-IDS-014'], response: ['network.block-ip', 'dns.block-domain'], prevention: ['Egress filtering and alerting on large outbound transfers'] },
      { tactic: 'impact', techniques: ['T1486', 'T1490'], what: ['Encryption of systems and removal of recovery options', 'تشفير الأنظمة وحذف خيارات الاستعادة'], evidence: ['endpoint.process_causality', 'endpoint.ransomware_posture'], rules: ['CG-MAL-LOLBIN-001', 'CG-RAN-005'], response: ['endpoint.isolate-device'], prevention: ['Offline, tested backups', 'Segment IT from OT networks'] }] },
  {
    id: 'wannacry-2017', title: ['WannaCry ransomware worm', 'دودة الفدية WannaCry'], year: 2017, sector: 'cross-sector',
    source: { publisher: 'US-CERT (CISA)', ref: 'Alert on WannaCry, MS17-010', url: 'https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware' },
    summary: ['A worm spread through the SMBv1 vulnerability fixed by MS17-010 and encrypted files on unpatched Windows systems.', 'دودة انتشرت عبر ثغرة SMBv1 التي أصلحها MS17-010 وشفّرت الملفات على أنظمة Windows غير المحدّثة.'],
    stages: [
      { tactic: 'initial-access', techniques: ['T1190'], what: ['SMB exposed to the network on unpatched hosts', 'خدمة SMB مكشوفة على أجهزة غير محدّثة'], evidence: ['software.inventory', 'vulnerability.catalog', 'firewall.ruleset'], rules: ['CG-VULN-KEV-024', 'CG-FW-EXPOSE-020'], response: ['network.block-port'], prevention: ['Apply MS17-010', 'Disable SMBv1', 'Block TCP 445 at the perimeter'] },
      { tactic: 'lateral-movement', techniques: ['T1210'], what: ['Self-propagation to other hosts over SMB', 'انتشار ذاتي إلى أجهزة أخرى عبر SMB'], evidence: ['log.batch', 'discovery.observed'], rules: ['CG-NET-LATERAL-015'], response: ['network.block-port', 'endpoint.isolate-device'], prevention: ['Internal segmentation for SMB'] },
      { tactic: 'impact', techniques: ['T1486'], what: ['File encryption', 'تشفير الملفات'], evidence: ['endpoint.ransomware_posture'], rules: ['CG-RAN-005'], response: ['endpoint.isolate-device'], prevention: ['Offline backups'] }] },
  {
    id: 'notpetya-2017', title: ['NotPetya destructive malware', 'البرمجية التخريبية NotPetya'], year: 2017, sector: 'cross-sector',
    source: { publisher: 'US-CERT (CISA)', ref: 'Petya Ransomware alert', url: 'https://www.cisa.gov/news-events/alerts/2017/07/01/petya-ransomware' },
    summary: ['Spread from a compromised software update, harvested credentials and moved laterally with administrative tools and SMB exploits before making systems unusable.', 'انتشرت من تحديث برمجي مخترق، وجمعت بيانات الاعتماد، وتحركت جانبيًا بأدوات الإدارة وثغرات SMB قبل تعطيل الأنظمة.'],
    stages: [
      { tactic: 'initial-access', techniques: ['T1195.002'], what: ['Malicious code in a vendor software update', 'شيفرة خبيثة في تحديث برمجي من مورد'], evidence: ['change.sensitive', 'software.inventory'], rules: ['CG-MAL-PERSIST-002'], response: ['endpoint.isolate-device', 'endpoint.block-app'], prevention: ['Isolate update servers', 'Monitor software changes on servers'] },
      { tactic: 'credential-access', techniques: ['T1003'], what: ['Credential harvesting from memory', 'جمع بيانات الاعتماد من الذاكرة'], evidence: ['endpoint.process_causality'], rules: ['CG-MAL-LOLBIN-001'], response: ['endpoint.isolate-device'], prevention: ['Credential Guard and least privilege for admins'] },
      { tactic: 'lateral-movement', techniques: ['T1569.002', 'T1047', 'T1210'], what: ['Remote execution with admin tools and SMB exploitation', 'تنفيذ عن بعد بأدوات الإدارة واستغلال SMB'], evidence: ['log.batch', 'endpoint.process_causality'], rules: ['CG-NET-LATERAL-015'], response: ['network.block-port', 'endpoint.isolate-device'], prevention: ['Restrict admin shares and remote service creation'] },
      { tactic: 'impact', techniques: ['T1486'], what: ['Disk and file encryption', 'تشفير القرص والملفات'], evidence: ['endpoint.ransomware_posture'], rules: ['CG-RAN-005'], response: ['endpoint.isolate-device'], prevention: ['Offline backups and rebuild procedures'] }] },
  {
    id: 'solarwinds-2020', title: ['SolarWinds Orion supply-chain compromise', 'اختراق سلسلة التوريد عبر SolarWinds Orion'], year: 2020, sector: 'government and enterprise',
    source: { publisher: 'CISA', ref: 'AA20-352A', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a' },
    summary: ['A trojanized Orion update gave the actor a backdoor; the actor then abused identity infrastructure, including forged SAML tokens and added credentials to cloud applications.', 'منح تحديث Orion الملغوم بابًا خلفيًا؛ ثم أساء المهاجم استخدام بنية الهوية، ومنها رموز SAML مزورة وإضافة بيانات اعتماد لتطبيقات سحابية.'],
    stages: [
      { tactic: 'initial-access', techniques: ['T1195.002'], what: ['Trojanized vendor update on a management server', 'تحديث مورد ملغوم على خادم إدارة'], evidence: ['change.sensitive', 'software.inventory'], rules: ['CG-MAL-PERSIST-002'], response: ['endpoint.isolate-device'], prevention: ['Isolate management servers from the internet'] },
      { tactic: 'command-and-control', techniques: ['T1071.001'], what: ['HTTP command and control and DNS lookups to actor domains', 'قيادة وتحكم عبر HTTP واستعلامات DNS لنطاقات المهاجم'], evidence: ['log.batch'], rules: ['CG-NET-DNS-017'], response: ['dns.block-domain', 'network.block-ip'], prevention: ['Egress allow-listing for servers'] },
      { tactic: 'persistence', techniques: ['T1606.002', 'T1098.001'], what: ['Forged SAML tokens and credentials added to cloud applications', 'رموز SAML مزورة وبيانات اعتماد مضافة لتطبيقات سحابية'], evidence: ['identity.idp_change', 'identity.oauth_consent', 'cloud.access_grant'], rules: ['CG-IDENT-IDP-013', 'CG-IDENT-OAUTH-012', 'CG-CLOUD-ACCESS-049'], response: [], prevention: ['Monitor federation and application credential changes', 'Protect token-signing keys'] }] },
  {
    id: 'moveit-cl0p-2023', title: ['MOVEit Transfer exploitation (CL0P)', 'استغلال MOVEit Transfer (CL0P)'], year: 2023, sector: 'cross-sector',
    source: { publisher: 'CISA · FBI', ref: 'AA23-158A', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a' },
    summary: ['An SQL injection vulnerability (CVE-2023-34362) in internet-facing MOVEit Transfer servers was exploited to install a web shell and steal data.', 'استُغلت ثغرة حقن SQL (CVE-2023-34362) في خوادم MOVEit Transfer المكشوفة للإنترنت لزرع web shell وسرقة البيانات.'],
    stages: [
      { tactic: 'initial-access', techniques: ['T1190'], what: ['Exploit of an internet-facing file transfer application', 'استغلال تطبيق نقل ملفات مكشوف للإنترنت'], evidence: ['vulnerability.catalog', 'software.inventory', 'log.batch'], rules: ['CG-VULN-KEV-024', 'CG-WAF-025', 'CG-FW-EXPOSE-020'], response: ['network.block-ip', 'network.block-port'], prevention: ['Patch and restrict internet exposure of file transfer services'] },
      { tactic: 'persistence', techniques: ['T1505.003'], what: ['Web shell on the application server', 'web shell على خادم التطبيق'], evidence: ['change.sensitive'], rules: ['CG-MAL-PERSIST-002'], response: ['endpoint.quarantine-file', 'endpoint.stop-service'], prevention: ['File integrity monitoring of web directories'] },
      { tactic: 'exfiltration', techniques: ['T1567'], what: ['Bulk data theft from the transfer server', 'سرقة بيانات بالجملة من خادم النقل'], evidence: ['log.batch'], rules: ['CG-LOG-IDS-014'], response: ['network.block-ip'], prevention: ['Alert on unusual outbound volume'] }] },
  {
    id: 'log4shell-2021', title: ['Log4Shell (CVE-2021-44228)', 'Log4Shell (CVE-2021-44228)'], year: 2021, sector: 'cross-sector',
    source: { publisher: 'CISA', ref: 'Apache Log4j vulnerability guidance', url: 'https://www.cisa.gov/news-events/news/apache-log4j-vulnerability-guidance' },
    summary: ['A JNDI lookup in Apache Log4j 2 allowed remote code execution through logged input; attackers used it to download and run tools.', 'سمح بحث JNDI في Apache Log4j 2 بتنفيذ شيفرة عن بعد عبر مدخلات تُسجَّل؛ واستخدمه المهاجمون لتنزيل أدوات وتشغيلها.'],
    stages: [
      { tactic: 'initial-access', techniques: ['T1190'], what: ['Crafted input logged by a vulnerable Java application', 'مدخل مصمم يُسجل في تطبيق Java ضعيف'], evidence: ['software.inventory', 'vulnerability.catalog', 'log.batch'], rules: ['CG-VULN-KEV-024', 'CG-WAF-025', 'CG-LOG-IDS-014'], response: ['network.block-ip'], prevention: ['Upgrade Log4j', 'Inventory Java dependencies'] },
      { tactic: 'command-and-control', techniques: ['T1105'], what: ['Outbound LDAP or DNS callback and tool download', 'اتصال LDAP أو DNS خارج وتنزيل أدوات'], evidence: ['log.batch'], rules: ['CG-NET-DNS-017'], response: ['dns.block-domain', 'endpoint.isolate-device'], prevention: ['Block outbound LDAP from servers'] }] },
  {
    id: 'scattered-spider-2023', title: ['Scattered Spider social engineering', 'الهندسة الاجتماعية لمجموعة Scattered Spider'], year: 2023, sector: 'cross-sector',
    source: { publisher: 'CISA · FBI', ref: 'AA23-320A', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a' },
    summary: ['The actors impersonate staff to IT help desks, push MFA prompts and install legitimate remote access tools, then steal data and deploy ransomware.', 'ينتحل المهاجمون صفة الموظفين لدى مكاتب الدعم، ويرسلون طلبات MFA متكررة، ويثبتون أدوات وصول عن بعد مشروعة، ثم يسرقون البيانات وينشرون الفدية.'],
    stages: [
      { tactic: 'initial-access', techniques: ['T1656', 'T1621'], what: ['Help desk impersonation and repeated MFA prompts', 'انتحال لدى مكتب الدعم وطلبات MFA متكررة'], evidence: ['identity.helpdesk_reset', 'identity.signin_activity', 'identity.idp_change'], rules: ['CG-IDENT-IDP-013', 'CG-IDENT-TRAVEL-011'], response: [], prevention: ['Verified identity checks before help desk resets', 'Phishing-resistant MFA'] },
      { tactic: 'command-and-control', techniques: ['T1219'], what: ['Legitimate remote access software installed', 'تثبيت برامج وصول عن بعد مشروعة'], evidence: ['remote.application_present', 'remote.active'], rules: ['CG-REMOTE-SUSPICIOUS', 'CG-REMOTE-EXPOSURE'], response: ['endpoint.block-app', 'network.block-ip'], prevention: ['Allow-list approved remote access tools'] },
      { tactic: 'impact', techniques: ['T1486'], what: ['Ransomware deployment', 'نشر الفدية'], evidence: ['endpoint.ransomware_posture'], rules: ['CG-RAN-005'], response: ['endpoint.isolate-device'], prevention: ['Offline backups'] }] },
  {
    id: 'volt-typhoon-2024', title: ['Volt Typhoon living-off-the-land intrusions', 'اختراقات Volt Typhoon بأدوات النظام نفسه'], year: 2024, sector: 'critical infrastructure',
    source: { publisher: 'CISA · NSA · FBI', ref: 'AA24-038A', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a' },
    summary: ['The actors exploit network edge devices, use valid accounts and built-in tools such as wmic and ntdsutil, and route traffic through compromised small-office routers.', 'يستغل المهاجمون أجهزة حافة الشبكة، ويستخدمون حسابات صحيحة وأدوات مدمجة مثل wmic وntdsutil، ويمررون الحركة عبر موجهات مكاتب صغيرة مخترقة.'],
    stages: [
      { tactic: 'initial-access', techniques: ['T1190'], what: ['Exploit of edge devices such as VPN or firewall appliances', 'استغلال أجهزة الحافة مثل VPN أو الجدران النارية'], evidence: ['network.device_config', 'firewall.ruleset', 'vulnerability.catalog'], rules: ['CG-VULN-KEV-024', 'CG-FW-EXPOSE-020'], response: ['network.block-ip'], prevention: ['Patch and harden edge devices first'] },
      { tactic: 'credential-access', techniques: ['T1003.003'], what: ['Active Directory database extraction with built-in tools', 'استخراج قاعدة Active Directory بأدوات مدمجة'], evidence: ['endpoint.process_causality', 'identity.directory_audit'], rules: ['CG-MAL-LOLBIN-001', 'CG-IDENT-PRIVADD-007'], response: ['endpoint.isolate-device'], prevention: ['Alert on ntdsutil and shadow copy use on domain controllers'] },
      { tactic: 'lateral-movement', techniques: ['T1078', 'T1047'], what: ['Valid accounts and WMI across the network', 'حسابات صحيحة وWMI عبر الشبكة'], evidence: ['log.batch', 'identity.signin_activity'], rules: ['CG-NET-LATERAL-015'], response: ['endpoint.isolate-device', 'network.switch-port-admin-down'], prevention: ['Restrict administrative protocols between segments'] },
      { tactic: 'command-and-control', techniques: ['T1090'], what: ['Traffic proxied through compromised small-office routers', 'تمرير الحركة عبر موجهات مكاتب صغيرة مخترقة'], evidence: ['log.batch', 'network.topology'], rules: ['CG-LOG-IDS-014'], response: ['network.block-ip'], prevention: ['Retire end-of-life routers'] }] },
];
export const tactics = ['initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact'];
export const tacticNames = { 'initial-access': ['Initial access', 'الوصول الأولي'], execution: ['Execution', 'التنفيذ'], persistence: ['Persistence', 'الاستمرارية'], 'privilege-escalation': ['Privilege escalation', 'رفع الصلاحيات'], 'defense-evasion': ['Defense evasion', 'تجاوز الدفاعات'], 'credential-access': ['Credential access', 'سرقة بيانات الاعتماد'], discovery: ['Discovery', 'الاستكشاف'], 'lateral-movement': ['Lateral movement', 'الحركة الجانبية'], collection: ['Collection', 'الجمع'], 'command-and-control': ['Command and control', 'القيادة والتحكم'], exfiltration: ['Exfiltration', 'تسريب البيانات'], impact: ['Impact', 'التأثير'] };
export const preventionAr = {
  'MFA on every remote access path': 'MFA على كل مسار وصول عن بعد', 'Disable unused and legacy VPN accounts': 'تعطيل حسابات VPN القديمة وغير المستخدمة',
  'Egress filtering and alerting on large outbound transfers': 'تصفية الحركة الخارجة والتنبيه على عمليات النقل الكبيرة', 'Offline, tested backups': 'نسخ احتياطية غير متصلة ومختبرة',
  'Segment IT from OT networks': 'فصل شبكة تقنية المعلومات عن شبكة التشغيل', 'Apply MS17-010': 'تطبيق التحديث MS17-010', 'Disable SMBv1': 'تعطيل SMBv1',
  'Block TCP 445 at the perimeter': 'حظر TCP 445 على حافة الشبكة', 'Internal segmentation for SMB': 'تقسيم داخلي لحركة SMB', 'Offline backups': 'نسخ احتياطية غير متصلة',
  'Isolate update servers': 'عزل خوادم التحديث', 'Monitor software changes on servers': 'مراقبة تغييرات البرمجيات على الخوادم',
  'Credential Guard and least privilege for admins': 'Credential Guard وأقل صلاحية للمسؤولين', 'Restrict admin shares and remote service creation': 'تقييد المشاركات الإدارية وإنشاء الخدمات عن بعد',
  'Offline backups and rebuild procedures': 'نسخ احتياطية غير متصلة وإجراءات إعادة بناء', 'Isolate management servers from the internet': 'عزل خوادم الإدارة عن الإنترنت',
  'Egress allow-listing for servers': 'قائمة سماح للحركة الخارجة من الخوادم', 'Monitor federation and application credential changes': 'مراقبة تغييرات الاتحاد وبيانات اعتماد التطبيقات',
  'Protect token-signing keys': 'حماية مفاتيح توقيع الرموز', 'Patch and restrict internet exposure of file transfer services': 'تحديث خدمات نقل الملفات وتقليل كشفها للإنترنت',
  'File integrity monitoring of web directories': 'مراقبة سلامة ملفات مجلدات الويب', 'Alert on unusual outbound volume': 'التنبيه على حجم خارج غير معتاد',
  'Upgrade Log4j': 'ترقية Log4j', 'Inventory Java dependencies': 'جرد مكتبات Java المعتمدة', 'Block outbound LDAP from servers': 'حظر LDAP الخارج من الخوادم',
  'Verified identity checks before help desk resets': 'تحقق موثوق من الهوية قبل إعادة التعيين في مكتب الدعم', 'Phishing-resistant MFA': 'MFA مقاوم للتصيد',
  'Allow-list approved remote access tools': 'قائمة سماح لأدوات الوصول عن بعد المعتمدة', 'Patch and harden edge devices first': 'تحديث أجهزة الحافة وتقويتها أولًا',
  'Alert on ntdsutil and shadow copy use on domain controllers': 'التنبيه على استخدام ntdsutil والنسخ الظلية على وحدات التحكم بالمجال',
  'Restrict administrative protocols between segments': 'تقييد بروتوكولات الإدارة بين الأجزاء', 'Retire end-of-life routers': 'إخراج الموجهات المنتهي دعمها من الخدمة' };
