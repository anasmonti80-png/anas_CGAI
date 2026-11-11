# CyberGuard AI — السجل التراكمي للبحث والمتطلبات

**الإصدار:** v1.9 (تحديث تراكمي محافظ على v0.3–v1.8؛ مراجعة نظافة النطاق وجمع السجلات دون تنفيذ)  
**تاريخ التحديث:** 2026-11-10 — مراجعة نطاق المشروع وجودة/انتقائية السجلات وتفادي تكرار الوظائف  
**الحالة:** دراسة وتوثيق فقط؛ **لا برمجة، ولا بروتوتايب، ولا نشر، ولا فحص لأجهزة فعلية**.  
**الاسم:** CyberGuard AI اسم عمل مؤقت؛ يجب إجراء فحص علامة تجارية ونطاق قبل اعتماده.  
**المرجع البصري:** لقطة لوحة SOC الكحلية/الرمادية/البرتقالية التي قدمها المستخدم؛ نحتفظ باتجاهها وتوزيعها دون نسخ أصول مملوكة لطرف آخر حرفيًا.

> مبدأ السجل: لا تُحذف أي فكرة سابقة دون تسجيل سبب القرار؛ نسجل كل متطلب بحالة (مطلوب/بحث/قابل للتنفيذ بشروط/مؤجل/مرفوض). هذه **أهداف تصميم** وليست قدرات منفذة أو مضمونة.

## أ. تعريف المنتج

منصة أمنية دفاعية تجمع SIEM وEDR/XDR وNDR وVulnerability Management وSecurity Posture وSOAR وAI Analyst، وتعمل بدءًا من جهاز PC محلي مع واجهة Windows ولوحة ويب آمنة للجوال والتابلت، وتتوسع لاحقًا إلى خوادم وحساسات موزعة وبيئات Multi-Vendor وMulti-Cloud وMulti-Tenant.

## أ-1. قرار النطاق النهائي للدراسة — يعلو على الاقتراحات السابقة (2026-11-10)

**قرار المستخدم الصريح:** اسم CyberGuard AI مؤقت، والمرحلة الحالية جمع أفكار وبحوث فقط؛ لا كود ولا بروتوتايب ولا نشر. تتكون منصة الحماية من **Security Core + AIOps/SOAR + DevSecOps + Cyber Resilience**.

| المشروع | مالك المجال | ما الذي نستثنيه أو نسمح به؟ |
|---|---|---|
| NCC | الإدارة والتشغيل والتحكم العام في أجهزة وشبكات Cisco/Huawei والمنافذ وVLAN والتغييرات | CyberGuard يجوز له كشف مخاطر الأجهزة والاتصالات، وإعداد طلب استجابة أمنية محدد لنظام NCC وفق API وموافقة وسجل تدقيق؛ **لا يملك محرك إدارة شبكات مستقلًا** |
| IT Twin | التوأم الرقمي والمحاكاة البصرية والهندسية | خارج نطاق CyberGuard؛ يجوز الاستفادة من بيانات مرجعية إن أتيح تكامل اختياري، ولا تعاد بناء محاكاة التوأم |
| Tickets / ITSM | البلاغات الفنية والصيانة والتذاكر وتوزيع الفنيين | خارج نطاق CyberGuard؛ **إدارة سجل حادث أمني وأدلته ليست نظام بلاغات صيانة**؛ الربط مع المنصة المستقبلية اختياري |
| CyberGuard | الأمن السيبراني والتحقيق والاستجابة السيبرانية + أتمتة محددة + فحص البرمجيات + التعافي | يشغل فقط إجراءات أمنية مدعومة ومفوضة مع تحقق وموافقة وتراجع؛ النسخ والتعافي تتم عبر منتجات ومخازن مدعومة بدل إعادة اختراعها |

### توضيح تعارضات المتطلبات التاريخية
- **CG-002، CG-005–009، CG-020–023، CG-029، CG-041–045، CG-897–912، CG-921–926:** تبقى معلومات اكتشاف ورؤية وقياس خطر ضمن CyberGuard فقط؛ أي إدارة شاملة للشبكة أو محاكاة هندسية تُنقل إلى NCC أو IT Twin. واجهة خريطة CyberGuard تعرض **سياقًا أمنيًا** فقط.
- **CG-913–920:** لا تُنفذ منصة ITSM داخل CyberGuard؛ نقل ميزات التذاكر والصيانة والأصول التشغيلية إلى مشروع Tickets، مع إبقاء موافقات الحوادث الأمنية والسجل التدقيقي داخل CyberGuard.
- **CG-927–936:** تبقى اشتراطات قبول إصدار الأمن صالحة كما هي. لا تُعد أي وظيفة جاهزة دون إثبات في بيئة مدعومة.
- لا يحذف هذا القرار معرفات المتطلبات القديمة؛ بل يصنّفها **منقولة/محدودة النطاق/مؤكدة**، مع حفظ تاريخ القرار.

## ب. سجل المتطلبات المرقم — معرّفات ثابتة

### 01 — التصميم وتجربة الاستخدام
- **CG-001** مطلوب — Dark SOC Dashboard كحلي/رمادي مع برتقالي للتأكيد وألوان حالة محدودة، قريب من الصورة المرجعية.
- **CG-002** مطلوب — شريط جانبي: Overview, Discover, Assets, Network Map, Threats, Incidents, Vulnerabilities, Identity, Cloud, Policies, Response, AI Analyst, Reports, Settings.
- **CG-003** مطلوب — دعم عربي/إنجليزي وRTL وResponsive للكمبيوتر والتابلت والجوال.
- **CG-004** مطلوب — شاشة وضع أمني واضحة مع «لم يتم فحصه/غير مرئي» وتفاصيل الأدلة، وعدم الادعاء بضمان أمن 100%.

### 02 — نطاق الشبكات والاكتشاف
- **CG-005** مطلوب — اكتشاف مصرح به للأجهزة، العناوين، الشبكات، المسارات، VLAN، المنافذ، الخدمات، تغيّر الأصول، الانقطاع أو الإضافة.
- **CG-006** مطلوب — اكتشاف متسلسل باستخدام LLDP/CDP وSNMPv3 وواجهات API وDNS/DHCP وAD وARP بحسب التوفر.
- **CG-007** مطلوب — دعم ثلاثة أوضاع: PC Local، Enterprise Collectors، Authorized Defense Validation Lab.
- **CG-008** مطلوب — إظهار حدود الرؤية: PC وحده لا يرى كل الحركة بين الأجهزة خلف السويتش؛ يدعم SPAN/TAP/Flow Logs/Agents عند الحاجة.
- **CG-009** هدف لاحق — قابلية التوسع إلى 20,000 جهاز بتصميم موزع، لا على جهاز PC واحد.

### 03 — أمن الأجهزة والسيرفرات
- **CG-010** مطلوب — Agents اختيارية للأجهزة المُدارة: Windows Event Logs، Sysmon، Linux audit/syslog، خدمات وعمليات وحالة AV/EDR.
- **CG-011** مطلوب — مراقبة التغييرات الحساسة: Registry/ملفات/خدمات/برامج/Firewalls/حسابات/سياسات.
- **CG-012** مطلوب — رصد مؤشرات الخبيث والفدية ومحاولة تعطيل الحماية وعمليات مشبوهة بأدلة وقواعد.
- **CG-013** مطلوب — جرد برامج وتحديثات وثغرات الأجهزة، وربطها بالإصدارات المثبتة.

### 04 — الهوية والوصول البعيد
- **CG-014** مطلوب — تكامل AD/LDAP، Windows Accounts، Microsoft Entra ID، IAM السحابي، ومراقبة تغيير المجموعات والامتيازات.
- **CG-015** مطلوب — اكتشاف MFA غير مفعل، الحسابات الراكدة، الدخول الشاذ، Password Spraying، موافقات OAuth الخطرة، تعديلات IdP.
- **CG-016** مطلوب — مراقبة مؤشرات RDP/SSH/AnyDesk وغيرها، مع التمييز بين وجود تطبيق واتصال مؤكد وبين اتصال مشروع أو مريب.
- **CG-017** مطلوب — Just-in-Time Privileges وتصاريح مؤقتة ذات مدة وحدود وأسباب وموافقات وتدقيق.

### 05 — كشف الشبكة والجدار الناري
- **CG-018** مطلوب — تجميع Syslog وNetFlow/IPFIX وIDS/IPS وDNS وDHCP وVPN وFirewall logs والتطبيع إلى نموذج أحداث مشترك.
- **CG-019** مطلوب — تحليل الاتصالات بين الأجهزة والتعرض للإنترنت وDNS غير المعتاد ومؤشرات الحركة الجانبية.
- **CG-020** مطلوب — Firewall Rule Analyzer: تعارض/تكرار/قواعد واسعة/قواعد قديمة/انتهاء الاستثناءات/تأثير تغيير.
- **CG-021** مطلوب — مراقبة تصحيحات وإصدارات أجهزة الشبكة والجدران النارية، تغيّر إعدادات DNS وVPN والإدارة الخارجية.
- **CG-022** مطلوب — التمييز بين TCP/UDP Port في جدار ناري وSwitch Physical Port؛ لا يخلط النظام بينهما.
- **CG-023** بحث — تكامل DNS security وWAF وIDS/IPS وNAC وNDR وZTNA بحسب بيئة العميل.

### 06 — الثغرات وتحقق الدفاع
- **CG-024** مطلوب — Vulnerability Assessment ضمن نطاق تفويض، باستخدام مصادر CVE/CVSS/EPSS/CISA KEV وسمات الانكشاف.
- **CG-025** مطلوب — ترتيب مخاطر الثغرات بحسب الأصل وأهميته والتعرض وإثبات الاستغلال والضوابط الحالية؛ لا يعتمد على CVSS وحده.
- **CG-026** مطلوب — ثلاث طبقات للاختبار: Passive، Low-Impact Authorized Validation، وAdversary Emulation في مختبر مصرح به.
- **CG-027** مطلوب — قياس نجاح الكشف أثناء الاختبارات وكتابة Detection Gap بدل الادعاء بأن كل ثغرة قابلة للاستغلال.
- **CG-028** مطلوب — معاملة الأصول الحرجة الإنتاجية بسياسات منع الفحوص المؤثرة حتى مع صلاحيات المسؤول.

### 07 — الاستجابة وإدارة الخدمات والمنافذ
- **CG-029** مطلوب — Actions: Block/Allow IP, Port, App, Domain؛ Stop/Disable Service؛ Quarantine File؛ Isolate/Reconnect Device؛ Shutdown managed host؛ Switch port admin-down فقط بتصريح.
- **CG-030** مطلوب — إزالة خدمة/تغيير دائم كإجراء عالي الخطورة بموافقة منفصلة وخطة استرداد؛ لا تستخدم إزالة عمياء.
- **CG-031** مطلوب — Temporary Permit: نطاق جهاز/مستخدم/مصدر/وجهة/منفذ/مدة/سبب/مالك/موافق؛ انتهاء آلي موثوق يثبت الإلغاء.
- **CG-032** مطلوب — Dry Run وImpact Analysis ثم Approve ثم Execute ثم Verify ثم Audit ثم Rollback.
- **CG-033** مطلوب — حفظ قناة الإدارة وتجنّب قطع السويتشات الأساسية أو DC أو اتصال منصة الأمن بنفسها.
- **CG-034** مطلوب — إجراءات حساسة تستدعي MFA حديثة، Two-Person Approval حين يلزم، Break-Glass مضبوط، وتسجيل immutable/append-only حيث أمكن.
- **CG-035** مطلوب — Playbooks لكل نوع حادث مع مسارات أدلة واستجابة آمنة، وإجراءات مؤتمتة منخفضة الخطورة فقط بعد الاعتماد.

### 08 — محلل الذكاء الاصطناعي
- **CG-036** مطلوب — AI يفسر «ماذا حدث؟ لماذا هو مشبوه؟ ما الدليل؟ ما مستوى الثقة؟ ما الحل؟» بالعربية والإنجليزية.
- **CG-037** مطلوب — AI Grounding من السجلات والقواعد والاستشارات ومراجع موثقة؛ مصدر لكل ادعاء، ومنع اختلاق حقائق.
- **CG-038** مطلوب — استخدام نموذج محلي أساسًا مع Cloud AI اختيارية للبيانات المنقحة بموافقة العميل.
- **CG-039** مطلوب — AI لا يرسل أوامر خام مباشرة؛ فقط يطلب إجراءات من كتالوج محدود يخضع لصلاحيات وموافقات ومحرك سياسات.
- **CG-040** مطلوب — Incident Timeline وEvidence Graph وAttack Path احتمالي مع الفصل بين إثبات حادث وفرضية تحليل.

### 09 — موصلات الشركات: الشبكات المحلية
- **CG-041** مطلوب — Cisco: IOS/IOS XE حيث تسمح النسخة؛ Catalyst Center للـinventory/topology/assurance؛ Cisco ISE ANC للعزل؛ Secure Firewall FMC لقواعد الجدار.
- **CG-042** مطلوب — Huawei: iMaster NCE-Campus/CloudCampus Northbound APIs للتجهيز والمراقبة؛ واجهات الأجهزة المباشرة حسب الإصدار والرخصة.
- **CG-043** بحث — Palo Alto PAN-OS/Panorama APIs، Fortinet FortiManager/FortiOS، Juniper، Aruba، MikroTik، pfSense/OPNsense، Linux routers.
- **CG-044** مطلوب — Capability Negotiation: نكشف ما يدعمه كل جهاز فعليًا من Read/Logs/Config/Policy/Isolation/Port Shutdown/Undo، مع التحقق من الإصدار والرخصة.
- **CG-045** مطلوب — فصل قراءة البيانات عن امتيازات التعديل واشتراط الموافقة والتفويض المحدد للأصول.

### 10 — موصلات السحابة
- **CG-046** مطلوب — AWS: Organizations/Cross-account IAM Roles، CloudTrail، GuardDuty، Security Hub CSPM، Inspector، Config، VPC Flow Logs، AWS Network Firewall، Security Groups، EventBridge؛ حسب الامتيازات والخدمة.
- **CG-047** مطلوب — Azure: Subscriptions/Resource Graph، Entra Sign-in/Audit، Defender for Cloud، Sentinel، Azure Monitor، VNet Flow Logs، Azure Firewall وNSG/ASG، Network Watcher.
- **CG-048** بحث — Google Cloud: SCC، Cloud Audit Logs، VPC Flow Logs، IAM، Cloud Armor، VPC Firewall Rules؛ لاحقًا Kubernetes/EKS/AKS/GKE.
- **CG-049** مطلوب — صلاحيات مؤقتة محدودة لكل حساب/اشتراك/مشروع، لا طلب Root أو Global Admin دائم.
- **CG-050** مطلوب — توحيد Cloud Asset Inventory والتنبيهات والسياسات عبر الأقاليم والحسابات والسحب، مع بيان الفجوات والرسوم.
- **CG-051** مهم — Azure NSG Flow Logs توقّف إنشاء الجديد منه وهو في طريقه للتقاعد في 2027-09-30؛ الجديد يعتمد VNet Flow Logs.

### 11 — الوصول والهوية والأمان الداخلي للمنصة
- **CG-052** مطلوب — HTTPS مع SSO/MFA وRBAC/ABAC وتقسيم Tenant/Site/Scope/Role، وLeast Privilege.
- **CG-053** مطلوب — Windows Desktop + Tablet/Mobile browser، والوصول الخارجي يكون من خلال بوابة Zero Trust أو VPN وقيود أجهزة.
- **CG-054** مطلوب — عدم تعريض محرك الأمان أو قواعد البيانات للعامة؛ تظل البيانات والسيطرة محلية افتراضيًا.
- **CG-055** مطلوب — تشفير أسرار الاتصالات وخزنها في Secret Store، تدوير الرموز، تفويض مجزأ، فصل أدوار التحليل والموافقة والتنفيذ.
- **CG-056** مطلوب — سجلات تدقيق موثوقة، إحصاءات التغطية والصحة، تقييم فقدان Agents، تنبيه على فشل إرسال السجلات.

### 12 — جودة المشروع والقابلية للتوسع
- **CG-057** مطلوب — لا ندّعي نسبة أمان مطلقة؛ Score يتضمن Coverage وEvidence وFreshness وConfidence.
- **CG-058** مطلوب — قياس Precision/False Positives وMTTD/MTTR وتغطية الأجهزة والقواعد وفشل إجراءات الاستجابة.
- **CG-059** مطلوب — Multi-Tenant عند التوسع: عزل بيانات كل عميل، حدود موارد، سياسات واحتفاظ وسجلات مستقلة.
- **CG-060** مطلوب — دعم الانقطاع: Local operation، Queue، Retry، Idempotency، Change Reconciliation، وتحقق بعد التراجع.
- **CG-061** مطلوب — مراجعة تراخيص البرمجيات المفتوحة والخصوصية والالتزامات القانونية قبل الدمج/التوزيع التجاري.
- **CG-062** مطلوب — مراحل تنفيذ تبدأ بمختبر معزول وبيانات اختبار، ثم تجربة نطاق محدود مصرح بها، ثم توسع مشروط بالاختبارات.
- **CG-063** مؤجل — Prompt تطوير شامل نهائي عند انتهاء الدراسة واعتماد المتطلبات؛ **لا نكتبه ولا نبدأ البرمجة الآن**.

### 13 — Threat Knowledge Engine (إضافة هذه الجلسة)
- **CG-064** مطلوب — مكتبة دراسات حوادث موثقة مرتبطة بمراحل الهجوم، ومصادر الرؤية، والاستجابة والوقاية.
- **CG-065** مطلوب — تحويل الأدلة المنشورة إلى فرضيات كشف وقواعد يتم اختبارها يدويًا قبل الاعتماد، لا تحويل نصوص الويب إلى تنفيذ آلي.
- **CG-066** مطلوب — تحديث قواعد الكشف ومعرفة التهديدات بشكل خاضع للمراجعة والتوقيع والنسخ السابقة والتراجع.
- **CG-067** مطلوب — وصف أفضل طريقة لإصلاح كل مشكلة بحسب بيئة الشبكة ونوع الأصل، وإظهار القيود وعدم اليقين.

## ج. دراسات الحوادث ومخرجاتها

| الرمز | الحادث | أسلوب الدخول الموثق | كشف/احتواء مقترح | معرفات المتطلبات |
|---|---|---|---|---|
| CASE-01 | Change Healthcare 2024 | بيانات دخول مسروقة عبر بوابة وصول غير محمية بـMFA | تدقيق MFA، مراقبة وصول بعيد وسلوك حسابات، تقسيم الشبكة والاستجابة | CG-014–017, CG-029 |
| CASE-02 | Microsoft Midnight Blizzard 2023/24 | Password spray على حساب اختبار قديم ثم إساءة استخدام OAuth | رصد حسابات قديمة وتغييرات OAuth والامتيازات والجلسات | CG-015, CG-040 |
| CASE-03 | Snowflake customers UNC5537 2024 | اعتمادات مسروقة قديمة ومفقود MFA/allow lists | رصد الجلسات السحابية والتحويلات الكبيرة ومراقبة الاعتمادات | CG-045–050 |
| CASE-04 | MGM Resorts 2023 | تقارير عن هندسة اجتماعية استهدفت مكتب الدعم | تدقيق MFA reset والهوية الاتحادية وتغييرات حسابات الامتياز | CG-014–017 |
| CASE-05 | MOVEit CL0P 2023 | استغلال ثغرة نقل ملفات مكشوفة؛ web shell وسحب بيانات | كشف exposure/patch/web changes/exfil | CG-024–028 |
| CASE-06 | Volt Typhoon 2024 advisory | إساءة استخدام أجهزة شبكة ضعيفة وأدوات شرعية | مراقبة Firmware/الإدارة الخارجية/DNS وVPN والسجلات | CG-020–023, CG-064 |
| CASE-07 | DNS hijack via compromised SOHO routers (DOJ 2026) | تعديل DNS في راوترات مصابة | Baseline DNS وFirmware والتعرض الخارجي | CG-021, CG-064 |

**تنبيه:** أمثلة إجراءات الكشف ليست ادعاء بأن تلك المؤسسات طبّقتها فعليًا أو أن المنتج قادر عليها الآن؛ هي متطلبات مستنبطة من قصص منشورة.

## د. مصفوفة تكامل أولية — ليست ضمان دعم كل جهاز

| البيئة | القراءة/الكشف | الاستجابة المشروطة | الحدود |
|---|---|---|---|
| Cisco Switches/Routers | SNMPv3, Syslog, LLDP/CDP, Catalyst Center APIs, telemetry | Port/VLAN/ACL وفق الجهاز والتحكم المخول | اختلاف IOS/IOS XE والامتيازات ونقطة التحكم |
| Cisco ISE / Secure Firewall | ANC/pxGrid/FMC APIs | Quarantine/Re-auth/Rules/Policy Deployment | يحتاج خدمة قائمة ورخصة مناسبة وموافقات |
| Huawei switches / iMaster NCE | NBI RESTful, alarms, device/interface/link data | Ports, VLANs, policy حسب API والإصدار | ليس مضمونًا لكل طراز أو ترخيص |
| Palo Alto / Fortinet | APIs/Syslog/logs | Rules/Objects حسب API وصلاحيات المشغل | Commit/Deploy، rate limits، اختلاف المنتج |
| Windows/AD | Event Logs, Sysmon, Agent, LDAP, AD logs | Service/Firewall/Isolation managed endpoint | Agent/Privileges/OS compatibility |
| Linux | Syslog/audit/eBPF وAgent عند الحاجة | Firewall/Service عبر عامل مصرح | فروق النظام والتوزيعة |
| AWS | CloudTrail/GuardDuty/Security Hub/VPC Flow Logs/Config | SG/Network Firewall/response workflow | IAM Role/Region/account/API limits |
| Azure | Entra/Defender/Sentinel/VNet Flow Logs/Monitor | Azure Firewall/NSG/managed resources | RBAC/licensing and Cloud costs |
| Google Cloud | SCC/Cloud Audit Logs/VPC Flow Logs | VPC Firewall/IAM response when authorized | Project/org scopes/licensing |

## هـ. دراسات الجدار الناري المطلوبة قبل التنفيذ

1. الفرق بين Stateless ACL وStateful Firewall وNGFW وWAF وIPS/IDS وDNS Security وNAC وZTNA.
2. قواعد ingress/egress وeast-west وnorth-south والتسلسل والأولوية والتعارض والـshadowed rules.
3. الفرق بين فتح منفذ TCP/UDP وبين إغلاق physical switchport.
4. التحقق من الارتباطات: IP→MAC→Switchport→Asset→Identity، قبل قطع الاتصال.
5. سياسة منع التعديل على Core/Trunk/Uplink/Management/DC إلا بعد تحقق ونافذة تغيير واستعادة.
6. استثناءات JIT ومدة صلاحيتها وموثوقية الإلغاء حتى بعد إعادة تشغيل النظام.
7. Pre-change backup وdry run وتأثير التغيير وpost-change verification وrollback.
8. Traffic encryption/privacy: عدم فك تشفير المحتوى بلا تفويض ونطاق وحوكمة.

## و. مرحلة ما قبل البروتوتايب (Checkpoints)

- CHECK-01 تعريف حالات استخدام قابلة للقياس وThreat Model ووضع الصلاحيات.
- CHECK-02 حصر أصول المختبر وبيانات Logs المطلوبة والأنظمة والإصدارات.
- CHECK-03 تحديد أقل تكامل يعمل لكل Vendor مع Read-only أولاً.
- CHECK-04 وضع مصفوفة صلاحيات مستقلة لكل Action وVendor وScope.
- CHECK-05 التحقق من طرق رصد RDP/AnyDesk وWindows Event/Sysmon والسجلات المتاحة.
- CHECK-06 مراجعة المصادر الأمنية والأدوات وترخيص كل أداة وكلفة التشغيل.
- CHECK-07 اختبار التفاعل بين Sensor وSIEM وAI على أحداث مصطنعة دون التأثير على الإنتاج.
- CHECK-08 تصميم واجهة محافظة على اتجاه الصورة المرجعية وقياس تجربة الجوال.
- CHECK-09 تقييم PC Local مقابل Linux VM مقابل موزع Hybrid، RAM/storage/log rate/retention.
- CHECK-10 اعتماد Threat Modeling وضوابط المنصة والاسترداد والفشل الآمن.
- CHECK-11 مراجعة معايير النجاح ودقة التنبيهات وCoverage وMTTD/MTTR.
- CHECK-12 عند اكتمال الدراسة فقط: كتابة Prompt نهائي متعقب لهذه المعرّفات ثم بناء بروتوتايب.

## ز. مصادر موثوقة للبحث الحالي

### حوادث
- Change Healthcare: https://www.cybersecuritydive.com/news/change-healthcare-compromised-credentials-no-mfa/714792/
- Microsoft Midnight Blizzard: https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
- Snowflake / Mandiant: https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion
- MGM reports: https://www.bloomberg.com/news/articles/2023-09-16/mgm-resorts-hackers-broke-in-after-tricking-it-service-desk
- MOVEit / CISA: https://content.govdelivery.com/accounts/USDHSCISA/bulletins/35ecb08
- Volt Typhoon official CISA/FBI announcement: https://content.govdelivery.com/accounts/USDHSCISA/bulletins/389465e
- DNS hijacking of SOHO routers, DOJ 2026: https://www.justice.gov/opa/pr/justice-department-conducts-court-authorized-disruption-dns-hijacking-network-controlled

### Network vendor APIs
- Cisco ISE ANC: https://developer.cisco.com/docs/pxgrid/adaptive-network-control-anc-policies/
- Cisco Secure Firewall FMC REST: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/API/REST_API_config_guide/secure-firewall-management-center-rest-api-for-access-control-policy.html
- Huawei iMaster NCE APIs: https://intl.devzone.huawei.com/en/enterprise/cloudcampus/quickStart.html
- Huawei CampusInsight: https://e.huawei.com/ma/products/network-analysis/campusinsight
- Palo Alto APIs: https://docs.paloaltonetworks.com/ngfw/api/get-started-with-the-pan-os-rest-api
- FortiManager: https://www.fortinet.com/products/management/fortimanager

### Cloud & security frameworks
- AWS GuardDuty: https://docs.aws.amazon.com/guardduty/latest/ug/
- AWS Security Hub CSPM: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-internal-providers.html
- AWS VPC security and flow: https://docs.aws.amazon.com/vpc/latest/userguide/monitoring.html
- AWS Cross-account: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html
- Azure Network Monitoring: https://learn.microsoft.com/en-us/azure/networking/design-guide/monitor
- Azure Entra to Sentinel: https://learn.microsoft.com/en-us/azure/sentinel/connect-azure-active-directory
- Azure NSG Flow Logs retirement: https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview
- GCP VPC Flow Logs: https://docs.cloud.google.com/vpc/docs/flow-logs
- MITRE ATT&CK Detection Strategies: https://attack.mitre.org/detectionstrategies/
- NIST SP 800-61 Rev 3: https://csrc.nist.gov/news/2025/nist-revises-sp-800-61

## ح. قرارات مؤجلة ومنهج التعديل

1. الاسم النهائي/العلامة والنطاق.
2. أي أدوات مفتوحة المصدر سندمج فعليًا مقابل استخدامها مرجعًا أو تشغيلها بشكل اختياري.
3. نموذج الترخيص، تكاليف السحابة، تخزين الأدلة، البلد والالتزامات التنظيمية.
4. اختيار أول مزود أجهزة نختبره داخل بيئة معملية مصرح بها؛ لا نفترض دعم كل Vendor منذ النسخة الأولى.
5. تحديد من يملك حق المشاهدة والتحليل والعزل والتغيير والموافقة، خاصة في الإنتاج.
6. كل إضافة مستقبلية تحفظ كمطلب جديد CG-068 فصاعدًا وتربط بسيناريو ومصدر وأولوية وحالة اختبار، ولا تُكتب البرمجة حتى يطلبها المستخدم.

**ملاحظة الاستمرارية:** هذه نسخة قابلة للتحميل/الاحتفاظ والرفع لاحقًا لاستكمال الدراسة. لا تُجري أبحاثًا تلقائية في الخلفية أو تحديثًا ذاتيًا بين الجلسات.


---

# ط. الجولة البحثية الموسعة — v0.4 بتاريخ 2026-11-09

**التحديث:** مراجعة مرجعية لممارسات فرق SOC والمؤسسات عالية الحساسية، مع تغطية أنظمة قديمة، الهوية، البرمجيات، أمن الشبكة، OT، الحاويات، التعافي، مخاطر الذكاء الاصطناعي، والمعايير السعودية. نتائج البحث هنا **ليست اختبارًا للمنصة أو توافقًا مضمونًا مع الأجهزة**. تبقى CG-001 إلى CG-067 سارية دون تعديل. نواصل الترقيم من CG-068.

## 14 — الحوكمة والمشهد الدفاعي
- **CG-068** مطلوب — Map Security Outcomes وفق وظائف NIST CSF 2.0 الست: GOVERN/IDENTIFY/PROTECT/DETECT/RESPOND/RECOVER، مع أدلة لكل وظيفة ونقص التغطية.
- **CG-069** مطلوب — Threat Model لكل بيئة: أصول ذات قيمة، حدود الثقة، سيناريوهات هجوم محتملة، وتأثير توقف الخدمة أو تسرب البيانات.
- **CG-070** مطلوب — Asset Criticality & Ownership: ربط الأجهزة والخدمات بالمالك، الخدمة التجارية/التشغيلية، الموقع، حساسية البيانات، أوقات الصيانة، ودرجة حرجية الخدمة.
- **CG-071** مطلوب — Visibility Gap Registry: كل نظام وشبكة وحساب خارج التغطية يظهر سبب عدم الرؤية (لا Agent / لا SPAN / لا سجلات / لا تفويض / انقطاع)، آخر رؤية، وتوصية.
- **CG-072** مطلوب — External Attack Surface Management للأصول المسجلة والمصرح بها فقط: سجلات DNS، شهادات TLS، الخدمات المكشوفة والملكية والتهيئة؛ لا مسح عشوائي للغير.
- **CG-073** مطلوب — Risk Register مؤسسي يربط المخاطر بالتغطية والدليل والمالك والتصحيح والاستثناء وقبول المخاطر مع مدة مراجعة.
- **CG-074** مطلوب — مفاضلة وقائية تستند إلى أهمية الأصول والاستغلال النشط KEV والتعرض والتعويضات الحالية؛ متطلبات حوكمة وقياس جودة لا مجرد قائمة CVE.

## 15 — الأنظمة القديمة والتعافي واستمرارية الأعمال
- **CG-075** مطلوب — Lifecycle Inventory: إصدار نظام التشغيل/المنتج، تاريخ انتهاء دعم الشركة وتحديثاتها الأمنية، وجود دعم ممتد، وخطة تحديث أو استبدال.
- **CG-076** مطلوب — Compatibility Matrix للأنظمة القديمة Windows Server 2008 R2 / 2012 R2 وLinux غير المدعوم وأجهزة الشبكة القديمة: Agent متاح؟ قراءة فقط؟ شبكات معزولة؟ مع قيود الأداء والترخيص.
- **CG-077** مطلوب — Legacy Compensating Controls: عزل شبكي أدق، وصول عبر jump host، منع وصول إنترنت غير لازم، MFA على نقطة الدخول، نسخ احتياطية ومراقبة، إلى حين الترحيل.
- **CG-078** مطلوب — Backup Security: نسخ احتياطية متعددة ومفصولة/غير قابلة للتغيير حيث تدعم المنصة، ومراقبة تعديل/حذف النسخ وصلاحيات النسخ.
- **CG-079** مطلوب — Restore Readiness: اختبارات استرجاع دورية موثقة، أهداف RPO/RTO لكل خدمة، وفحص سلامة النسخ، وعدم مساواة وجود Backup بإمكانية التعافي.
- **CG-080** مطلوب — Incident Recovery Workflows: احتواء ثم استرداد وثائق الهوية والتكوينات والأجهزة، ثم التحقق من خلو البيئة من آثار التهديد قبل إعادة الاتصال.
- **CG-081** مطلوب — Resilience Controls: نسخ إعدادات الشبكة، خارج النطاق، موصل إدارة بديل، Playbook انقطاع محرك SOC، وحالة Fail-safe للسياسات المؤقتة.

## 16 — الهوية والامتيازات والثقة
- **CG-082** مطلوب — تدقيق AD/Entra: صلاحيات Tier 0/control plane، تغييرات Domain Admins، المستخدمين الخدميين، trust relationships، وسياسات الدخول.
- **CG-083** مطلوب — Windows LAPS posture: وجود سياسة تغيير كلمة مرور مسؤول محلي لكل جهاز، مؤشرات فشل التدوير، وتدقيق عرض أسرار LAPS دون جمع كلمات المرور نفسها.
- **CG-084** مطلوب — حماية AD CS وKerberos: إعدادات شهادات وإصدارها وخدمات AD CS، delegation، مشكلات NTLM القديمة، وتسجيل تغيرات التوثيق حسب صلاحية الوصول.
- **CG-085** مطلوب — Privileged Access Management: JIT/PIM، أجهزة إدارة محمية PAW، جلسات إدارية مؤقتة، مراجعة وتفويض الوصول العالي الحساسية.
- **CG-086** مطلوب — SaaS/OAuth/Service Accounts Inventory: تعيين مالك كل تطبيق وهوية خدمية ومفاتيحها وصلاحياتها ومواعيد تدويرها وأعمالها.
- **CG-087** مطلوب — Identity Attack Correlation: ربط تسجيل الدخول، MFA reset، إنشاء رموز وتغيّر دور Administrator، ثم تغييرات الملفات أو الموارد أو التنقل داخل الشبكة.
- **CG-088** مطلوب — Help Desk Abuse Controls: موافقة وتدقيق في إعادة ضبط الحسابات أو MFA، التحقق من هوية صاحب الطلب وتسجيل الترخيص المؤقت ومتابعته.

## 17 — حماية الأجهزة والبرمجيات الخبيثة
- **CG-089** مطلوب — Process Causality: شجرة عمليات وأوامر تنفيذ وتغييرات الخدمات والمهام المجدولة والاتصالات؛ مع إخفاء البيانات الشخصية الحساسة وتحديد الثقة.
- **CG-090** مطلوب — Defense Tamper Detection: تعطيل AV/EDR/Firewall، حذف Logs، توقف Agent، تغيير الوقت أو السياسات، التفريق بين عطل ونشاط متعمد.
- **CG-091** مطلوب — Anti-Ransomware Posture: Controlled Folder Access/ASR عند التوفر، سلوك تعديل الملفات غير المعتاد، سلامة النسخ، وحماية مخازن التعافي.
- **CG-092** بحث — فحص ملفات مشبوهة بقواعد YARA/Hashes وسمعة توقيع/ناشر البرمجيات، وعزل الملف مع حماية سلسلة الأدلة؛ لا تنفيذ ملفات مشبوهة على مضيف الإنتاج.
- **CG-093** بحث — Sandboxing/Detonation معزول وتحليل سلوكي للبرمجيات في مختبر منفصل، ضوابط تفويض وحظر الاتصال بالإنتاج، وعدم تفعيله تلقائيًا.
- **CG-094** مطلوب — Linux Security via auditd/journald/eBPF/Falco حيث يسمح Kernel والدعم، بالإضافة إلى مراقبة صلاحيات sudo وتغييرات cron/systemd.
- **CG-095** بحث — macOS وiOS/Android وBYOD: إشارة التغطية عن طريق MDM/MAM/EDR مع حصر الإمكانات التي توفرها المنصة وخصوصية المستخدم.

## 18 — الشبكات والتقنيات التشغيلية الحساسة
- **CG-096** مطلوب — Network Posture يشمل IPv4 وIPv6 وWi-Fi وDNS/DHCP وVPN وVLAN وTrunks وACL وNAT وBGP/OSPF posture عند الحاجة والمصرح به، مع عدم افتراض إمكان قراءة كل تكوين.
- **CG-097** مطلوب — Firewall Review: كشف open-any/any-any وshadowed/overlapping rules والفرق بين ingress/egress وeast-west، مع عرض الأثر قبل التعديل.
- **CG-098** مطلوب — Zero Trust Segmentation وNAC posture: التحقق من أصالة الجهاز والمستخدم، ووجود سياسة واضحة للأجهزة الجديدة والضيوف والأجهزة غير المُدارة.
- **CG-099** مطلوب — Network Threat Correlation: DNS وTLS metadata وHTTP proxy وFlow Logs وNetwork IDS، مع شرح حدود التشفير والمراقبة واحترام الخصوصية.
- **CG-100** مطلوب — OT/ICS Safety Mode: قراءة سلبية أولًا، حظر المسح النشط والتحكم الافتراضي في PLC/SCADA/BMS/الأجهزة الحيوية، واجهة موافقة سلامة منفصلة، إرشادات NIST SP 800-82.
- **CG-101** مطلوب — Physical/Network Relationship Verification: التحقق IP→MAC→Switch Port→VLAN→User→Asset قبل أي عزل؛ تجنب Trunk/Uplink وVirtualization Hosts المشتركة.
- **CG-102** مطلوب — Management Plane Protection: رصد وتقييد SSH/RDP/WinRM وSNMP وسياسات VPN، وفرض بروتوكولات آمنة، مع تنبيه استخدام وصول إداري خارج الإجراء المعتمد.

## 19 — السحابة، الحاويات، التطبيقات وسلسلة التوريد
- **CG-103** مطلوب — OCSF Normalization Layer للأحداث متعددة الشركات، مع تتبع Schema Version ومصدر الحدث والحقول المفقودة وفقد المعنى عند التحويل.
- **CG-104** مطلوب — Cloud Detection Coverage: مطابقة وصول IAM ومصادر CloudTrail/GuardDuty وAzure Entra/Defender وGCP Audit/SCC مع سلوك الهوية والموارد والتخزين والمفاتيح.
- **CG-105** مطلوب — Kubernetes/Container Security: K8s audit events وRBAC وAdmission وruntime events، مع Falco وTrivy كمصادر مرشحة، ودعم EKS/AKS/GKE لاحقًا.
- **CG-106** مطلوب — Software Supply Chain: SBOM وDependency Vulnerabilities وImage Signing وArtifact Provenance وCI/CD Secrets، مع فحص تحديثات البرامج ومصداقية المصدر.
- **CG-107** مطلوب — API & Web Security: WAF events، اكتشاف ضعف التوثيق/API Keys وCORS وRate Limits، واختبارات مصرح بها ومعزولة لتكوين التطبيقات.
- **CG-108** بحث — Email Security & Phishing: إشارات SPF/DKIM/DMARC ومرفقات وروابط مشبوهة ومراقبة تغييرات forwarding rules وفق وصلات البريد المصرح بها.
- **CG-109** بحث — Data Security Posture & DLP: وضع حساسية البيانات ومؤشرات الحركة الكبيرة أو غير المألوفة؛ معالجة خصوصية وقانونية قبل فحص المحتوى.

## 20 — هندسة الكشف والتحقيق القابل للقياس
- **CG-110** مطلوب — ATT&CK + MITRE D3FEND Mapping لكل استخدام: التقنية الهجومية، الحساس، الحدث الدال، التحليلات، الإجراء الدفاعي، اختبار النجاح.
- **CG-111** مطلوب — Detection-as-Code: قواعد موقعة ومراجعة مع اختبار وحدة/جودة، Environment Tuning، تحليل false positives، وإرجاع نسخة عند خطأ تحديث.
- **CG-112** مطلوب — Threat Intelligence Quality: مصدر وتاريخ وتقييم ثقة وتاريخ انتهاء IOC وحقوق إعادة التوزيع؛ عدم الحظر الآلي لمجرد وجود Indicator غير موثوق.
- **CG-113** مطلوب — Multi-Signal Correlation: ربط endpoint + identity + network + cloud، وتقليل الضوضاء عبر deduplication وتخصيص سياق الأصل دون إسكات الإنذارات المهمة.
- **CG-114** مطلوب — Evidence Integrity & Chain of Custody: تجميع الدليل الأصلي والتوقيت ومصدره وhash والتغييرات والجهة التي اطلعت عليه مع حماية السجلات.
- **CG-115** مطلوب — Detection Validation Lab: تشغيل أنماط اختبار دفاعية آمنة ومصرح بها، وإعادة تشغيل أحداث مختبرية مخزنة ومقارنة expected vs observed alerts.
- **CG-116** مطلوب — Hunt Workbench: استعلامات زمنية عن الحسابات والعمليات والاتصالات والتنقل والتغيرات، مع حفظ الاستعلامات والملاحظات والتقارير.

## 21 — الاستجابة الآمنة والذكاء الاصطناعي
- **CG-117** مطلوب — Response Preflight: تحديد الهدف المتعدد (IP/MAC/Hostname/CloudID) والتأثير والتراخيص وحالة القناة الإدارية والتبعيات قبل أي إجراء.
- **CG-118** مطلوب — Control Outcome Verification: إثبات نجاح Block/Isolate/Stop Service/Shutdown ومدة تطبيقه؛ إظهار الخطأ أو فشل الإلغاء دون تمويه.
- **CG-119** مطلوب — Safety Tiers: قراءة فقط/استجابة منخفضة التأثير/تغيير حساس/إجراء مدمر؛ مع موافقات متفاوتة وتأكيد منفصل وأوقات تغيير.
- **CG-120** مطلوب — Cross-Provider Playbooks: تسلسل تنسيق Cisco/Huawei/Windows/AWS/Azure حسب القدرة وليس نص أوامر عام؛ Idempotency وRetry وRollback عند الفشل.
- **CG-121** مطلوب — AI Prompt-Injection Defense: اعتبار السجلات ورسائل البريد والتذاكر ونتائج البحث بيانات غير موثوقة؛ عزل تعليماتها عن سياسات تنفيذ النظام وإخضاع أي إجراء للتحقق.
- **CG-122** مطلوب — AI Evidence-RAG: ربط الأجوبة بنسخ مؤرخة من المصادر والدليل الفعلي، وإخفاء الأسرار وPII بحسب الدور وإبراز عدم اليقين.
- **CG-123** مطلوب — AI Evaluation & Guardrails: اختبارات الهلوسة والدقة وتجاوز الصلاحيات والكلفة والتأثير؛ AI لا يمتلك حسابات تعديل حر ولا يستطيع اختيار أمر مدمر من تلقاء نفسه.

## 22 — الحوكمة السعودية ومنتج مؤسسي قابل للنمو
- **CG-124** مطلوب — Compliance Evidence Mapping لهيئة الأمن السيبراني السعودية NCA ECC 2-2024 وCCC 2:2024، وما ينطبق من OTCC/CSCC/DCC، مع تحديد نطاق الانطباق وليس ادعاء امتثال تلقائي.
- **CG-125** بحث — عند تحويل المشروع إلى خدمة SOC/MSSP في السعودية، مراجعة National Policy for Managed Security Operations Centers وتراخيص الخدمة والالتزامات التنظيمية السارية قبل التسويق.
- **CG-126** مطلوب — Multi-Tenant Isolation & Data Residency: تحديد مكان معالجة/تخزين البيانات والأدلة ومفاتيح التشفير، سياسات الاحتفاظ، حق الحذف والتصدير، وحاجز منع اختلاط العملاء.
- **CG-127** مطلوب — Operational SOC Workflow: التناوب والمناوبات، إدارة التذاكر والتصعيد، سياسات الإغلاق، تمارين tabletop، تقارير Lessons Learned، وتحويل نتائج الحوادث لقواعد كشف محسنة.
- **CG-128** مطلوب — Product Self-Defense: حماية حسابات الإدارة وAPI وSecrets وUpdate Signatures وSupply Chain والنسخ الاحتياطية للمنصة؛ منصة الأمن نفسها هدف حساس.
- **CG-129** مطلوب — Budget/Capacity Model: معدل الأحداث EPS/GB-day، التخزين والاحتفاظ، تكلفة السحابات وAPI، متطلبات GPU/CPU/RAM، قياس الضغط ورفع قابلية التوسع دون التضحية بموثوقية الكشف.
- **CG-130** مطلوب — Research Evidence Register: لكل فكرة مصدر رسمي/مستودع، تاريخ، ملخص دقيق، قابلية التطبيق، تبعيات، مخاطر، أولوية، حالة التحقق، وقرار القبول أو التأجيل؛ معيار توقف البحث هو تضاؤل الأفكار الجديدة ذات القيمة بعد تغطية نطاقات محددة، لا الادعاء باستحالة العثور على أفكار جديدة.

## ي. سيناريوهات أمنية معيارية للمراجعة — ليست وقائع اختراق مُثبتة

| السيناريو | الإشارات الدفاعية | إجراءات الوقاية/الاحتواء | المتطلبات |
|---|---|---|---|
| LEGACY-01: Windows Server 2012 R2 قديم في إنتاج | EOL status + listening ports + backup + segmentation + EDR/Logs availability | تحديث أو ترحيل؛ تعويضات مؤقتة وعزل مقيد؛ اختبار استعادة | CG-075–081 |
| ID-01: تغيير صلاحية إداري واسع | AD/Entra group change + sign-ins + MFA/PIM events | تحقق من طلب تغيير معتمد؛ سحب صلاحية مشبوهة عبر إجراء مخوّل | CG-082–088 |
| NET-01: خدمة جديدة مكشوفة على Firewall | rule diff + asset owner + connection logs + dependency | مراجعة أثر المنع، تغيير محدود/مؤقت، تحقق وتراجع | CG-096–102, CG-117 |
| END-01: تعطيل الحماية على مضيف | AV service events + Sysmon/process logs + agent heartbeat | تحقق من التلاعب مقابل عطل الخدمة؛ عزل إذا ثبتت الخطورة وبإذن | CG-089–095 |
| CLOUD-01: حساب سحابي يستعرض موارد كثيرة فجأة | CloudTrail/Entra/Audit + identity context + resource listing | تحقق من automation مشروعة؛ صلاحيات مؤقتة/تعطيل اعتماد مشبوه بموافقة | CG-104, CG-113 |
| OT-01: وحدة تحكم صناعية فقدت الاتصال | passive health signals + process owner + safety status | التنبيه وإبلاغ فريق OT؛ لا فحص نشط ولا فصل جهاز دون مراجعة سلامة | CG-100, CG-119 |
| AI-01: سجل أمني يحتوي تعليمات زائفة للمساعد | untrusted text + policy engine decisions + tool-call audit | منع تحول النص إلى أوامر وتقييد إجراء AI مع فصل سياق المصادر | CG-121–123 |

## ك. مصفوفة المصادر التي راجعتها في الجولة v0.4

| الموضوع | المصدر الرسمي أو المستودع | رابط |
|---|---|---|
| NIST CSF 2.0 | NIST | https://www.nist.gov/cyberframework/faqs |
| كشف أنماط المهاجم | MITRE ATT&CK Detection Strategies | https://attack.mitre.org/detectionstrategies/ |
| تقنيات الدفاع | MITRE D3FEND | https://d3fend.mitre.org/faq/ |
| ثغرات مستغلة بالفعل | CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| نهاية دعم Windows Server 2012/R2 | Microsoft Lifecycle | https://learn.microsoft.com/en-us/windows/release-health/status-windows-8.1-and-windows-server-2012-r2 |
| دعم Windows Server في Defender for Endpoint | Microsoft Learn | https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/onboard-windows-server |
| حماية الحساب المحلي LAPS | Microsoft Learn | https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview |
| نموذج امتيازات المؤسسة | Microsoft Learn | https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model |
| كشف تهديدات الهوية | Microsoft Defender for Identity | https://learn.microsoft.com/en-us/defender-for-identity/quick-installation-guide |
| مراقبة تشغيل Linux والحاويات | Falco | https://github.com/falcosecurity/falco |
| فحص SBOM | Trivy | https://github.com/aquasecurity/trivy/blob/main/docs/guide/target/sbom.md |
| معيار تطبيع السجلات | OCSF | https://ocsf.io/ |
| أمن الأنظمة الصناعية | NIST OT Security | https://csrc.nist.gov/pubs/sp/800/82/r3/final |
| أنظمة OT / مستندات جديدة | NIST OT Publications | https://csrc.nist.gov/projects/operational-technology-security/publications |
| ضوابط السعودية الأساسية | NCA ECC | https://nca.gov.sa/en/regulatory-documents/controls-list/ecc/ |
| ضوابط السحابة السعودية | NCA CCC | https://nca.gov.sa/en/regulatory-documents/controls-list/ccc/ |
| أدلة التطبيق السعودية | NCA Guides | https://nca.gov.sa/en/regulatory-documents/guidelines-list/igcc/ |
| سياسة SOC المدارة السعودية | NCA MSOC | https://nca.gov.sa/en/regulatory-documents/frameworks-and-standard-list/npmcoc/ |
| حماية تطبيقات LLM | OWASP LLM Top 10 | https://owasp.org/projects/top-10-for-large-language-model-applications |
| الحماية من تشفير الملفات | Microsoft Controlled Folder Access | https://learn.microsoft.com/en-us/defender-endpoint/enable-controlled-folders |

## ل. قائمة الدراسات غير المكتملة قبل اتخاذ قرار التطوير

1. تصميم معمارية بيانات وتخزين سجلات على مقاييس: 100، 2,000، 20,000 جهاز (EPS، تكاليف، تخزين، احتفاظ).
2. اختبار قانوني/ترخيصي لكل أداة مفتوحة المصدر ولكل خدمة سحابية، خاصة عند التوزيع التجاري.
3. نموذج تهديد مستقل للمنصة ومفاتيح الإدارة وعزل المستأجرين وتحديثات القواعد.
4. لوحة قياس تغطية MITRE مع قواعد مثبتة عمليًا ومعدل إنذارات كاذبة لكل بيئة.
5. دراسة حوادث فعلية إضافية بمصادر أولية ووقت الحادث والتكتيك والدليل، وليس مجرد إعادة سرد الأخبار.
6. دراسة حدود التحكم لكل مزود/طراز/نسخة وترخيص، أولًا Read-Only، ثم وضع مختبر مصرح به لإجراءات التغيير.
7. دراسة قرار Local/Hybrid/Cloud بحسب متطلبات سيادة البيانات، ووقت الانقطاع، والكلفة، وأداء نماذج AI الصغيرة.
8. إجراء مراجعة أمنية مستقلة لكل فعل يغيّر خدمة أو منفذًا أو جهازًا أو حسابًا، مع التراجع والحفاظ على اتصال الإدارة.
9. تغطية Web/SaaS/Email/Databases/Endpoints/Network/OT/Containers/Cloud/AI بنماذج Detection Use Cases وتكاليف مجدية.
10. تأجيل البرومبت النهائي والبروتوتايب حتى الطلب الصريح من المستخدم.

### ملاحظة زمنية واستمرارية

تمت هذه الجولة في جلسة 2026-11-09. محاولة إنشاء بحث آلي يومي جديد **لم تنجح** لأن الحساب لديه 5 مهام نشطة وهو الحد المتاح. لا توجد مهمة بحث CyberGuard فعالة حاليًا؛ لن تتغير هذه النسخة تلقائيًا في الخلفية. لا توقف أو تعدل أي مهمة قائمة دون موافقة المستخدم. يستكمل السجل عند عودة المستخدم أو بعد تهيئة مهمة جديدة بتفويضه.

---

# ن. الجولة البحثية الخامسة — v0.5 بتاريخ 2026-11-10

**امتداد تراكمي:** لا تحل هذه الجولة محل النسخة v0.4؛ المتطلبات CG-001..CG-130 باقية. أضيف هنا CG-131..CG-180 فقط. **لا كود ولا فحص حقيقي ولا نشر.**  
**منهج التحقق:** دراسة وثائق رسمية ومشاريع مفتوحة المصدر؛ لا يُعد ذكر أداة إثباتًا لعملها في جهاز أو ترخيص محدد. المصادر أدناه تدعم الاتجاه الفني، ولا تعني تنفيذًا أو تكاملًا مكتملًا.

## 23 — أمان تغييرات الشبكة والأصول والشبكات الكبرى (CG-131–CG-138)
- **CG-131** مطلوب — **Network Change Safety / Batfish Research:** تحليل Config Snapshots قبل ACL/Firewall/Route Change، والتحقق من Reachability قبل/بعد وتغيّر المسارات والاعتمادات. مصدر مرشح: Batfish؛ تُستبعد النماذج/الميزات غير المدعومة من القرار، ولا نتعامل مع التحليل كضمان أداء الشبكة الفعلي.
- **CG-132** مطلوب — **Intended vs Observed State:** التمييز بين جرد NetBox/مصدر حقيقة معتمد وبين المكتشف فعليًا، مع مراجعة تضارب IP/VLAN/Interface والمالك وتاريخ تغيّر السجل قبل تحديث مصدر الحقيقة.
- **CG-133** مطلوب — **Network Change Impact Graph:** ربط كل إجراء بتبعيات DNS/AD/DHCP/Storage/VoIP/Hypervisor/Management وShared Uplink، وعرض خدمة المستخدم المتأثرة قبل تنفيذ السياسة، مع منع تلقائي لأي تغيير لا نعرف أثره على Core أو مسار الإدارة.
- **CG-134** مطلوب — **Layer-2 Security Posture:** مراقبة ما تدعمه الأجهزة من DHCP Snooping وDynamic ARP Inspection وIP Source Guard و802.1X؛ تنبيه Rogue DHCP وMAC Move وARP Conflict دون افتراض إثبات هجوم من إشارة واحدة.
- **CG-135** بحث — **Routing Security / RPKI & ROA:** للأطراف التي تشغّل BGP/AS: مراقبة Route Origin Validation، تغيّر Prefix/Route Announcement وPrefix Filters وأثر Hijack/Leak؛ لا تنطبق على كل LAN صغيرة؛ مرجع NIST SP 800-189 Rev.1 لا يزال Draft عند الاستشهاد به.
- **CG-136** مطلوب — **Wireless & Guest Network Assurance:** جرد SSID وWPA2/3-Enterprise و802.1X/RADIUS وGuest Isolation وRogue AP signals عن طريق متحكمات Wi-Fi المصرح بها؛ قيود تغطية RF واضحة، دون هجوم لاسلكي نشط.
- **CG-137** مطلوب — **Infrastructure Management-Plane Audit:** مقارنة NTP/AAA/TACACS+/RADIUS/SSH/SNMPv3/Syslog/ACL للوصول الإداري وإعدادات النسخ الاحتياطي مع baseline لكل Vendor/IOS version.
- **CG-138** مطلوب — **Vendor Adapter Validation Registry:** لكل Cisco/Huawei/Juniper/Fortinet وغيرها: طراز+Firmware+API+ترخيص+Read/Write/Undo+اختبار في المختبر+تاريخ آخر تحقق؛ الادعاء بالدعم يتم على مستوى الوظيفة لا اسم الشركة فقط.

## 24 — نماذج الهجمات وتقييم قابلية كشفها (CG-139–CG-145)
- **CG-139** مطلوب — **SharePoint ToolShell Case (2025):** نموذج متعدد الإشارات يربط خادم SharePoint exposed + CVE + IIS unusual worker process + تغيّر حماية + تغيّر scheduled tasks/GPO؛ لا يساوي توقيع ملف واحد إثباتًا قاطعًا.
- **CG-140** مطلوب — **Telecom / Salt Typhoon Defensive Study:** دراسة دليل NSA/CISA/FBI حول الرؤية والتحصين لأجهزة الاتصالات، مع مراقبة التكوين والوصول الإداري ونقل السجلات خارج أجهزة الشبكة؛ لا تُفترض القدرة على فحص المشغلين العموميين أو معدات الاتصالات بدون تصريح.
- **CG-141** مطلوب — **Remote-Access Session Correlation:** التمييز بين Install/Start/Connect/Authenticated Session/External Peer اعتمادًا على سجلات RDP/AnyDesk/VPN/SSH؛ لا تسمية حادث اختراق بلا إثبات هوية/سلوك.
- **CG-142** مطلوب — **Identity-to-Endpoint Kill Chain:** تجميع الحساب/Token/OAuth/دخول غير معتاد/عملية على Endpoint/اتصال شبكة/تغيير سياسة في رسم حادث واحد مع تفادي التسلسل السببي الخاطئ.
- **CG-143** مطلوب — **Hypothesis-based Threat Hunting:** لكل فرضية دخول/استمرار/تنقل/تهريب بيانات: البيانات المطلوبة، استعلام آمن، حالات تجاهل مشروعة، مدة الاحتفاظ، نتيجة مثبتة أو «الرؤية غير كافية».
- **CG-144** مطلوب — **Past-Compromise Check After Patching:** عند اكتشاف CVE مستغلة ومكشوفة سابقًا لا يكفي تأكيد تثبيت الرقعة؛ يُنشأ تحقيق للأدلة التاريخية والعمليات والحسابات قبل اعتماد الإغلاق.
- **CG-145** مطلوب — **Attack Technique Coverage by Evidence:** مصفوفة تغطية ATT&CK لا تحتسب قاعدة لمجرد وجودها؛ لا تُعد التقنية مغطاة إلا إذا توفرت Telemetry ونجح اختبار detection وتوثقت قيود الأداء.

## 25 — إدارة الهويات والصلاحيات وSaaS (CG-146–CG-152)
- **CG-146** مطلوب — **Microsoft 365 Baseline Assessment:** دراسة CISA SCuBA/ScubaGear لفحص إعدادات M365 الأمنية، وإظهار الانحرافات والنسخة المرجعية، مع عمل Read-only ما أمكن وصلاحيات واجهات محدودة.
- **CG-147** بحث — **Google Workspace Security Baselines:** مقارنة Google Workspace مع خطوط SCuBA المدعومة وفحص MFA والمشاركات وقواعد البريد والتطبيقات الخارجية حسب APIs والتراخيص الفعلية.
- **CG-148** مطلوب — **AWS IAM Access Analyzer Integration:** اكتشاف External/Internal/Unused Access وتفسير حدود Zone of Trust، وتوضيح أن بعض أنواع التحليل مدفوعة وليست نشطة دون تهيئة.
- **CG-149** مطلوب — **Entra Workload Identity Security:** رصد Service Principals والتطبيقات والمفاتيح وSign-in deviations وتغير Consent/Permissions؛ التنبيه لنطاقات Conditional Access التي لا تشمل Managed Identities أو Multitenant Apps تلقائيًا.
- **CG-150** مطلوب — **Phishing-Resistant Authentication Posture:** تمييز MFA عام عن Passkeys/FIDO2/WebAuthn والاعتمادات الصلبة، مع استثناءات Legacy Protocols ونطاق التطبيقات التي لا تدعمها.
- **CG-151** بحث — **Service-to-Service Zero Trust:** خدمات API وMicroservices عبر mTLS وWorkload Identity وSPIFFE/Service Mesh في البيئات المناسبة، وفق NIST SP 800-207A، مع مراجعة العمر والسرّيات والتجديد.
- **CG-152** مطلوب — **Permission Reduction Recommendation:** محرك يقترح تقليل صلاحيات زائدة بعد تحليل usage ومالك الحساب وطلب تغيير، مع تقرير Dry Run وعدم سحبها تلقائيًا لمجرد عدم الاستخدام خلال نافذة قصيرة.

## 26 — السحابة وتطبيقات الويب والنسخ الاحتياطية (CG-153–CG-160)
- **CG-153** مطلوب — **Cloud Attack Path Evidence Graph:** ربط Exposure + Misconfiguration + IAM + Assets + Sensitive Target في مسارات محتملة، مع تمييز المسار الاستدلالي عن validated external reachability؛ مقارنة تصور Microsoft Defender for Cloud.
- **CG-154** مطلوب — **GCP Attack Exposure Posture:** استيعاب Security Command Center Attack Exposure Score وToxic Combinations إذا كانت الخدمة/الطبقة متاحة، مع تجنب اختراع درجة مشابهة إذا غابت إشاراتها.
- **CG-155** مطلوب — **AWS Multi-account and Multi-region Completeness:** اكتشاف الحسابات والمناطق غير المفعلة، وبيان أن Security Hub CSPM لا يجمع أحداثًا تاريخية قبل التفعيل ولا يلغي الحاجة لتفعيل وتكوين الخدمات في كل منطقة.
- **CG-156** مطلوب — **Temporary Azure VM JIT Access:** دراسة تكامل Microsoft Defender for Cloud JIT للتحكم في المصدر والمنفذ والوقت وعمليات التدقيق في VM المستهدف، مع إظهار متطلبات Defender for Servers Plan 2 والأذونات.
- **CG-157** مطلوب — **Resilient Immutable Backups:** مراقبة حالة Backup Vault Lock، وتصنيف Governance/Compliance والاحتفاظ واحتمال ارتفاع التكلفة وصعوبة التراجع، واختبار الاستعادة قبل الاعتماد على الاستراتيجية.
- **CG-158** مطلوب — **Signed Artifact Admission:** توثيق سلامة نسخ تطبيق CyberGuard وAgent وقواعد الكشف/الصور بالحزم الموقعة؛ دراسة Sigstore Cosign وKubernetes Policy Controller حيث مناسب.
- **CG-159** بحث — **SaaS Shadow-IT and App-to-App Access:** جرد تكاملات التطبيقات الخارجية والمشاركة العامة وسياسات الموافقات ونطاقات OAuth، مع عدم فحص محتوى موظفين دون سياسة خصوصية وتفويض.
- **CG-160** مطلوب — **Cloud Cost & API Permissions Preview:** قبل تفعيل CloudTrail/VPC Flows/SCC وغيرها تُعرض توقعات Data Volume، رسوم API/Storage/Egress، الصلاحيات والمناطق، وآلية إيقاف الجمع دون تعريض سجل الحوادث للفقد.

## 27 — هندسة الكشف وموثوقية تدفق الأحداث (CG-161–CG-169)
- **CG-161** مطلوب — **Stateful Correlation Rules:** أنماط اكتشاف متعددة الأحداث وTime Windows وThresholds وAllow-lists مع التقييم وفق عينات سليمة وخبيثة؛ مرجع مفيد Google SecOps YARA-L 2.0، وليس شرط دمجه.
- **CG-162** مطلوب — **Event Data Contract:** لكل موصل Data Schema Version/Time Zone/Clock Source/Event Source/Raw Event Hash/Parser Quality/Field Completeness؛ عرض نسبة الفشل في التحليل.
- **CG-163** مطلوب — **Tamper-evident Collection:** عند انقطاع/تعطيل Agent أو حذف Logs أو تغيّر ساعة الجهاز أو فشل النقل، يُنشأ حدث فقد رؤية مستقل ويربط بقواعد الكشف، دون اعتبار انقطاع الاتصال اختراقًا مؤكدًا.
- **CG-164** بحث — **High-Signal Deception:** Honeytokens/Decoy Accounts/Decoy Files بموافقة واضحة وبدون بيانات اعتماد حقيقية، مع عزل آمن؛ مستند إلى MITRE D3FEND Deceive.
- **CG-165** مطلوب — **Detection Content Lifecycle:** توقيع القواعد، بيئة Test/Canary، backtest على سجلات مختبرية، قياس False Positive قبل النشر، وتراجع تلقائي إلى آخر قاعدة سليمة إذا ارتفع الضجيج.
- **CG-166** مطلوب — **Incident Confidence Separation:** فصل (Observed Event) و(Suspicious Indicator) و(Verified Security Incident) و(Confirmed Compromise)؛ AI لا يحوّل الشبهة إلى خبر يقيني.
- **CG-167** مطلوب — **Telemetry Minimization & Privacy:** قواعد حذف بيانات حساسة قبل الفهرسة/الإرسال إلى AI، وتشفير الحقول الحساسة وإدارة retention حسب نوع المصدر والجهة والالتزام القانوني.
- **CG-168** مطلوب — **Event Volume and Detection Reliability:** إظهار EPS المدخل/المُعالج/المرفوض/المتأخر، Queue Lag، وأخطاء Parser، وتأثير تغيّر معدل البيانات على زمن الكشف.
- **CG-169** مطلوب — **IOC Feed Change Governance:** تطبيق Diff لمصادر KEV/Threat Intel مع تاريخ مصدر وترخيص وتراجع وموافقة؛ لا يؤدي تغير تغذية خارجية إلى Block جماعي مباشر.

## 28 — إجراءات الحماية الموثوقة والسلامة التشغيلية (CG-170–CG-176)
- **CG-170** مطلوب — **Isolation Connectivity Survival Test:** قبل عزل مضيف خلف Full Tunnel VPN/Proxy أو Hypervisor Host يتم فحص بقاء قناة إدارة أو تحديد طريقة استعادة خارج النطاق؛ لا تعرض النتيجة كنجاح قبل إثبات العزل الفعلي.
- **CG-171** مطلوب — **Blast Radius Calculator:** تحذير محدد عند Stop Service / Switch Port Shutdown / Disable User / Security Group Change وفق العلاقات المرئية؛ لو لم تتوفر العلاقات نُصنّف الأثر Unknown ونطلب مراجعة بشرية.
- **CG-172** مطلوب — **Just-in-Time Rule Lease Engine:** Policy lease به Scope+TTL+Owner+Ticket+Approver+Revocation Deadline، ينتهي على طبقة التنفيذ وليس ساعة الواجهة، مع Reconciliation عقب انقطاع المحرك.
- **CG-173** مطلوب — **Evidence-backed Action Ledger:** ربط كل أمر بمن أطلقه ولماذا، والسجل/التذكرة والدليل والتفويض والـPreflight ونتيجة API وتحقيق Outcome والتراجع، مع عدم وضع كلمات مرور في السجل.
- **CG-174** مطلوب — **No-Single-Action Critical Shutdown:** حماية DC وCore/Uplink وBackup Controller وESXi/Hyper-V Hosts ومنصات الأمن من الأوامر المنفردة؛ إجراءات مركبة بموافقتين وMaintenance Window/Out-of-band Recovery.
- **CG-175** مطلوب — **Adapter Idempotency & Conflict Detection:** منع تكرار الإجراء أو تعارض سياسات من عدة جهات؛ تسجيل Change-ID وProvider Request-ID وأسلوب الاستعادة للموارد المشاركة.
- **CG-176** بحث — **Network Policy Simulation Coverage:** نُحدِّد مع كل محاكاة نطاق البروتوكولات والموردين المدعومين ومخرجات reachability، ولا نطبّق نتائج محاكاة غير مؤهلة على شبكة إنتاج حساسة.

## 29 — المعمارية والجاهزية المستقبلية (CG-177–CG-180)
- **CG-177** مطلوب — **Least-Privilege Connector Grants:** منح Read-only كافتراضي وSeparate Write Role+Approval لكل Tenant/Cloud Account/Site مع جرد Token، Expiry وRevocation وتحقق من التفويض على مستوى Target ID.
- **CG-178** مطلوب — **CIS Benchmark Evidence Mapping:** ربط Baseline كل نظام/إصدار من Windows Server وCisco IOS XE وM365 وFirewall بمعرف مصدر ودليل/تاريخ فحص، والتنبيه أن ملفات PDF المجانية قد تكون مقيدة للاستخدام غير التجاري.
- **CG-179** بحث — **Crypto-Agility Inventory:** جرد TLS/SSH/VPN والاعتماد على RSA/ECC والخوارزميات القديمة والاستعداد لترحيل Post-Quantum عند نضج المنتجات؛ لا فرض خوارزمية جديدة عشوائيًا على جهاز لا يدعمها؛ مرجع NIST FIPS 203/204/205.
- **CG-180** مطلوب — **Evidence-to-Requirement Traceability:** لكل CG نربط: السؤال الأمني، الأدلة والمصدر وتاريخ مراجعته، Connector/API، حالة التحقق، الاختبار، تكلفة التشغيل، الأولوية، القيود، مع Dashboard يبين «مدروس/متحقق/مُؤجل/غير مدعوم» قبل اعتماد أي برومبت تنفيذ.

## س. دراسات حالات جديدة وربطها بالمنتج

| الحالة | ما ثبت في مصدر أصلي | سيناريو اختبار دفاعي مستقبلي (ليس منفذًا) | المتطلبات الجديدة |
|---|---|---|---|
| CASE-08 — SharePoint ToolShell (2025) | CISA أصدرت تحذيرًا وتحليل Malware حول SharePoint، ومايكروسوفت وثّقت هجمات تضمنت web shell وتغييرات حماية وGPO وانتشار فدية | ربط سيرفر ويب exposed → تغيير عمليات/مهام → تعديل حماية → GPO ثم تدقيق إصلاح + تحقيق تاريخي | CG-139, CG-144, CG-145 |
| CASE-09 — Salt Typhoon Telecommunications | FBI/NSA وحلفاؤهما نشروا تحذيرات وإرشادات بشأن اختراق مقدمي الاتصالات وضرورة تقوية الرؤية والتحصين | مقارنة إعدادات راوتر/Firewall بـBaseline وتدقيق SSH والنسخ الاحتياطية والسجلات ومراقبة تغيرات ACL والإدارة | CG-135, CG-137, CG-140 |
| CASE-10 — Risky Workload Identity | Microsoft توثق اكتشاف سلوك Service Principal غير معتاد وConditional Access متاح بشروط ترخيص ونطاق | تغيير غير متوقع في تطبيق Service Principal ثم وصول غير مألوف لبيانات سحابية؛ عرض مصدر الأدلة والتصريح المطلوب قبل الاستجابة | CG-149, CG-152 |
| CASE-11 — Misconfigured Cloud Path | Microsoft Defender for Cloud يربط exposure وidentity/network permissions في Graph والمسارات المحتملة | شرح مسار تعرض افتراضي بين أصل مكشوف ومخزن حساس وعرض أولوية إصلاح طرف واحد قبل انتشار الخطر | CG-153–155 |

## ع. النتائج التقنية العملية ذات الأولوية في هذه الجولة

1. **ابدأ مستقبلاً بتحليل تغيير الشبكة Offline قبل تفعيل زر الإغلاق:** Batfish مع Source of Truth يمكن أن يبيّنا اعتمادًا حرِجًا ويقللا من خطر قطع الخدمة، لكن لا يغنيان عن اختبار التنفيذ الحقيقي.
2. **الهوية غير البشرية أصبحت نطاقًا أوليًا:** حسابات التطبيقات/Service Principals وOAuth وCloud IAM ليست مجرد تفاصيل إضافية؛ يمكن أن تكون أساس حادث كبير حتى مع وجود MFA لدى المستخدمين.
3. **المراجعة الأمنية تأتي بعد التصحيح أيضًا:** إذا استُغلت ثغرة قبل التحديث، فالرقعة لا تزيل تلقائيًا وسائل الاستمرار أو الاعتمادات التي سرقت؛ نحتاج Historical Compromise Assessment.
4. **بطاقة «نجاح العزل» يجب أن تكون مبنية على قياس:** جهاز خلف Full Tunnel VPN قد يفقد اتصال الإدارة؛ والـHypervisor قد يحمل أجهزة أخرى، لذا قد تكون النتيجة «العزل مطلوب لكنه غير آمن الآن».
5. **الأدوات المفتوحة المصدر وسيلة لتقليل تكلفة بناء المحركات، وليست سببًا لدمجها جميعًا:** نختار أصغر مجموعة ذات تغطية قابلة للاختبار.

## ف. جدول مراجع جديدة — المصدر وتاريخ التدقيق 2026-11-10

| الرقم | المرجع | مصدر مباشر | الاستفادة | حدود |
|---|---|---|---|---|
| SRC-51 | Batfish | https://github.com/batfish/batfish | تحليل Reachability وACL/Firewall قبل/بعد | لا يغطي كل تفاصيل Vendors/Features؛ يحتاج config snapshots |
| SRC-52 | NetBox | https://github.com/netbox-community/netbox | Source of Truth/IPAM/DCIM | لا يكتشف الأجهزة ذاتيًا بمجرد تثبيته |
| SRC-53 | CISA SharePoint Malware Report | https://content.govdelivery.com/accounts/USDHSCISA/bulletins/3ecbd7d | قصة اختراق ونقاط كشف | الحالة منشورة 2025، لا تخص شبكتنا |
| SRC-54 | Microsoft SharePoint exploitation | https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/ | ربط IIS/Webshell وEDR وGPO | لا نحول المؤشرات القديمة لقاعدة حظر أعمى |
| SRC-55 | NSA Enhanced Visibility Guide | https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/ | تحصين الشبكة وحفظ السجلات | توصيات قطاع اتصالات؛ تُكيّف حسب البيئة |
| SRC-56 | CISA SCuBA/ScubaGear | https://github.com/cisagov/ScubaGear | تقييم M365 Baselines | أدوات/صلاحيات وربما تغيّر النطاق |
| SRC-57 | AWS IAM Access Analyzer | https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html | External/Internal/Unused | بعض التحليلات مدفوعة وقد تتطلب تفعيلًا منفصلًا |
| SRC-58 | Microsoft Workload Identity Protection | https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/concept-workload-identity-risk | مخاطـر Service Principals | التغطية والترخيص وشروط النطاق مختلفة |
| SRC-59 | NIST Zero Trust for Multi-Cloud | https://csrc.nist.gov/pubs/sp/800/207/A/final | mTLS/Service Identity & microservices | توجيه معماري لا Connector |
| SRC-60 | Microsoft Defender for Cloud Attack Paths | https://learn.microsoft.com/azure/defender-for-cloud/concept-attack-path | Exposure Graph ومخاطر السحابة | يعتمد على الاشتراك ونوع الموارد والتفعيل |
| SRC-61 | GCP Attack Exposure | https://docs.cloud.google.com/security-command-center/docs/attack-exposure-learn | Prioritization | طبقات مدفوعة أو محددة النطاق |
| SRC-62 | Azure VM JIT | https://learn.microsoft.com/en-us/azure/defender-for-cloud/enable-just-in-time-access | فتح مؤقت مقيد لـRDP/SSH | Defender for Servers Plan 2 وأدوار وأصول مدعومة |
| SRC-63 | AWS Backup Vault Lock | https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html | مقاومة الحذف والتغيير | وضع Compliance بالغ الأثر وقد يعجز حتى المالك عن إلغائه بعد grace |
| SRC-64 | Sigstore Policy Controller | https://github.com/sigstore/policy-controller | التحقق من صور التطبيقات | سياسة admission opt-in وتوافق Kubernetes |
| SRC-65 | Google SecOps YARA-L | https://docs.cloud.google.com/chronicle/docs/detection/default-rules | أمثلة قواعد correlation | لغة متخصصة، ليست مجانية تلقائيًا |
| SRC-66 | MITRE D3FEND Decoys | https://d3fend.mitre.org/tactic/d3f%3ADeceive/ | أنماط Deception/Honeytokens | لا تستخدم بيانات اعتماد حقيقية أو إغراء خارجيًا بلا تفويض |
| SRC-67 | Microsoft Defender Device Isolation | https://learn.microsoft.com/defender-endpoint/respond-machine-alerts | قيود عزل endpoints والتحقق | VPN/Proxy/Hypervisor/OS/license concerns |
| SRC-68 | CIS Windows Server Benchmarks | https://www.cisecurity.org/benchmark/microsoft_windows_server | Baseline hardening لأنظمة قديمة وحديثة | حقوق إعادة التوزيع والاستخدام التجاري مختلفة |
| SRC-69 | CIS Cisco Benchmarks | https://www.cisecurity.org/benchmark/cisco | Baseline IOS XE وغيرها | يدقق الطراز والإصدار والترخيص |
| SRC-70 | NIST PQC Guidance | https://pages.nist.gov/nccoe-migration-post-quantum-cryptography/ | Crypto agility | تدريجي، وليس سببًا لتغيير شامل الآن |
| SRC-71 | CISA Known Exploited Vulnerabilities | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | تحديثات الاستغلال وتحديد الأولويات | فيض CVEs يحتاج ربطًا بأصول حقيقية وإصدارات |

## ص. قائمة أسئلة مفتوحة تُحسم قبل البرومبت النهائي

1. أول بيئة اختبار ستكون **Read-only** لتوثيق الأصول والضمانات دون تغييرات على إنتاج.
2. نحدد أين تعمل Batfish وNetBox إن اخترناهما: خدمات منفصلة داخل Linux VM/Server، وليس افتراض أنها تطبيق Windows واحد صغير.
3. نحتاج خطة حدود أداء دقيقة: موقع واحد، ثم 100/2000/20000 جهاز، ومعدل EPS المتوقع، لا التوسع بالاسم فقط.
4. تقيّد عمليات Stop/Disable/Remove Service وPort Shutdown وIsolate Device وShutdown بScope وموافقة وخطة استرداد، مع حماية شبكات الإدارة.
5. نجمع مصفوفة دعم حقيقية لكل Vendor وطراز وإصدار وصلاحيات؛ Huawei تحديدًا يتطلب بحثًا مستقلاً لتغطية واجهاته المحددة.
6. نمنع استخدام أدوات الكشف أو محاكاة الاختراق على شبكات غير مصرّح بها، أو على OT دون تنسيق سلامة منفصل.
7. لا نعلن خلو الشبكة من الاختراق إذا كانت هناك فجوات في السجلات أو توقفت أدوات المراقبة.
8. لا يوجد بحث خلفي جارٍ؛ متابعة هذا الملف تحتاج جلسة جديدة أو مهمة مجدولة متاحة.

**حالة التسليم في نهاية v0.5:** دراسة فقط. بدأت جولة v0.6 من `CG-181` دون استبدال متطلبات النسخ السابقة.


---

# جولة البحث السادسة — الوقاية والدفاع المتعدد الطبقات (v0.6)

**تاريخ الجولة:** 10 نوفمبر 2026 — **الوضع:** بحث نظري ومواصفات متطلبات فقط؛ دون تنفيذ على شبكة أو بناء بروتوتايب.

## نطاق هذه الجولة
التركيز على **Prevent → Contain → Recover → Verify**: تدابير حماية لا مجرد كشف؛ Active Directory، أجهزة Windows، DNS والبريد، Firewall/ZTNA، السحابة، سلسلة التوريد، Ransomware/Backup، OT/ICS، والدفاع عن AI نفسه. تستمر أرقام CG-001..180 كاملة في الأجزاء السابقة.

## 30 — الوقاية الفعلية على الأجهزة ونظام Windows (CG-181–CG-188)
- **CG-181** **[بحث / متطلب مقترح]** — **Windows Endpoint Protection Coverage:** إظهار فاعلية Antivirus/EDR وRealtime Protection وتحديث التواقيع وCloud Protection وFirewall وExploit Protection بناءً على دليل من الجهاز؛ لا يعني وجود التطبيق أن الحماية مفعلة، ولا يعني انقطاع Agent إثبات اختراق. **مرجع:** Microsoft Defender ASR; Sensor health.
- **CG-182** **[بحث / متطلب مقترح]** — **Attack Surface Reduction Rollout:** فحص قواعد ASR لكل جهاز وأسماء الاستثناءات؛ اقتراح نشر Audit أولًا، وقياس أثر الأعمال، ثم Block تدريجيًا على مجموعات تجريبية؛ مع صلاحية تطبيق منفصلة ومراجعة. **مرجع:** Microsoft ASR settings.
- **CG-183** **[بحث / متطلب مقترح]** — **Controlled Folder Access Policy:** إدارة حالة Controlled Folder Access والمجلدات المحمية والتطبيقات المستثناة عبر تكامل إدارة مؤسسي؛ إعادة تقييم الاستثناءات ونتائج Audit قبل Block، ولا يُعتمد بديلاً للنسخ الاحتياطي. **مرجع:** Microsoft Controlled Folder Access.
- **CG-184** **[بحث / متطلب مقترح]** — **EDR Tamper-Resilience Verification:** مراقبة محاولات إيقاف EDR أو حذف ملفات الحساس أو تغيير Registry/Exclusions، ثم مراجعة أن وضع المنع فعال وليس مجرد وضع Audit؛ تسجيل القيود الخاصة بكل Windows/macOS/Linux. **مرجع:** Microsoft Tamper Protection.
- **CG-185** **[بحث / متطلب مقترح]** — **Vulnerable Driver and Application Control:** دراسة App Control for Business وقواعد منع تحميل Kernel Drivers الضعيفة وسلوك تثبيت البرامج غير المصرح بها؛ عدم تفعيل المنع دون تجريب التوافق والتراجع، خصوصًا برامج المؤسسة القديمة. **مرجع:** Microsoft Tamper Resiliency.
- **CG-186** **[بحث / متطلب مقترح]** — **Credential Guard and Secret Isolation:** فحص دعم وتفعيل VBS/Credential Guard، وتسجيل أن الحماية تقلل سرقة بعض أسرار NTLM/Kerberos لكنها لا تمنع جميع أساليب إساءة استخدام الهوية؛ قيود الإصدارات والأجهزة تظهر بالواجهة. **مرجع:** Microsoft Credential Guard.
- **CG-187** **[بحث / متطلب مقترح]** — **Secure Boot/TPM/BitLocker Baseline:** تقييم Secure Boot وTPM وقرص النظام المشفر وحالة مفاتيح الاسترداد؛ لا يُعرض مفتاح BitLocker للمحلل العادي؛ أي تغيير في إعدادات الإقلاع أو التشفير يستلزم إجراء استعادة موثقًا. **مرجع:** Windows platform security.
- **CG-188** **[بحث / متطلب مقترح]** — **Endpoint Protection Policy Drift:** مقارنة حالة الحماية الفعلية بالسياسة المعتمدة من Intune/GPO/EDR، وكشف أجهزة فشلت في تلقي السياسات أو تعذر تقييمها؛ لا يرسل نفس التغيير من مصدرين إداريين متعارضين. **مرجع:** Defender policy management.

## 31 — حماية الهويات الإدارية والرموز والجلسات (CG-189–CG-196)
- **CG-189** **[بحث / متطلب مقترح]** — **Enterprise Control Plane Protection:** تصنيف Domain Controllers وEntra وCA وPAM وأدوات إدارة الشبكة كأصول Control Plane؛ يمنع الاعتماد على حساب Admin عام لإدارة كل بيئة، ويعرض سلسلة الصلاحيات عبر الهوية والجهاز والهدف. **مرجع:** Microsoft Enterprise Access Model.
- **CG-190** **[بحث / متطلب مقترح]** — **Privileged Access Workstation Policy:** فحص استخدام محطة إدارية محصنة وحساب إدارة منفصل وعدم الدخول الإداري من جهاز شخصي غير مُدار، مع استثناءات مبررة ووضع طوارئ موثق. **مرجع:** Microsoft privileged access.
- **CG-191** **[بحث / متطلب مقترح]** — **Native Windows LAPS Hygiene:** تقييم نشر Windows LAPS ودورة تدوير كلمة المرور وحالة النسخ إلى AD/Entra ومن يمتلك صلاحية الاسترجاع؛ لا تخزن CyberGuard كلمات المرور محليًا ولا يعرضها في سجلات أحداث. **مرجع:** Microsoft Windows LAPS.
- **CG-192** **[بحث / متطلب مقترح]** — **FIDO2/Passkey Enforcement:** مصفوفة تبين أنواع MFA القادرة على مقاومة التصيد، وأين ما زال SMS/OTP أو مصادقة قديمة مستخدمة؛ اقترح ترقية تدريجية مع دعم الطوارئ والأجهزة القديمة. **مرجع:** NIST 800-63B-4; CISA phishing resistant MFA.
- **CG-193** **[بحث / متطلب مقترح]** — **Risk-Adaptive Conditional Access:** قراءة سياسات الوصول المشروط وإشارات خطورة تسجيل الدخول من Entra، مع إظهار متطلبات P2/التراخيص وسياسة Break-glass؛ لا يطبق حظرًا عامًا يمكن أن يقفل جميع المسؤولين خارج الحساب. **مرجع:** Microsoft Entra Risk Based Access.
- **CG-194** **[بحث / متطلب مقترح]** — **OAuth Token and Session Life Cycle:** جرد Token Issuers وAudience وExpiry وSigning Keys وReplay/Token Reuse Signals وRevocation capabilities لواجهات SSO/APIs؛ التمييز بين إبطال رمز ودخول جلسة نشطة وأدوات الدعم. **مرجع:** NIST IR 8587 Sep 2026.
- **CG-195** **[بحث / متطلب مقترح]** — **Service-Account Secret Minimization:** فحص أسرار حسابات الخدمات والتطبيقات، ومدة صلاحيتها واتساع أدوارها، مع توصية Managed Identity/Workload Federation عند الدعم؛ لا تُنسخ الأسرار الخام إلى قاعدة AI أو السجلات. **مرجع:** NIST IR 8587; IAM vendor docs.
- **CG-196** **[بحث / متطلب مقترح]** — **Emergency Access Governance:** تحديد حسابات Break-glass، حفظ أدلة اختبارها الدوري، التنبيه لاستخدامها وتغيّر عواملها، مع مسار استرجاع لا يعتمد على نفس الجهة المعطلة؛ ثنائي الموافقة عند سحب امتيازات حساسة. **مرجع:** Microsoft Privileged Access; Entra Conditional Access.

## 32 — حماية DNS والبريد والوصول للويب (CG-197–CG-202)
- **CG-197** **[بحث / متطلب مقترح]** — **Protective DNS Enforcement:** فحص وجود Protective DNS/Filtering عند Resolver واعتماد سجل قرار Allow/Block مع سبب وجود نطاق ضار، وعدم مزج فشل DNS الاعتيادي بدليل إصابة؛ دراسة تكامل resolver محلي وسحابي. **مرجع:** NIST SP 800-81 Rev 3 Mar 2026.
- **CG-198** **[بحث / متطلب مقترح]** — **DNS Integrity and DNSSEC:** مراقبة إعدادات Authoritative/Recursive Resolvers وDNSSEC وDynamic Updates وZone Transfers ونسخ الإعدادات والمعلومات غير المعتادة؛ بتمييز السلوك المسموح والتطبيقات التي تستخدم DNS مشفرًا. **مرجع:** NIST SP 800-81 Rev 3.
- **CG-199** **[بحث / متطلب مقترح]** — **Encrypted DNS and Visibility Gaps:** جرد DoH/DoT في الشبكة والسياسات المسموح بها، وإظهار أن فلترة DNS التقليدية لا ترى كل طلبات DNS المشفرة؛ لا نكسر TLS تلقائيًا ولا نتجاوز سياسات الخصوصية. **مرجع:** NIST SP 800-81 Rev 3.
- **CG-200** **[بحث / متطلب مقترح]** — **Email Domain Authentication Guard:** فحص SPF/DKIM/DMARC وTLS للنطاقات المملوكة مع تقديم اقتراح الانتقال التدريجي إلى DMARC reject بعد مراجعة التقارير والتحقق من الجهات التي ترسل البريد باسم المؤسسة. **مرجع:** NIST SP 800-177 Rev 1.
- **CG-201** **[بحث / متطلب مقترح]** — **Phishing Exposure Context:** ربط إشارات بريد مشبوه بحساب المستلم والنطاق والروابط والنتيجة من Safe Browsing أو بريد المؤسسة، دون تسريب نص البريد الشخصي أو فتح روابط مجهولة تلقائيًا على بيئة الإدارة. **مرجع:** NIST email security; privacy.
- **CG-202** **[بحث / متطلب مقترح]** — **Web and Browser Protection Posture:** تقييم Safe Browsing/Network Protection وسياسات الإضافات والتنزيلات، والتنبيه إلى مواقع إدارة الشبكة المكشوفة على الإنترنت؛ عند الاشتباه تستخدم بيئة تحليل معزولة. **مرجع:** Microsoft ASR/Web protection.

## 33 — دفاعات Firewall والشبكات وإيقاف الحركة الجانبية (CG-203–CG-210)
- **CG-203** **[بحث / متطلب مقترح]** — **East-West Microsegmentation:** التحقق من فصل VLAN/VRF/Firewall Policies بين معامل وأجهزة المستخدمين وAD والنسخ الاحتياطية والإدارة، لا الاكتفاء بجدار محيط الإنترنت؛ عرض تدفقات الأعمال التي ستتأثر. **مرجع:** NIST SP 800-207; segmentation.
- **CG-204** **[بحث / متطلب مقترح]** — **Default-Deny with Evidence:** اقتراح قواعد Least-Privilege افتراضيًا وفق حركة شبكة موثقة ونافذة قياس، ثم عرض Exceptions محددة المصدر والوجهة والبروتوكول والمنفذ؛ لا تنشر Default Deny مباشرة على الإنتاج. **مرجع:** NIST Zero Trust.
- **CG-205** **[بحث / متطلب مقترح]** — **Outbound Egress Controls:** كشف الاتصالات الخارجة إلى منافذ وأماكن غير معتادة ومراقبة تغيير السياسة؛ عرض شرعية الاتصالات SaaS/CDN والبيانات الناقصة قبل الحظر. **مرجع:** Network firewall guidance.
- **CG-206** **[بحث / متطلب مقترح]** — **Secure Administrative Access:** مراجعة انكشاف SSH/RDP/SNMP/HTTP Management وVPN وفتح لوحات الإدارة عبر الإنترنت؛ اقتراح Trusted Management Zone وBastion/ZTNA وMFA بحسب الجهاز. **مرجع:** NIST SP 800-207; vendor baselines.
- **CG-207** **[بحث / متطلب مقترح]** — **IPS Rule Staging and Rollback:** تفعيل IDS للتجربة قبل IPS منع على قطاعات الإنتاج، ومراجعة False Positives وLatency وPacket Drop مع خطة تعطيل في حالات الطوارئ؛ لا نخلط دقة IDS مع ثبوت IPS Block. **مرجع:** Suricata deployment principle.
- **CG-208** **[بحث / متطلب مقترح]** — **IPv6 Security Parity:** مقارنة قواعد IPv4 وIPv6، وشبكات Dual Stack، وRA Guard وNeighbor Discovery Policies عند الدعم؛ لا نعلن Firewall Secure إذا كانت IPv6 خارج النطاق. **مرجع:** Network dual-stack security.
- **CG-209** **[بحث / متطلب مقترح]** — **Firewall Rule Lifetime & Expiry:** مطابقة التصاريح المؤقتة إلى enforcement policy ذات TTL وOwner وTicket، مع إثبات إعادة غلق المسار خلال المدة؛ التحقق من أثر القواعد على VoIP/DNS/AD وطرق الاستعادة. **مرجع:** JIT and NIST Zero Trust.
- **CG-210** **[بحث / متطلب مقترح]** — **NAC Device Trust Signals:** استقبال حالة شهادات 802.1X/MDM/EDR من حلول NAC إن توفرت؛ توصية Quarantine بحسب السياق والمالك لا مجرد ظهور MAC جديد، مع عزل استثناءات الطوارئ. **مرجع:** NIST Zero Trust; Cisco ISE research.

## 34 — دفاع متعدد السحابات وحماية البيانات (CG-211–CG-216)
- **CG-211** **[بحث / متطلب مقترح]** — **Prowler Cloud Posture Adapter:** تقييم Prowler OSS كمرجع لفحوص AWS/Azure/GCP/Kubernetes ومقدمي خدمات آخرين، بمفاتيح Read-only مؤقتة وبعزل كامل للتوكن والـTenant. لا نعمم الدعم خارج موصل وإصدار محدد. **مرجع:** Prowler Github.
- **CG-212** **[بحث / متطلب مقترح]** — **Cloud Security Hub Baselines:** ربط إعدادات AWS Security Hub CSPM وGuardDuty وCloudTrail وEKS/S3/RDS بالحساب والمنطقة؛ توفير نسبة Coverage واقعية لغياب التفعيل أو البيانات مع إظهار كلفة الخدمات. **مرجع:** AWS Security Hub controls.
- **CG-213** **[بحث / متطلب مقترح]** — **Cloud Identity Policy Enforcement:** استيعاب Risk-based Conditional Access في Entra وتحليل OAuth/Service Principals وAWS IAM وGCP IAM في شكل موحد؛ الإجراءات التنفيذية منفصلة ومقيّدة حسب المورد. **مرجع:** Microsoft Entra; NIST tokens.
- **CG-214** **[بحث / متطلب مقترح]** — **Cloud Data Exposure Inventory:** معرفة إن كانت قواعد بيانات/Storage Buckets/Secrets مكشوفة أو تسمح بتجاوز التشفير، وتحديد مالك البيانات وتصنيفها قبل تغيير الوصول؛ إخفاء محتويات الملفات الحساسة افتراضيًا. **مرجع:** AWS security controls; GCP SCC.
- **CG-215** **[بحث / متطلب مقترح]** — **Cloud Attack Graph with Confidence:** ربط Public Exposure + IAM + Vulnerability + Data Target في مسار محتمل مع مصدر كل رابط، ولا يصنف المسار اختراقًا فعليًا؛ راجع Google Cloud attack exposure documentation. **مرجع:** GCP SCC Attack Paths.
- **CG-216** **[بحث / متطلب مقترح]** — **Cloud API and Credential Budgeting:** حساب حدود API وQuota والتكاليف ومعدلات الاستعلام وتخزين الأحداث قبل تشغيل المراقبة؛ منع استدعاء واسع عبر حسابات/مناطق متعددة دون نطاق وخطة تكلفة. **مرجع:** AWS/Cloud provider usage.

## 35 — حماية سلسلة التوريد وبيئة بناء CyberGuard نفسها (CG-217–CG-222)
- **CG-217** **[بحث / متطلب مقترح]** — **Checkov Infrastructure-as-Code Gate:** دراسة Checkov لفحص Terraform/CloudFormation/Kubernetes/Bicep/OpenTofu قبل النشر وإرجاع Policy Violations للمطور؛ لا يعوض الفحص الفعلي للبيئة ولا ينشر تغييرات تلقائية. **مرجع:** Checkov Github.
- **CG-218** **[بحث / متطلب مقترح]** — **Trivy SBOM and Image Checks:** دراسة Trivy لصور الحاويات والأكواد وSBOM والأسرار والثغرات، وتوضيح موضع الدليل وحدود التغطية ومخاطر False Positives؛ تجنب فحص أسرار خاصة خارج النطاق. **مرجع:** Trivy Github.
- **CG-219** **[بحث / متطلب مقترح]** — **Supply-Chain Incident Response:** اعتماد فحص سلامة المكونات والأدوات نفسها؛ دراسة حادثة Trivy supply-chain advisory المؤرخة 21 مارس 2026 لتحديد ضوابط pinning/signatures/provenance/rotation بعد الاختراق. **مرجع:** Trivy Github advisory GHSA-69fq-xp46-6x23.
- **CG-220** **[بحث / متطلب مقترح]** — **Signed Updates and Rollback Channel:** توقيع تحديثات CyberGuard وAgents وقواعد detection والتحقق من digest/attestation قبل التثبيت، مع قنوات Stable/Canary وإمكانية التراجع؛ لا تنفذ تحديثات من روابط غير موثقة. **مرجع:** Supply chain defense.
- **CG-221** **[بحث / متطلب مقترح]** — **Open-Source Maintenance and License Gate:** لكل Dependency تسجّل سياسة SECURITY وحالة الصيانة والرخصة وCVE وتواتر الإصدارات؛ إضافة أداة إلى الدراسة لا يجيز إعادة توزيعها تجاريًا أو نسخ ميزاتها المحمية. **مرجع:** OpenSSF scorecard; GitHub security advisories.
- **CG-222** **[بحث / متطلب مقترح]** — **Scanning Tool Sandbox:** تشغيل تحليل ملفات/قوالب/حاويات غير موثوقة في بيئة معزولة محدودة الموارد ودون مفاتيح إدارة الإنتاج؛ تطبيق سياسات الحد من الاستهلاك قبل إدخال الأدوات في Core. **مرجع:** Trivy security advisories.

## 36 — الحماية من الفدية والتعافي الموثوق (CG-223–CG-228)
- **CG-223** **[بحث / متطلب مقترح]** — **Ransomware Defense-in-Depth Profile:** مطابقة الضوابط الخاصة بالفدية إلى NIST IR 8374 Rev.1 (2026)، ومنها تقليل الصلاحيات وASR والمراقبة والاستجابة والتعافي، مع توثيق أين يفتقر الجهاز إلى أي طبقة. **مرجع:** NIST ransomware publications Jun 2026.
- **CG-224** **[بحث / متطلب مقترح]** — **Backup Survivability Assessment:** تمييز وجود Backup Job عن وجود نسخة يمكن استعادتها؛ فحص النسخ المشفرة وخارج الاتصال أو المعزولة والحماية من الحذف ودورة الوصول للمستودعات. **مرجع:** CISA StopRansomware Guide.
- **CG-225** **[بحث / متطلب مقترح]** — **Recovery Drill Evidence:** تسجيل آخر اختبار Restore وتاريخ النسخة وحجمها وRTO/RPO وقابلية إقلاع VM واسترجاع AD ومفاتيح التشفير، دون نسخ بيانات حساسة للمنصة أو إجراء Restore على إنتاج. **مرجع:** CISA StopRansomware; NIST.
- **CG-226** **[بحث / متطلب مقترح]** — **Ransomware Early Signals Correlation:** ربط تغيّر جماعي للملفات مع إيقاف خدمات/تعطيل حماية ومحاولة حذف نسخ وحركة جانبية؛ تصنيف الإشارة وعدم إطلاق عزل شامل دون تحقق وسلامة تشغيل. **مرجع:** Wazuh FIM; Microsoft CFA.
- **CG-227** **[بحث / متطلب مقترح]** — **Clean-Room Recovery Plan:** تحديد VLAN وشبكة إدارة بديلة لاستعادة الأنظمة النظيفة، وفحص البرمجيات/الاعتمادات قبل إعادة ربطها بالإنتاج؛ خطوات اعتماد وتقارير تجربة. **مرجع:** CISA StopRansomware.
- **CG-228** **[بحث / متطلب مقترح]** — **Data Integrity and Restoration Proof:** حفظ أدلة checksum/signature وحالة Object Lock وتاريخ النسخ وسجل تغييرات مفاتيح التشفير، وتوضيح أن Lock لا يضمن صحة بيانات النسخة إذا كانت مشوهة قبل حفظها. **مرجع:** NIST data integrity; AWS backup.

## 37 — حماية OT/ICS والأنظمة شديدة الحساسية (CG-229–CG-232)
- **CG-229** **[بحث / متطلب مقترح]** — **OT Passive-First Policy:** مراقبة حركة OT/ICS بالأساليب السلبية وموافقات سلامة منفصلة؛ منع فحوص الثغرات النشطة وPort Shutdown وReboot على PLC/SCADA افتراضيًا، وتحديد Owner وحساسية السلامة. **مرجع:** NIST SP 800-82 Rev 3.
- **CG-230** **[بحث / متطلب مقترح]** — **OT Rev4 Draft Research Watch:** وثق أن NIST SP 800-82 Rev.4 كان Draft بتاريخ 21 سبتمبر 2026 والتعليقات مفتوحة حتى 30 نوفمبر 2026؛ لا يوضع كمعيار نهائي ملزم حتى اعتماده. **مرجع:** NIST SP 800-82 Rev 4 IPD.
- **CG-231** **[بحث / متطلب مقترح]** — **Legacy Isolation Compensating Controls:** عندما يكون OS/Firmware غير مدعوم أو لا يقبل Agent، يقترح Segmentation/Allowlist/Jump Host/Monitoring/Replacement Roadmap مع بيان الخطر المتبقي وليس علامة أخضر كاذبة. **مرجع:** NIST OT; Zero Trust.
- **CG-232** **[بحث / متطلب مقترح]** — **Critical Infrastructure Change Safeguards:** حماية DC وDNS وCore وHypervisor وBackup Controller وOT Controllers من العزل والإغلاق الآلي، مع Dual-Approval وOut-of-band Recovery وسجل تغيير؛ مع سياسات تختلف حسب حساسية الخدمات. **مرجع:** NIST OT; Microsoft privileged access.

## 38 — قياس فعالية الحماية وإدارة الأدلة (CG-233–CG-238)
- **CG-233** **[بحث / متطلب مقترح]** — **Protection-Verified Status Model:** حالات موحدة: Configured/Enforced/Audited/Failed/Unknown/Not Supported؛ لا تعتبر أداة الحماية مفعلة دون إثبات من نقطة تطبيق الحماية. **مرجع:** Defender policy states.
- **CG-234** **[بحث / متطلب مقترح]** — **Coverage Gap Dashboard:** لكل موقع/شبكة وأصل: نسبة Agents وFlow Sources وDNS وIdentity وFirewall Logs وتاريخ آخر حدث وسبب عدم الرؤية؛ لا تعطي درجة أمان عالية إذا كانت تغطية البيانات ضعيفة. **مرجع:** Security telemetry coverage.
- **CG-235** **[بحث / متطلب مقترح]** — **Control-to-Threat Traceability:** خريطة Threat Technique → Preventive Control → Evidence → Validation Test → Remediation → Owner مع حالات Tested/Untested/Unsupported ومرجع المصدر. **مرجع:** NIST CSF 2.0; MITRE ATT&CK.
- **CG-236** **[بحث / متطلب مقترح]** — **Safe Protection Validation Lab:** اختبار ASR/CFA/IDS/Firewall/WAF في مختبر أو Canary مصرح به، باستخدام أحداث ومحاكاة غير مدمرة؛ تسجيل هل صدر Event وهل تم المنع فعلًا وما آثار الأداء. **مرجع:** Microsoft ASR Audit; NIST practices.
- **CG-237** **[بحث / متطلب مقترح]** — **False Positive and Service Impact Budget:** قياس تنبيهات الحماية الكاذبة وانقطاع الخدمة بسبب السياسات، وMedian Time to Restore وأثر Latency؛ إذا ارتفعت الحوادث الناتجة عن سياسة تُوقف ترقيتها وتعود إلى Last Known Good. **مرجع:** Change safety evidence.
- **CG-238** **[بحث / متطلب مقترح]** — **Research Evidence Quality and Staleness:** لكل قاعدة/مصدر/موصل: رابط رسمي، إصدار، تاريخ مراجعة، حالة نهائي/مسودة، صلاحيات، تكلفة، ترخيص، حالات دعم، نتائج اختبار؛ مع وسم الأبحاث غير المؤكدة وعدم ترقيتها إلى قرار تنفيذي. **مرجع:** Scientific research governance.

## 39 — تأمين AI والوصول الآمن من التابلت والجوال (CG-239–CG-242)
- **CG-239** **[بحث / متطلب مقترح]** — **AI No-Privilege-by-Default:** فصل نموذج AI عن واجهات التنفيذ: يقتصر دوره على تفسير الأدلة وصياغة طلب محدد؛ صلاحية التنفيذ تُراجع عبر Policy Engine والموافقة والهدف والتاريخ؛ لا يقرأ أسرار API الخام. **مرجع:** OWASP LLM secure AI principle.
- **CG-240** **[بحث / متطلب مقترح]** — **Prompt-Injection and Tool-Response Defense:** التعامل مع سجلات الحوادث ومخرجات GitHub وHTML وThreat Feeds كنصوص غير موثوقة؛ لا تتحول التعليمات المحقونة في تلك البيانات إلى أوامر إدارة أو تغييرات سياسة. **مرجع:** Prompt injection defense.
- **CG-241** **[بحث / متطلب مقترح]** — **Mobile Step-up Approval for Dangerous Action:** من الهاتف أو التابلت: MFA قوي وإعادة تحقق قبل العزل والإيقاف/الحجب المؤثر؛ عرض المتأثرين ومدة التأثير وطريقة التراجع، ولا يُرسل قرار غير معتمد عند انقطاع الجلسة. **مرجع:** NIST identity; privileged access.
- **CG-242** **[بحث / متطلب مقترح]** — **Security Console Attack Surface Minimization:** خادم الإدارة Local-First مع SSO/MFA وAccess proxy أو VPN وآلية Session expiry وتدقيق وحماية من CSRF والتقييد بالهوية والجهاز؛ لا تكشف API إدارة مباشرة إلى الإنترنت. **مرجع:** NIST Zero Trust; secure admin access.

## دراسات تهديد ودروس دفاعية مضافة

| المعرف | الواقعة/المصدر | العبرة الدفاعية | الارتباط |
|---|---|---|---|
| CASE-12 | Trivy OSS Security Advisory GHSA-69fq-xp46-6x23، مارس 2026 | حتى أدوات الفحص يمكن أن تتأثر بسلسلة التوريد؛ لا تُدمَج تحديثات أو Plugins دون تحقق من الإصدارات ومصدر الملفات والتوقيع وسياسة عزل | CG-219 إلى CG-222 |
| CASE-13 | NIST IR 8587، سبتمبر 2026: تهديد تزوير/سرقة/إساءة استخدام Tokens وAssertions | MFA وحده لا يكفي إذا كان SSO Token مخترقًا؛ نحتاج إدارة دورة حياة Token وسحب/تدوير وتوثيق الجلسات والرموز | CG-194 إلى CG-196 |
| CASE-14 | سيناريو تعافي اختباري: فدية تصيب جهازًا ويظهر نسخ احتياطي ناجح لكن استعادة بيانات مفقودة | مؤشر نجاح Backup Job لا يكفي؛ يلزم اختبار فعلي من نسخة سليمة والتأكد من استقلال حسابات النسخ عن AD المصاب | CG-223 إلى CG-228 |
| CASE-15 | سيناريو OT اختباري: أمر إغلاق منفذ يقطع Controller عن خدمة حيوية | دفاع مُصرَّح به قد يصبح خطر تشغيل وسلامة؛ الأصل هو المراقبة السلبية وخطة تغيير مستقلة للـOT | CG-229 إلى CG-232 |

## قرار هندسي مبدئي — لا يعني اعتماد التنفيذ

| المسار | المحرك/التكامل المرشح | الوضع المبدئي | ما يجب إثباته قبل التنفيذ |
|---|---|---|---|
| حماية Windows | Defender status + ASR + CFA + Tamper + Credential Guard | استعلام Read-only أولاً | نسخة Windows وترخيص الإدارة ودقة الحالة على الجهاز |
| حماية هوية AD/Entra | Windows LAPS + Microsoft security posture + NIST Token controls | تحليل Read-only | الأدوار والصلاحيات ومسار Break-glass وسجل التغييرات |
| DNS والبريد | DNS Security baseline + SPF/DKIM/DMARC | تدقيق تكوين فقط | صلاحيات مالك النطاق، عدم كسر البريد المشروع |
| الشبكة وFirewall | Vendor APIs + Config Diff + Batfish | Simulation/Dry Run | نوع الجهاز/API واستمرار مسار الإدارة والتراجع |
| السحابة | Prowler OSS + AWS Security Hub + Entra + GCP SCC | Read-only + source mapping | RBAC وكلفة API وتغطية المناطق وحدود كل منتج |
| سلسلة التوريد | Checkov + Trivy + توقيع إصدارات | Sandbox/Build Gate | صلاحية النسخة وسلامة الأداة والرخصة |
| التعافي | Backup Inventory + Restore Evidence | إثبات وخطة تجربة | فصل الصلاحيات ونتائج Restore وRPO/RTO |
| OT | NIST 800-82 | Passive-First | موافقة مالك السلامة ونطاق الفحص وتحمل الخدمة |

## مصادر موثقة مختارة — روابط مراجعة رسمية/أصلية

- [Microsoft — Attack Surface Reduction](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-overview)
- [Microsoft — Controlled Folder Access](https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-overview)
- [Microsoft — Tamper Protection](https://learn.microsoft.com/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection)
- [Microsoft — Tamper Resiliency](https://learn.microsoft.com/en-us/defender-endpoint/tamper-resiliency)
- [Microsoft — Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [Microsoft — Windows LAPS](https://learn.microsoft.com/windows-server/identity/laps/laps-overview)
- [Microsoft — Privileged Access](https://learn.microsoft.com/en-us/security/zero-trust/security-concept-privileged-access)
- [Microsoft — Entra Risk-Based Access](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-policies)
- [NIST — SP 800-63B-4 (2025)](https://www.nist.gov/publications/nist-sp-800-63b-4digital-identity-guidelines-authentication-and-authenticator)
- [NIST — IR 8587 (Sep 2026): Tokens and Assertions](https://csrc.nist.gov/pubs/ir/8587/final)
- [NIST — SP 800-81 Rev.3 (Mar 2026): DNS Security](https://csrc.nist.gov/pubs/sp/800/81/r3/final)
- [NIST — SP 800-177 Rev.1: Trustworthy Email](https://csrc.nist.gov/pubs/sp/800/177/r1/final)
- [NIST — SP 800-207: Zero Trust](https://csrc.nist.gov/pubs/sp/800/207/final)
- [NIST — Ransomware Research and IR 8374 Rev1 (June 2026)](https://csrc.nist.gov/Projects/ransomware-protection-and-response/publications)
- [NIST — OT Security SP 800-82 Rev3 (Final)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [NIST — OT Security SP 800-82 Rev4 (Sep 2026 Initial Public Draft)](https://csrc.nist.gov/pubs/sp/800/82/r4/ipd)
- [AWS — Security Hub CSPM Controls](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html)
- [AWS — Security Reference Architecture Checklist](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/checklist.html)
- [Google Cloud — Attack Exposure Paths](https://docs.cloud.google.com/security-command-center/docs/attack-exposure-learn)
- [Prowler OSS](https://github.com/prowler-cloud/prowler)
- [Checkov OSS](https://github.com/bridgecrewio/checkov)
- [Trivy OSS](https://github.com/aquasecurity/trivy)
- [Trivy Security Advisories (March 2026)](https://github.com/aquasecurity/trivy/security/advisories)
- [Wazuh SCA](https://github.com/wazuh/wazuh/blob/main/docs/ref/modules/sca/README.md)
- [Wazuh FIM](https://github.com/wazuh/wazuh/blob/main/docs/ref/modules/fim/configuration.md)

## تحقق اكتمال سجل v0.6

- عدد المتطلبات الجديدة **62**: CG-181 إلى CG-242.
- المجموع **242**: CG-001 إلى CG-242 بدون فقد المعرفات السابقة.
- كل المتطلبات الجديدة **في حالة دراسة** حتى يتم بناء مصفوفة API/OS/Permissions/Cost/Testing؛ ليست ميزات مفعّلة.
- التصميم ما زال مستندًا إلى صورة SOC الداكنة الكحلية/البرتقالية؛ المنتج Local-First Hybrid للكمبيوتر مع Web HTTPS آمن للجوال/التابلت.
- **استكمال بحث لاحق يبدأ CG-243**، مع أولوية دراسة حوادث SaaS/AD وRansomware الجديدة، وتجربة التكاملات في المختبر عند إذن المستخدم، دون تنفيذ الآن.


# الجولة البحثية السابعة — أنماط الاختراق والتعرّف الاستدلالي والاستجابة (v0.7)

**تاريخ البحث:** 2026-11-10  | **النطاق:** بحث دفاعي وتهديدات مؤسسية، دون فحوص فعلية أو تنفيذ أكواد المنتج.  
**المبدأ الجديد:** التعرف على *سلوك وتقنيات* الهجمات عبر الأدلة، مع التمييز بين احتمال الخطر والاختراق المؤكد؛ لا يمكن ضمان معرفة «كل الاختراقات» أو اكتشاف هجوم لم تُجمع له أي بيانات.  
**حالة كل ما يلي:** دراسة ومتطلبات مقترحة، غير منفذة أو مختبرة. لا تُنشأ صلاحيات أو طلبات تنفيذ على شبكات حقيقية.

## 40 — محرك التعرّف على الاختراق وقاعدة المعرفة (CG-243–CG-254)
- **CG-243** — **Attack Pattern Knowledge Graph:** نموذج موحد لكل أسلوب تهديد يربط TTPs وتقنيات MITRE ATT&CK والإصدارات ومراحل الهجوم بالأصول المتأثرة والضوابط وأدلة الكشف والاستجابة ونتائج الاختبار. [MITRE ATT&CK Detection Strategies]
- **CG-244** — **Evidence-First Incident Classifier:** لا يُصدر وصف «اختراق مؤكد» دون أدلة قابلة للمراجعة؛ لكل تصنيف مستوى ثقة ومبررات وفرضيات بديلة ومصدر لكل مؤشر. [Mandiant M-Trends 2026]
- **CG-245** — **Behavior over Actor Names:** يعتمد التعرف أساسًا على الأفعال/السلوك وليس اسم مجموعة APT أو عائلة فدية أو SHA256 سريع التغير؛ يُفصل Attribution عن Detection. [MITRE ATT&CK]
- **CG-246** — **Versioned Threat Casebook:** دراسة حوادث مرقمة مع اسم السيناريو، شجرة الأدلة، المصادر، الزمن، سؤال التحقق، الإجراء المعتمد، حالة الاختبار، وتاريخ آخر مراجعة. [CISA Advisories]
- **CG-247** — **Time-Bounded IOC and Feed Hygiene:** لكل IP/Domain/Hash مصدر ووقت ملاحظة وصلاحية ودرجة ثقة؛ منعه الآلي لا يتم بمجرد ظهوره في Feed دون موازنة False Positives. [CISA threat intelligence]
- **CG-248** — **Sequence-Driven Correlation:** قواعد تعتمد ارتباط أحداث متعددة حسب الزمن والأصل والحساب والعملية وليس حدثًا منفردًا؛ التحقق من أن Backend يدعم semantics الخاصة بـSigma. [Sigma Correlation Spec 2.1]
- **CG-249** — **Threat Evidence Completeness Score:** عرض أي إشارات متاحة وأيها مفقود (Endpoint/Identity/Network/Cloud/Email/Backup)، وعدم ترقية ظن ضعيف إذا كانت السجلات ناقصة. [CISA/ASD event logging]
- **CG-250** — **Knowledge Freshness & Supersession:** ترقية أو إلغاء قواعد كشف عند تغيّر TTPs أو دعم المنتج أو إصدار ضابط جديد، مع أثر تغيير وتاريخ وحزم متوقعة وقابلة للتراجع. [MITRE ATT&CK v18]
- **CG-251** — **ATT&CK v18 Detection Schema Migration:** عدم الاعتماد في الاستيراد على Data Sources القديمة وحدها بعد إيقاف تحديثها؛ يدعم Detection Strategies/Analytics/Data Components وما يتغير في نموذج STIX. [ATT&CK release and data model]
- **CG-252** — **Unknown Threat Behavior Queue:** للأحداث الجديدة التي لا تطابق قاعدة حالية: تصنيف Behavioral Anomaly بمستوى ثقة منخفض وطلب إثراء/تحقيق بدلاً من ادعاء معرفة تهديد مجهول. [Detection engineering practices]
- **CG-253** — **Analyst Feedback and Disposition:** حفظ True Positive وBenign True Positive وFalse Positive وUnknown؛ تعليم القواعد تحت حوكمة ولا يُسمح لرد واحد بإلغاء كشف عالمي. [Microsoft Defender for Identity playbooks]
- **CG-254** — **Threat Source Integrity:** مواد CISA والتقارير وصفحات GitHub ومخرجات LLM هي مدخلات غير موثوقة تنقل إلى منطقة مراجعة؛ فحص المصدر وتاريخ النشر والتحذير من Prompt Injection. [OWASP LLM security]

## 41 — هجمات الهوية وActive Directory بعمق (CG-255–CG-269)
- **CG-255** — **DCSync Replication Baseline:** المقارنة بين مصادر نسخ الدليل المشروعة والمصادر غير المتوقعة؛ تسجيل الحساب والجهاز والوقت، مع قيود توفّر سجل RPC على إصدارات DC. [ASD/CISA AD guidance 2026]
- **CG-256** — **Shadow Credentials Changes:** تدقيق تعديل خصائص الهوية المعتمدة على المفاتيح العامة ومراجعة هوية المنفذ/الحساب الذي أحدث التغيير؛ التنبيه عند إسناد غير مصرح به. [ASD/CISA AD guidance 2026]
- **CG-257** — **AD CS Certificate Abuse:** تدقيق قوالب الشهادات وصلاحيات الإصدار وإعدادات CA وأحداث طلب الشهادات غير المعتادة، مع عدم إلغاء CA دون خطة. [Microsoft Defender for Identity]
- **CG-258** — **Kerberos Abuse and Ticket Lifecycles:** ربط أنماط طلبات التذاكر ومخالفات التوقيت والامتيازات والأجهزة المصدرة؛ التمييز عن الخدمات المعتمدة على Kerberos بصورة شرعية. [MITRE ATT&CK]
- **CG-259** — **NTLM Exposure and Relay Hardening:** جرد استخدام NTLM/SMB وإعدادات LDAP signing وchannel binding وSMB signing حيث تدعمها البيئة؛ وضع Audit قبل Enforcement لتجنب تعطيل تطبيقات قديمة. [Microsoft hardening guidance]
- **CG-260** — **Credential Dumping Behavioral Chain:** ربط الوصول غير المعتاد لعمليات حساسة بإنشاء ملفات مؤقتة أو أدوات غير اعتيادية، مع حفظ الأدلة وعدم افتراض أن كل أداة إدارة اختراق. [MITRE DET0363]
- **CG-261** — **Privilege Escalation Chain:** تتبع ترقية عضوية المجموعات والحقوق المحلية وتعديل GPO أو إضافة حساب خدمة وارتباطها بتسجيل الدخول الفعلي. [Microsoft Defender Identity]
- **CG-262** — **Privileged Admin Workstation Isolation:** تدقيق استخدام حسابات Tier 0 على أجهزة المستخدمين العادية؛ اقتراح أجهزة إدارة معزولة وسياسات دخول صارمة. [Privileged Access guidance]
- **CG-263** — **GPO & SYSVOL Integrity Correlation:** الربط بين تغييرات Group Policy بالـAD وتعديل ملفات SYSVOL وعمليات نشر البرامج، مع تمييز تغييرات المشرفين الموثقة. [MITRE DET0305]
- **CG-264** — **Service Account Misuse:** جرد الحسابات غير البشرية، الامتيازات غير المستخدمة، مصادقاتها خارج الخوادم المعتادة، وإجراءات تدوير الاعتمادات بشكل مجدول. [Defender for Identity]
- **CG-265** — **Interactive Remote Access Identity Graph:** ربط RDP/SSH/WinRM/AnyDesk (حسب سجلات التوافر) بالحساب والجهاز والمصدر والوقت والتصريح المؤقت؛ وجود تطبيق تحكم وحده لا يعني جلسة خبيثة. [Microsoft Windows security logging]
- **CG-266** — **Session Token Theft & Replay Detection:** مؤشرات جلسات سحابية من جهاز أو سياق غير مألوف، مع خيار فرض إعادة تحقق مقاوم للتصيد وسحب الجلسة بعد موافقة. [Microsoft Entra Token Protection]
- **CG-267** — **Helpdesk Social Engineering Controls:** متابعة Reset MFA وPassword Reset والتسجيل الجديد لأجهزة المصادقة للحسابات الحساسة؛ الربط بتذاكر التصريح وتأكيد هوية الموظف من قناة مستقلة. [M-Trends 2026]
- **CG-268** — **Enterprise Password Spraying Correlation:** ربط فشل الدخول الموزع عبر عدة حسابات وعناوين ونجاح لاحق؛ عدم مساواة كثرة فشل الدخول باختراق مؤكد. [MITRE DET0551]
- **CG-269** — **Domain Compromise Recovery Path:** قائمة مستقلة لكيفية حفظ الأدلة وحصر حسابات الامتيازات وتدوير مفاتيح ومراجعة علاقات الثقة والتعافي المنضبط لـAD عند التأكد من اختراق مجال واسع. [ASD/CISA AD guidance]

## 42 — الأجهزة الحدودية والشبكات والاتصالات (CG-270–CG-281)
- **CG-270** — **VPN Credential Exposure Response:** اكتشاف حسابات VPN عالية الخطورة ومؤشرات تغير IP/Geo وسجلات الدخول ووجود MFA؛ خيارات إلغاء الجلسات وتدوير الاعتمادات حسب API وموافقة مسؤول. [CISA Fortinet 2026]
- **CG-271** — **Network Edge Management Exposure:** جرد منافذ إدارة Firewall/VPN/Router المكشوفة خارجيًا وفحص وجود قيود ACL/OOB وتوثيق MFA وحالة التصحيح. [CISA Edge Device Guidance]
- **CG-272** — **Router/Firewall Configuration Diff with Approval:** كشف تغيّر قواعد الوصول وNAT والـDNS وإعدادات الإدارة والمستخدمين مع تقييم ما إذا كان تغيّرًا مصرحًا به. [CISA Fortinet 2026]
- **CG-273** — **Firmware Integrity & Unsupported Versions:** مطابقة طراز جهاز الشبكة وإصدار OS/firmware مع إشعارات الأمان ونهاية الدعم؛ عدم محاولة تحديثه أو استبداله دون نافذة تغيير. [Vendor advisories]
- **CG-274** — **Out-of-Band Egress and Alternative Paths:** اكتشاف استخدام قنوات خروج أو واجهات إضافية غير معتادة متى توفرت NetFlow/Firewall/Proxy/Agent؛ تمثيل فجوات الرؤية. [MITRE DET0077]
- **CG-275** — **Traffic Sequence C2 Analytic:** ربط عمليات endpoint مع DNS وHTTP/HTTPS وNetFlow غير المعتادة بدل حظر اتصالات عادية لمجرد دوريتها. [MITRE DET0027]
- **CG-276** — **DNS & Proxy Evasion Analytics:** تدقيق تغييرات Resolver/Proxy وDNS filtering وDoH/DoT المسموح وغير المسموح حسب سياسة المؤسسة. [NIST SP 800-81 Rev3]
- **CG-277** — **Internal Lateral Movement Baselines:** نموذج للأجهزة والخدمات التي تتواصل عادة عبر SMB/RDP/WinRM/SSH وما يخرج عن هذا النمط؛ يستبعد أعمال الدعم والتشغيل المعتمدة. [Microsoft Defender Identity]
- **CG-278** — **Safe Network Quarantine Selector:** اختيار الأقل ضررًا بين EDR isolation أو Firewall block أو NAC quarantine أو Switch Port action، مع توثيق الفرق بينها والقدرات المتاحة. [CISA/zero trust]
- **CG-279** — **Network Management Channel Continuity:** قبل تغيير ACL أو حظر أو عزل يتحقق من استمرار مسار الإدارة والتراجع، خصوصًا لوصول عبر تابلت أو VPN. [Change safety]
- **CG-280** — **Encrypted Traffic Metadata Boundary:** تحليل بيانات TLS/DNS/flow المصرح بها دون ادعاء قراءة محتوى تشفير غير متاح، وحصر TLS inspection في السياسات والبيئات المصرح بها. [Privacy by design]
- **CG-281** — **Fortinet Multi-Vendor Exposure Profiles:** نموذج خاص بواجهات FortiGate وCisco وHuawei وغيرها يتعامل مع تسريب اعتمادات أو ضعف Firmware أو VPN بغض النظر عن اختلاف API. [CISA FortiBleed June 2026]

## 43 — الفدية والبرمجيات الضارة واختراق السيرفرات (CG-282–CG-294)
- **CG-282** — **SafePay Ransomware Defensive Playbook:** ربط VPN/Edge compromise والتصيّد وسحب البيانات ومحاولات العبث بالنسخ ثم تشفير الأنظمة مع استجابة مرحلية. [CISA/FBI SafePay Oct 2026]
- **CG-283** — **NAS/Backup Destruction Warning:** تنبيه عند حذف Shadow Copies أو إعادة ضبط NAS أو حذف Snapshot/Backup Catalog بصورة غير معتادة؛ عزل واجهات الإدارة مع التأكد من استمرار النسخ السليمة. [CISA/FBI SafePay]
- **CG-284** — **Ransomware Behavior Context:** ربط تغيرات ملفات جماعية مع تسلسل العمليات والخدمات وعمليات القرص والحساب المستخدم، مع استبعاد التشفير والنسخ الاحتياطي المشروع بعد التأكد. [MITRE ATT&CK]
- **CG-285** — **Mass Service Stop & EDR Impairment:** الكشف المبكر عن سلسلة إيقاف خدمات الأمن والتسجيل والنسخ الاحتياطي بشكل مترابط، مع أولوية حفظ الدليل. [MITRE DET0497]
- **CG-286** — **Web Server Compromise Evidence Chain:** طلب ويب مشبوه يتبعه تشغيل عملية غير معتادة أو اتصال خارجي وخدمة/ملف جديد؛ ربط الإشارات قبل تقرير الاختراق. [MITRE DET0080]
- **CG-287** — **Hypervisor Control Plane Audit:** جرد تحكم VMware ESXi/vCenter وHyper-V وعمليات الدخول/إطفاء VM وتغيير الشبكات أو Datastores، وإجراءات تغيير عالية الخطورة بموافقة مضاعفة. [Hypervisor security design]
- **CG-288** — **Restore Under Compromised Admin Scenario:** اختبار نظري/مخبري لاستمرار إمكانية الوصول إلى نسخ نظيفة عند اختراق AD أو Hypervisor، مع فصل حسابات النسخ والهوية ومفاتيح التشفير. [CISA ransomware]
- **CG-289** — **Malware Static Capability Triage:** دراسة Mandiant capa لتحليل قدرات ملفات مشتبه بها داخل Sandbox دون تشغيلها على الإنتاج؛ النتائج ليست حكمًا نهائيًا على نية الملف. [Mandiant capa]
- **CG-290** — **Signature and Behavior Fusion:** الجمع بين Hash/Rules/Signatures وسلوك العمليات والاتصال وملامح الحادث؛ لا يعتمد منع التطبيق على Hash منفرد سريع التغيير. [MITRE detection]
- **CG-291** — **Evidence-Safe Quarantine:** عند عزل ملف يحتفظ بالبيانات الوصفية/الأدلة والتجزئة ومسار الاسترجاع، ويمنع إتاحة الملف لغير المحقق المصرح. [DFIR practice]
- **CG-292** — **Destructive Action Two-Person Rule:** منع أوامر إيقاف خادم إنتاج أو مسح خدمة أو حذف بيانات أو عزل Domain Controller دون موافقة ثانية ومراجعة التأثير والتراجع؛ المنع الافتراضي على الأصول الحرجة. [Safety by design]
- **CG-293** — **Insider-vs-Automation Context:** ربط سلوك جمع البيانات الجماعي بصاحب الحساب ونوع الوظيفة والتذاكر المعتمدة، مع حماية خصوصية الموظفين ومنع اتهام تلقائي. [Insider threat risk]
- **CG-294** — **Recovery Integrity & Re-Infection Watch:** بعد إعادة جهاز للخدمة يتحقق من التسجيل والحماية والتصحيحات وعدم تكرار نفس مؤشرات السلوك؛ لا يعتبر التعافي ناجحًا بمجرد أن الجهاز عاد يرد Ping. [NIST incident recovery]

## 44 — الاختراقات السحابية وSaaS وخطوط الثقة (CG-295–CG-303)
- **CG-295** — **OAuth App & Consent Abuse Graph:** تنبيه عند تغيير صلاحيات تطبيق أو تفويض وصول واسع إلى بريد وملفات المؤسسة، مع قائمة للموافقات المصرح بها. [Microsoft Defender Cloud Apps]
- **CG-296** — **Business Email Compromise Sequence:** ربط تسجيل دخول غير معتاد + OAuth app أو Forwarding Rule + Graph mail read + نشاط تحويل خارج النطاق؛ التحقيق قبل إزالة القاعدة. [Microsoft Defender XDR]
- **CG-297** — **Device-Code / Token Phishing Risk:** مراقبة مؤشرات Device-code وToken compromise والجلسات المرتفعة الخطورة حيث تتوفر السجلات؛ تفضيل MFA المقاوم للتصيد وسياسات Conditional Access. [CERT-In M365 Aug 2026]
- **CG-298** — **AWS Cross-Region Cloud Access Coverage:** استخدم IAM Access Analyzer لكل Region مناسب عند تقييم الوصول الخارجي؛ بيان غياب التغطية وتكلفة خيارات Internal/Unused. [AWS IAM Access Analyzer]
- **CG-299** — **Unused Cloud Identity & Rights Review:** اكتشاف الأدوار والمفاتيح والأذونات غير المستخدمة ومقارنة الحد الأدنى المطلوب، مع مراجعة الاستثناءات قبل الإزالة. [AWS IAM Access Analyzer]
- **CG-300** — **Cloud Attack Sequence Correlation:** تجميع أحداث Cloud API وRuntime وNetwork إلى حادث واحد (AWS GuardDuty Extended Threat Detection أو ما يعادله)، مع توضيح مصادر مفعلة ومفقودة. [AWS GuardDuty]
- **CG-301** — **Kubernetes Runtime Coverage Gaps:** تحديد هل الـRuntime sensor يعمل على EKS/ECS/EC2 وما لا يدعمه، بدل افتراض أن أي Cluster تحت التغطية؛ اجمع audit logs منفصلة. [AWS GuardDuty Runtime]
- **CG-302** — **Cross-Cloud Permission Paths:** ربط هوية Cloud/SaaS بالمورد الحساس وتعرّضه الخارجي والثغرات وتوصيات أقل امتياز؛ لا تبالغ في القطع بإمكان تنفيذ مسار غير مختبر. [Microsoft Defender for Cloud]
- **CG-303** — **Cloud API Rate, Privilege and Storage Budget:** لكل Connector حصة استدعاءات وتكاليف واستعلامات ملغاة وسجل اعتماد وتغطية Regions/Accounts؛ لا استخدام مفاتيح Root. [Cloud security docs]

## 45 — هندسة الكشف والتجريب وإدارة الاستجابة (CG-304–CG-314)
- **CG-304** — **Sigma Rule Lifecycle:** ربط قواعد Sigma بالإصدار والمصدر والتصنيف ووسوم ATT&CK والاستثناءات وبيئة الاختبار والـBackend؛ مراجعة أي تحويل غير مدعوم قبل النشر. [Sigma specification 2.1]
- **CG-305** — **Correlation Backend Capability Checks:** رفض تحويل ارتباط Sigma temporal/temporal_ordered إذا كان backend غير قادر على تمثيله بدقة؛ لا يتم تجاوز الخطأ بصورة صامتة. [Sigma correlation spec]
- **CG-306** — **Purple-Team Outcome Register:** اعتماد أدوات مثل VECTR لتوثيق هل كُشف السلوك وهل مُنع وهل استجاب الفريق بالوقت المطلوب، داخل مختبر مرخص فقط. [VECTR OSS]
- **CG-307** — **Continuous Non-Destructive Detection Tests:** أحداث اختبار صناعية/محاكاة آمنة وقواعد Golden Dataset لقياس تدهور الكشف وتغيّر False Positive وFalse Negative بعد كل تحديث. [Detection as Code]
- **CG-308** — **Attack-to-Control Evidence Mapping:** من كل CASE/TTP إلى الضوابط الواقية ومصدر البيانات المطلوب والقواعد واختبارات نجاحها، مع Missing Controls وUnsupported في لوحة تغطية. [MITRE ATT&CK/D3FEND]
- **CG-309** — **Confidence-Calibrated Triage:** مستويات Confirmed/Suspected/Benign/Unverified، وميزة طلب أدلة إضافية؛ لا يأخذ LLM قرار إغلاق التهديد استنادًا إلى عنوان حادث فقط. [Incident classification]
- **CG-310** — **Containment with Measured Blast Radius:** درجة تأثير الإجراء على المستخدمين والخدمات وأجهزة الإدارة، تنفيذ Canary أو Dry Run متى توفر، واعتماد إجراءات الحفاظ على التحقيق والتراجع. [Response best practice]
- **CG-311** — **Forensic Timeline & Chain of Custody:** جمع الأحداث والملفات المُصرح بها مع Hash وتوقيت موحد ومصدر وهوية المستخدم وتاريخ وصول لكل دليل؛ الاحتفاظ يخضع للحوكمة. [Digital forensics]
- **CG-312** — **Security Research Approval Gate:** لا تتحول معلومات عن استغلال جديد أو عينة برمجية أو Detection Rule عامة تلقائيًا إلى Scanner أو Exploit أو Block دون مراجعة بشرية للأصل والترخيص والنطاق والسلامة. [Secure research]
- **CG-313** — **AI Explains What It Does Not Know:** يذكر صراحة أين لا توجد حوادث أو سجلات كافية أو طريقة تحقق مؤكدة، ويقترح جمع أدلة إضافية؛ يمنع اختلاق IP/CVE/أوامر أو نسبة أمان. [AI reliability]
- **CG-314** — **SOC Learning Metrics:** مؤشرات قابلة للقياس: التغطية، نسبة حالات CASE المرتبطة بكشف مختبر، MTTD/MTTR، الدقة والتصنيف، نسبة الاستجابة الناجحة، حالات التراجع، المراقبة غير المدعومة. [SOC measurement]

## CASEBOOK — أدلة التعرف والاستجابة حسب أسلوب الهجوم

> كل صف نموذج تحقيق دفاعي وليس تقرير وقوع حادث على شبكة المستخدم. عند عدم وجود المصدر المطلوب، تعرض المنصة «غير قابل للتحقق» وليس «سليم».

| # | نمط الهجوم | الأدلة ذات الأولوية | إجراء الاحتواء/الإصلاح المقترح | حدود الاستدلال |
|---|---|---|---|---|
| 01 | Password Spraying | فشل دخول موزع بين حسابات ومصادر ثم نجاح غير معتاد | MFA مقاوم للتصيد، حماية حسابات، ضبط سياسات الدخول | قد تكون مشكلات مصادقة شرعية |
| 02 | RDP/SSH Lateral Movement | جلسات جديدة من جهاز مصدر لم يسبق له إدارة الهدف، وتزامن عمليات | مراجعة تصريح الوصول وتقييد المصدر أو الحساب | RDP شائع للدعم المشروع |
| 03 | DCSync Abuse | نسخ دليل من أصل/حساب خارج Baseline | مراجعة حقوق replication، حصر حسابات Tier0، حفظ الأدلة | أدوات مزامنة شرعية يمكنها النسخ |
| 04 | Shadow Credentials | تعديل خصائص اعتماد مفاتيح المستخدم/الجهاز خارج سير العمل | إبطال التغيير المعتمد، مراجعة الشهادات والجلسات | بعض أنظمة الهوية تعدلها شرعيًا |
| 05 | AD CS Abuse | شهادة أو قالب ذي صلاحيات مفرطة وطلب غير عادي | مراجعة القالب والإصدار وسحب شهادة مؤكدة بخطة | لا كل إصدار شهادة خطر |
| 06 | GPO Hijack | تعديل AD GPO وSYSVOL خارج نافذة تغيير متفق عليها | تجميد تغييرات مشبوهة والتحقق من سلامة GPO | نشر برامج مؤسسي قد يشبه الحدث |
| 07 | LSASS Credential Access | وصول عمليات غير معتاد إلى الذاكرة أو ملفات حساسة | عزل أصل مُدار إذا دعمت الأدلة، تدوير الاعتمادات | أدوات مراقبة شرعية قد تتداخل |
| 08 | Session Token Replay | جلسة من جهاز وسياق جديد رغم مصادقة سابقة | إلغاء الجلسة وإعادة مصادقة قوية وفحص الجهاز | VPN والسفر قد يغيران السياق |
| 09 | MFA Reset Social Engineering | إعادة تسجيل وسيلة تحقق للحساب العالي قبل تغيرات صلاحيات | تحقق مستقل من صاحب الحساب وإبطال الجهاز غير المعتمد | إعادة التسجيل عملية دعم عادية أحيانًا |
| 10 | OAuth App Consent Abuse | تفويض نطاقات عالية ثم قراءات بريد/ملفات غير معتادة | مراجعة التطبيق وسحب التفويض الضار | تطبيقات مؤسسية قد تحتاج النطاق |
| 11 | BEC Inbox Rule | قاعدة تحويل جديدة ورسائل أو نشاط قراءة خارج السلوك المعتاد | إلغاء التحويل الخبيث، حماية الجلسة، تدقيق التسرب | تحويل البريد المشروع شائع |
| 12 | VPN Gateway Compromise | دخول غير معتاد أو حساب إداري جديد أو تغير إعدادات | حصر الجلسات، تدوير كلمات السر، إغلاق إدارة الإنترنت | السجلات قد تكون ناقصة على الجهاز |
| 13 | Firewall Rule Tamper | قواعد Allow واسعة أو تعديل سياسة دون تذكرة | مقارنة Desired/Actual وتراجع مدروس | تغيير طارئ مشروع قد يحدث |
| 14 | Router DNS Hijacking | تغير Resolver وDNS forwarder أو تحويل وجهات غير متوقع | استعادة تكوين موثوق ومراجعة الأسرار | اختلاف DNS ليس دليلًا قطعيًا |
| 15 | Command-and-Control Channel | عملية جديدة مع DNS واتصال دوري غير مألوف | حظر وجهات مؤكدة وتقييد العملية بعد مراجعة | الخدمات السحابية قد تتصل دوريًا |
| 16 | Web Server Exploitation | Web request غير معتاد + child process/خدمة/egress | عزل الخدمة ضمن سياسة وتحديث/تدوير الأسرار | سجل الويب وحده لا يثبت نجاح استغلال |
| 17 | Malware Persistence | خدمة جديدة أو Scheduled Task غير مصرح به | مراجعة التوقيع والمسار والمصدر قبل التعطيل | أدوات الإدارة تنشئ خدمات شرعية |
| 18 | Defense Evasion | توقف Logs/EDR مع تعديلات سياسات/حماية | حماية القناة البديلة وتحقيق عاجل | Agent قد يتوقف بسبب عطل |
| 19 | Ransomware Pre-Encryption | محاولات إزالة Shadow Copies/تعطيل Backup ثم تغير ملفات جماعي | احتواء مقيّد لحفظ النسخ، حماية الهوية | برامج صيانة قد تنفذ عمليات مشابهة |
| 20 | NAS Backup Sabotage | حذف نسخ أو Reset/NAS config change خارج نافذة معتمدة | قفل إدارة النسخ وعزل صلاحياتها واستعادة نسخ سليمة | أعمال الصيانة تحتاج استثناءات معتمدة |
| 21 | Hypervisor Compromise | دخول إداري جديد لـvCenter/ESXi، تغيير Datastore، إطفاء VMs | حماية Management Plane، منع توسع الضرر بموافقة | عمليات تشغيل VM قد تكون شرعية |
| 22 | Cloud IAM Overreach | دور قديم مفتوح خارجيًا أو مفاتيح مهجورة أو Rights زائدة | خفض الامتياز بعد إثبات الحاجة والتبعية | بعض الأدوار الاستثنائية ضرورية |
| 23 | Cloud Container Compromise | Runtime process/network شاذ مع Kubernetes audit/Cloud API | عزل workload بموافقة وتدوير Secrets المتأثرة | التغطية تختلف حسب خدمة Cloud |
| 24 | Data Exfiltration | حجم نقل غير معتاد + تجميع ملفات + حساب/عملية مرتبطة | منع مسار مدعوم وحفظ أدلة وسجلات | نسخ احتياطي وتصدير مشروع قد يشبهه |
| 25 | Supply Chain Update Tamper | تحديث/Artifact غير موقع أو Digest مختلف عن الإصدار المعتمد | منع النشر والتحقق من المصدر وتدوير أسرار متأثرة | اختلاف Digest قد ينتج عن بناء شرعي |
| 26 | Insider Permission Abuse | دخول لمورد حساس خارج دور وظيفي أو تصريح واضح | مراجعة صفة المستخدم وموافقة الإدارة المختصة | عدم استنتاج نية خبيثة بلا تحقق |
| 27 | OT Unsafe Change | تغيير PLC/SCADA أو مسار تحكم خارج خطة السلامة | إنذار لمسؤول السلامة، مراقبة سلبية، خطة تشغيل | لا أوامر توقف آلي في OT |
| 28 | Unknown Anomaly | انحراف متعدد المصادر لا يطابق تقنية معروفة | فتح تحقيق واستخراج Baseline دون تصنيف جازم | الذكاء الاصطناعي لا يعلم الغيب |

## دراسات واقعية جديدة ومراجعها

| Case | التاريخ | الواقعة والدرس | موضع المرجع |
|---|---|---|---|
| CASE-16 | 2026-10-20 | **SafePay:** CISA/FBI وثقت مداخل عبر VPN واعتمادات مكشوفة وEdge vulnerabilities، وعرقلة التعافي باستهداف NAS وShadow Copies؛ الدرس كشف سلسلة الدخول إلى تدمير النسخ بدل البحث عن ملف الفدية فقط | [CISA SafePay Advisory](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/42fd782) |
| CASE-17 | 2026-06-18 | **Fortinet Credential Exposure:** تحذير CISA من استهداف أجهزة Fortinet المكشوفة باستخدام اعتمادات مسربة؛ استجابة تشمل انتهاء الجلسات وتدوير كلمات المرور وتحليل السجلات وإغلاق واجهات الإدارة العامة | [CISA Fortinet Advisory](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/41cb9c0) |
| CASE-18 | 2026-09-15 | **AD Detection Updates:** توسيع إرشادات DCSync/Shadow Credentials وإبراز أهمية Baseline؛ توجد ملاحظة تحريرية: الملخص الأسترالي يقول 18 تقنية بينما رسالة CISA ونص الوثيقة يقولان 17؛ نعتمد *عناوين النص الأساسي* قبل تحديد عدد رسمي نهائي | [ACSC guidance](https://www.cyber.gov.au/publication/detecting-and-mitigating-active-directory-compromises) |
| CASE-19 | 2026-03-23 | **M-Trends 2026:** الرؤية الضعيفة على Edge وأسلوب التسليم السريع بين مجموعات المهاجمين وازدياد التصيد الصوتي؛ علينا تسريع الرصد دون الاعتماد على EDR فقط | [Mandiant M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026) |
| CASE-20 | 2026-08-07 | **M365 Identity Campaigns:** CERT-In ينبه إلى Password Spraying وDevice-code phishing وToken abuse وBEC؛ نحتاج تحليل أحداث Microsoft 365/OAuth والبريد معًا | [CERT-In CIAD-2026-0037](https://www.cert-in.org.in/s2cMainServlet?VLCODE=CIAD-2026-0037&pageid=PUBVLNOTES02) |

## الأدوات/المصادر المكتشفة أو المدققة — ليست إضافات مثبتة

| المشروع/المصدر | الوظيفة المثبتة بالمصدر | المخاطر والقيود |
|---|---|---|
| [MITRE ATT&CK Detection Strategies](https://attack.mitre.org/detectionstrategies/) | استراتيجيات كشف مرتبطة بتقنيات مهاجم | تتغير الإصدارات؛ لا تعني تحقق المراقبة |
| [SigmaHQ Rules](https://github.com/SigmaHQ/sigma) | قاعدة كبيرة من قواعد الكشف والسلوك والبحث | قواعد تحتاج Backend وتوليف واختبار، لا تنقل مباشرة إلى إنتاج |
| [Sigma Correlation Specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md) | ربط أحداث متعددة زمنيًا أو بعددياتها | استعلامات بعض Backends لا تدعم الدلالة بدقة |
| [VECTR](https://github.com/SecurityRiskAdvisors/VECTR) | تتبع اختبارات Red/Purple/Blue Team ونجاح الكشف والمنع | يجب مراجعة EULA وتكلفة الإعداد؛ لا اختبار خارج مختبر |
| [Mandiant capa](https://github.com/mandiant/capa) | تحليل القدرات المحتملة للملفات التنفيذية دون تشغيلها | Static analysis محدود مع packing/obfuscation؛ sandbox آمن للعينات |
| [Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/what-is) | رصد هجمات الهوية والتصعيد والحركة الجانبية | تراخيص وموصلات ومراقبة DC مطلوبة |
| [Microsoft Entra Token Protection](https://learn.microsoft.com/en-us/entra/identity/devices/protecting-tokens-microsoft-entra-id) | توصيات لمنع Theft/Replay وإدارة المخاطر | MFA وحده لا يمنع جميع اختراقات الجلسات |
| [AWS IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html) | External/Internal/Unused Access findings | أنماط مدفوعة/محدودة وأنظمة موارد وأقاليم مختلفة |
| [AWS GuardDuty Runtime](https://docs.aws.amazon.com/guardduty/latest/ug/runtime-monitoring.html) | تغطية Runtime لموارد محددة وعبر Agent | لا يغطي كل وضع تشغيل EKS/Fargate، ويحتاج تفعيلًا |
| [Microsoft OAuth App Governance](https://learn.microsoft.com/en-us/defender-cloud-apps/app-governance-anomaly-detection-alerts) | اكتشاف أنماط OAuth/Inbox rule واستغلال البريد | يتوقف على مصدر الأذونات والتراخيص والتغطية |
| [CISA/ASD logging guide](https://www.cyber.gov.au/publication/best-practices-for-event-logging-and-threat-detection) | أولويات جمع السجلات وحفظها وربطها عبر الشبكة والسحابة | حجم التخزين والخصوصية وفترات الاحتفاظ |
| [MITRE ATT&CK v18 Data Model](https://mitre-attack.github.io/attack-data-model/docs/principles/attack-detections/) | تعريف Detection Strategies وAnalytics وData Components | يحتاج تحديث مخطط المعرفة بعد تغير نموذج MITRE |

## تصميم بطاقة الحادث التي ستظهر لاحقًا في تطبيق CyberGuard

**Incident ID → الاسم المحتمل → حالة الثقة → الأدلة → مصادر البيانات المطلوبة/المفقودة → المسار الزمني → الأصول والمستخدمون المتأثرون → درجة الخطورة → الآثار المحتملة → خيارات الاحتواء المتاحة فعليًا → مستوى الموافقة → معاينة الأثر → تنفيذ موثق (إن أذن المسؤول) → تحقق من النجاح → استعادة/تراجع → درس مستفاد → مرجع المصدر وتاريخ التحديث.**

**نموذج تمثيل نتيجة (بيانات افتراضية):**

- النمط: Suspected VPN Credential Compromise → Possible Lateral Movement.
- أدلة: دخول VPN من مصدر غير معتاد؛ تسجيل دخول بعيد بعدها إلى خادم حساس؛ ظهور تغيير سياسة خارج نافذة تغيير.
- لا يكفي لإثبات اختراق: كل حدث مفرد يمكن أن يكون مشروعًا. يجب مطابقة موافقة الوصول والـMFA والجهاز والوقت.
- الاستجابة المقترحة: طلب مراجعة الجلسة والسجلات ثم إنهاء جلسة مؤكدة غير معتمدة وتدوير الاعتماد، مع تأكيد وصول الإدارة البديلة.
- لا تنفيذ تلقائي لقطع Core Firewall أو إغلاق الجهاز، ولا إرسال أوامر تنفيذ من نص مولد بالـAI.

## ما لا نستطيع الجزم به بعد — موانع الانتقال للبروتوتايب

1. لم يتم اختبار أي من قواعد الكشف الجديدة، لذا لا يمكن إعطاء نسب نجاح أو عدد هجمات «محمية» فعليًا.
2. لا يمكن وعد المستخدم باكتشاف كل الاختراقات: Zero-day وحركة مشفرة وAgent معطل وشبكات خارج مجال الرؤية قد تفلت من الكشف.
3. نسب حوادث Mandiant تخص نطاق التحقيقات الوارد في التقرير وليست قياسًا لكل القطاعات.
4. تعارض 17/18 تقنية في وثائق AD الرسمية يستلزم مراجعة عناوين النص لا تقرير رقم نهائي بلا تحقق.
5. تراخيص Sigma/VECTR/capa والـBackends والتكاليف والاستضافة الحساسة بحاجة مراجعة تجارية وتقنية مستقلة.
6. نحتاج نموذج صلاحيات لكل إجراء: نسخ احتياطي آمن، OOB management، تصاريح Change، ومراجعة أثر العزل.
7. يجب بناء بروتوكول تقييم من سيناريوهات معروفة ومجهولة ومتوافقة مع سياسات بيئات الاختبار، وحساب True/False Positives وDetection Delay.
8. ينبغي اختبار موصلات AD/Cisco/Huawei/Windows/AWS/Azure/GCP في بيئات معزولة بالتصريح قبل وعد العميل بدعم منتج/إصدار.
9. لا توجد حاليًا عملية بحث مستقلة تعمل في الخلفية أو قاعدة تهديدات تُحدَّث تلقائيًا؛ البحث موثق هنا فقط.

**موعد الاستكمال:** CG-315. محاور الجولة التالية المقترحة: كشف الأنشطة الخفية في Linux وmacOS، الأجهزة الذكية والشبكات اللاسلكية، أمن المتصفحات والإضافات، قياس هجمات سلسلة التوريد والـCI/CD، حوكمة احتفاظ الأدلة والتشريعات، واختبارات تحمل استجابة المنصة في بيئات كبيرة. 


---

# ملحق v0.8 — تحقيق قانوني وتتبع مصدر الهجمات وجمع أدلة البلاغ

**تاريخ البحث:** 2026-11-10  
**النطاق:** Cyber Threat Attribution / Digital Forensics / Deception / Incident Reporting.  
**الحالة:** متطلبات بحث وتصميم فقط؛ لا اختراق مضاد أو فحص أوامر على بنية خارج التصريح.

## متطلبات جديدة (CG-315 إلى CG-328)

- **CG-315** مطلوب — صفحة **Attacker Intelligence** تعرض مؤشرات تقنية للحادث لا هوية شخصية مفترضة: IP، منفذ، طوابع زمنية، أسماء نطاقات، بصمات ملفات، اتصال C2 محتمل، وأنظمة الرصد التي أنتجت الأدلة.
- **CG-316** مطلوب — **Attribution Confidence Model** يقيس الثقة ويفصل بين *البنية التي صدر منها الاتصال* و*الجهة الفاعلة*؛ VPN/Proxy/Tor أو خادم مخترق قد يخفي هوية الفاعل ويمنع نسبتها من IP فقط.
- **CG-317** مطلوب — **Passive OSINT Enrichment** عبر RDAP/ASN وسمعة IP/domain وأدلة عامة، دون مسح أو استغلال أنظمة خارج نطاق التصريح، مع زمن المصدر والمصداقية.
- **CG-318** مطلوب — **Controlled Honeypot Zone** في بنية معزولة، تعزل أي بيئة خداع عن الإنتاج، ولا تسمح بإرسال هجمات إلى أطراف ثالثة أو باستضافة بيانات حقيقية حساسة.
- **CG-319** مطلوب — دراسة دمج **Cowrie** كحساس طُعم SSH/Telnet لتسجيل محاولات الدخول وسلوك التفاعل ضمن بيئة خاضعة لسيطرتنا؛ التوافق مع البيانات وسياسة الاحتفاظ أساسي.
- **CG-320** مطلوب — دراسة دمج **Canarytokens** وملفات وبيانات طُعم غير حقيقية ومحددة الاستخدام، مع إنذار عند الاستخدام، وآلية منع جمع بيانات شخصية غير ضرورية.
- **CG-321** مطلوب — **Forensic Evidence Collector** يجمع أحداث Windows/Linux/AD/Firewall/Network/Cloud التي نملك صلاحيتها، مع طابع زمني موحد وتحديد مصدر كل دليل، ويمنع التعديلات المدمّرة للأدلة.
- **CG-322** مطلوب — **Chain of Custody**: سجل من جمع الدليل ومتى ومن اطلع عليه، SHA-256 للتحقق من سلامته، فصل الأصل عن نسخ التحليل، صلاحيات وصول، وسياسة احتفاظ وتشفير.
- **CG-323** مطلوب — **Incident Case Builder**: رقم قضية، خط زمني، الأصول المتأثرة، السلوك/أسلوب ATT&CK المرصود، مستوى الثقة، الإجراءات المتخذة، أدلة غير معدّلة، وما بقي مجهولًا.
- **CG-324** مطلوب — **Reporting Pack Generator**: ملف PDF/JSON/ZIP لإرفاق الأدلة (حسب الجهات المصرح لها)، يتضمن ملخصًا واضحًا وHash وسجل الإجراءات مع تصنيف الحساسية وتنقيح الأسرار قبل التسليم.
- **CG-325** مطلوب — **Reporting Route Assistant**: للأفراد في السعودية خدمة «بلاغات الجرائم المعلوماتية» عبر تطبيق الجهات الأمنية؛ ولحوادث الجهات الوطنية قناة الهيئة الوطنية للأمن السيبراني الرسمية؛ التحقق من الجهة المختصة قبل عرض مسار التقرير.
- **CG-326** مطلوب — **Abuse Desk Escalation**: ربط IP بجهة الاستضافة/الشبكة عبر بيانات عامة، وإعداد إشعار Abuse للمزود دون نشر اتهام شخصي أو إفشاء بيانات سرية دون موافقة.
- **CG-327** قيد سلامة — **No Hack Back**: يحظر دخول أجهزة أو حسابات المشتبه بهم دون تفويض قانوني منفصل؛ حتى مع هجوم وارد لا يساوي ذلك تصريحًا بالاختراق المضاد.
- **CG-328** مطلوب — **Evidence-First Response**: وقف الضرر وعزل الأصول المملوكة، حفظ سجلات قبل ضياعها، وعدم الاتصال بالبنية المشتبه بها للتجسس أو الثأر، مع إبقاء قناة عمل قانونية للمحققين.

## سيناريو دفاعي CASE-21 — اتصال SSH مشبوه من عنوان خارجي

**الحادث الافتراضي:** يسجل حساس مصرح به محاولة دخول إلى خدمة وهمية.  
**ما يمكن معرفته:** وقت المحاولة، عنوان المصدر المرئي، أسماء المستخدمين التي جُربت وفق السجل، وسلوك التفاعل أو الملفات في الطُعم إذا توفرت.  
**ما لا يمكن إثباته:** الاسم الحقيقي أو العنوان الفعلي للمهاجم؛ عنوان المصدر قد يعود إلى VPN أو Proxy أو جهاز ضحية.  
**التحقيق:** مطابقة الأحداث مع سجلات جدارنا الناري، إثراء RDAP/ASN، فحص مؤشرات الملفات دون تشغيل ضار، تجميع بصمات الأدلة وحفظ الأصل.  
**الاستجابة:** عزل مواردنا المتأثرة، حظر محدد بشروط إن لزم، إخطار الأمن الداخلي أو الجهة المخولة، تجهيز حزمة بلاغ. لا دخول لنظام الطرف الآخر.

## مسارات الإبلاغ الموثقة (تُراجع قبل استخدامها)

- البلاغات الفردية عن الاختراق وسرقة الحسابات: [المنصة الوطنية — بلاغات الجرائم المعلوماتية](https://my.gov.sa/.well-known/services/398352)، عبر التطبيق المشار إليه في الخدمة.
- حوادث الأمن السيبراني المتعلقة بجهة وطنية: [NCA — الإبلاغ عن حادثة أمن سيبراني](https://nca.gov.sa/ar/report-incident/)؛ تذكر الصفحة 936 وis@nca.gov.sa، مع مراعاة صلاحية الجهة المبلّغة والإجراءات المؤسسية.
- خدمة الاستجابة لدى الهيئة للجهات: [NCA — الاستجابة للحوادث السيبرانية](https://nca.gov.sa/ar/services/cyber-incident-response/).
- إن كان الأمر متعلقًا بمخالفة سيبرانية تنظيمية، وليس حادثة اختراق، توجد [خدمة الإبلاغ عن مخالفة أمن سيبراني](https://nca.gov.sa/en/services/report-a-cybersecurity-violation/) بمسار مستقل.
- [نظام مكافحة جرائم المعلوماتية السعودي](https://laws.boe.gov.sa/BoeLaws/Laws/SearchDetails/?Id=25df73d6-0f49-4dc5-b010-a9a700f2ec1d&Query=%D8%AC%D8%B1%D8%A7%D8%A6%D9%85) يعرّف الدخول غير المشروع؛ لا نعتبر تلقي هجوم تصريحًا بدخول جهاز صاحبه.

## مصادر تقنية موثوقة

- [NIST SP 800-86 — Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final) — أدلة أنظمة وشبكات وسجلات، وضوابط التعامل مع النسخ والأصل.
- [MITRE D3FEND — Deceive](https://d3fend.mitre.org/tactic/d3f%3ADeceive/) — تعريف Honeypots/Decoy Objects/Honeytokens.
- [Cowrie Project](https://github.com/cowrie/cowrie) — مشروع تسجيل التفاعلات مع SSH/Telnet الوهميين.
- [Thinkst Canarytokens](https://github.com/thinkst/canarytokens) — إشارات طُعم للكشف عند الاستخدام.
- [ICANN RDAP](https://www.icann.org/rdap/) — بيانات تسجيل النطاقات وليس تعريف الشخص وراء الهجوم.

## تنبيه النطاق والضمانات

- لا يمكن ضمان معرفة «كل شيء عن المخترق» أو ربط IP بمواطن حقيقي أو نسبة هجوم لدولة دون تحقيق متعدد المصادر ومعلومات من الجهات المختصة.
- يحفظ المشروع الأدلة ذات الصلة فقط، مع التقليل من البيانات الشخصية والامتثال للخصوصية.
- الدفاع الخداعي (deception) يُنفذ داخل بيئة نملكها، وبشكل منفصل عن الشبكات الإنتاجية الحساسة؛ أي تفاعل خارج نطاقها يحتاج تفويضًا مستقلًا.
- **نقطة الاستكمال التالية: CG-329**. لا برمجة ولا بروتوتايب ولا تنفيذ اختبار فعلي حتى يأذن المستخدم.


---

# جولة بحث v0.9 — GitHub والأدوات الدفاعية والتكاملات والقيود

**تاريخ البحث:** 2026-11-10 (Asia/Riyadh)  
**التراكم:** حفظ CG-001 إلى CG-328 دون حذف؛ إضافة CG-329 إلى CG-408 (80 متطلبًا جديدًا).  
**حدود هذه الجولة:** مراجعة وثائق ومشاريع منشورة فقط. لم تُثبَّت أو تُشغَّل الأدوات، ولم تُختبر أنظمة أو شبكات حقيقية.

**نتيجة بحثية مركزية:** لا يكفي مستودع GitHub عظيم أو عشرات آلاف القواعد وحدها؛ نجاح النظام يتطلب بيانات صحيحة وتغطية معروفة وتوافق المحرك واختبارات كشف وتحكمًا بالتغييرات وحوكمة ترخيص وتكلفة.


## 46 — قواعد الكشف وتدقيق جودة البيانات (CG-329–CG-338)

- **CG-329** مطلوب — Detection Coverage Matrix: كل سلوك ATT&CK له مصادر أدلة مفترضة ومصادر متاحة فعليًا ونسبة التغطية ودرجة الثقة والفجوات.
- **CG-330** مطلوب — Detection Content Registry: تخزين مصدر القاعدة وإصدارها وترخيصها ومراجعتها وربطها بالتقنيات والـOS والحقول المطلوبة.
- **CG-331** بحث — تصنيف Sigma إلى Generic/Hunting/Emerging Threats لمنع التعامل مع قواعد البحث الواسعة كأدلة اختراق مؤكدة.
- **CG-332** مطلوب — Correlation Compatibility: اختبار دعم count/temporal/value_count لكل محرك SIEM، وإظهار القواعد غير المدعومة بوضوح.
- **CG-333** قيد قانوني — مراجعة Elastic License v2 قبل إدماج قواعد Elastic Detection Rules داخل منتج يُوزع أو يُباع؛ لا نفترض إعادة ترخيصها.
- **CG-334** بحث — استلهام قاعدة بيانات Splunk Security Content (detections, baselines, macros, analytic stories, playbooks) مع تقييم الترخيص وتوافق صيغ البحث.
- **CG-335** مطلوب — Schema Contract & Mapping: توحيد بيانات المصدر والحقول عبر OCSF/محوّلات شفافة، مع اختبار فقد المعلومات أثناء التحويل.
- **CG-336** مطلوب — Windows Audit Readiness: التحقق من تفعيل سجلات Security وSysmon وPowerShell والحد الأقصى للحجم والاحتفاظ والمناطق الزمنية.
- **CG-337** مطلوب — Rule Test Corpus: ملفات EVTX/PCAP وسيناريوهات صناعية أو مختبرية آمنة بإجابات متوقعة لاختبارات الانحدار مع كل تحديث.
- **CG-338** مطلوب — Rule Lifecycle QA: تقييم الاستدعاء/الدقة والضجيج والأثر على الموارد وحالات false positive ونشر آمن مع رجوع للإصدار السابق.

## 47 — التحقيق الجنائي وتحليل الأجهزة (CG-339–CG-348)

- **CG-339** بحث — Velociraptor Connector: جمع أدلة endpoints المملوكة بقوالب استعلام معتمدة وسجلات تنفيذ وضبط حجم البيانات وتحكم بالصلاحيات.
- **CG-340** بحث — Hayabusa Offline Analyzer: تحويل EVTX إلى Timeline وتطبيق قواعد Sigma واستخدامه عندما لا يعمل Agent بصورة دائمة.
- **CG-341** بحث — Chainsaw Fast Triage: تحليل EVTX والأدلة المرتبطة وقياس الفجوات في EventRecordID والزمن كإشارات تحتاج تأكيدًا.
- **CG-342** بحث — Plaso Timeline Parser: توحيد الأحداث الزمنية من نظم وملفات متعددة مع الاحتفاظ بالمصدر الأصلي لكل توقيت.
- **CG-343** بحث — Timesketch Investigation Workspace: تعليقات المحللين على تسلسلات الأدلة دون المساس بالنسخ الأصلية.
- **CG-344** بحث — Volatility 3 Memory Forensics: تحليل صورة RAM مُصرح بها من دون تنفيذ ملفات ضارة، وتوثيق قيود توافق الذاكرة.
- **CG-345** قيد ترخيص — Dissect Forensics: تحليل E01/VMDK/QCOW2 وWindows/Linux/ESXi؛ مراجعة AGPL-3.0 قبل استخدام أجزاء منه في المنتج.
- **CG-346** مطلوب — Evidence Collection Profiles: ملفات جمع متدرجة (Minimum/Standard/Deep) مع موافقات للذاكرة والملفات الحساسة.
- **CG-347** بحث — Linux Runtime Coverage: Falco للكشف من syscall وحساسات الحاويات، مع اختبار توافق kernel والأداء.
- **CG-348** بحث — macOS Protection Adapter: Santa لمراقبة والتحكم بتشغيل البرامج إذا كان النظام مُدارًا وتوافرت صلاحيات macOS المطلوبة.

## 48 — رؤية حركة الشبكة وحساسات NDR (CG-349–CG-358)

- **CG-349** بحث — Zeek Protocol Telemetry: تحليل بروتوكولات وحالة الاتصالات وتحويل السجلات إلى نمط CyberGuard الموحد.
- **CG-350** بحث — Suricata IDS/IPS Policy: البدء بـIDS/Alert ثم دراسة IPS Inline مستقلة وتحليل أثر قطع المرور والتوافر.
- **CG-351** بحث — Arkime Full Packet Investigation: حفظ PCAP موسوم ومشفّر بسياسة قصيرة ومحددة وواجهة بحث مع حماية الخصوصية.
- **CG-352** بحث — RITA Behavioral Analytics: تحليل Beaconing والاتصالات الطويلة وDNS tunneling من Zeek مع معايرة الإشارات والضجيج.
- **CG-353** بحث — Malcolm Evaluation: دراسة حزمة CISA لتحليل Zeek/Suricata/PCAP وتحديد ما إن كان اعتمادها الكامل ثقيلاً على PC.
- **CG-354** بحث — IVRE Inventory: استخدام اكتشاف/رؤية سلبية أولًا وربط المسح النشط بقائمة نطاق وتوقيت ومعدل مصرح بها.
- **CG-355** مطلوب — Network Sensor Coverage Map: عرض منافذ SPAN/TAP/VPC Flow وعمق الرؤية وتحديد حركة East-West غير المرئية.
- **CG-356** مطلوب — Encrypted Traffic Limitations: رصد TLS metadata وشهادات وسلوك وجهة الاتصال دون ادعاء قراءة محتوى مشفّر بلا تصريح أو مفاتيح.
- **CG-357** مطلوب — Attribution Boundaries: فصل الـNAT والـVPN والـproxy والبنية الوسيطة عن الهوية الشخصية وتوثيق مستوى الثقة.
- **CG-358** مطلوب — Network Telemetry Cost: ميزانية PCAP/Flow/Zeek وSampling وسياسة الاحتفاظ وإشعار عند فقد الحزم أو أحداث الرصد.

## 49 — الثغرات وترتيب إصلاحها (CG-359–CG-368)

- **CG-359** مطلوب — CVE Source of Record: استيراد CVE JSON v5 الرسمي بالتغييرات الدورية مع ربط رقم المنتج/الإصدار وعدم اعتبار كل CVE إصابة محققة.
- **CG-360** مطلوب — KEV Prioritization: رفع أولوية الثغرات المؤكدة الاستغلال مع البحث عن مؤشرات اختراق قبل/بعد التحديث.
- **CG-361** مطلوب — NVD Enrichment Gap: عدم اعتبار غياب CVSS أو CVE enrichment على NVD دليلًا على عدم وجود خطر؛ تحديد مصدر بديل.
- **CG-362** مطلوب — EPSS Context: عرض احتمال الاستغلال خلال 30 يومًا كإشارة إحصائية مستقلة وليس تقييم خطر المؤسسة الكامل.
- **CG-363** بحث — SSVC Response Decision: تصنيف Track/Track*/Attend/Act بالاستناد إلى التأثير والسياق، وليس الرقم CVSS فقط.
- **CG-364** مطلوب — Risk-by-Asset: إضافة حساسية الأصل والتعرض الخارجي ووجود استغلال وشروط التخفيف وأثر التعطيل إلى ترتيب الإصلاح.
- **CG-365** بحث — Greenbone/OpenVAS Connector: الفحص النشط فقط وفق نطاق معتمد وبطء مناسب ووسم احتمالات تأثر الأنظمة القديمة.
- **CG-366** بحث — Nuclei Template Governance: فحص سلامة مصدر الـTemplates وفصل القوالب غير التدخلية عن القوالب العالية التأثير قبل التفعيل.
- **CG-367** بحث — Dependency Vulnerability Matrix: مقارنة Trivy وGrype وOSV Scanner مع اختلاف قواعد البيانات والإصدارات لتقليل النتائج الخاطئة.
- **CG-368** مطلوب — SBOM + VEX: توليد قائمة مكونات بـSyft وإرفاق حالة قابلية التأثر وتوثيق أسباب عدم التأثر بدل إخفاء النتائج.

## 50 — الهوية والسحابة والأنظمة متعددة المنصات (CG-369–CG-378)

- **CG-369** بحث — BloodHound Risk Graph: استيراد علاقات AD/Entra المصرّح بها لإظهار مسارات الصلاحيات غير المقصودة ومقترحات تقليلها.
- **CG-370** بحث — PingCastle Domain Health: تقييم وضع AD على شكل Snapshots منفصلة، مع مراجعة شروط الترخيص وتجربة المجال.
- **CG-371** قيد سلامة — AD CS Assessment: مراجعة قوالب الشهادات والـCA بالقراءة فقط؛ لا تختلط مع إمكانات الاستغلال المتوفرة في أدوات الفحص المزدوج.
- **CG-372** بحث — Cloudsplaining IAM: اكتشاف صلاحيات AWS الزائدة وتحديد مسارات قراءة الأسرار أو البيانات خارج مبدأ أقل امتياز.
- **CG-373** بحث — Prowler Cloud Posture: تقييم AWS/Azure/GCP/M365/GitHub/OCI بحسب دعم النسخة؛ تعريف المطلوب من APIs وصلاحيات read-only.
- **CG-374** بحث — ScoutSuite Snapshot: مقارنة تقارير cloud point-in-time وعدم اعتبارها مراقبة آنية أو استجابة مستقلة.
- **CG-375** بحث — Google Cloud Security Analytics: استخدام عينات Cloud Audit وVPC Flow وDNS بقواعد تحتاج تكييفًا للبيئة.
- **CG-376** مطلوب — Service Identity Register: جرد حسابات الخدمة والتطبيقات ومفاتيح CI/CD وToken lifetime وتغييرات الأذونات.
- **CG-377** مطلوب — Cross-Cloud Identity Mapping: تجميع ما إذا كان نفس الشخص/التطبيق مرتبطًا بحسابات AWS/Azure/GCP دون خلط الثقة بين الموفرين.
- **CG-378** بحث — Kubernetes Runtime/Policy: مقارنة Tetragon وFalco وKubescape وkube-bench بحسب المراقبة والإنفاذ والامتثال.

## 51 — معلومات التهديدات وتحليل البرمجيات الخبيثة (CG-379–CG-388)

- **CG-379** بحث — MISP Threat Feed: استيراد مؤشرات التهديد مع TLP وأذونات التوزيع وصلاحية المؤشر والسياق والمصدر.
- **CG-380** بحث — OpenCTI STIX Graph: ربط التقرير بجهة نشره وتاريخه وادعاءات النسبة للمهاجم ومستوى الثقة.
- **CG-381** بحث — IntelOwl Enrichment: استعلام IP/domain/hash عبر موصلات متعددة مع حجب الأسرار والبيانات الحساسة عن الخدمات الخارجية.
- **CG-382** قيد ترخيص — YARA/IOC Repository Vetting: فحص ترخيص Signature-Base DRL 1.1 وغيرها قبل إعادة التوزيع ولا نفترض أن الملفات صالحة لكل محرك.
- **CG-383** بحث — YARA-X File Triage: قواعد موقعة أو مراجعة لتمييز أنماط الملفات مع تقارير False Positive وعدم الحذف التلقائي.
- **CG-384** بحث — capa Static Capabilities: تفسير قدرات الملف المشبوه كاحتمالات لا إثبات لسلوك وقع داخل الشبكة.
- **CG-385** قيد سلامة — Malware Artifact Handling: حفظ عينات مجهولة في مخزن معزول بلا تنفيذ تلقائي وحظر إرسالها لخدمات خارجية دون موافقة.
- **CG-386** مطلوب — Indicator Provenance: توثيق first/last-seen والمصدر والتاريخ والطابع القانوني والموثوقية لكل IP/Domain/Hash.
- **CG-387** مطلوب — Indicator Expiration: انتهاء الحظر القائم على IP تلقائيًا أو مراجعته حتى لا تستمر سمعة قديمة على عنوان متغير المالك.
- **CG-388** مطلوب — Untrusted Intel Guard: عزل النصوص والتعليمات داخل تقارير التهديد عن نظام تنفيذ CyberGuard وAI Analyst.

## 52 — إجراءات المنع والعزل الآمن (CG-389–CG-398)

- **CG-389** بحث — CrowdSec Decoupled Response: فصل محرك تحليل السجلات عن بواعث المنع مع Dry Run وتجنب الحظر الخاطئ للأصول الحرجة.
- **CG-390** بحث — OWASP CRS + Coraza WAF: مراجعة قواعد تطبيقات الويب في Audit Mode ومعايرة الاستثناءات قبل المنع.
- **CG-391** مطلوب — Temporary Permit Ledger: صلاحية من-إلى ومصدر ووجهة وبورت ومدة ووثيقة اعتماد وانتهاء تلقائي قابل للتحقق.
- **CG-392** مطلوب — Policy Diff & Impact: مقارنة قواعد Firewall الحالية بالمقترحة قبل التطبيق وملاحظة الأصول/الاتصالات المتضررة المحتملة.
- **CG-393** مطلوب — Emergency Access Preservation: منع عزل DC أو VPN concentrator أو hypervisor أو منفذ uplink دون خطة وصول بديلة.
- **CG-394** بحث — Network Change Verification: دراسة Batfish لتحليل وصول ACL وتبعات التغيير قبل تعديل أجهزة فعلية.
- **CG-395** بحث — Network Multivendor Adapter: دراسة NAPALM وربط مصفوفة القدرات الفعلية والإصدار والبائع والصلاحيات.
- **CG-396** بحث — Network Desired State: دراسة Nautobot لمقارنة الحالة المرغوبة بالحالة الملاحظة مع مراجعات وتدقيق للتغييرات.
- **CG-397** مطلوب — Response Transaction Log: تسجيل الطلب/الموافقة/أمر التنفيذ/النتيجة/خطوة التراجع بترتيب زمني لا يقبل التعديل من المحلل.
- **CG-398** مطلوب — Safe Recovery Gate: لا يعتبر الحظر أو العزل ناجحًا قبل اختبار الاتصال البديل وحفظ القدرة على الاستعادة.

## 53 — متطلبات المنتج المؤسسي وحوكمة GitHub (CG-399–CG-408)

- **CG-399** بحث — DFIR-IRIS Case Integration: تحقيقات تعاونية وربط أحداث وأدلة بملف قضية منفصل عن التنبيهات الخام.
- **CG-400** بحث — Forensic Timeline Collaboration: الجمع بين Plaso وTimesketch وVelociraptor وVolatility 3 حسب الدليل والنظام.
- **CG-401** مطلوب — Tenant + Site Isolation: فصل أذونات وبيانات مؤسسات متعددة وعدم السماح لمحلل واحد بجمع معلومات خارج النطاق.
- **CG-402** مطلوب — Privacy by Design: تقليل PCAP والرسائل والأسماء الحساسة وتشفير البيانات ومنع إدخالها إلى AI خارجي دون سياسة.
- **CG-403** مطلوب — Connector Supply-Chain Security: مراجعة إصدار وHash وتوقيع ومصدر كل موصل وقاعدة تحديث قبل التثبيت.
- **CG-404** مطلوب — OSS Licensing Matrix: GPL/AGPL/Elastic License/DRL/Apache/Commercial terms وتسجيل قرار embed/sidecar/reference لكل مشروع.
- **CG-405** مطلوب — Resource Envelope: فصل نموذج PC خفيف عن المحركات الثقيلة التي تحتاج Linux/server وتحديد RAM/CPU/storage/SLO لكل عنصر.
- **CG-406** مطلوب — SOC Quality Indicators: MTTD/MTTR ودقة التنبيه وفقد الأحداث وزمن الاستجابة ونسبة إغلاق التذاكر وتغطية الاستشعار.
- **CG-407** مطلوب — GitHub Research Governance: تقييم نشاط المستودع والترخيص والتنبيهات الأمنية وقابلية الصيانة قبل اعتبار أي كود صالحًا للدمج.
- **CG-408** مطلوب — Pre-Prototype Readiness Gate: اختيار 10 حالات اختبار دفاعية رئيسية مع بيانات اختبار قانونية ومقاييس نجاح/فشل واضحة.

## نتيجة البحث: مصفوفة مقارنة الأدوات — ليست قائمة تثبيت

| المجال | المشاريع الرسمية التي راجعتها | طريقة الإفادة | تحذير/قيد |
|---|---|---|---|
| Detection Engineering | SigmaHQ, Elastic Detection Rules, Splunk Security Content, Hayabusa Rules | قواعد وتحقق وتغطية | تنوع التراخيص وصيغ المحركات واحتياج سجلات مناسبة |
| Windows DFIR | Velociraptor, Hayabusa, Chainsaw, Plaso, Timesketch | جمع الأدلة وإنشاء Timeline | موارد وأذونات وحفظ الأصل |
| Memory/Images | Volatility 3, Dissect | أدلة RAM والقرص | حساسية العينات وتوافق الصيغ وترخيص AGPL لـDissect |
| Malware | YARA-X, capa, Signature-Base | أنماط الملفات وقدراتها | عدم حذف الملفات أو تنفيذها بلا تحقق؛ تراخيص القواعد |
| NDR/Packets | Suricata, Zeek, Arkime, RITA, Malcolm | إنذارات وبروتوكولات وجلسات وتحليل سلوك | SPAN/TAP والخصوصية وتكلفة الاحتفاظ |
| Discovery & Network | IVRE, Nautobot, NAPALM | جرد ووضع الشبكة المرجعي وتكاملات | فحص نطاقات مصرّح بها فقط؛ دعم البائعين متفاوت |
| Vulnerabilities | Nuclei, Greenbone, Trivy, Grype, OSV Scanner | قياس الثغرات والتكوينات | اختبارات نشطة قد تسبب أثرًا على الإنتاج |
| Software Supply Chain | Syft, Grype, Semgrep, Gitleaks, TruffleHog | SBOM وثغرات الكود والأسرار | فحص الأسرار في نطاق مملوك ومنع تسرب النتائج |
| AD & Identity | BloodHound, PingCastle, Cloudsplaining | مسارات امتياز وIAM ضعيفة | بيانات الرسم حساسة؛ استخدام القراءة فقط قدر الإمكان |
| Cloud | Prowler, ScoutSuite, GCP Community Security Analytics | قياس وضع الأمن ومراقبة الأصول | بعض النتائج لحظية فقط، ودعم النسخ/الخدمات متفاوت |
| Linux/Kubernetes/macOS | Falco, Tetragon, Kubescape, kube-bench, Santa | كشف وتشغيل وامتثال وسياسات | إنفاذ Linux/macOS يحتاج صلاحيات وتأثير الأداء |
| Threat Intel | MISP, OpenCTI, IntelOwl | مؤشرات وروابط المصدر والتقارير | جودة المعلومات والخصوصية والاتهام الخاطئ |
| Web/Blocking | CrowdSec, OWASP CRS, Coraza | تحليلات السجلات وWAF وحظر مقيّد | حظر خاطئ قد يسبب انقطاع خدمة |
| Cases/Automation | DFIR-IRIS, Shuffle | إدارة الحوادث والإجراءات | مراجعات بشرية وحماية مفاتيح التكامل |

## دراسات سيناريوهات دفاعية إضافية (افتراضية ولا تُعد مؤشرات اختراق مؤكدة)

### CASE-22: عمليات دخول Windows مشبوهة ثم إنشاء خدمة جديدة
- **المصادر:** Windows Security/Service Control Manager وSysmon إن توفر.
- **الربط:** فشل متكرر ثم دخول ناجح + خدمة جديدة + اتصال شبكة غير مألوف.
- **القرار:** الاشتباه مشروط بملكية الحساب ووجود تذكرة تغيير/أداة إدارة رسمية.
- **الاستجابة:** جمع الأدلة ومراجعة الخدمة والتصريح، وطلب عزل الجهاز فقط عند الضرورة وبموافقة.
- **الاختبار:** سجلات EVTX اصطناعية أو محفوظة قانونيًا، والتحقق من عدم تنبيه نشاط الإدارة المعتمد بلا داعٍ.

### CASE-23: Beaconing أو DNS Tunneling محتمل
- **المصادر:** Zeek DNS/conn، RITA، Firewall/DNS logs.
- **الربط:** دورية الاتصالات، عدد أسماء فرعية كبير، سلوك غير معتاد، تطبيق متسبب.
- **التقييد:** بعض برامج النسخ الاحتياطي والتحديث تنتج نمطًا دوريًا مشروعًا؛ ليست كل الإشارات ضارة.
- **الاستجابة:** إثراء الوجهة والعملية، ثم تقييد اتصال محدد إن كانت الأدلة قوية.

### CASE-24: تعديل صلاحيات تطبيق سحابي
- **المصادر:** Entra ID/AWS IAM/GCP audit logs وفق الخدمة.
- **الربط:** تفويض واسع + إنشاء مفتاح أو token + وصول إلى بيانات حساسة غير معتاد.
- **الاستجابة:** تدقيق التفويض وسحب الامتياز أو المفتاح المتضرر بموافقة، وحفظ سجلات API.
- **الاختبار:** حساب تجريبي مع صلاحيات منخفضة وتغيير مصرح به في مختبر.

### CASE-25: ثغرة CVE موجودة لكن أولوية المعالجة غير واضحة
- **المصادر:** CVE JSON v5 + NVD + CISA KEV + FIRST EPSS + جرد المكونات + تعرض الأصل.
- **الربط:** تحقّق الإصدار والحزمة ومسار الوصول والتأثر الفعلي قبل اعتماد الخطر.
- **القرار:** لا تكفي CVSS أو EPSS منفردة؛ أثر الأصل وKEV وإمكانية الوصول وSSVC تحدد الأولوية.
- **الإجراء:** تصحيح/تقييد/عزل مؤقت بحسب التأثير والاختبار.

### CASE-26: تغيير قاعدة Firewall يعطل خدمة أعمال
- **المصادر:** Configuration Diff، مصدر الحقيقة Nautobot، وصول الشبكة وفق Batfish حيث يدعم الجهاز.
- **الربط:** منفذ يحمل عدة أجهزة أو خدمة تعتمد على قاعدة سيُطلب حجبها.
- **الإجراء:** منع تطبيق تغيير عالِ المخاطر دون خطة وصول بديلة وRollback وموافقة.
- **التحقق:** مقارنة حالة الوصول قبل/بعد وإظهار أي اتصالات فُقدت.

### CASE-27: تسريب مفتاح API عبر مستودع برمجي
- **المصادر:** مستودع المؤسسة المصرح به، Gitleaks/TruffleHog، سجلات استخدام المفتاح لدى الموفر.
- **الإجراء:** إلغاء/تدوير المفتاح ومراجعة الاستخدام قبل الحذف والتأكد من عدم تعريض الأسرار للـAI أو خدمات خارجية.
- **التحقق:** نموذج بيانات تجريبي ومفتاح وهمي غير صالح للإنتاج.

## أولوية البحث بعد v0.9

1. بناء **Data Requirement Matrix** مفصلة لـ40 نمط تهديد؛ لكل نمط حقول وأحداث وتغطية ومخاطر أخطاء الكشف.
2. تقييم جدوى Windows PC مقابل Linux VM: الموارد، التخزين، دعم الميزات دون تثبيت شامل.
3. مراجعة حماية قواعد البيانات: SQL Server Audit وPostgreSQL pgaudit وOracle Unified Auditing ومصادر الأدلة الصالحة.
4. حماية Wi-Fi/IoT و802.1X وNAC في Cisco/Huawei وتحديد أوضاع المراقبة غير التدخلية.
5. مراجعة قيود تراخيص جميع المشاريع قبل اعتماد بنية تجارية.
6. تصميم 10 اختبارات دفاعية مختبرية آمنة والقبول بناءً على قياس النتائج.
7. متابعة دراسات إساءة استخدام AI والمساعدين الأمنيين وPrompt Injection وسلامة بيانات المصادر.

## مصادر أصلية مدققة لهذه الجولة — 2026-11-10

- [MITRE Detection Strategies](https://attack.mitre.org/detectionstrategies/) — استراتيجيات كشف مختلفة عن Data Sources القديمة؛ [Analytics](https://attack.mitre.org/analytics/).
- [SigmaHQ](https://github.com/SigmaHQ/sigma), [Hayabusa](https://github.com/Yamato-Security/hayabusa), [Hayabusa Rules](https://github.com/Yamato-Security/hayabusa-rules), [Chainsaw](https://github.com/WithSecureOpenSource/chainsaw), [Windows Logging Guidance](https://github.com/Yamato-Security/EnableWindowsLogSettings).
- [Elastic Detection Rules](https://github.com/elastic/detection-rules), [Splunk Security Content](https://github.com/splunk/security_content), [FalconFriday](https://github.com/FalconForceTeam/FalconFriday).
- [Velociraptor](https://github.com/Velocidex/velociraptor), [Plaso](https://github.com/log2timeline/plaso), [Timesketch](https://github.com/google/timesketch), [Dissect](https://github.com/fox-it/dissect), [Volatility 3](https://github.com/volatilityfoundation/volatility3), [DFIR-IRIS](https://github.com/dfir-iris/iris-web).
- [YARA-X](https://github.com/VirusTotal/yara-x), [capa](https://github.com/mandiant/capa), [Signature-Base](https://github.com/Neo23x0/signature-base).
- [Suricata](https://github.com/OISF/suricata), [Zeek](https://github.com/zeek/zeek), [Arkime](https://github.com/arkime/arkime), [RITA](https://github.com/activecm/rita), [CISA Malcolm](https://github.com/cisagov/Malcolm), [IVRE](https://github.com/ivre/ivre).
- [Nautobot](https://github.com/nautobot/nautobot), [NAPALM](https://github.com/napalm-automation/napalm), [BloodHound](https://github.com/SpecterOps/BloodHound), [PingCastle](https://github.com/netwrix/pingcastle), [Cloudsplaining](https://github.com/salesforce/cloudsplaining).
- [Prowler](https://github.com/prowler-cloud/prowler), [Scout Suite](https://github.com/nccgroup/ScoutSuite), [GCP Security Analytics](https://github.com/GoogleCloudPlatform/security-analytics), [Falco](https://github.com/falcosecurity/falco), [Tetragon](https://github.com/cilium/tetragon), [Santa](https://github.com/northpolesec/santa), [Kubescape](https://github.com/kubescape/kubescape), [kube-bench](https://github.com/aquasecurity/kube-bench).
- [Nuclei](https://github.com/projectdiscovery/nuclei), [Greenbone](https://github.com/greenbone/openvas-scanner), [Trivy](https://github.com/aquasecurity/trivy), [Grype](https://github.com/anchore/grype), [Syft](https://github.com/anchore/syft), [OSV Scanner](https://github.com/google/osv-scanner), [Semgrep](https://github.com/semgrep/semgrep), [Gitleaks](https://github.com/gitleaks/gitleaks), [TruffleHog](https://github.com/trufflesecurity/trufflehog).
- [MISP](https://github.com/MISP/MISP), [OpenCTI](https://github.com/OpenCTI-Platform/opencti), [IntelOwl](https://github.com/intelowlproject/IntelOwl), [CrowdSec](https://github.com/crowdsecurity/crowdsec), [OWASP CRS](https://github.com/coreruleset/coreruleset), [Coraza](https://github.com/corazawaf/coraza).
- [Official CVE List JSON 5](https://github.com/CVEProject/cvelistV5), [NIST NVD](https://www.nist.gov/itl/nvd), [FIRST EPSS FAQ](https://www.first.org/epss/faq), [CISA SSVC Guide](https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf).
- [Awesome Threat Detection](https://github.com/0x4D31/awesome-threat-detection), [Awesome Detection Engineer](https://github.com/st0pp3r/awesome-detection-engineer) — فهارس لا تثبت صلاحية أي أداة وحدها.

## قيود ختامية لجولة v0.9

- عدد المستودعات والقواعد يتغير بمرور الزمن؛ لا نعتمد أعدادًا ثابتة كضمان كشف.
- لا يُسمح بالمسح أو الاستغلال أو الاختراق المضاد خارج نطاق تفويض صريح ومستقل.
- لا تُدمج قواعد وأكواد المستودعات قبل التحقق من التراخيص وسلاسل التوريد وقابلية الصيانة.
- **نقطة الاستكمال التالية: CG-409.** لا برمجة ولا بروتوتايب ولا إرسال برومبت تنفيذ حتى يطلب المستخدم.



---

# ملحق الجولة العاشرة — v1.0 | توسيع البحث في التشفير والحماية المتقدمة

**النطاق:** دراسة وتوثيق فقط. لا تشغيل أدوات ولا فحص أجهزة فعلية ولا تطبيق إجراءات. **جميع المعرّفات CG-001..408 محفوظة أعلاه دون حذف.**
**القرار المبدئي:** التشفير القوي يعتمد على تطبيق معياري ومفاتيح مُدارة وتوافق الأنظمة، وليس على اسم خوارزمية أو أطول طول مفتاح فقط.

## 54 — أساسيات الخوارزميات واختيارها

- **CG-409** مطلوب — Cryptographic Purpose Map — تصنيف الأهداف: تشفير السرية، تحقق السلامة، توقيع الهوية، اشتقاق المفاتيح، تخزين كلمات المرور؛ منع الخلط بين SHA-256 غير المعتمد على مفتاح والتشفير القابل للفك.
- **CG-410** مطلوب — AEAD Profiles — دراسة AES-128/256-GCM وChaCha20-Poly1305 ضمن مكتبات موثوقة؛ توثيق طول المفتاح والـNonce والـTag وAAD، ورفض إعادة استخدام Nonce مع المفتاح نفسه.
- **CG-411** مطلوب — Integrity vs Authenticity — بصمات SHA-256 للأدلة، وHMAC/التوقيع للتأكد من مصدرها؛ مجرد Hash مطابق لا يثبت وحده أن المصدر موثوق.
- **CG-412** مطلوب — Password KDF Policy — Argon2id مفضل لتخزين كلمات مرور التطبيق، وPBKDF2-HMAC-SHA-256 عند متطلبات FIPS، مع Salts فريدة ومعايرة التكلفة على الجهاز.
- **CG-413** مطلوب — Cryptographic Anti-Patterns — اكتشاف MD5/SHA-1 عندما تستخدم للتوقيع/الأمن، وRC4/DES/3DES وECB وTLS قديم وAES-GCM بNonces غير منضبطة؛ تصنيف الاستخدام قبل الحكم.
- **CG-414** مطلوب — CSPRNG Assurance — منع استخدام مولدات عشوائية غير تشفيرية للمفاتيح والتوكينات والرموز؛ الاعتماد على CSPRNG نظام التشغيل أو مزود HSM مع مراقبة فشل التوليد.
- **CG-415** مطلوب — Context-Bound Authentication — استخدام AAD وBinding بين البيانات وسياق المستأجر/المورد حيث تدعمه الخدمة، وعدم وضع بيانات حساسة في AAD أو سجلات التشفير.
- **CG-416** مطلوب — Library & Validation Register — توثيق مكتبة التشفير وإصدارها ونتائج اختبار التشغيل والاعتماد FIPS عند الطلب؛ عدم مساواة اسم الخوارزمية بشهادة اعتماد للمكتبة أو المنصة.

## 55 — TLS / PKI وإدارة الشهادات

- **CG-417** مطلوب — TLS Baseline Inspector — قراءة الخدمات المصرح بفحصها مع بروتوكولات TLS والتشفير المفاوض والشهادات وسلسلة الثقة وhostname؛ تفضيل TLS 1.3 وتقييم TLS 1.2 مع التوافق.
- **CG-418** مطلوب — TLS Downgrade Detection — إنذار عن تفعيل SSLv2/v3 أو TLS 1.0/1.1 أو السماح بتشفير ضعيف أو فشل تفاوض متكرر؛ لا تنفيذ حظر شامل قبل فحص العملاء المتأثرين.
- **CG-419** مطلوب — Certificate Inventory — جرد Subject/SAN/Issuer/Serial/Algorithm/Expiry والكيانات المالكة والشبكات المرتبطة والشهادات الداخلية والخارجية.
- **CG-420** مطلوب — Certificate Trust & Change Alerts — رصد شهادة انتهت/قاربت الانتهاء أو Root CA جديدة أو تغيير CA/Subject غير مصرح، مع تقليل الإنذارات المشروعة بسبب التجديد.
- **CG-421** مطلوب — Automated Certificate Lifecycle — دراسة ACME وstep-ca وcert-manager للإصدار والتجديد والاختبار والرجوع وCRL/OCSP حيث تدعم النسخة؛ لا نفترض توافر خصائص إصدار تجارية في المجانية.
- **CG-422** بحث — mTLS & Machine Identity — دراسة الشهادات قصيرة الأجل وربط هوية الخدمة بحمل العمل عبر SPIFFE/SPIRE، مع Trust Domains ودورة تدوير وربط الوصول.
- **CG-423** مطلوب — SSH Host Trust — رصد تغيّر مفاتيح مضيف SSH وتوثيق SSH CA والمستخدمين المصرح لهم وإزالة خوارزميات تفاوض قديمة دون كسر الأجهزة القديمة بلا خطة.
- **CG-424** بحث — X.509 Conformance — تقييم ZLint وCertificate Transparency وقيود تمديد الشهادات للتحقق من أخطاء الإصدار والشهادات المشتبه بها ضمن النطاق.

## 56 — التشفير المقاوم للكم ومرونة الانتقال

- **CG-425** مطلوب — Crypto Asset Bill of Materials — جرد خوارزميات التشفير والمكتبات والمفاتيح والشهادات والبروتوكولات وأماكن استخدامها بما يشمل الأجهزة والبرمجيات وFirmware والخدمات السحابية.
- **CG-426** مطلوب — PQC Readiness — إظهار اعتماد مفاتيح عامة تقليدية مثل RSA/ECDH/ECDSA والحاجة إلى تخطيط استبدالها حيث يقتضي عمر سرية البيانات ذلك؛ لا وصف AES على أنه مكسور كميا.
- **CG-427** بحث — ML-KEM Adoption — دراسة FIPS 203 كآلية تأسيس سر، والتكامل الهجين مع مفاتيح كلاسيكية من خلال مكتبات واتصالات معتمدة؛ لا إنشاء خوارزمية مخصصة.
- **CG-428** بحث — ML-DSA/SLH-DSA Readiness — دراسة FIPS 204/205 للتوقيع، وأحجام المفاتيح والتوقيعات، وقيود HSM/PKI والبرامج القديمة.
- **CG-429** مطلوب — PQC Migration Sequencing — تصنيف أولويات التحول وفق حساسية البيانات ومدى احتفاظ المهاجم بنسخ منها، وعمر الأجهزة والتوافق وخطط العودة.
- **CG-430** مطلوب — Crypto Agility Layer — تصميم موصلات قابلة لتغيير خوارزميات ومزودي التشفير بسياسات نسخ وتوافق، من دون الاحتياج لإعادة كتابة كل محركات CyberGuard.
- **CG-431** بحث — OpenSSL PQC Compatibility — رصد دعم OpenSSL 3.5 للـML-KEM/ML-DSA/SLH-DSA وتفاوت اعتماد FIPS ودعم طرفي الاتصال؛ دعم المكتبة لا يعني أن كل خدمة مهيأة.
- **CG-432** مطلوب — PQC Verification Gates — فحص Handshake ومكتبة/إصدار الطرفين وحجم الرسائل والأداء والتوافق والاستعادة قبل إعلان قناة مقاومة للكم.

## 57 — مفاتيح التشفير والأسرار

- **CG-433** مطلوب — Central Key Inventory — جرد Key IDs والمالكين وسياقات الاستخدام والمواقع والاستحقاقات وخيارات HSM/KMS دون استخراج قيم مفاتيح سرية إلى لوحة العرض.
- **CG-434** مطلوب — Rotation & Revocation Workflow — وضع سياسة دوران مفاتيح وشهادات مبنية على مستوى الخطر، وتوثيق نجاح تغيير النسخ وتطبيقات تعتمد عليها وإبطال القديمة.
- **CG-435** مطلوب — Envelope Encryption Governance — فصل DEK عن KEK وتوثيق متى يحدث Re-wrap مقابل Re-encrypt وحماية مفاتيح فك النسخ الاحتياطية.
- **CG-436** بحث — OpenBao Secrets Engine — دراسة أسرار مؤقتة وعقود صلاحية وانتهاء واستعادة، وإدارة تشفير كخدمة؛ تقييم الأداء والتوفر والترخيص والتعقيد.
- **CG-437** مطلوب — Secret Leak Detection — فحص مستودعات الجهة وCI/CD والملفات وأذونات القراءة المصرح بها عبر Gitleaks/TruffleHog؛ حجب المخرجات وعدم التحقق من سر بواجهة خارجية بلا موافقة.
- **CG-438** مطلوب — Key Access Anomaly — رصد زيادة مفاجئة في عمليات Decrypt أو تصدير أو تغيير سياسات KMS/HSM، مع تمييز أنشطة النسخ والترحيل المشروعة.
- **CG-439** مطلوب — Key Loss Disaster Recovery — إجراءات اختبار لاستعادة مفاتيح/نسخ محمية بموافقات متعددة، وتسجيل خطر فقد التشفير بسبب حذف المفتاح الأساسي.
- **CG-440** مطلوب — Separation of Duties for Keys — فصل دور من يشاهد الحوادث عن من يوافق على تدوير أو تعطيل مفاتيح الإنتاج وإجراء حذف مدمر مع منع الموافقة الذاتية.

## 58 — تشفير الشبكات وحمايتها

- **CG-441** مطلوب — Transport Security Map — تحديد مواضع TLS/SSH/IPsec/MACsec/SMB تشفيرًا وتوقيعًا وهوية، وعرض الفروقات بين الرابط والقناة والتطبيق.
- **CG-442** بحث — MACsec Capabilities — التحقق من 802.1AE على موديلات Cisco/Huawei القابلة للدعم ومن مفاتيح MKA وأثر التغيير على التجميع والروابط والطرف الآخر؛ لا تعميم دعم MACsec.
- **CG-443** مطلوب — VPN/IPsec Baseline — جرد IKEv2 وخوارزميات ESP وPFS والمجموعات وخيارات المصادقة ومرونة الدوران لمكونات VPN المصرح بها.
- **CG-444** مطلوب — SMB Negotiation & Encryption — مراقبة إصدارات SMB والتوقيع والتشفير وNTLM والحساب الضيف وفق نظام التشغيل؛ فحص توافق طرفي الاتصال قبل فرض المنع.
- **CG-445** بحث — Wi-Fi Enterprise Credentials — دراسة 802.1X/EAP-TLS وWPA3 Enterprise ومطابقة شهادات RADIUS وحماية هوية الجهاز، مع دعم وضع قراءة فقط حسب مزود الشبكة.
- **CG-446** مطلوب — DNS Trust & Transport — رصد DNSSEC حيث يوجد وDNS-over-TLS/HTTPS عند الحاجة، وفجوات رؤية DNS المشفر أو تغير مزود DNS.
- **CG-447** مطلوب — Network Crypto Change Dry Run — محاكاة تأثير تعطيل بروتوكول/تشفير قديم على الطابعات والهواتف IP والكاميرات والأنظمة الصناعية قبل التنفيذ.
- **CG-448** مطلوب — Certificate-Based Network Access — ربط شهادات 802.1X/NAC بالهوية وVLAN ومستوى الثقة ومدتها وحالة الإبطال، وعدم حظر جهاز بمجرد فشل شهادة دون تحقق.

## 59 — مفاتيح التشفير في السحابة

- **CG-449** مطلوب — AWS KMS Posture — جرد سياسات المفاتيح وIAM Grants وعمليات Decrypt وKey Disable والجهة المالكة والتدوير وسياق Encryption Context؛ التعامل مع الأخير كبيانات غير سرية.
- **CG-450** مطلوب — Azure Key Vault/Managed HSM — مراقبة الوصول والدوران وSoft Delete/Purge Protection والعطل وحالات إصدار المفتاح حسب الموارد والتراخيص.
- **CG-451** مطلوب — GCP Cloud KMS Integration — جرد السياسات والأدوار وإجراءات Disable/Destroy Versions والنسخ وتسجيل الأنشطة والاختبارات قبل تنفيذ تغيير مؤثر.
- **CG-452** مطلوب — Multi-Cloud Encryption Drift — المقارنة بين سياسات حماية البيانات في S3/EBS/RDS وAzure Storage/Disks وGCP Storage حسب تفاصيل كل مورد.
- **CG-453** مطلوب — Storage Encryption vs Access Control — التأكيد أن التخزين المشفر لا يعوض IAM وسلامة التطبيق؛ التحقق من الوصول الزائد للمستخدمين المخولين.
- **CG-454** مطلوب — SaaS BYOK/HYOK Decision — دراسة مفاتيح يتحكم فيها العميل ومخاطر تعطيلها أو فقدها، وخيارات الاستعادة والنطاق التعاقدي للخدمة.
- **CG-455** مطلوب — Key Residency & Sovereignty — تسجيل منطقة المفتاح ومكان معالجة البيانات والأذونات ومتطلبات سياسة الجهة والسيادة القانونية دون ادعاء امتثال تلقائي.
- **CG-456** مطلوب — Cloud Key Failure Injection in Lab — اختبار سيناريو فقد الوصول إلى KMS وأثره على التشغيل والنسخ والتعافي داخل بيئة مختبرية فقط.

## 60 — جهاز Windows وهوية الجهاز والتشفير

- **CG-457** مطلوب — BitLocker Coverage — التحقق من تشفير الأقراص وأجهزة المفاتيح وحالة الحماية وعدم التصدير الحر لمفاتيح Recovery إلى سجلات CyberGuard.
- **CG-458** مطلوب — TPM/Secure Boot Health — قراءة حالة TPM وSecure Boot وMeasured Boot عبر القنوات المدعومة، وتصنيف الأجهزة التي لا توفر Attestation.
- **CG-459** مطلوب — Device Health Attestation — توثيق قياسات Boot وبلوغ نقطة ثقة قبل منح جهاز وصولًا حساسًا، مع مراعاة مصادر سلامة مستقلة عن الجهاز المشتبه به.
- **CG-460** مطلوب — Code Signing & App Trust — مراقبة الملفات التنفيذية الموقعة والمصدر والناشر وحالة توقيع البرامج والدرايفرات؛ التوقيع وحده لا يجعل الملف آمنًا.
- **CG-461** بحث — Application Control Policies — دراسة App Control for Business وقواعد التنفيذ المسموح وAudit Mode ثم Block مع تقييم التوافق.
- **CG-462** مطلوب — RDP/WinRM/SSH Secure Defaults — مراقبة شهادات TLS وإعدادات المصادقة والمجموعات ومدة الجلسات وMFA/VPN حيث يدعم.
- **CG-463** مطلوب — Security Key Material Exposure — كشف مفاتيح شهادات محلية وصلاحيات وصول زائدة ونسخ غير آمنة، دون جمع الأسرار في قاعدة بيانات SIEM.
- **CG-464** مطلوب — Legacy Windows Crypto Exception — تسجيل استثناءات بروتوكولية لحالات Windows Server 2012 R2 وغيرها، وتقديم مسار عزل/ترقية بدل تطبيق حظر قد يوقف الإنتاج.

## 61 — توقيع البرمجيات وسلسلة التوريد

- **CG-465** مطلوب — Signed Releases Gate — سياسة منع تثبيت موصلات أو Agents من Releases مجهولة المصدر حتى يتم تحقق الهوية والتوقيع والـDigest.
- **CG-466** بحث — Sigstore Cosign — دراسة توقيع صور الحاويات وArtifacts والتحقق من هوية موقّع OIDC وتوقيعات keyless وKMS مع سياسات ثابتة.
- **CG-467** بحث — Policy Controller — دراسة رفض نشر صور Kubernetes غير المطابقة لسياسة التواقيع والتحقق داخل CI/CD وقبل التشغيل.
- **CG-468** مطلوب — OpenSSF Scorecard Checks — تقييم المستودعات وفق مراجعة الكود والفروع والتحديثات وسلسلة التوريد والسجل الأمني، وعدم اعتماد التقييم وحده دليل أمان.
- **CG-469** مطلوب — Reproducible Build Considerations — توثيق مصدر البناء وSBOM وسلسلة إصدار وتوقيع التجزئة ونشر الحد الأدنى من الصلاحيات.
- **CG-470** مطلوب — Dependency Crypto Inventory — اكتشاف مكتبات OpenSSL/LibreSSL/BoringSSL وأصداراتها المباشرة وغير المباشرة وتحديد أولوية التحديث.
- **CG-471** مطلوب — CI/CD Secrets & OIDC — تقليل مفاتيح CI طويلة العمر واستخدام هويات مؤقتة في تكاملات المستودعات والخدمات متى دعمت.
- **CG-472** مطلوب — Malicious Update Containment — تحقق توقيع مصدر تحديث أداة أمنية في بيئة تجريبية، مع تراجع ومراقبة مصادر رسمية وتقييم خطر اختراق سلسلة التوريد.

## 62 — الرؤية والتحليل والكشف عن خلل التشفير

- **CG-473** مطلوب — Crypto Findings Evidence Model — لكل نتيجة: أصل وخدمة وإصدار وبروتوكول ودليل وخطر وتوافق وتأثير الإصلاح وحدود الثقة وتاريخ التحقق.
- **CG-474** مطلوب — TLS Audit Adapter — دراسة testssl.sh وsslscan وCryptoLyzer في فحوص نطاق مصرح، مع أخذ أثر فحص الخدمات القديمة في الاعتبار.
- **CG-475** مطلوب — PKI Anomaly Correlation — ربط إصدار شهادة جديدة وتغيير Root CA وتبديل Fingerprint وحدث دخول مشبوه وتغيير سياسات Firewall؛ لا إعلان MITM من تغيير شهادة وحيد.
- **CG-476** مطلوب — Key Usage Risk Model — تقييم عمليات Decrypt خارج نمط المؤسسة مع تفريق الاستخدام الطبيعي المرتفع في خدمات ذات حجم كبير.
- **CG-477** مطلوب — Expiry & Renewal Calendar — عرض الاستحقاقات الحرجة للشهادات والمفاتيح والتراخيص والاختبارات، وإشعار قبل الانتهاء مع حالة التجديد.
- **CG-478** مطلوب — Log Privacy — منع تسجيل Plaintext وكلمات المرور والمفاتيح وتشفير تقارير الحوادث والتحكم في الوصول إلى Metadata.
- **CG-479** مطلوب — Crypto Control Test Harness — اختبارات إيجابية وسلبية لTLS وشهادة خاطئة ومفتاح منتهي وقيود Nonce ضمن بيئة تجريبية وباستخدام متجهات اختبار رسمية.
- **CG-480** مطلوب — Crypto Risk Prioritization — ترتيب الضعف وفق انكشاف الخدمة وسرية البيانات وعمرها وإمكانية الاستغلال وموعد الانتهاء وأثر الانقطاع.

## 63 — هندسة المنتج والتحقق قبل البروتوتايب

- **CG-481** مطلوب — Crypto Module Boundary — الفصل بين لوحة عرض النتائج ومحرك التشفير وخزنة الأسرار؛ لا يمكن لAI Analyst استدعاء فك تشفير عشوائي.
- **CG-482** مطلوب — Connector Capability Matrix — لكل Cisco/Huawei/Windows/AWS/Azure/GCP تعريف ما يمكن قراءته وما يمكن تغييره بحسب الطراز/الإصدار/الترخيص/الصلاحية.
- **CG-483** مطلوب — Crypto Remediation Approval — تغيير TLS أو شهادة أو مفاتيح إنتاج يحتاج Change Request وDry Run وتأكيد مالك الأصل وموافقة مناسبة.
- **CG-484** مطلوب — Break-Glass Recovery — خطة نجاة إذا فقدت الشهادة أو المفتاح أو انقطع Access/VPN، بمراجعة فصل الصلاحيات وتوثيق استخدام الطوارئ.
- **CG-485** مطلوب — Key Rotation Rollback Analysis — التفريق بين إعادة مفتاح سابق وبين إبطال مفتاح مخترق؛ لا يجوز استعادة مفتاح مكشوف لمجرد استعادة التشغيل.
- **CG-486** مطلوب — Crypto Benchmark & Resource Budget — قياس أداء AES-GCM/PQC/TLS والمراقبة والذاكرة وCPU والتخزين دون تعميم أداء PC على 20k جهاز.
- **CG-487** مطلوب — Security Score With Unknown — لا يعرض CyberGuard نتيجة آمنة إذا لم تستطع أدواته الجزم بنوع التشفير أو بمدى اكتمال رصد مفاتيح السحابة.
- **CG-488** مطلوب — Readiness Acceptance Tests — قبل أي بروتوتايب: 12 اختبارًا معلوم النتيجة للتحقق من توصيات التشفير والشهادات والمفاتيح والتراجع وعدم جمع أسرار حساسة.

## ملخص المقارنة العملية للخوارزميات والسياسات

| الفئة | مبدأ البحث | مخاطر تطبيق خاطئ | قرارنا |
|---|---|---|---|
| التشفير الموثق | AES-GCM أو ChaCha20-Poly1305 عبر مكتبات موثوقة | تكرار Nonce أو تسريب Key أو تسجيل plaintext | لا بناء خوارزمية خاصة |
| كلمات المرور | Argon2id أو PBKDF2 حسب السياسة ومتطلبات FIPS | تخزين كلمة المرور قابلة للفك، أو Hash سريع | مراقبة الإعداد وكلفة الHash |
| TLS | تفضيل 1.3 وتكوين 1.2 آمن عند الحاجة | انقطاع العملاء عند إيقاف القديم دفعة واحدة | جرد ثم تغيير مرحلي |
| الشهادات | PKI وACME وسلسلة الثقة والتجديد | انقطاع الخدمة أو قبول شهادات مزيفة | تحقق قبل تجديد/إبطال |
| المستقبل الكمّي | ML-KEM/ML-DSA/SLH-DSA حسب NIST | اعتبار دعم المكتبة دليل اعتماد النظام كاملاً | جرد وقياس وتخطيط انتقال |
| السحابة | KMS/HSM وEnvelope Encryption وIAM | حذف مفتاح يمنع فك بيانات قديمة | صلاحيات متعددة وخطة استعادة |
| حماية الشبكة | MACsec/IPsec/SMB/mTLS | إغلاق خدمات قديمة أو قطع قناة إدارة | مصفوفة قدرات لكل جهاز |

## ستة سيناريوهات بحث دفاعية جديدة

### CASE-28 — خدمة HTTPS تدعم خوارزمية ضعيفة
- **الملاحظة:** نتيجة TLS scanner من سيرفر تابع للمؤسسة تبين قبول بروتوكول أو cipher suite متقادمة.
- **مصادر الأدلة:** إصدار الخدمة، تهيئة الويب/الموازن، نتيجة فحص مصرح، قوائم العملاء وFlow logs.
- **الاستجابة:** اختبار الإيقاف على مختبر، تأكيد العملاء المتأثرين، تعديل على مراحل مع Rollback واختبار مصافحة من عدة عملاء.
- **خطأ يجب تجنبه:** ادعاء اكتشاف اختراق فعلي من وجود Cipher ضعيف فقط.

### CASE-29 — تغيير شهادة غير متوقع أو انتهاء وشيك
- **الملاحظة:** تغير شهادة VPN/HTTPS دون Change Request، أو قرب انتهاء شهادة API حيوية.
- **مصادر الأدلة:** سلسلة الثقة، SAN، تاريخ الإصدار، سجلات ACME، Certificate Transparency عند صلاحيتها، موافقات التغيير.
- **الاستجابة:** التحقق من ملكية التجديد؛ التنبيه ثم عزل أثر التغيير قبل تراجع؛ إصدار أو تجديد من CA موثوقة.
- **خطأ يجب تجنبه:** اتهام MITM من مجرد بصمة جديدة.

### CASE-30 — زيادة طلبات KMS Decrypt مع تغيير IAM
- **الملاحظة:** حجم فك تشفير غير معتاد من هوية تطبيق وسياق مورد مختلف.
- **مصادر الأدلة:** CloudTrail / Azure diagnostic / GCP audit، أذونات وGrants وسياق Data Access وسلوك التطبيق.
- **الاستجابة:** تحقيق في سبب التغيير وتقييد مفتاح/هوية متضررة تدريجيا؛ حماية مفاتيح النسخ الاحتياطية.
- **خطأ يجب تجنبه:** تعطيل KMS الإنتاجي دون تحليل أثره على البيانات والتوافر.

### CASE-31 — تشفير SMB غير متوافق مع الأجهزة القديمة
- **الملاحظة:** مشاركة ملفات تحتوي بيانات حساسة لا تستخدم تشفير SMB، أو عميل قديم لا يدعم فرضه.
- **مصادر الأدلة:** SMB dialect، Windows build، GPO، حالة signing/encryption، جرد الاعتماديات.
- **الاستجابة:** تفعيل الحماية تدريجيا حيث ممكنة، واستثناء مضبوط بمدة، وترقية أو تقسيم شبكة للأجهزة القديمة.
- **خطأ يجب تجنبه:** فرض SMB 3.1.1 على جميع الأجهزة دون فحص أجهزة NAS والطابعات.

### CASE-32 — جاهزية PQC غير مكتملة
- **الملاحظة:** جهة تحتفظ ببيانات سرية طويلة العمر لكن أغلب بروتوكولاتها تستخدم تبادل مفاتيح تقليدي.
- **مصادر الأدلة:** Cryptographic inventory، دعم OpenSSL/PKI وTLS/SSH، حساسية البيانات وتاريخ انتهاء الأجهزة.
- **الاستجابة:** خريطة ترحيل، Pilot في المختبر لمصافحات هجينة مدعومة، قياس الأداء والأجهزة غير المتوافقة.
- **خطأ يجب تجنبه:** القول إن RSA أو ECDH أصبح مكسورا اليوم أو إن PQC متاح في كل الشبكات.

### CASE-33 — مفتاح منشور في GitHub تابع للمؤسسة
- **الملاحظة:** اكتشاف Secret حقيقي أو تجريبي في تاريخ Git مع قدرة استخدام محتملة.
- **مصادر الأدلة:** scanner result من مستودع مخول، سجل استخدام API، Audit logs، مالك السر.
- **الاستجابة:** تدوير/إبطال المفتاح، تحديث التبعيات، تنظيف الأثر بعد حفظ دليل مناسب؛ عدم عرض القيمة في UI أو إرسالها لـAI.
- **خطأ يجب تجنبه:** تجربة مفتاح على خدمة خارجية دون تصريح.

## مصفوفة أدوات GitHub ومخاطر إدخالها إلى منتج تجاري

| أداة / مرجع رسمي | المنفعة المحتملة | ملاحظة تحقق |
|---|---|---|
| [testssl.sh](https://github.com/testssl/testssl.sh) | جرد TLS/ciphers والشهادات | GPLv2؛ استخدام فحص مأذون به وتأثير خدمات قديمة |
| [sslscan](https://github.com/rbsec/sslscan) | تدقيق SSL/TLS | GPLv3؛ قد يحتاج Windows binaries |
| [CryptoLyzer](https://github.com/c0r0n3r/cryptolyzer) | TLS/SSH/DNSSEC وغيرها | مستودع GitHub مرآة read-only؛ تحقق من المصدر الفعلي والترخيص |
| [ZLint](https://github.com/zmap/zlint) | فحص امتثال X.509 | ليس بديل تحقق شهادة حيّة على الشبكة |
| [step-ca](https://github.com/smallstep/certificates) | CA داخلي وشهادات X509/SSH | بعض قدرات المؤسسة متاحة تجاريًا فقط |
| [cert-manager](https://github.com/cert-manager/cert-manager) | دورة شهادات Kubernetes | يتطلب cluster RBAC وتكوين CRDs |
| [OpenBao](https://github.com/openbao/openbao) | تخزين أسرار وتشفير كخدمة | موارد وتشغيل عالي التوفر واختبار الاسترداد |
| [SPIRE](https://github.com/spiffe/spire) | هوية أعباء العمل وmTLS | يتطلب Trust Domain ومكونات تشغيلية |
| [Cosign](https://github.com/sigstore/cosign) | توقيع ملفات/صور وتحقق الهوية | التحقق من هوية الموقّع وعدم الاكتفاء بوجود توقيع |
| [Sigstore Policy Controller](https://github.com/sigstore/policy-controller) | تفعيل سياسات قبول الصور | اختبار الاستثناءات والتوافر قبل Enforce |
| [OpenSSF Scorecard](https://github.com/ossf/scorecard) | تقييم صحة وسلسلة توريد مشاريع GitHub | إشارة تقييم لا ضمان أمان |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | كشف أسرار في مستودعات وأصول مُدارة | مراجعة التحقق الخارجي للأسرار وإخفاء القيم |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | فحص تسريب الأسرار في Git | نطاق المؤسسة والتعامل مع False Positives |

## المصادر المرجعية الأساسية التي تحققنا منها في هذه الجولة

- [NIST FIPS 203, 204, 205](https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved) — معايير PQC المعتمدة.
- [NIST IR 8547 (2026)](https://csrc.nist.gov/pubs/ir/8547/final) — خطة الانتقال من المعايير الكلاسيكية.
- [NIST Crypto Agility CSWP 39-upd1](https://csrc.nist.gov/pubs/cswp/39/upd1/considerations-for-achieving-crypto-agility/final) — منهجية تغيير خوارزميات دون تعطيل.
- [NIST NCCoE PQC FAQ](https://pages.nist.gov/nccoe-migration-post-quantum-cryptography/) — جرد التشفير والأدوات.
- [RFC 8446 TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html) و[RFC 9325 TLS Best Practices](https://www.rfc-editor.org/rfc/rfc9325.html).
- [OWASP Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) و[OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) و[OWASP Key Management](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html).
- [Microsoft SMB Security](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-feature-descriptions) و[SMB Encryption Requirements](https://learn.microsoft.com/en-us/windows-server/storage/file-server/configure-smb-client-require-encryption).
- [Microsoft TPM and Secure Boot](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/how-windows-uses-the-tpm) و[System Guard](https://learn.microsoft.com/windows/security/threat-protection/windows-defender-system-guard/how-hardware-based-root-of-trust-helps-protect-windows).
- [Cisco MACsec IEEE 802.1AE APIC](https://www.cisco.com/c/en/us/td/docs/dcn/aci/apic/6x/l2-configuration/cisco-apic-layer-2-networking-configuration-guide-62x/g_macsec/macsec.html).
- [OpenSSL 3.5 release](https://openssl-library.org/post/2025-04-08-openssl-35-final-release/) — ML-KEM/ML-DSA/SLH-DSA.
- [AWS KMS Encryption Context](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html) و[Azure Managed HSM Key Rotation](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/key-rotation).
- [OpenBao](https://openbao.org/) و[SPIRE](https://github.com/spiffe/spire) و[Cosign](https://github.com/sigstore/cosign).

## مستوى اليقين والأسئلة المتبقية

- **مدعوم بوثائق:** وجود خوارزميات ومعايير وأدوات ومزايا إصدار موثق بالروابط أعلاه.
- **مرشح يحتاج Proof of Concept:** دمج الأدوات مع CyberGuard، توافق الموارد والتراخيص، أداء Windows PC وتشغيل Linux VM.
- **غير مثبت بعد:** دقة كشف CyberGuard للثغرات الناتجة عن خوارزميات ضعيفة، دعم كل Cisco/Huawei، أداء PQC بكامل التطبيقات.
- **قرار سلامة:** لا نجمع Raw Private Keys إلى SIEM ولا ننفذ Key Disable أو إبطال CA أو تغيير TLS على أنظمة الإنتاج قبل تفويض وموافقة وخطة استرداد.
- **متابعة:** من CG-489 يتم البحث في أمن قواعد البيانات (TDE / TLS / masking / audit) وتشفير النسخ الاحتياطية والتعامل مع ransomware، ثم دراسة Security Monitoring لكل صناعة.


---

## جولة البحث الحادية عشرة — الدفاع الاستباقي وتوسيع المنصة خارج SIEM

**التاريخ:** 2026-11-10
**نطاق التعديل:** CG-489 إلى CG-548، إضافة إلى المتطلبات الـ488 السابقة دون حذفها أو تنفيذها.
**الهدف:** Security Hardening, Policy-as-Code, Runtime Protection, Database Protection, Wireless/Firmware, AppSec, Privacy, Network Reliability, DFIR, Platform Security.

> جميع الإضافات تصميمات أو دراسات، وليست قدرات منفذة. الامتيازات والترخيص وتأثير التنفيذ تُراجع قبل البدء.

### 01 — أمن التكوينات وتقوية الأنظمة (CG-489–CG-494)
- **CG-489** **[بحث/متطلب مقترح]** — **Hardening Profiles Registry:** مستودع ملفات Baseline معتمد لكل إصدار من Linux/Windows وخدمات السيرفر؛ يُوثّق الأصل، نسخة السياسة، الاستثناء، وتاريخ المراجعة. [مصدر للمراجعة](https://github.com/ComplianceAsCode/content).
- **CG-490** **[بحث/متطلب مقترح]** — **Applicability Before Score:** لا تُحسب قاعدة تقوية غير قابلة للتطبيق إخفاقًا؛ يفحص النظام نوع الـOS ووظيفته والاعتمادات قبل احتساب نسبة الالتزام. [مصدر للمراجعة](https://github.com/OpenSCAP/openscap).
- **CG-491** **[بحث/متطلب مقترح]** — **Evidence-first Configuration Audit:** فحص إعدادات الحماية في وضع قراءة فقط، والاحتفاظ بقيمة الدليل المسموح بحفظها مع إخفاء الأسرار والبيانات الشخصية. [مصدر للمراجعة](https://github.com/CISOfy/lynis).
- **CG-492** **[بحث/متطلب مقترح]** — **Hardening Drift Attribution:** ربط انحراف إعداد الحماية بآخر تعديل معتمد، وهوية المستخدم، وإصدار الأداة، وعدم الادعاء بمعرفة الفاعل عند غياب السجلات. [مصدر للمراجعة](https://github.com/ComplianceAsCode/content).
- **CG-493** **[بحث/متطلب مقترح]** — **Staged Hardening Rollout:** اقتراح التقوية على حلقة مختبر ثم أجهزة تجريبية ثم توسيع تدريجي، مع تحقق توافق وتراجع موثق قبل تطبيق شامل. [مصدر للمراجعة](https://github.com/ComplianceAsCode/content).
- **CG-494** **[بحث/متطلب مقترح]** — **Conflicting Baseline Resolver:** رصد التضارب بين قواعد CIS وSTIG ومتطلبات التطبيق وسياسات المؤسسة؛ يمنع إصدار أوامر متناقضة لنفس الخدمة. [مصدر للمراجعة](https://github.com/OpenSCAP/openscap).

### 02 — السياسة الوقائية ككود (CG-495–CG-500)
- **CG-495** **[بحث/متطلب مقترح]** — **Policy Decision Contract:** تحديد واجهة قرار السياسة: هوية مقدم الطلب، الأصل، السياق، القرار، السبب، نسخة السياسة، وأدلة التقييم. [مصدر للمراجعة](https://github.com/open-policy-agent/opa).
- **CG-496** **[بحث/متطلب مقترح]** — **Infrastructure Preflight Guardrails:** فحص موارد IaC والخدمات قبل النشر بحثًا عن تخزين مكشوف، صلاحيات مفرطة، أو واجهات إدارة عامة. [مصدر للمراجعة](https://github.com/cloud-custodian/cloud-custodian).
- **CG-497** **[بحث/متطلب مقترح]** — **Cloud Policy Dry-run and Proof:** كل إجراء سحابي مقترح يسبقه Dry-run يعرض الموارد المطابقة والتأثير، ثم تحقق بعد التنفيذ عبر API رسمي. [مصدر للمراجعة](https://github.com/cloud-custodian/cloud-custodian).
- **CG-498** **[بحث/متطلب مقترح]** — **Exception Lifecycle as Policy:** تسجيل الاستثناء بمبرر ومالك وتاريخ انتهاء، مع اكتشاف الاستثناء الذي بقي نافذًا بعد موعده بسبب خطأ تنفيذي. [مصدر للمراجعة](https://github.com/open-policy-agent/opa).
- **CG-499** **[بحث/متطلب مقترح]** — **Explainable Policy Denial:** إظهار أي قاعدة منعت المستخدم من تنفيذ أمر أو نشر مورد، وكيف يمكن طلب استثناء صحيح بدل تجاوز الحماية. [مصدر للمراجعة](https://github.com/open-policy-agent/opa).
- **CG-500** **[بحث/متطلب مقترح]** — **Cloud Firewall Policy Convergence:** مقارنة سياسة المؤسسة بواقع AWS Security Groups وAzure NSG والجدران المحلية؛ اكتشاف حدود التنفيذ والتعارض دون فرض تساوٍ غير موجود. [مصدر للمراجعة](https://github.com/cloud-custodian/cloud-custodian).

### 03 — حماية Linux والحاويات أثناء التشغيل (CG-501–CG-506)
- **CG-501** **[بحث/متطلب مقترح]** — **Runtime Event Coverage Matrix:** تحديد أنواع أحداث العمليات وsyscalls والملفات والشبكة المدعومة فعليًا في نسخة Linux أو Kubernetes، لا الاكتفاء بحالة Agent = online. [مصدر للمراجعة](https://github.com/cilium/tetragon).
- **CG-502** **[بحث/متطلب مقترح]** — **Runtime Enforcement Approval:** تعطيل/حظر السلوك عبر eBPF أو سياسات تشغيل فقط بعد اختبار التوافق وقياس احتمال تعطيل أحمال الإنتاج. [مصدر للمراجعة](https://github.com/cilium/tetragon).
- **CG-503** **[بحث/متطلب مقترح]** — **Kernel and Privilege Compatibility:** فحص إصدار kernel وBPF capabilities وقيود SELinux/AppArmor والصلاحيات قبل تثبيت حساس runtime. [مصدر للمراجعة](https://github.com/cilium/tetragon).
- **CG-504** **[بحث/متطلب مقترح]** — **Detection versus Prevention Labels:** عرض Falco بوصفه أداة كشف وتنبيه، وعدم وعد المستخدم بأنه ينفذ عزلًا بنفسه دون محرك استجابة منفصل. [مصدر للمراجعة](https://github.com/falcosecurity/falco).
- **CG-505** **[بحث/متطلب مقترح]** — **Kubernetes Admission Guardrails:** سياسات تحقق للتوقيع والصور والامتيازات وإعدادات Pod باستخدام Kyverno أو بديل مناسب، مع تقارير للسياسات. [مصدر للمراجعة](https://github.com/kyverno/kyverno).
- **CG-506** **[بحث/متطلب مقترح]** — **Admission Service Resilience:** اختبار انقطاع Policy Admission وتحديد سلوك fail-open/fail-closed بحسب حساسية الخدمة مع مسار طوارئ موثق. [مصدر للمراجعة](https://github.com/kyverno/kyverno).

### 04 — حماية قواعد البيانات الفعلية (CG-507–CG-512)
- **CG-507** **[بحث/متطلب مقترح]** — **SQL Server Auditing Map:** دراسة Microsoft SQL Server Audit وExtended Events وتسجيل تغييرات أدوار DBA والنسخ والاستخراج وفق الإصدار والترخيص. [مصدر للمراجعة](https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine).
- **CG-508** **[بحث/متطلب مقترح]** — **PostgreSQL Targeted Auditing:** دراسة pgAudit بتمكين أصناف READ/WRITE/ROLE/DDL حسب المخاطر؛ حساب أثر حجم السجلات ومنع تخزين نصوص حساسة دون ضرورة. [مصدر للمراجعة](https://github.com/pgaudit/pgaudit).
- **CG-509** **[بحث/متطلب مقترح]** — **Oracle Unified Audit Adapter:** تصميم تكامل موائم لإصدار Oracle Unified Auditing مع اكتشاف أحداث الصلاحيات وعمليات التصدير والإعدادات المغلقة. [مصدر للمراجعة](https://docs.oracle.com/en/database/).
- **CG-510** **[بحث/متطلب مقترح]** — **MySQL Audit Capability Check:** تمييز خصائص التدقيق المدعومة في MySQL والبدائل التجارية أو التوزيعات المختلفة قبل إعلان توفر فحص كامل. [مصدر للمراجعة](https://dev.mysql.com/doc/).
- **CG-511** **[بحث/متطلب مقترح]** — **Database Extraction Anomaly Model:** ربط زيادة حجم SELECT/COPY أو عمليات التصدير بهوية المستخدم والوقت والتطبيق المعتمد دون اتهام نسخ مشروع للبيانات. [مصدر للمراجعة](https://github.com/pgaudit/pgaudit).
- **CG-512** **[بحث/متطلب مقترح]** — **DB Privilege and Secret Lifecycle:** مراقبة منح امتيازات قواعد البيانات وتدوير حسابات الخدمات وفق التبعيات، مع ضمان عدم حفظ كلمات المرور مكشوفة. [مصدر للمراجعة](https://github.com/open-policy-agent/opa).

### 05 — أمن الأجهزة اللاسلكية والبرمجيات الثابتة (CG-513–CG-518)
- **CG-513** **[بحث/متطلب مقترح]** — **Passive Wireless Visibility:** جرد نقاط Wi-Fi الظاهرة ومؤشرات Rogue AP بالتقاط سلبي مصرح به؛ لا يُعد مجرد SSID شبيه إثباتًا لهجوم. [مصدر للمراجعة](https://github.com/kismetwireless/kismet).
- **CG-514** **[بحث/متطلب مقترح]** — **Wireless Hardware Support:** فحص حاجة حساسات Wi-Fi/Bluetooth/Zigbee إلى شرائح وهوائيات ودعم monitor mode، مع مراعاة القوانين والخصوصية. [مصدر للمراجعة](https://github.com/kismetwireless/kismet).
- **CG-515** **[بحث/متطلب مقترح]** — **Firmware Lifecycle Register:** تسجيل إصدار BIOS/UEFI والبرمجية الثابتة على الأجهزة المدعومة ومصادر التحديث والتوقيع وسجل Rollback إن كان متاحًا. [مصدر للمراجعة](https://github.com/chipsec/chipsec).
- **CG-516** **[بحث/متطلب مقترح]** — **CHIPSEC Lab-only Policy:** أي اختبار CHIPSEC منخفض المستوى يتم في جهاز مختبر معزول بعد قراءة التحذيرات، وليس على أجهزة إنتاج. [مصدر للمراجعة](https://github.com/chipsec/chipsec).
- **CG-517** **[بحث/متطلب مقترح]** — **Network Device Provenance:** التحقق من موثوقية صور Firmware وملفات Config وطرق ترقية الأجهزة المصرح بها والتعرف على الإصدارات المنتهية الدعم. [مصدر للمراجعة](https://github.com/nautobot/nautobot).
- **CG-518** **[بحث/متطلب مقترح]** — **Sensor Field of View Registry:** لكل حساس لاسلكي أو شبكي نحدد الترددات والقنوات والموقع والفترات غير المراقبة ونمنع الادعاء برؤية شاملة. [مصدر للمراجعة](https://github.com/kismetwireless/kismet).

### 06 — أمن التطبيقات وسلسلة توريد البرمجيات (CG-519–CG-524)
- **CG-519** **[بحث/متطلب مقترح]** — **ASVS 5.0 Control Mapping:** ربط متطلبات التطبيق بـOWASP ASVS 5.0 ونتائج الاختبارات اليدوية والآلية؛ لا نساوي الفحص الآلي بتغطية ASVS كاملة. [مصدر للمراجعة](https://asvs.owasp.org/).
- **CG-520** **[بحث/متطلب مقترح]** — **Authorized Dynamic Testing Windows:** دراسة فحوص DAST منخفضة التأثير للتطبيقات المملوكة مع نافذة اختبار وحدود طلبات واستثناءات لخدمات الإنتاج. [مصدر للمراجعة](https://www.zaproxy.org/).
- **CG-521** **[بحث/متطلب مقترح]** — **API Inventory and Shadow Endpoint Review:** ربط تعريفات OpenAPI والبوابات والسجلات لاكتشاف مسارات API المتروكة أو المعرضة بلا سياسة مناسبة. [مصدر للمراجعة](https://asvs.owasp.org/).
- **CG-522** **[بحث/متطلب مقترح]** — **Cross-scanner Deduplication and Ownership:** دمج نتائج الثغرات المكررة من عدة أدوات وتحديد مالك الإصلاح وتاريخ التحقق، مع الاحتفاظ بمصدر كل دليل. [مصدر للمراجعة](https://github.com/DefectDojo/django-DefectDojo).
- **CG-523** **[بحث/متطلب مقترح]** — **Continuous SBOM Risk Monitoring:** ربط SBOM بمشروع وإصدار ومخزن وبنية النشر ثم مراقبة تحديثات الثغرات؛ دراسة Dependency-Track v5 لتجنب نهاية دعم v4 في ديسمبر 2026. [مصدر للمراجعة](https://github.com/DependencyTrack/dependency-track).
- **CG-524** **[بحث/متطلب مقترح]** — **Repository Policy Governance:** فحص تفعيل الحماية على مستودعات GitHub عبر Allstar عند تشغيله ذاتيًا؛ الخدمة المستضافة من OpenSSF توقفت، فلا نعتمد عليها. [مصدر للمراجعة](https://github.com/ossf/allstar).

### 07 — خصوصية البيانات وحمايتها (CG-525–CG-530)
- **CG-525** **[بحث/متطلب مقترح]** — **PII Discovery with Human Review:** فحص البيانات الشخصية المحتملة في نصوص السجلات بمرشحات قابلة للتخصيص، مع مراجعة نتائج التمويه الخاطئة. [مصدر للمراجعة](https://github.com/data-privacy-stack/presidio).
- **CG-526** **[بحث/متطلب مقترح]** — **Arabic-sensitive Data Classifiers:** قواعد محلية لاكتشاف أرقام الهوية والبريد والهواتف والعناوين ضمن النص العربي، تختبر على مجموعات بيانات اصطناعية دون تسريب. [مصدر للمراجعة](https://github.com/data-privacy-stack/presidio).
- **CG-527** **[بحث/متطلب مقترح]** — **Privacy by Default AI Context:** تمويه سجلات المستخدمين والأسرار قبل إرسال ملخص إلى AI خارجي وإظهار ما أُرسل والسبب وإمكانية إيقاف النقل. [مصدر للمراجعة](https://github.com/data-privacy-stack/presidio).
- **CG-528** **[بحث/متطلب مقترح]** — **Sensitive Data Access Ledger:** تسجيل من فتح أدلة تحتوي بيانات حساسة ولماذا، ووضع صلاحيات وصول ومدة احتفاظ وحذف عند انتهاء الحاجة. [مصدر للمراجعة](https://github.com/usnistgov/oscal).
- **CG-529** **[بحث/متطلب مقترح]** — **Data Exposure Triage:** ربط مشاركة ملفات عامة أو نسخ تخزين سحابي بلا قيود بحساسية البيانات الفعلية، وعدم تعميم أنها تسريب مؤكد. [مصدر للمراجعة](https://github.com/cloud-custodian/cloud-custodian).
- **CG-530** **[بحث/متطلب مقترح]** — **Privacy Control Coverage Proof:** تقييم نسبة البيانات التي تم اختبار اكتشافها ضمن مجموعة معرفة وعدم الإعلان أن إزالة الهوية مضمونة آليًا. [مصدر للمراجعة](https://github.com/data-privacy-stack/presidio).

### 08 — أمن الشبكة مع الاعتمادية التشغيلية (CG-531–CG-536)
- **CG-531** **[بحث/متطلب مقترح]** — **Network Intended-state Reconciliation:** مقارنة NetBox/Nautobot بالحالة الفعلية للواجهات وVLAN وIP والاعتماديات، مع تمييز مصدر الحقيقة والمزامنة. [مصدر للمراجعة](https://github.com/nautobot/nautobot).
- **CG-532** **[بحث/متطلب مقترح]** — **Critical-service Change Dependency:** تحديد اعتماد التطبيقات على سويتش أو خدمة DNS/AD قبل تنفيذ الحظر، وإظهار احتمال تأثير العملية على أعمال المؤسسة. [مصدر للمراجعة](https://github.com/nautobot/nautobot).
- **CG-533** **[بحث/متطلب مقترح]** — **Read-only Network Change Evidence:** حفظ نسخة تكوين موثقة ومراجعة الفروقات قبل تغيير ACL أو منفذ، مع منع إدخال كلمات السر إلى سجلات التغييرات. [مصدر للمراجعة](https://github.com/nautobot/nautobot).
- **CG-534** **[بحث/متطلب مقترح]** — **Security SLO and Telemetry Health:** قياس تأخر وصول السجلات وتغطية الحساسات وزمن انقطاع الخدمة، لأن غياب الإنذارات لا يعني عدم وجود تهديدات. [مصدر للمراجعة](https://github.com/nautobot/nautobot).
- **CG-535** **[بحث/متطلب مقترح]** — **Safety Budget for Automated Actions:** تحديد عدد أقصى من الأجهزة المسموح بعزلها في موجة واحدة وحد للحظر التلقائي، مع إيقاف عند ارتفاع أثر التغيير. [مصدر للمراجعة](https://github.com/open-policy-agent/opa).
- **CG-536** **[بحث/متطلب مقترح]** — **Change-window and Emergency Operations:** فصل التغييرات العادية المجدولة عن إجراء استجابة طارئ موثق مع موافقات مختلفة واختبار استعادة الخدمة. [مصدر للمراجعة](https://github.com/cloud-custodian/cloud-custodian).

### 09 — إدارة الحوادث والتحقيق والتعافي (CG-537–CG-542)
- **CG-537** **[بحث/متطلب مقترح]** — **Case Workspace and Roles:** استعراض DFIR-IRIS كنموذج لقضية موحدة فيها أدلة ومحاضر ومالكون وصلاحيات، دون نشر واجهته مباشرة على الإنترنت. [مصدر للمراجعة](https://github.com/dfir-iris/iris-web).
- **CG-538** **[بحث/متطلب مقترح]** — **Correlated Forensic Timeline:** استخدام منهج Timesketch لدمج سجلات الأجهزة والسحابة والشبكة في خط زمني واحد ومناقشة الفرضيات. [مصدر للمراجعة](https://github.com/google/timesketch).
- **CG-539** **[بحث/متطلب مقترح]** — **Evidence Clock Offset Tracking:** قياس اختلاف وقت كل حساس والسيرفر والسحابة وإظهار الخطأ الزمني في الجدول؛ لا نختلق ترتيبًا دقيقًا لأحداث غير متزامنة. [مصدر للمراجعة](https://github.com/google/timesketch).
- **CG-540** **[بحث/متطلب مقترح]** — **Preservation without Mutation:** نسخ الأدلة إلى مساحة تحقيق منفصلة والتحقق من Hash وتوثيق سلسلة الحيازة والتعامل مع البيانات المشفرة والأدلة الناقصة. [مصدر للمراجعة](https://github.com/dfir-iris/iris-web).
- **CG-541** **[بحث/متطلب مقترح]** — **Incident SLA with Safe Escalation:** تعريف شدة الحادث ومالكه وموعد المراجعة والتصعيد دون إخطار أطراف غير مخولة أو اتخاذ إجراء على حسابات خارج النطاق. [مصدر للمراجعة](https://github.com/dfir-iris/iris-web).
- **CG-542** **[بحث/متطلب مقترح]** — **Recovery Verification as Evidence:** تسجيل تجربة استعادة فعلية في بيئة منفصلة ونتيجة التحقق، وليس الاكتفاء بسجل Backup Success. [مصدر للمراجعة](https://github.com/restic/restic).

### 10 — أمن منصة CyberGuard نفسها وجودة المنتج (CG-543–CG-548)
- **CG-543** **[بحث/متطلب مقترح]** — **Signed Integration Capability Manifest:** تعريف لكل Adapter للصلاحيات والعمليات المسموحة ومصدره والإصدارات التي اختُبر عليها وأثر كل إجراء، مع توقيع وتدقيق تغييرات المكونات. [مصدر للمراجعة](https://github.com/open-policy-agent/opa).
- **CG-544** **[بحث/متطلب مقترح]** — **Third-party License and Lifecycle Gate:** تقييم تراخيص GitHub وحالة الصيانة والإصدارات والثغرات والتوافق قبل الدمج؛ النجوم لا تعني جواز إعادة التوزيع. [مصدر للمراجعة](https://github.com/ossf/allstar).
- **CG-545** **[بحث/متطلب مقترح]** — **Resilient Offline and Degraded Mode:** استمرار جمع الأحداث المحلية وعرض حالة فقد الربط بالسحابة، ومنع نجاح كاذب لإجراءات الحظر أثناء تعطل واجهة التحكم. [مصدر للمراجعة](https://github.com/falcosecurity/falco).
- **CG-546** **[بحث/متطلب مقترح]** — **Detection Efficacy Scorecard:** قياس تغطية سيناريوهات الاختبار ومعدلات الإنذارات الخاطئة وزمن وصول الأحداث واستجابة المشغل، وليس عدد القواعد المثبتة. [مصدر للمراجعة](https://github.com/DefectDojo/django-DefectDojo).
- **CG-547** **[بحث/متطلب مقترح]** — **High-risk Automation Circuit Breaker:** إيقاف سلسلة أوامر تلقائية عند ظهور أخطاء أو فقد الاتصال أو زيادة أثر التغييرات عن الحد، مع وجود مسار إلغاء يدوي آمن. [مصدر للمراجعة](https://github.com/open-policy-agent/opa).
- **CG-548** **[بحث/متطلب مقترح]** — **Trusted AI Tool Boundary:** تقييد AI في قراءة ملخصات الأدلة والإجراءات المسموحة حسب دور المستخدم، ورفض تعليمات تنفيذ واردة داخل log أو issue أو وثيقة GitHub. [مصدر للمراجعة](https://github.com/open-policy-agent/opa).

## أدوات GitHub المرجعية في هذه الجولة — ليست كلها مطلوبة في الإصدار الأول
| المجال | المشاريع التي تم التأكد من مستودعاتها الرسمية | الفائدة المميزة | شرط/قيد أساسي |
|---|---|---|---|
| تقوية Linux | [ComplianceAsCode](https://github.com/ComplianceAsCode/content), [Lynis](https://github.com/CISOfy/lynis), [OpenSCAP](https://github.com/OpenSCAP/openscap) | معايير وضوابط وقياس الانحراف | عدم تطبيق الإصلاحات تلقائيًا على إنتاج |
| سياسات موحدة | [OPA](https://github.com/open-policy-agent/opa), [Cloud Custodian](https://github.com/cloud-custodian/cloud-custodian) | منع الخطأ قبل النشر وتحليل السحابة | بعض الإجراءات تغيّر البنية؛ Dry-run أولًا |
| أمن Kubernetes/Linux | [Falco](https://github.com/falcosecurity/falco), [Tetragon](https://github.com/cilium/tetragon), [Kyverno](https://github.com/kyverno/kyverno) | كشف Runtime وإنفاذ Policies متى كانت مدعومة | Falco كشف وتنبيه، ليس حظرًا بذاته |
| إدارة الثغرات البرمجية | [DefectDojo](https://github.com/DefectDojo/django-DefectDojo), [Dependency-Track](https://github.com/DependencyTrack/dependency-track) | إزالة التكرار وربط الثغرة بالمالك والإصدار | Dependency-Track v4 ينتهي دعمه ديسمبر 2026 |
| الخصوصية | [Presidio](https://github.com/data-privacy-stack/presidio) | اكتشاف بعض البيانات الحساسة وتمويهها | لا يضمن اكتشاف كل PII أو ملاءمة كل لغة |
| Wi-Fi وFirmware | [Kismet](https://github.com/kismetwireless/kismet), [CHIPSEC](https://github.com/chipsec/chipsec) | مراقبة سلبية لاسلكية وفحوص Firmware متقدمة | CHIPSEC للاختبار في بيئة مختبر وفق تحذيرات المشروع |
| شبكات وقواعد بيانات | [Nautobot](https://github.com/nautobot/nautobot), [pgAudit](https://github.com/pgaudit/pgaudit) | مرجع حالة الشبكة وتدقيق PostgreSQL | صلاحيات دقيقة وتكلفة سجلات مرتفعة محتملة |
| تحقيق وتعافٍ | [DFIR-IRIS](https://github.com/dfir-iris/iris-web), [Timesketch](https://github.com/google/timesketch), [restic](https://github.com/restic/restic) | قضايا وحفظ أدلة وجدول زمني وفحص النسخ | IRIS يحذر من تعريض واجهته مباشرة للإنترنت |
| سياسة مستودعات GitHub | [Allstar](https://github.com/ossf/allstar) | فحص سياسات المستودعات | الخدمة المستضافة توقفت، يحتاج تشغيلًا ذاتيًا |

## ما الذي يجعله Security وأيضًا IT Operations / Resilience؟
1. **Security:** تدقيق الإعدادات، حماية الهوية، الوقاية، الكشف، السياسة والتصاريح، التحقيق والتحكم الآمن.
2. **Network Operations:** الحالة المطلوبة والفعلية، تحليل الاعتماديات، اختبار تغييرات الشبكة قبل التنفيذ، إدارة الانقطاع.
3. **Data Protection:** مراقبة قواعد البيانات والتشفير والخصوصية وتصنيف البيانات وحركة خروجها.
4. **Business Resilience:** نسخ احتياطي متحقق منه، اختبارات الاستعادة، قياس التوقف، حدود أثر العزل والحظر.
5. **DevSecOps:** سياسات المستودعات والبناء وSBOM وحوكمة الأسرار وثغرات التطبيقات.

## تنبيهات خاصة بالدقة والتحقق
- لا يمكن ضمان حماية 100% أو اكتشاف كل أنواع الاختراقات. نجاح النظام يقاس بنتائج اختبارات الدفاع، وشمول الرؤية، وزمن الاستجابة، والتعافي.
- مستودع GitHub مفيد للبحث وليس إذنًا تلقائيًا لإعادة توزيع الشفرة؛ يجب مراجعة الرخصة والإصدارات وحالة الصيانة.
- لا يُجرى مسح متصل أو اختبار على أصول خارج تفويض المستخدم. أدوات Firmware والبرمجيات الضارة تحتاج مختبرًا آمنًا.
- الفرق بين مراقبة وحظر في كل أداة أساسي؛ لا نعِد بأمر تحكم لا تدعمه المنصة والإصدار والصلاحية.
- المراجع الجديدة تساعد على تصميم متطلبات؛ لا تعني أن محركات الاختبار أو الكشف قد دُمجت أو اختُبرت.
- لا نغيّر الواجهة المرجعية الداكنة البرتقالية، ولا نبدأ كودًا أو بروتوتايب أو البرومبت النهائي في هذه المرحلة.

**نقطة الاستكمال:** CG-549، مع أولوية لاختبار تطبيقات Web/API وفق ASVS، أمن قواعد البيانات المُدارة، وحوكمة البيانات والنسخ الاحتياطية متعددة البيئات.


---

## جولة البحث الثانية عشرة — تأمين منافذ الشبكة والبنية التحتية والدومين (v1.2)

**التاريخ:** 2026-11-10. **النطاق:** تعميق متطلبات الأمان في المنافذ المادية، ضوابط Layer 2 وNAC، Management/Control/Data Plane، الهوية والـAD/AD CS، منافذ السيرفرات، والتحكم الآمن متعدد الشركات. جميع البنود **دراسة أو متطلبات مستقبلية فقط**، ولم تُنفّذ أو تُختبر على شبكة إنتاج.

### استنتاجات لا ينبغي إغفالها
1. «Port» قد يعني منفذًا فيزيائيًا على سويتش أو منفذ خدمة TCP/UDP أو سياسة جدار ناري؛ إجراءات الإغلاق مختلفة ولا يجوز مساواتها.
2. ليست كل وسائل الحماية قابلة للجمع: Cisco Catalyst 9200 يوثق عدم دعم 802.1X وPort Security التقليدي معًا على المنفذ في الإصدار المرجعي؛ تُراجع خصائص الطراز والإصدار قبل التوصية.
3. DAI/IPSG يعتمدان غالبًا على DHCP Snooping bindings، والأجهزة الثابتة قد تحتاج استثناءات؛ عدم وجود binding صحيح قد يقطع جهازًا مشروعًا.
4. حماية AD لا تعني مراقبة حسابات Domain Admins فقط؛ تشمل Tier 0 وAD CS والنسخ الاحتياطية وأجهزة الإدارة وخدمات المصادقة والـGPO.
5. CyberGuard يجب أن يفصل قناة قراءة آمنة عن قناة التغيير، مع موافقة وتسجيل واختبار أثر وإمكانية عودة، وخصوصًا في السويتشات الأساسية وDCs.

### 12-A — هوية الجهاز والمصادقة على منافذ السويتش (CG-549–CG-560)
- **CG-549** **[بحث/متطلب مقترح]** — **Port Context Inventory:** عرض interface وswitch وVLAN وLLDP/CDP وMAC(s) وIP(s) ونوع الطرف والـPoE ووقت آخر ظهور؛ مصدر كل قيمة ووقت تحديثها. [مرجع رسمي/مستودع للمراجعة](https://github.com/netdisco/netdisco).
- **CG-550** **[بحث/متطلب مقترح]** — **Port Role Classification:** تصنيف المنفذ تلقائيًا/بموافقة المسؤول إلى endpoint أو uplink أو trunk أو AP أو IP phone أو hypervisor أو printer، وعدم تطبيق سياسة مستخدم على uplink. [مرجع رسمي/مستودع للمراجعة](https://github.com/netdisco/netdisco).
- **CG-551** **[بحث/متطلب مقترح]** — **802.1X Capability Matrix:** التحقق من دعم 802.1X ونمط EAP وخادم RADIUS ونظام العميل وإصدار السويتش قبل اقتراح تفعيله. [مرجع رسمي/مستودع للمراجعة](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/26-x/configuration_guide/sec/b_26x_sec_9200_cg/configuring_ieee_802_1x_port_based_authentication.html).
- **CG-552** **[بحث/متطلب مقترح]** — **NAC Identity Decision Evidence:** ربط المستخدم أو شهادة الجهاز أو جلسة MAC Authentication بنتيجة Allow/Deny/Quarantine مع إظهار حالة عدم اليقين. [مرجع رسمي/مستودع للمراجعة](https://info.support.huawei.com/info-finder/encyclopedia/en/Client+Plug-and-Play.html).
- **CG-553** **[بحث/متطلب مقترح]** — **MAB Exception Expiry:** تصاريح استثناء مؤقتة للأجهزة غير الداعمة لـ802.1X (طابعات/هواتف) مع تقييد VLAN والمالك والمدة ومراجعة الاعتماد على MAC وحده. [مرجع رسمي/مستودع للمراجعة](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/26-x/configuration_guide/sec/b_26x_sec_9200_cg/configuring_ieee_802_1x_port_based_authentication.html).
- **CG-554** **[بحث/متطلب مقترح]** — **Port Security MAC Limit Audit:** اكتشاف منافذ تقبل MACs أكثر من المتوقع أو تتجاوز العدد، مع مراعاة السويتش خلف المنفذ أو الهاتف مع PC. [مرجع رسمي/مستودع للمراجعة](https://info.support.huawei.com/info-finder/encyclopedia/en/detail?action=queryEntityDetail&keyword=Port+Security).
- **CG-555** **[بحث/متطلب مقترح]** — **Violation Handling Profile:** تمييز protect/restrict/shutdown ووضع الاستجابة الصحيحة حسب خطورة الخدمة وحساسية المنفذ، بدل الإغلاق التلقائي الشامل. [مرجع رسمي/مستودع للمراجعة](https://info.support.huawei.com/info-finder/encyclopedia/en/detail?action=queryEntityDetail&keyword=Port+Security).
- **CG-556** **[بحث/متطلب مقترح]** — **Authentication Fail-safe Design:** تمييز سلوك فشل RADIUS/NAC (fail open/fail closed/critical VLAN) وتحديد أثره على الأجهزة والتشغيل قبل تطبيقه. [مرجع رسمي/مستودع للمراجعة](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/26-x/configuration_guide/sec/b_26x_sec_9200_cg/configuring_ieee_802_1x_port_based_authentication.html).
- **CG-557** **[بحث/متطلب مقترح]** — **802.1X + Port Security Conflict Gate:** كشف تعارض 802.1X مع port-security أو مع أنواع المنافذ حسب وثائق المنصة والإصدار؛ عدم تقديم إعدادين متعارضين. [مرجع رسمي/مستودع للمراجعة](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/26-x/configuration_guide/sec/b_26x_sec_9200_cg/configuring_ieee_802_1x_port_based_authentication.html).
- **CG-558** **[بحث/متطلب مقترح]** — **Voice and Data VLAN Safety:** مراجعة Voice VLAN وAccess VLAN والجهازين المتصلين ومنافذ هواتف IP قبل المصادقة أو تغيير VLAN. [مرجع رسمي/مستودع للمراجعة](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/26-x/configuration_guide/sec/b_26x_sec_9200_cg/configuring_ieee_802_1x_port_based_authentication.html).
- **CG-559** **[بحث/متطلب مقترح]** — **Temporary Network Access Pass:** تصريح شبكة مؤقت للمقاول/الفني محدد المستخدم والمنفذ والوجهة والنافذة، مع إبطال مؤكد لا مجرد انتهاء مؤقت الواجهة. [مرجع رسمي/مستودع للمراجعة](https://info.support.huawei.com/info-finder/encyclopedia/en/Client+Plug-and-Play.html).
- **CG-560** **[بحث/متطلب مقترح]** — **Port Identity Change Timeline:** تسجيل تغير الجهاز المرتبط بالمنفذ ونتيجة المصادقة وMAC وVLAN وسبب القرار، مع تنبيه على تكرار إعادة المصادقة. [مرجع رسمي/مستودع للمراجعة](https://github.com/netdisco/netdisco).

### 12-B — حماية الطبقة الثانية والتلاعب بحركة الشبكة (CG-561–CG-572)
- **CG-561** **[بحث/متطلب مقترح]** — **Rogue DHCP Guard:** فحص تفعيل DHCP Snooping والـtrusted interfaces على VLAN المعنية؛ التنبيه من عروض DHCP القادمة من مصدر غير مصرح. [مرجع رسمي/مستودع للمراجعة](https://www.cisco.com/c/en/us/support/docs/switches/lan-switch-software/222274-troubleshoot-dynamic-arp-inspection-dai.html).
- **CG-562** **[بحث/متطلب مقترح]** — **DAI Binding Integrity:** التحقق من أن Dynamic ARP Inspection يحمي VLAN المطلوبة ويعتمد على bindings صحيحة من DHCP Snooping أو ARP ACL للأجهزة الثابتة. [مرجع رسمي/مستودع للمراجعة](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-18/configuration_guide/sec/b_1718_sec_9300_cg/configuring_dynamic_arp_inspection.html).
- **CG-563** **[بحث/متطلب مقترح]** — **IP Source Guard Dependencies:** مراجعة binding وIP/MAC وport والـVLAN والتطبيقات الحساسة قبل اقتراح IPSG، مع كشف الأجهزة الثابتة غير المدرجة. [مرجع رسمي/مستودع للمراجعة](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/sec-crypto/fhs-sisf/fhs-and-sisf-configuration-guide/ip-source-guard.html).
- **CG-564** **[بحث/متطلب مقترح]** — **Static-IP Exception Register:** سجل مُوقع لاستثناءات static IP (سيرفرات وطابعات وكاميرات) لا يسمح بقطعها عند تفعيل DAI أو IPSG. [مرجع رسمي/مستودع للمراجعة](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-18/configuration_guide/sec/b_1718_sec_9300_cg/configuring_dynamic_arp_inspection.html).
- **CG-565** **[بحث/متطلب مقترح]** — **Trusted Port Topology Audit:** مقارنة منافذ DHCP/ARP trusted مع خريطة uplinks والسيرفرات المصرح بها، والتنبيه إذا أصبح منفذ مستخدم موثوقًا. [مرجع رسمي/مستودع للمراجعة](https://www.cisco.com/c/en/us/support/docs/switches/lan-switch-software/222274-troubleshoot-dynamic-arp-inspection-dai.html).
- **CG-566** **[بحث/متطلب مقترح]** — **ARP Spoofing Evidence Correlation:** ربط انحراف IP-MAC مع MAC table وDHCP bindings وتنبيهات DAI؛ لا يعتبر تغير ARP وحده إثبات اختراق. [مرجع رسمي/مستودع للمراجعة](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-18/configuration_guide/sec/b_1718_sec_9300_cg/configuring_dynamic_arp_inspection.html).
- **CG-567** **[بحث/متطلب مقترح]** — **STP Edge Protection:** مراجعة BPDU Guard وRoot Guard وLoop Guard حسب وظيفة المنفذ وموقعه في STP قبل اقتراح التعديل. [مرجع رسمي/مستودع للمراجعة](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9200-series-switches/221191-troubleshoot-layer-2-loops.html).
- **CG-568** **[بحث/متطلب مقترح]** — **Loop and Storm Safety:** رصد حالات loop وMAC flapping وbroadcast storm وتفعيل Storm Control أو استجابة متدرجة حسب دعم العتاد. [مرجع رسمي/مستودع للمراجعة](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9200-series-switches/221191-troubleshoot-layer-2-loops.html).
- **CG-569** **[بحث/متطلب مقترح]** — **Unused Port Secure State:** اكتشاف المنافذ غير المستخدمة واقتراح shutdown/parking VLAN وطبقة مصادقة مناسبة بعد استثناءات الطوارئ. [مرجع رسمي/مستودع للمراجعة](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening).
- **CG-570** **[بحث/متطلب مقترح]** — **Trunk Native VLAN Drift:** مراجعة تغيّر trunk/access وnative VLAN وallowed VLANs ودعم الأجهزة الطرفية، وتسجيل التغيير غير المصرح. [مرجع رسمي/مستودع للمراجعة](https://support.huaweicloud.com/intl/en-us/moredocuments-qiankuncs/qiankuncs_moredoc_specifications_0001.html).
- **CG-571** **[بحث/متطلب مقترح]** — **IPv6 First-Hop Safety:** جرد وجود DHCPv6/RA/ND snooping والحماية من بوابات IPv6 غير مصرح بها حيث تدعمها المنصة. [مرجع رسمي/مستودع للمراجعة](https://support.huaweicloud.com/intl/en-us/moredocuments-qiankuncs/qiankuncs_moredoc_specifications_0001.html).
- **CG-572** **[بحث/متطلب مقترح]** — **PoE Impact Guard:** قبل إغلاق منفذ أو قطع PoE عرض هل عليه هاتف VoIP أو كاميرا أو Access Point ومَن سيتأثر، مع قيد الاستجابة. [مرجع رسمي/مستودع للمراجعة](https://github.com/netdisco/netdisco).

### 12-C — حماية الراوترات والسويتشات والجدار الناري (CG-573–CG-584)
- **CG-573** **[بحث/متطلب مقترح]** — **Management Plane Exposure Audit:** حصر بروتوكولات الإدارة الفعالة (SSH/HTTPS/SNMP/NETCONF) ومن يسمح بالوصول إليها ومقارنتها مع Management ACL/OOB. [مرجع رسمي/مستودع للمراجعة](https://sec.cloudapps.cisco.com/security/center/resources/principles_secure_operations).
- **CG-574** **[بحث/متطلب مقترح]** — **Legacy Management Protocol Flag:** كشف Telnet وFTP وHTTP وSNMPv1/v2 حيث لا ضرورة، وتقديم خطة نقل مع احتفاظ بقناة إدارة. [مرجع رسمي/مستودع للمراجعة](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening).
- **CG-575** **[بحث/متطلب مقترح]** — **Secure SNMPv3 Profile:** التحقق من SNMPv3 مع المصادقة والتشفير ومستوى أقل الصلاحيات، وعدم حفظ أسرار SNMP في التقارير. [مرجع رسمي/مستودع للمراجعة](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening).
- **CG-576** **[بحث/متطلب مقترح]** — **AAA Session Accountability:** مقارنة TACACS+/RADIUS وتسجيل الدخول وتفويض الأوامر وAAA accounting مع السياسة، والاحتفاظ بوصول طوارئ مقيد. [مرجع رسمي/مستودع للمراجعة](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening).
- **CG-577** **[بحث/متطلب مقترح]** — **Out-of-Band Recovery Path:** توثيق قنوات الإدارة خارج نطاق الخدمة والـconsole وما إذا كانت متاحة عند فقد الوصول بعد تغيير ACL. [مرجع رسمي/مستودع للمراجعة](https://sec.cloudapps.cisco.com/security/center/resources/principles_secure_operations).
- **CG-578** **[بحث/متطلب مقترح]** — **Control-Plane Protection Audit:** فحص السياسات على مستوى CoPP/Control Plane Rate Limits وبروتوكولات التوجيه والإدارة حسب دعم الجهاز. [مرجع رسمي/مستودع للمراجعة](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening).
- **CG-579** **[بحث/متطلب مقترح]** — **Routing Adjacency Drift:** التنبيه على جار توجيه جديد أو تغيّر BGP/OSPF وإعدادات المصادقة وprefix limits في الشبكات التي تستخدمها. [مرجع رسمي/مستودع للمراجعة](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening).
- **CG-580** **[بحث/متطلب مقترح]** — **Firewall and ACL Rule Intent:** ربط كل ACL أو firewall rule بالمالك وسبب الإنشاء والنطاق والتاريخ ووجود استثناء مؤقت؛ قياس اختلاف intended/actual. [مرجع رسمي/مستودع للمراجعة](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening).
- **CG-581** **[بحث/متطلب مقترح]** — **Config Change Provenance:** استخدام snapshot/diff لكشف تغييرات إعدادات الشبكة والتوقيت ومنفذ الإدارة، مع إخفاء بيانات الاعتماد من النسخ. [مرجع رسمي/مستودع للمراجعة](https://github.com/ytti/oxidized).
- **CG-582** **[بحث/متطلب مقترح]** — **Signed Backup and Restore Validation:** نسخ إعدادات الشبكة إلى مخزن محمي مع بصمات تحقق، واختبار استعادة التكوين في مختبر أو جهاز بديل معتمد. [مرجع رسمي/مستودع للمراجعة](https://github.com/ytti/oxidized).
- **CG-583** **[بحث/متطلب مقترح]** — **Vendor Parsing Quality Gate:** التمييز بين مخرجات show غير المفهومة والمعلومات المؤكدة؛ اختبار CLI parsers ضد إصدارات أجهزة معروفة. [مرجع رسمي/مستودع للمراجعة](https://github.com/networktocode/ntc-templates).
- **CG-584** **[بحث/متطلب مقترح]** — **Vendor Adapter Safe Capabilities:** عدم تمكين زر الحظر أو التغيير ما لم يدعم الجهاز/الترخيص/الإصدار/الصلاحية عملية محددة ثبتت بالاختبار. [مرجع رسمي/مستودع للمراجعة](https://github.com/carlmontanari/scrapli).

### 12-D — حماية Active Directory والتحكم في الحسابات (CG-585–CG-596)
- **CG-585** **[بحث/متطلب مقترح]** — **Tier-0 Asset Mapping:** رسم نطاق Tier 0 ويشمل DC وAD CS وEntra Connect وأجهزة الإدارة والنسخ ذات السلطة على الهوية، ورفض تمكين وكلاء عالية الصلاحية بلا داع. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/tier-model).
- **CG-586** **[بحث/متطلب مقترح]** — **Privileged Access Workstations:** إظهار أين أُدخلت بيانات دخول Tier 0 وهل الجهاز PAW معتمد، والتنبيه عند استخدامها على جهاز مستخدم عادي. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/tier-model).
- **CG-587** **[بحث/متطلب مقترح]** — **Privileged Group Membership Watch:** تسجيل إضافات وإزالات Domain/Enterprise Admins والمجموعات الحساسة وربطها بالطلب والموافق والتوقيت. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration).
- **CG-588** **[بحث/متطلب مقترح]** — **Sensitive Directory Object Auditing:** رصد تغير كائنات وACL وأذونات AD باستخدام 5136 والأحداث المرتبطة، مع التحقق من تمكين Audit وSACL ومصدر الحدث. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration).
- **CG-589** **[بحث/متطلب مقترح]** — **DCSync Replication Risk Review:** مراجعة من يملك أذونات النسخ المتماثل الحساسة ومراقبة النشاط غير المتوقع بأكثر من دليل، دون قراءة أسرار الدومين. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/defender-for-identity/deploy/event-collection-overview).
- **CG-590** **[بحث/متطلب مقترح]** — **GPO Unauthorized Change Watch:** كشف تعديل GPO أو ربطها أو صلاحياتها، وتحديد الأجهزة التي ستتأثر قبل استعادة نسخة أو إلغاء سياسة. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration).
- **CG-591** **[بحث/متطلب مقترح]** — **Windows LAPS Coverage & Rotation:** فحص حالة نشر Windows LAPS ودورة تغيير كلمات مرور المسؤول المحلي دون إظهار كلمات المرور نفسها للمحلل. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).
- **CG-592** **[بحث/متطلب مقترح]** — **LAPS Legacy Encryption Compatibility:** تمييز قيود تشفير كلمة مرور Windows LAPS إذا كان Domain Functional Level أقدم من 2016، مع اقتراح ترقية مدروسة. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory).
- **CG-593** **[بحث/متطلب مقترح]** — **Managed Service Account Inventory:** حصر حسابات الخدمة المشتركة مقابل gMSA/dMSA حسب نسخة Windows وقيود التطبيقات، ورصد حسابات ذات امتياز زائد. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model).
- **CG-594** **[بحث/متطلب مقترح]** — **Identity Hygiene and Dormant Accounts:** رصد الحسابات القديمة والحسابات دون مالك ونقاط الدخول غير المستخدمة والاستثناءات الأمنية الحساسة. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/tier-model).
- **CG-595** **[بحث/متطلب مقترح]** — **Cross-tier Administrative Session Alert:** ربط تسجيل دخول إداري من Tier أقل إلى Tier أعلى مع سجل الجلسة وطلب التغيير، ومنع استنتاج اختراق من التنبيه وحده. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/tier-model).
- **CG-596** **[بحث/متطلب مقترح]** — **AD Audit Pipeline Self-test:** سيناريو آمن في مختبر لتوليد أحداث 4728/4756/5136 ثم التحقق من وصولها كاملة إلى CyberGuard. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/defender-for-identity/deploy/event-collection-overview).

### 12-E — حماية AD CS وKerberos والتعافي من اختراق الدومين (CG-597–CG-608)
- **CG-597** **[بحث/متطلب مقترح]** — **CA Permissions and Templates Review:** تقييم من يدير CA ومن يستطيع طلب/إصدار شهادات وأنواع القوالب وصلاحياتها، مع مراجعة بشرية للحالات الحساسة. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/secure-delegate-audit-certification-authority).
- **CG-598** **[بحث/متطلب مقترح]** — **Certificate Issuance Audit:** رصد أحداث 4886/4887/4888 لطلبات إصدار الشهادات ونتائجها مع التحقق من تفعيل تدقيق CA فعليًا. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/secure-delegate-audit-certification-authority).
- **CG-599** **[بحث/متطلب مقترح]** — **CA Policy Tamper Alert:** التنبيه على تغيّر أذونات CA أو إعداداتها وأحداث 4882/4885/4890 وعدم تصنيفها خبيثة دون تحقق. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/secure-delegate-audit-certification-authority).
- **CG-600** **[بحث/متطلب مقترح]** — **Certificate Revocation Operations:** مراقبة صحة CRL وانتهاء صلاحيتها والتغييرات المؤثرة على إصدار/إبطال الشهادات المستخدمة بالمصادقة. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/secure-delegate-audit-certification-authority).
- **CG-601** **[بحث/متطلب مقترح]** — **Kerberos Legacy Encryption Inventory:** جرد استخدام RC4 ومكونات الخدمة التي تعتمد عليه وخطة انتقال إلى AES دون إيقاف مصادقة تطبيقات قديمة عشوائيًا. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration).
- **CG-602** **[بحث/متطلب مقترح]** — **NTLM Usage and Reduction Plan:** جمع بيانات استخدام NTLM حسب المصادر المتاحة وتحديد الحسابات/الخدمات المعتمدة قبل فرض قيود تمنع التشغيل. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/defender-for-identity/deploy/event-collection-overview).
- **CG-603** **[بحث/متطلب مقترح]** — **LDAP Signing and TLS Readiness:** التعرف على العملاء غير المتوافقين مع LDAP signing/channel binding وLDAPS قبل تشديد المصادقة في الإنتاج. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/tier-model).
- **CG-604** **[بحث/متطلب مقترح]** — **Domain Trust Modification Watch:** رصد إنشاء وتعديل Trusts وتغيّر صلاحياتها وربط الحدث بموافقة فريق الهوية. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration).
- **CG-605** **[بحث/متطلب مقترح]** — **Directory Backup Integrity:** مراقبة نجاح System State Backup للـDC وNTDS/SYSVOL بحسب نوع النسخة، وتحديد صلاحيات مخزن النسخ. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/system-center/dpm/back-up-system-state-and-bare-metal).
- **CG-606** **[بحث/متطلب مقترح]** — **Forest Recovery Playbook:** خطة اختبار تعافٍ في مختبر منفصل بما فيها سيناريو فشل كل DCs، دون إجراء authoritative restore على الإنتاج. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/system-center/dpm/back-up-system-state-and-bare-metal).
- **CG-607** **[بحث/متطلب مقترح]** — **Identity Attack Path Graph:** ربط الحسابات والمجموعات وACL والأجهزة ذات الامتياز بمسارات تعرض محتملة عبر BloodHound بفحص مصرح ومحدود. [مرجع رسمي/مستودع للمراجعة](https://github.com/SpecterOps/BloodHound).
- **CG-608** **[بحث/متطلب مقترح]** — **AD Emergency Action Dual Approval:** عمليات تعطيل حساب Tier0 أو تعديل GPO أو إزالة ثقة دومين تتطلب تحقق أثر وموافقتين عند اللزوم ومسار استرداد. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/tier-model).

### 12-F — حماية منافذ السيرفرات والخدمات الحرجة (CG-609–CG-620)
- **CG-609** **[بحث/متطلب مقترح]** — **Network Port vs Service Port Model:** التمييز الصريح بين physical switch interface وTCP/UDP listening port وfirewall rule وapplication service لمنع الأوامر الخاطئة. [مرجع رسمي/مستودع للمراجعة](https://github.com/netdisco/netdisco).
- **CG-610** **[بحث/متطلب مقترح]** — **Server Listener Inventory:** جمع حالة TCP/UDP listeners والخدمة والعملية والمالك والبروتوكول والتعرض الخارجي من Agent موثوق أو جدار ناري. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration).
- **CG-611** **[بحث/متطلب مقترح]** — **Critical Server Port Guard:** سياسة افتراضية أكثر صرامة لبروتوكولات إدارة DCs وقواعد البيانات والـHypervisors والنسخ الاحتياطي مع استثناءات معتمدة. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/tier-model).
- **CG-612** **[بحث/متطلب مقترح]** — **Service Stop Dependency Graph:** قبل Stop/Disable/Remove يراجع اعتماد الخدمات المتصلة وسيناريو العودة ولا يسمح بإزالة خدمة حيوية آليًا. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/tier-model).
- **CG-613** **[بحث/متطلب مقترح]** — **Hypervisor and Virtual Switch Impact:** ربط منفذ مضيف Hyper-V/VMware بأجهزة VM وvSwitch وuplinks قبل العزل أو shutdown. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/tier-model).
- **CG-614** **[بحث/متطلب مقترح]** — **Network Isolation Escalation Ladder:** اختيار منع IP/service ثم NAC quarantine ثم port shutdown بحسب الأدلة والقدرة والأثر، مع منع قطع قناة الإدارة. [مرجع رسمي/مستودع للمراجعة](https://support.huaweicloud.com/intl/en-us/moredocuments-qiankuncs/qiankuncs_moredoc_specifications_0001.html).
- **CG-615** **[بحث/متطلب مقترح]** — **Temporary Port Firewall Exception:** منح استثناء RDP/SSH محدد المصدر والوجهة والوقت على السيرفر أو الشبكة مع متابعة إلغائه الفعلي. [مرجع رسمي/مستودع للمراجعة](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening).
- **CG-616** **[بحث/متطلب مقترح]** — **High Availability Change Awareness:** التعرف على أعضاء cluster والـVIP وروابط الإدارة قبل إيقاف منفذ أو إعادة تهيئة خدمة تفاديًا لتعطيل الخدمة الاحتياطية. [مرجع رسمي/مستودع للمراجعة](https://sec.cloudapps.cisco.com/security/center/resources/principles_secure_operations).
- **CG-617** **[بحث/متطلب مقترح]** — **Server Firewall Drift Detection:** مقارنة إعدادات Windows/Linux firewalls المتاحة مع سياسة المؤسسة ومطابقة المنافذ المفتوحة مع الخدمة المالكة. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration).
- **CG-618** **[بحث/متطلب مقترح]** — **Sensitive Service Logging:** التأكد من وصول سجلات RDP وSMB وLDAP وDNS وDB وSSH من مصادرها المصرح بها مع إظهار فجوات التغطية. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/defender-for-identity/deploy/event-collection-overview).
- **CG-619** **[بحث/متطلب مقترح]** — **Break-glass Infrastructure Channel:** تحديد مسار إدارة بديل قبل أي تعديل قد يعزل السويتش أو DC أو الجدار الناري أو Hypervisor. [مرجع رسمي/مستودع للمراجعة](https://sec.cloudapps.cisco.com/security/center/resources/principles_secure_operations).
- **CG-620** **[بحث/متطلب مقترح]** — **Post-change Reachability & Identity Test:** بعد كل إجراء يتحقق من الاتصال المصرح والخدمات الأساسية والمصادقة ومن أن الاستثناء المؤقت قد انتهى، مع إيقاف عند الفشل. [مرجع رسمي/مستودع للمراجعة](https://sec.cloudapps.cisco.com/security/center/resources/principles_secure_operations).

### 12-G — GitHub والتكاملات والتحقق من جودة الحماية (CG-621–CG-632)
- **CG-621** **[بحث/متطلب مقترح]** — **Port-to-User-to-Device Graph:** دمج بيانات Netdisco وLLDP/CDP وDHCP وAD/NAC لمشاهدة من يستخدم المنفذ ومتى، مع توثيق موثوقية كل ربط. [مرجع رسمي/مستودع للمراجعة](https://github.com/netdisco/netdisco).
- **CG-622** **[بحث/متطلب مقترح]** — **Switch Port Change Approval Ledger:** تسجيل طلب تعطيل/فتح منفذ والسبب ومقدم الطلب والموافق والوقت ونتيجة المنفذ بعد التنفيذ. [مرجع رسمي/مستودع للمراجعة](https://github.com/netdisco/netdisco).
- **CG-623** **[بحث/متطلب مقترح]** — **Config Drift Collector Comparison:** مقارنة Oxidized وScrapli وLibreNMS في قراءة/تخزين ومراقبة الاختلافات وتحديد أفضل نطاق لكل واحد. [مرجع رسمي/مستودع للمراجعة](https://github.com/ytti/oxidized).
- **CG-624** **[بحث/متطلب مقترح]** — **Polling Permission Split:** استخدام حساب Read-only للاستكشاف والجرد، وحساب تنفيذي منفصل مقيد بطلبات موقعة وموافقات عند الحاجة. [مرجع رسمي/مستودع للمراجعة](https://github.com/carlmontanari/scrapli).
- **CG-625** **[بحث/متطلب مقترح]** — **CLI Parse Validation Corpus:** مجموعة مخرجات اصطناعية/مختبرية من Cisco/Huawei/غيرهما لقياس دقة استخراج VLAN والواجهة وMAC وACL. [مرجع رسمي/مستودع للمراجعة](https://github.com/networktocode/ntc-templates).
- **CG-626** **[بحث/متطلب مقترح]** — **Infrastructure Telemetry Freshness:** بيان متى تم آخر Poll أو Syslog أو AD event والتأخر والانقطاع وعدم تحويل بيانات قديمة إلى قرار حظر آلي. [مرجع رسمي/مستودع للمراجعة](https://github.com/librenms/librenms).
- **CG-627** **[بحث/متطلب مقترح]** — **Platform-specific Policy Compiler:** ترجمة Intent مثل deny lateral RDP إلى سياسة لكل مورد فقط عندما تدعمها واجهة رسمية مع اختبار وتحقيق نتيجة. [مرجع رسمي/مستودع للمراجعة](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening).
- **CG-628** **[بحث/متطلب مقترح]** — **Prevent Unsafe Global Changes:** حماية uplink وCore وDomain Controller وCluster وAAA وManagement VLAN من الحظر الجماعي بأوامر منفردة. [مرجع رسمي/مستودع للمراجعة](https://sec.cloudapps.cisco.com/security/center/resources/principles_secure_operations).
- **CG-629** **[بحث/متطلب مقترح]** — **Safe Playbook Evidence Bundle:** كل Incident لديه السجلات والمصدر والإصدار والاستثناءات والتوقيت وتوقيع الموافقة والتحقق بعد الإجراء. [مرجع رسمي/مستودع للمراجعة](https://learn.microsoft.com/en-us/defender-for-identity/deploy/event-collection-overview).
- **CG-630** **[بحث/متطلب مقترح]** — **Security Baseline Crosswalk:** ربط فحوص الشبكة وAD بمرجع البائع وضوابط M365 ScubaGear مع إمكانية تمييز متطلب غير قابل للتطبيق. [مرجع رسمي/مستودع للمراجعة](https://github.com/cisagov/ScubaGear).
- **CG-631** **[بحث/متطلب مقترح]** — **Multi-vendor Port Feature Matrix:** مصفوفة vendor/model/software version/license لكل 802.1X وDAI وIPSG وNAC وPoE وتعطيل المنفذ وأثرها. [مرجع رسمي/مستودع للمراجعة](https://support.huaweicloud.com/intl/en-us/moredocuments-qiankuncs/qiankuncs_moredoc_specifications_0001.html).
- **CG-632** **[بحث/متطلب مقترح]** — **Lab Validation before Active Enforcement:** لا نعتمد ميزة حجب/عزل جديدة دون اختبار جهاز فعلي مُلك/مصرح في مختبر وتوثيق خطأ وتراجع وفشل اتصال. [مرجع رسمي/مستودع للمراجعة](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/26-x/configuration_guide/sec/b_26x_sec_9200_cg/configuring_ieee_802_1x_port_based_authentication.html).

## دراسات حالات دفاعية محددة — الإضافة الجديدة

| الحالة | إشارات الكشف المطلوبة | التفسير الممكن | استجابة آمنة مقترحة | شرط إثبات النجاح |
|---|---|---|---|---|
| CASE-40: شخص يوصل DHCP Server على منفذ مستخدم | DHCP offer من منفذ untrusted، MAC وVLAN والخادم المعتمد | DHCP rogue *محتمل*، لا يعني تحديد الشخص | منع DHCP غير المصرح من المنفذ بعد تحقق topology | اختفاء العروض غير المصرح بها واستمرار توزيع DHCP الصحيح |
| CASE-41: محاولة ARP spoofing | DAI drops ومطابقة bindings وسجلات DHCP | انتحال ARP أو binding ناقص | مراجعة trusted ports والاستثناءات الثابتة قبل التفعيل | سلامة الاتصالات وغياب dropped packets المشروعين |
| CASE-42: جهاز غير معروف في معمل | MAC جديد على access port، تغير NAC authentication | جهاز جديد وليس اختراقًا مؤكدًا | Request review أو guest/quarantine VLAN آمنة | التأكد من هوية الجهاز ومالك المنفذ واستمرار الأجهزة المشروعة |
| CASE-43: STP loop | BPDU وMAC flapping وSTP events وارتفاع broadcast | مشكلة بنية أو عبث محتمل | تحقيق في المنفذ واعتماد root/edge guard مناسب | استقرار STP ومعدلات الحركة دون تعطيل uplink |
| CASE-44: إضافة مستخدم إلى Domain Admins | Events 4728/4756، سياق حساب، change ticket | تصعيد صلاحيات مشروع أو غير مشروع | مراجعة، تجميد استثناء، تقييد الحساب بعد تحقق | إزالة الامتياز غير المصرح ووجود موافقة وسجل |
| CASE-45: تغيّر شهادة AD CS | Events 4882/4885/4887/4890، template والطلب والناشر | احتمال إساءة استخدام CA أو تحديث مشروع | عزل أعمال الإدارة الحساس، مراجعة الطلبات والسياسات | التحقق من أن مسار الإصدار آمن مع استمرار مصادقة الخدمات |
| CASE-46: ربط GPO غير مصرح | AD object changes، سياسة، نطاق OU المتأثر | تغيّر أمني/تشغيلي، ليس اختراقًا بحد ذاته | مقارنة baseline وطلب، استعادة مدروسة بموافقة | تحقق انطباق GPO على الأجهزة المطلوبة فقط |
| CASE-47: إيقاف منفذ سويتش يربط IP Phone وPC | LLDP-MED وMAC متعدد وPoE ونوع المنفذ | قد ينقطع الصوت والكمبيوتر معًا | اقتراح تقييد TCP/service أو NAC بدل shutdown | الخدمة والـVoIP باقيان والتهديد احتُوي |
| CASE-48: إغلاق منافذ إدارة DC خطأ | اتصال LDAP/Kerberos/DNS وhealth checks | خطر توقف الدومين وليس حادثًا أمنيًا | منع التنفيذ دون Change Safety وBreak-glass | AD صحي ومتاح وتزامن الحدث وإمكانية التراجع |
| CASE-49: تبديل إعداد SNMPv3 | SNMP auth failures، فرق config وسجل AAA | فقد مراقبة أو سوء إعداد/تلاعب | تصحيح موثق للمستخدم/السر دون عرضه في التقارير | عودة Polling وقياس freshness الفعلي |

## مستودعات GitHub التي جرى التحقق منها في هذه الجولة

| المشروع | الوظيفة | قرار الدراسة | حدود مهمة |
|---|---|---|---|
| [Netdisco](https://github.com/netdisco/netdisco) | تحديد MAC/IP على منفذ سويتش وبعض إدارة المنافذ | **مهم جدًا** لـPort-to-Device | الصلاحيات التنفيذية تُعزل عن قراءة الجرد |
| [Oxidized](https://github.com/ytti/oxidized) | نسخ إعدادات الأجهزة واكتشاف الاختلافات | **مهم جدًا** للـConfig Drift | إخفاء كلمات السر وحماية النسخ |
| [Scrapli](https://github.com/carlmontanari/scrapli) | أتمتة اتصال SSH/NETCONF بالشبكات | مكوّن Adapter مرشح | لا يستخدم Telnet في الإنتاج؛ يراجع الدعم حسب النظام |
| [NTC Templates](https://github.com/networktocode/ntc-templates) | تحويل show output إلى حقول منظمة | مرشح لتطبيع جرد السويتشات | اختبار parser ضد موديلات وإصدارات محددة |
| [LibreNMS](https://github.com/librenms/librenms) | SNMP monitoring واكتشاف الأجهزة | مرجع مراقبة وPerformance | قد يتطلب تكاملًا بدل دمج كامل؛ مراجعة GPL |
| [BloodHound](https://github.com/SpecterOps/BloodHound) | رسم علاقات الصلاحيات ومسارات التحكم بالهوية | مرشح لتقييم تعرض AD | جمع بيانات AD معلومات حساسة تتطلب إذنًا ومحدودية وصول |
| [ScubaGear](https://github.com/cisagov/ScubaGear) | فحص M365/Entra مقابل ضوابط CISA | مرجع سياسات سحابية | ليس بديلًا لمراقبة AD المحلي |

## مصادر تقنية رسمية إضافية / نقاط تحقق

- [Cisco: Dynamic ARP Inspection](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-18/configuration_guide/sec/b_1718_sec_9300_cg/configuring_dynamic_arp_inspection.html): الاعتماد على DHCP Snooping bindings، ووضع static hosts.
- [Cisco: IP Source Guard and DHCP Snooping](https://www.cisco.com/c/en/us/support/docs/switches/lan-switch-software/222274-troubleshoot-dynamic-arp-inspection-dai.html): الضوابط المتسلسلة وسيناريوهات الخطأ.
- [Cisco: 802.1X Restrictions](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/26-x/configuration_guide/sec/b_26x_sec_9200_cg/configuring_ieee_802_1x_port_based_authentication.html): عدم افتراض توافق Port Security التقليدي مع 802.1X.
- [Huawei: CloudCampus Port Security Management](https://support.huaweicloud.com/intl/en-us/moredocuments-qiankuncs/qiankuncs_moredoc_specifications_0001.html): الفروق بين DHCP/ARP/ND snooping وDAI وIPSG وغيرها حسب الخدمة والجهاز.
- [Cisco: Principles of Secure Operations](https://sec.cloudapps.cisco.com/security/center/resources/principles_secure_operations): إدارة Management/Control/Data planes وخيارات الحماية.
- [Microsoft: AD Tier Model](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/tier-model): فصل Tier 0/1/2 وحماية أجهزة الإدارة والهوية.
- [Microsoft: Advanced Audit Policy](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration): أحداث 4728/4756/5136 وغيرها ومتطلبات تمكين التدقيق.
- [Microsoft: Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory): قيود DFL الأقدم من 2016 لتشفير كلمات المرور داخل AD.
- [Microsoft: Secure, Delegate, Audit AD CS](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/secure-delegate-audit-certification-authority): تدقيق الشهادات والـCA مع بيانات 4886/4887/4888.
- [Microsoft: System State Backup](https://learn.microsoft.com/en-us/system-center/dpm/back-up-system-state-and-bare-metal): ما يتضمنه النسخ الاحتياطي للـDomain Controllers.

## نطاق الحماية الذي أصبح محددًا تقنيًا أكثر

**Port / Network Access:** 802.1X وMAB وPort Security وDHCP Snooping وDAI وIPSG وSTP وIPv6 First Hop وStorm Control وVLAN/PoE مع تراخيص/موديلات مختلفة.

**Switch/Router/Firewall:** Management ACL + SSH + SNMPv3 + AAA + syslog + config backup/diff + CoPP + routing authentication وRBAC وBreak-glass.

**Active Directory:** Tier 0 + privileged groups + GPO/ACL + AD CS + Windows LAPS + Kerberos/NTLM/LDAP readiness + System State recovery + audit coverage.

**Servers/Virtualization:** منفذ TCP/UDP مقابل منفذ Switch، خدمات حيوية، Hypervisor، Firewall per-host، توقف الخدمة، والرجوع والتعافي.

**جوّال/تابلت:** شاشة Port أو AD Incident تعرض أثر القرار، لا تمنح إجراء حظر إلا إذا توفرت صلاحيات معتمدة ووسيلة تراجع. لا تعرض كلمات سر LAPS أو مفاتيح SNMP.

**القرار:** لا تطبيق حماية شامل بضغطة زر على جميع السويتشات؛ نبدأ بقراءة فقط وفحص توافق، ثم Dry Run، ثم Pilot في مختبر، ثم صلاحيات محددة في إنتاج بعد التفويض.

**نقطة الاستكمال التالية:** CG-633. ما زالت أدوات الحماية مجرد مكونات مرشحة، وليست منظومة منفذة.


---

# إضافة البحث — v1.3: اكتشاف الأجهزة المتعدد المصادر ونقاط الاتصال والصلاحيات

**تاريخ الإضافة:** 2026-11-10  
**قاعدة الاستمرار:** احتفظنا حرفيًا بجميع المتطلبات CG-001…CG-632 ونضيف بعدها متطلبات قابلة للمراجعة، دون برمجة أو فحص أنظمة حقيقية.  
**النطاق:** Discovery من جهاز PC بإذن، أجهزة Cisco/Huawei، IP/MAC/VLAN/Switchport، هاتف/بروجيكتور/طابعة، DHCP/AD/NAC، أجهزة غير مصرح بها، رؤية الشبكات السلكية واللاسلكية، الحماية والاستجابة المصرح بها.  

## خلاصة البحث

**القرار المقترح:** Hybrid Discovery Fabric وليس `ping sweep` واحدًا: Local PC → authorized infrastructure read-only → FDB/ARP/DHCP/AD/RADIUS/LLDP/CDP → fingerprint evidence fusion → topology and risk evaluation → approved response.

**نقطة هندسية:** ليس ممكنًا إثبات كشف 100% من PC وحده؛ لا يرى تلقائيًا كل حركة VLAN الأخرى، ولا أجهزة خلف NAT، ولا Wi-Fi خارج مدى حساساته، ولا أجهزة صامتة تمامًا. في جميع الأحوال تُعرض حدود الرؤية.

**الصلاحيات:** يبدأ التطبيق بقراءة محولات الجهاز وشبكاته المعتمدة؛ ثم يُعرض Wizard لإدخال SNMPv3 RO أو API/SSH محدود وبيانات خدمة DHCP/AD/NAC مع إذن مسبق. أي صلاحيات تنفيذ وعزل تستلزم فصلًا وموافقة إضافية.

## المتطلبات الجديدة — معرّفات ثابتة


### 13-A — التشغيل من PC والصلاحيات الآمنة (CG-633–CG-644)

- **CG-633** **[بحث/متطلب مقترح]** — **Local-first Starting Workflow:** عند تشغيل التطبيق يعرض كروت الشبكة الفعلية والافتراضية وVPN ونطاقها، ويطلب تحديد الشبكة المصَرّح بها وقرار Read-only قبل الاستكشاف؛ لا يفترض أن كل واجهة مسموحة. [المصدر/مرجع الدراسة](https://github.com/siltus/lan-discovery).
- **CG-634** **[بحث/متطلب مقترح]** — **Interface Identification:** التفريق بين Ethernet/Wi-Fi/VPN/Hyper-V/WSL/Tailscale وواجهات الشبكات المتعددة، مع تجنب اختيار محول افتراضي تلقائيًا. [المصدر/مرجع الدراسة](https://github.com/siltus/lan-discovery).
- **CG-635** **[بحث/متطلب مقترح]** — **Authorization Scope Ledger:** تسجيل مالك الشبكة ونطاق IP/VLAN/المواقع وموافقة الفحص وحدود التوقيت والبروتوكولات المسموحة، وإيقاف الاستكشاف عند تجاوز النطاق. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/cloud-systems-management/network-automation-and-management/catalyst-center/3-1-x/user_guide/b_cisco_catalyst_center_user_guide_3_1_x/b_cisco_catalyst_center_ug_3_1_x_chapter_011.html).
- **CG-636** **[بحث/متطلب مقترح]** — **Read-only Credential Wizard:** صفحة صلاحيات منفصلة: SNMPv3 authPriv قراءة، API token قراءة، SSH حساب محدود بلا تغيير، DHCP/AD قراءة، WLC/NAC حسب الحاجة. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/cloud-systems-management/network-automation-and-management/catalyst-center/3-1-x/user_guide/b_cisco_catalyst_center_user_guide_3_1_x/b_cisco_catalyst_center_ug_3_1_x_chapter_011.html).
- **CG-637** **[بحث/متطلب مقترح]** — **Privilege Capability Check:** فحص قدرة الحساب على قراءة FDB وLLDP/CDP وجداول ARP/واجهات/سجلات DHCP؛ إظهار أسباب نقص النتائج عند غياب الأذونات. [المصدر/مرجع الدراسة](https://github.com/netdisco/netdisco).
- **CG-638** **[بحث/متطلب مقترح]** — **Local Privilege Disclosure:** توضيح أن Windows/Npcap أو التقاط إطارات Raw قد يتطلب امتيازًا إداريًا، بينما يمكن جمع ARP المحلي وDNS والمعلومات المصرح بها بامتيازات أقل. [المصدر/مرجع الدراسة](https://github.com/siltus/lan-discovery).
- **CG-639** **[بحث/متطلب مقترح]** — **Secret Vault Reference:** تخزين بيانات الاعتماد في مخزن أسرار محمي وعدم عرض كلمات السر أو SNMP secrets أو مفاتيح API في الواجهة أو التقارير. [المصدر/مرجع الدراسة](https://github.com/netdisco/snmp-info).
- **CG-640** **[بحث/متطلب مقترح]** — **Credential Rotation and Test:** اختبار صلاحيات القراءة وتاريخ صلاحية الرموز وتدويرها وإلغاء ربطها من دون تعطيل جلسة الاكتشاف بالكامل. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/cloud-systems-management/network-automation-and-management/catalyst-center/3-1-x/user_guide/b_cisco_catalyst_center_user_guide_3_1_x/b_cisco_catalyst_center_ug_3_1_x_chapter_011.html).
- **CG-641** **[بحث/متطلب مقترح]** — **Separate Change Identity:** عدم استخدام حساب الاكتشاف read-only لإطفاء منفذ أو حظر جهاز؛ التنفيذ بحساب منفصل وموافقة معتمدة. [المصدر/مرجع الدراسة](https://github.com/netdisco/netdisco).
- **CG-642** **[بحث/متطلب مقترح]** — **One-click Authorized Discovery:** زر Discover All Authorized Sources يشغّل المصادر المعتمدة تدريجيًا ويعرض التقدم والنتائج وحدودها؛ ليس تعهدًا بكشف كل الأجهزة. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/cloud-systems-management/network-automation-and-management/catalyst-center/3-1-x/user_guide/b_cisco_catalyst_center_user_guide_3_1_x/b_cisco_catalyst_center_ug_3_1_x_chapter_011.html).
- **CG-643** **[بحث/متطلب مقترح]** — **No-credentials Limited Mode:** وضع محدود دون أسرار: أجهزة LAN المرئية فقط وبيانات mDNS/SSDP/DNS/ARP المتاحة؛ يوضح سبب عدم رؤية شبكات VLAN أخرى. [المصدر/مرجع الدراسة](https://github.com/netalertx/NetAlertX).
- **CG-644** **[بحث/متطلب مقترح]** — **Offline First and Later Sync:** تمكين جمع محلي وتخزين أدلة موقّتة دون إنترنت؛ مشاركة النتائج مع مركز مؤسسي مشفر عند السماح بذلك. [المصدر/مرجع الدراسة](https://github.com/netalertx/NetAlertX).

### 13-B — محركات اكتشاف متعددة تكمل بعضها (CG-645–CG-656)

- **CG-645** **[بحث/متطلب مقترح]** — **Network Seed Discovery:** استخدام Default Gateway وواجهات LAN ونتائج البنية الحالية كنقاط بدء للشبكات المصرح بها، لا تخمين نطاقات خارجية. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/cloud-systems-management/network-automation-and-management/catalyst-center/3-1-x/user_guide/b_cisco_catalyst_center_user_guide_3_1_x/b_cisco_catalyst_center_ug_3_1_x_chapter_011.html).
- **CG-646** **[بحث/متطلب مقترح]** — **Layer2 Local Neighbor Discovery:** جمع ARP/IPv6 Neighbor Discovery المحلي مع الزمن ومصدر الربط والتمييز بين الرؤية الفعلية وتاريخ الكاش. [المصدر/مرجع الدراسة](https://github.com/netalertx/NetAlertX).
- **CG-647** **[بحث/متطلب مقترح]** — **DHCP Lease Collector:** قراءة DHCPv4/v6 leases وأسماء العملاء ومدة التأجير وعنوان MAC/Client ID من الخادم بصلاحية قراءة. [المصدر/مرجع الدراسة](https://learn.microsoft.com/en-us/powershell/module/dhcpserver/get-dhcpserverv4lease?view=windowsserver2025-ps).
- **CG-648** **[بحث/متطلب مقترح]** — **AD/DNS Endpoint Join:** ضم Computer Objects وDNS A/AAAA/PTR وDHCP وسجلات الأجهزة بلا افتراض أن كل جهاز لديه حساب AD. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/security/ise/cisco-ise-performance-scalability-and-best-practices.html).
- **CG-649** **[بحث/متطلب مقترح]** — **Switch ARP and FDB Collectors:** قراءة جداول ARP من L3 وجداول MAC/FDB من سويتشات Layer2 وربط النتائج على مستوى VLAN ووقت الالتقاط. [المصدر/مرجع الدراسة](https://docs.librenms.org/Support/Discovery%20Support/).
- **CG-650** **[بحث/متطلب مقترح]** — **LLDP/CDP Seed Crawl:** الزحف من جهاز معروف عبر LLDP/CDP وإضافة الجيران المصرح بهم، مع حدود hops واستثناءات المواقع وأجهزة النواة. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/cloud-systems-management/network-automation-and-management/catalyst-center/3-1-x/user_guide/b_cisco_catalyst_center_user_guide_3_1_x/b_cisco_catalyst_center_ug_3_1_x_chapter_011.html).
- **CG-651** **[بحث/متطلب مقترح]** — **IPv6 Discovery Coverage:** جمع جيران IPv6 وDHCPv6 وRA وDNS AAAA ومصادر NAC وتجنب اختزال الاكتشاف في IPv4 فقط. [المصدر/مرجع الدراسة](https://docs.librenms.org/Support/Discovery%20Support/).
- **CG-652** **[بحث/متطلب مقترح]** — **mDNS and DNS-SD Enrichment:** الاستفادة من خدمات mDNS/DNS-SD للتعرف على طابعات وبروجيكتور وAirPlay/Chromecast وأجهزة محلية، مع احترام multicast domains. [المصدر/مرجع الدراسة](https://github.com/jeremy-dolan/lan-scan).
- **CG-653** **[بحث/متطلب مقترح]** — **SSDP/UPnP Descriptors:** قراءة أوصاف manufacturer/model/friendlyName من SSDP/UPnP ضمن نطاق التصريح وبحدود طلبات آمنة. [المصدر/مرجع الدراسة](https://nmap.org/nsedoc/scripts/broadcast-upnp-info.html).
- **CG-654** **[بحث/متطلب مقترح]** — **WS-Discovery and IPP:** التعرف على الطابعات وأجهزة العرض والكاميرات التي تدعم WS-Discovery أو IPP/ONVIF باستعلامات آمنة ومصرح بها. [المصدر/مرجع الدراسة](https://github.com/jeremy-dolan/lan-scan).
- **CG-655** **[بحث/متطلب مقترح]** — **Low Impact Active Validation:** استخدام ICMP/ARP/TCP connect وNmap service identification بعد الموافقة مع معدل محدود وباستثناء OT/أجهزة حساسة. [المصدر/مرجع الدراسة](https://nmap.org/book/man-os-detection.html).
- **CG-656** **[بحث/متطلب مقترح]** — **Flow and Passive Event Intake:** تغذية اكتشاف الأجهزة من NetFlow/IPFIX/DHCP/RADIUS/Suricata وSyslog بدل الاعتماد على دورات فحص فقط. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/security/ise/cisco-ise-performance-scalability-and-best-practices.html).

### 13-C — معرفة السويتش والمنفذ الفيزيائي بدقة (CG-657–CG-668)

- **CG-657** **[بحث/متطلب مقترح]** — **MAC-IP Cross-source Resolution:** ربط IP↔MAC من DHCP وARP وNAC وIPDT وتاريخ الربط ودرجة الثقة، وعدم اعتبار DHCP lease وحده إثباتًا أن الجهاز متصل الآن. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/cloud-systems-management/network-automation-and-management/catalyst-center/3-1-x/user_guide/b_cisco_catalyst_center_user_guide_3_1_x/b_cisco_catalyst_center_ug_3_1_x_chapter_011.html).
- **CG-658** **[بحث/متطلب مقترح]** — **VLAN-aware MAC FDB Lookup:** قراءة Q-BRIDGE-MIB dot1qTpFdbPort وجدول VLAN لتحديد bridge port المرتبط بعنوان MAC، مع التعامل مع تعدد FDB. [المصدر/مرجع الدراسة](https://datatracker.ietf.org/doc/rfc4363/).
- **CG-659** **[بحث/متطلب مقترح]** — **Bridge Port to ifIndex to ifName:** تحويل bridge port إلى ifIndex ثم ifName/ifDescr من MIB أو CLI، وعدم عرض رقم bridge port كأنه رقم Ethernet للمستخدم. [المصدر/مرجع الدراسة](https://github.com/netdisco/snmp-info).
- **CG-660** **[بحث/متطلب مقترح]** — **Uplink vs Access Edge Traversal:** استخدام LLDP/CDP ومعلومات trunk للوصول إلى أقرب access switch؛ لا نسمّي uplink منفذ جهاز نهائي لمجرد ظهور MAC عليه. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/lyr2-fwd/cdp-lldp-mac-udld/cdp-lldp-mac-udld-configuration-guide/c-configure-lldp.html).
- **CG-661** **[بحث/متطلب مقترح]** — **Wireless Association Mapping:** عند اتصال Wi-Fi نعرض AP/SSID/BSSID والـWLC association بدل ادعاء اتصال الجهاز مباشرة بـGigabitEthernet. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/security/ise/cisco-ise-performance-scalability-and-best-practices.html).
- **CG-662** **[بحث/متطلب مقترح]** — **Phone and PC Shared Port Awareness:** كشف تعدد MAC وVoice VLAN/LLDP-MED وPoE عندما يتشارك IP Phone والكمبيوتر منفذًا واحدًا، وتحذير قبل أي shutdown. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/lyr2-fwd/cdp-lldp-mac-udld/cdp-lldp-mac-udld-configuration-guide/c-configure-lldp.html).
- **CG-663** **[بحث/متطلب مقترح]** — **Downstream Unmanaged Switch Detection:** إذا ظهرت MACs متعددة على منفذ واحد بلا LLDP downstream، نصنف الوضع Possible downstream switch/bridge ونمتنع عن تخمين المنفذ الفرعي. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/lyr2-fwd/cdp-lldp-mac-udld/cdp-lldp-mac-udld-configuration-guide/c-configure-mac.html).
- **CG-664** **[بحث/متطلب مقترح]** — **MAC Table Aging and Staleness:** حفظ أول/آخر ظهور ووقت polling ومدة انتهاء MAC/FDB؛ علامة قديم/غير مؤكد إذا تغير MAC أو اختفى من الجدول. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/lyr2-fwd/cdp-lldp-mac-udld/cdp-lldp-mac-udld-configuration-guide/c-configure-mac.html).
- **CG-665** **[بحث/متطلب مقترح]** — **MAC Mobility and Port Flap Detection:** تتبع انتقال MAC بين منافذ أو سويتشات والتحقق من حالات الحركة المشروعة عبر Wi-Fi أو افتراضية قبل تصنيف spoofing. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/lyr2-fwd/cdp-lldp-mac-udld/cdp-lldp-mac-udld-configuration-guide/c-configure-mac.html).
- **CG-666** **[بحث/متطلب مقترح]** — **Port Physical Inventory:** عرض الواجهة والـVLAN والسرعة والـduplex والـPoE والإدارة/up/down والوصف والجيران والموقع حسب البيانات المتاحة. [المصدر/مرجع الدراسة](https://github.com/netdisco/snmp-info).
- **CG-667** **[بحث/متطلب مقترح]** — **Switch Chain Evidence Trail:** عرض المسار Router → Distribution → Access → Interface مع كل علاقة ومصدرها ودرجة الثقة، وإظهار الفجوات بدل بناء صلة وهمية. [المصدر/مرجع الدراسة](https://github.com/netdisco/netdisco).
- **CG-668** **[بحث/متطلب مقترح]** — **Switch Readback Verification:** التحقق من حداثة جدول FDB قبل اقتراح حظر، وإعادة قراءة المنفذ من الجهاز عند طلب أي تغيير يؤثر على الاتصال. [المصدر/مرجع الدراسة](https://github.com/netdisco/netdisco).

### 13-D — كشف نوع الجهاز والطراز والمستخدم (CG-669–CG-680)

- **CG-669** **[بحث/متطلب مقترح]** — **Evidence-based Device Classifier:** تصنيف Router/Switch/PC/Server/Printer/Projector/Camera/IP Phone/AP/IoT/Unknown من أدلة متعددة مع نسبة ثقة ونص تفسير. [المصدر/مرجع الدراسة](https://info.support.huawei.com/info-finder/encyclopedia/en/detail?action=queryEntityDetail&keyword=Terminal+Identification).
- **CG-670** **[بحث/متطلب مقترح]** — **SNMP SysObjectID and SysDescr:** استخدام sysObjectID/sysDescr والبيانات المعيارية وطرازات MIB عندما يتيح الجهاز SNMP قراءة. [المصدر/مرجع الدراسة](https://github.com/netdisco/snmp-info).
- **CG-671** **[بحث/متطلب مقترح]** — **MAC Vendor with Randomization Guard:** OUI مؤشر للشركة وليس دليلًا كافيًا للنوع؛ كشف MAC المحلي/العشوائي وعرض عدم يقين. [المصدر/مرجع الدراسة](https://github.com/siltus/lan-discovery).
- **CG-672** **[بحث/متطلب مقترح]** — **DHCP Fingerprint Classifier:** استخدام Option 55/60 وhostname والفئة وClient ID كمؤشرات لتحديد نوع الجهاز، مع قواعد Fingerbank إن كان الترخيص يسمح. [المصدر/مرجع الدراسة](https://github.com/inverse-inc/packetfence/blob/devel/docs/installation/fingerbank_integration.asciidoc).
- **CG-673** **[بحث/متطلب مقترح]** — **LLDP-MED Phone Media Endpoint Profiles:** التعرف على هواتف IP وأجهزة المؤتمرات عبر LLDP-MED مع سياسة voice VLAN ومعلومات PoE إذا أرسلها الجهاز. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/lyr2-fwd/cdp-lldp-mac-udld/cdp-lldp-mac-udld-configuration-guide/c-configure-lldp.html).
- **CG-674** **[بحث/متطلب مقترح]** — **Projector and Display Fingerprints:** مطابقة mDNS/SSDP/UPnP وmanufacturer/modelName وDNS وHTTP metadata (إن توفر) للتعرف على Projector/Display. [المصدر/مرجع الدراسة](https://github.com/jeremy-dolan/lan-scan).
- **CG-675** **[بحث/متطلب مقترح]** — **Printer Detection and Attributes:** استعلامات IPP/WS-Discovery/mDNS لجرد الطابعات والطرازات مع تفادي التباس أجهزة الطباعة الافتراضية. [المصدر/مرجع الدراسة](https://github.com/jeremy-dolan/lan-scan).
- **CG-676** **[بحث/متطلب مقترح]** — **Managed Asset Evidence Priority:** ترجيح MDM/EDR/AD/NAC المعتمد على تخمين عنوان MAC أو خدمة HTTP، مع إظهار التعارض بين المصادر. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/security/ise/cisco-ise-performance-scalability-and-best-practices.html).
- **CG-677** **[بحث/متطلب مقترح]** — **OS Fingerprint Confidence:** وسم نتيجة Nmap أو TCP banner كتقدير OS لا حقيقة مطلقة؛ اختلاف الردود والجدران النارية يؤثر في الدقة. [المصدر/مرجع الدراسة](https://nmap.org/book/man-os-detection.html).
- **CG-678** **[بحث/متطلب مقترح]** — **Manual Classification with Audit:** السماح بتصحيح النوع أو الاسم أو الموقع يدويًا مع سجل تغييرات، وعدم ضياع التصحيح عند دورة اكتشاف جديدة. [المصدر/مرجع الدراسة](https://github.com/netalertx/NetAlertX).
- **CG-679** **[بحث/متطلب مقترح]** — **Unknown Device Treatment:** النوع Unknown حالة طبيعية قابلة للتحقيق، وليست تلقائيًا خبيثًا أو جهازًا دخل دون تصريح. [المصدر/مرجع الدراسة](https://info.support.huawei.com/info-finder/encyclopedia/en/detail?action=queryEntityDetail&keyword=Terminal+Identification).
- **CG-680** **[بحث/متطلب مقترح]** — **Classifier Rule Provenance and Drift:** حفظ قاعدة التصنيف وإصدار قاعدة البصمات والمصدر، ومراجعة التدهور عند تحديث Firmware/OS. [المصدر/مرجع الدراسة](https://info.support.huawei.com/info-finder/encyclopedia/en/detail?action=queryEntityDetail&keyword=Terminal+Identification).

### 13-E — الأجهزة الجديدة والإنترنت الشخصي والنقاط غير المصرح بها (CG-681–CG-692)

- **CG-681** **[بحث/متطلب مقترح]** — **New Device Change Stream:** التنبيه لجهاز جديد مع وقت الاتصال الأول وMAC/IP والموقع والمنفذ ونوعه ومالك الأصل وأدلة الحدث. [المصدر/مرجع الدراسة](https://github.com/netalertx/NetAlertX).
- **CG-682** **[بحث/متطلب مقترح]** — **Missing Device Distinction:** الفصل بين جهاز اختفى من الشبكة وجهاز نائم أو فحص فاشل أو VLAN معزولة؛ عدم إصدار إنذار خطير آليًا. [المصدر/مرجع الدراسة](https://github.com/netalertx/NetAlertX).
- **CG-683** **[بحث/متطلب مقترح]** — **Unapproved Hotspot Investigation:** دراسة كشف نقطة Wi-Fi شخصية عبر WIDS/WLC/Kismet إن توفرت حساسات لاسلكية؛ عدم الادعاء أن PC سلكي يراها كلها. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/support/docs/wireless/4400-series-wireless-lan-controllers/112045-handling-rogue-cuwn-00.html).
- **CG-684** **[بحث/متطلب مقترح]** — **Rogue Wired AP Correlation:** ربط SSID/BSSID المكتشف لاسلكيًا مع MAC/FDB لمنفذ سلكي عندما تسمح الأدلة؛ خلف NAT قد لا يمكن معرفة العملاء. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/support/docs/wireless/4400-series-wireless-lan-controllers/112045-handling-rogue-cuwn-00.html).
- **CG-685** **[بحث/متطلب مقترح]** — **Rogue DHCP Event Correlation:** كشف عروض DHCP من مصدر غير معتمد باستخدام DHCP snooping/PacketFence/logging عند وجود رؤية مناسبة. [المصدر/مرجع الدراسة](https://github.com/inverse-inc/packetfence/blob/devel/conf/pf.conf.defaults).
- **CG-686** **[بحث/متطلب مقترح]** — **Unauthorized Gateway and DNS Change:** تنبيه عند ظهور Default Gateway/DNS جديد للمضيفين أو تغييرات DHCP options مشبوهة مع سياق التغيير. [المصدر/مرجع الدراسة](https://github.com/inverse-inc/packetfence/blob/devel/conf/pf.conf.defaults).
- **CG-687** **[بحث/متطلب مقترح]** — **Personal Mobile Data Blind-spot:** الهاتف الذي يستخدم بياناته الخلوية فقط خارج الشبكة لا يظهر لماسح الشبكة؛ هاتف يشارك NAT يخفي غالبًا أجهزة خلفه. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/support/docs/wireless/4400-series-wireless-lan-controllers/112045-handling-rogue-cuwn-00.html).
- **CG-688** **[بحث/متطلب مقترح]** — **Unmanaged Mini-switch and Bridge Risk:** متابعة منفذ تظهر عليه عناوين MAC متعددة بشكل غير معتاد وتحديد هل هو IP Phone/AP/سويتش مصرح، دون حظر تلقائي. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/lyr2-fwd/cdp-lldp-mac-udld/cdp-lldp-mac-udld-configuration-guide/c-configure-mac.html).
- **CG-689** **[بحث/متطلب مقترح]** — **IPv6 Rogue RA and ND Signals:** إضافة مراقبة Rogue Router Advertisements وتغيرات IPv6 Router/DNS من مصادر موثوقة حسب الدعم. [المصدر/مرجع الدراسة](https://docs.librenms.org/Support/Discovery%20Support/).
- **CG-690** **[بحث/متطلب مقترح]** — **Wireless BYOD and Guest Policy:** تمييز الأجهزة الضيف والمصرح بها مؤقتًا عن المجهولة، وربط NAC مع الهوية ومدة التصريح. [المصدر/مرجع الدراسة](https://github.com/inverse-inc/packetfence).
- **CG-691** **[بحث/متطلب مقترح]** — **Projector/IoT Risk Profiling:** التعرف على البروجيكتور والطابعة والـIoT لاقتراح VLAN مخصصة وحظر الإدارة غير الضرورية ضمن سياسة مصرح بها. [المصدر/مرجع الدراسة](https://info.support.huawei.com/info-finder/encyclopedia/en/detail?action=queryEntityDetail&keyword=Terminal+Identification).
- **CG-692** **[بحث/متطلب مقترح]** — **No Silent Rogue Attribution:** تغيير IP أو MAC أو DHCP لا يثبت وجود مهاجم؛ يطلب النظام التحقق من الأدلة والمصدر قبل اتهام المستخدم. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/security/ise/cisco-ise-performance-scalability-and-best-practices.html).

### 13-F — ربط الاكتشاف بالحماية المصرح بها (CG-693–CG-702)

- **CG-693** **[بحث/متطلب مقترح]** — **Device Admission and 802.1X/NAC Hook:** عند انضمام جهاز جديد تُقرأ حالة 802.1X/MAB/NAC وتُعرض السياسة؛ العزل عبر تكامل مدعوم وموافقة. [المصدر/مرجع الدراسة](https://github.com/inverse-inc/packetfence).
- **CG-694** **[بحث/متطلب مقترح]** — **Quarantine VLAN Safety:** اختيار Quarantine VLAN عند القدرة الفنية، مع فحص Voice VLAN وDHCP وطرق الاسترداد. [المصدر/مرجع الدراسة](https://github.com/inverse-inc/packetfence).
- **CG-695** **[بحث/متطلب مقترح]** — **Switchport Security Baseline:** مراجعة DHCP Snooping/DAI/IPSG/802.1X/Port Security وBPDU/Storm Control حسب توافق الطراز ونسخة النظام. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/security/ise/cisco-ise-performance-scalability-and-best-practices.html).
- **CG-696** **[بحث/متطلب مقترح]** — **Unexpected MAC Count and PoE Changes:** كشف منافذ تجاوزت MACs المعتادة أو تغير PoE أو ظهرت نقطة وصول على منفذ مخصص لجهاز آخر. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/lyr2-fwd/cdp-lldp-mac-udld/cdp-lldp-mac-udld-configuration-guide/c-configure-mac.html).
- **CG-697** **[بحث/متطلب مقترح]** — **Port Disable Risk Warning:** قبل تعطيل منفذ يُعرض هل هو trunk أو uplink أو IP Phone أو AP أو server teaming، ويُمنع الإجراء الحساس دون موافقات. [المصدر/مرجع الدراسة](https://github.com/netdisco/netdisco).
- **CG-698** **[بحث/متطلب مقترح]** — **Per-port Temporary Admission:** تصريح مؤقت لجهاز/منفذ/VLAN ووقت بداية ونهاية، مع تحقق إلغاء السياسة عند الانتهاء. [المصدر/مرجع الدراسة](https://github.com/inverse-inc/packetfence).
- **CG-699** **[بحث/متطلب مقترح]** — **Protection Status for Unknown Device:** فتح قضية Unknown Device مع سبب الاشتباه ودرجة التغطية، دون أن يحكم عليها الذكاء الاصطناعي بأنها اختراق. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/security/ise/cisco-ise-performance-scalability-and-best-practices.html).
- **CG-700** **[بحث/متطلب مقترح]** — **Identity and Asset Owner Linking:** الربط الاختياري بين الجهاز والمالك أو المستخدم من AD/NAC/MDM أو الجرد، مع الحد الأدنى من البيانات. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/cloud-systems-management/network-automation-and-management/catalyst-center/3-1-x/user_guide/b_cisco_catalyst_center_user_guide_3_1_x/b_cisco_catalyst_center_ug_3_1_x_chapter_011.html).
- **CG-701** **[بحث/متطلب مقترح]** — **Enforcement Read-after-write:** عند السماح بإجراء مستقبلي يجب التحقق من التطبيق الفعلي على الجهاز وتسجيل التراجع؛ لا يكفي نجاح HTTP 200. [المصدر/مرجع الدراسة](https://intl.devzone.huawei.com/en/enterprise/cloudcampus/quickStart.html).
- **CG-702** **[بحث/متطلب مقترح]** — **Fail Safe Management Channel:** عدم قطع الوصول الإداري أو قناة الاسترجاع عند عزل منفذ/جهاز؛ سياسات عدم لمس Core وDC وManagement. [المصدر/مرجع الدراسة](https://github.com/netdisco/netdisco).

### 13-G — تشغيل مؤسسي وتغطية دقيقة وقابلية للتوسع (CG-703–CG-714)

- **CG-703** **[بحث/متطلب مقترح]** — **Event-driven Discovery:** دمج RADIUS/DHCP/syslog/SNMP traps لتحديث الجهاز سريعًا عند الحدث، إلى جانب polling دوري. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/security/ise/cisco-ise-performance-scalability-and-best-practices.html).
- **CG-704** **[بحث/متطلب مقترح]** — **Scan Rate Limit and Scheduling:** حدود معدلات لكل جهاز وVLAN ومبنى، وقائمة استثناءات للأجهزة الحساسة، وعدم جعل 20k جهاز هدف فحص مكثف متزامن. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/security/ise/cisco-ise-performance-scalability-and-best-practices.html).
- **CG-705** **[بحث/متطلب مقترح]** — **Distributed Collector Architecture:** حساسات موزعة قرب VLAN/المواقع مع مركز واحد، لتجاوز محدودية ARP/multicast على PC واحد. [المصدر/مرجع الدراسة](https://github.com/netalertx/NetAlertX).
- **CG-706** **[بحث/متطلب مقترح]** — **Read-only First Principle:** جميع الوحدات تبدأ قراءة فقط؛ أوامر التغيير منفصلة وصلاحيات مختلفة وإثبات نتيجة. [المصدر/مرجع الدراسة](https://github.com/netdisco/netdisco).
- **CG-707** **[بحث/متطلب مقترح]** — **Cross-site Duplicate Reconciliation:** إزالة تكرار نفس الأصل بين DHCP وARP وAD وNAC وNMS والواجهات الافتراضية وتسجيل هوية مرجعية. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/cloud-systems-management/network-automation-and-management/catalyst-center/3-1-x/user_guide/b_cisco_catalyst_center_user_guide_3_1_x/b_cisco_catalyst_center_ug_3_1_x_chapter_011.html).
- **CG-708** **[بحث/متطلب مقترح]** — **Asset Evidence Freshness:** حقل First Seen/Last Seen/Last Confirmed مع TTL للمصادر والتمييز بين اتصال حالي وسجل تاريخي. [المصدر/مرجع الدراسة](https://github.com/netalertx/NetAlertX).
- **CG-709** **[بحث/متطلب مقترح]** — **Discovery Coverage Dashboard:** قياس تغطية VLAN والشبكات والأجهزة المصرح بها ونسبة أجهزة ذات نوع معروف ومنفذ موثوق ومصادر بيانات فعالة. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/security/ise/cisco-ise-performance-scalability-and-best-practices.html).
- **CG-710** **[بحث/متطلب مقترح]** — **Privacy Sensitive Inventory:** ضوابط إخفاء بيانات المالك والموقع والسجلات الحساسة حسب الأدوار وفترات الاحتفاظ المصرح بها. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/cloud-systems-management/network-automation-and-management/catalyst-center/3-1-x/user_guide/b_cisco_catalyst_center_user_guide_3_1_x/b_cisco_catalyst_center_ug_3_1_x_chapter_011.html).
- **CG-711** **[بحث/متطلب مقترح]** — **Vendor Compatibility Profiles:** مصفوفة Cisco/Huawei/Juniper/Aruba/غيرها بحسب الإصدار وSNMP MIB وAPI وNAC، لا وعد بدعم جميع التفاصيل دائمًا. [المصدر/مرجع الدراسة](https://intl.devzone.huawei.com/en/enterprise/cloudcampus/quickStart.html).
- **CG-712** **[بحث/متطلب مقترح]** — **Failure and Stale Source Handling:** التمييز بين جهاز مختف وSNMP timeout أو انقطاع API أو Collector offline؛ إظهار أن البيانات غير حديثة. [المصدر/مرجع الدراسة](https://github.com/netalertx/NetAlertX).
- **CG-713** **[بحث/متطلب مقترح]** — **Audit of Discovery Access:** تسجيل من شغّل الفحص والنطاق والاعتمادات المشار إليها والمصادر المجمعة والأخطاء والتواريخ. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/cloud-systems-management/network-automation-and-management/catalyst-center/3-1-x/user_guide/b_cisco_catalyst_center_user_guide_3_1_x/b_cisco_catalyst_center_ug_3_1_x_chapter_011.html).
- **CG-714** **[بحث/متطلب مقترح]** — **Discovery Confidence Calibration:** قياس دقة تصنيف الأجهزة وربط المنافذ بمقارنة عينة ميدانية موثقة؛ تقليل الإنذارات الخاطئة. [المصدر/مرجع الدراسة](https://info.support.huawei.com/info-finder/encyclopedia/en/detail?action=queryEntityDetail&keyword=Terminal+Identification).

### 13-H — دراسات التحقق والمنتج النهائي (CG-715–CG-724)

- **CG-715** **[بحث/متطلب مقترح]** — **Test Lab Mixed Device Matrix:** مجموعة تجارب مصرّح بها: Cisco Switch + Huawei Switch + Windows + Linux + VoIP + Printer + Projector + AP + DHCP + AD. [المصدر/مرجع الدراسة](https://info.support.huawei.com/info-finder/encyclopedia/en/detail?action=queryEntityDetail&keyword=Terminal+Identification).
- **CG-716** **[بحث/متطلب مقترح]** — **Port Path Validation Study:** قياس نسبة الأجهزة التي عُرفت نقاط اتصالها بصورة صحيحة مقابل مراجعة السويتش وFDB وLLDP؛ حالات trunk/phone/virtualization. [المصدر/مرجع الدراسة](https://github.com/netdisco/netdisco).
- **CG-717** **[بحث/متطلب مقترح]** — **Projector and Unknown IoT Study:** اختبار نجاح المعرّف مع أجهزة عرض قديمة وحديثة باستخدام mDNS/SSDP/WS-Discovery والاعتماد على المصدر لا التخمين. [المصدر/مرجع الدراسة](https://github.com/jeremy-dolan/lan-scan).
- **CG-718** **[بحث/متطلب مقترح]** — **Rogue DHCP False Positive Study:** مقارنة أحداث PacketFence/Cisco/NAC في مختبر مع خادم DHCP غير مصرح محاكى وتوثيق حساسية المستشعر. [المصدر/مرجع الدراسة](https://github.com/inverse-inc/packetfence/blob/devel/conf/pf.conf.defaults).
- **CG-719** **[بحث/متطلب مقترح]** — **Personal Hotspot Visibility Study:** تجارب منفصلة لهاتف Wi-Fi hotspot وهاتف USB tethering وهاتف يستخدم cellular وحده، لتوثيق ما يُرى وما لا يُرى. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/support/docs/wireless/4400-series-wireless-lan-controllers/112045-handling-rogue-cuwn-00.html).
- **CG-720** **[بحث/متطلب مقترح]** — **Network Outage Recovery Study:** اختبار فقد SNMP/NAC/WLC وظهور stale coverage دون إعلان خاطئ بأن جميع الأجهزة انفصلت. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/td/docs/security/ise/cisco-ise-performance-scalability-and-best-practices.html).
- **CG-721** **[بحث/متطلب مقترح]** — **Multi-vendor Parser Validation:** تجميع مخرجات معتمدة أو اصطناعية من IOS-XE وVRP وغيرها لاختبار استخراج MAC/Port/VLAN وطراز الجهاز. [المصدر/مرجع الدراسة](https://github.com/netdisco/snmp-info).
- **CG-722** **[بحث/متطلب مقترح]** — **Commercial License Review:** تقييم تراخيص Netdisco/LibreNMS/PacketFence/Nmap والمكونات الإضافية قبل ضمها لتطبيق تجاري. [المصدر/مرجع الدراسة](https://github.com/netdisco/netdisco).
- **CG-723** **[بحث/متطلب مقترح]** — **Prototype Acceptance Criteria:** تعريف نتائج تقبل لاحقًا: اكتشاف جهاز جديد، تصنيف مع دليل، العثور على السويتش/المنفذ عند توفر المصدر، تنبيه rogue DHCP، بدون تعطيل. [المصدر/مرجع الدراسة](https://github.com/netalertx/NetAlertX).
- **CG-724** **[بحث/متطلب مقترح]** — **No Full Discovery Guarantee:** النتيجة يجب أن تقول الرؤية جزئية حيث لا تتوفر صلاحية أو مصدر أو يكون الجهاز مخفيًا وراء NAT/شبكة غير مرئية. [المصدر/مرجع الدراسة](https://www.cisco.com/c/en/us/support/docs/wireless/4400-series-wireless-lan-controllers/112045-handling-rogue-cuwn-00.html).


## نتائج مقارنة مشاريع GitHub والمنتجات المرجعية — v1.3

| الأداة | قوتها الموثقة | حدودها أو سبب عدم اعتمادها وحدها | قرار البحث |
|---|---|---|---|
| [Netdisco](https://github.com/netdisco/netdisco) | IP/MAC إلى switchport، جرد، API، port controls | يعتمد على القدرة على قراءة السويتشات؛ وظيفة التنفيذ تفصل عن القراءة | أساس مرجعي قوي لمنفذ Ethernet |
| [LibreNMS](https://github.com/librenms/librenms) | CDP/LLDP وARP وFDB وVLAN وSNMP مراقبة | كشف مخصص للشبكات لا يكفي لتصنيف كل أجهزة IoT | اكتشاف وتجسيد topology |
| [PacketFence](https://github.com/inverse-inc/packetfence) + [Fingerbank integration](https://github.com/inverse-inc/packetfence/blob/devel/docs/installation/fingerbank_integration.asciidoc) | NAC وDHCP fingerprinting وRADIUS وRogue DHCP | يحتاج تصميم NAC/TX/RADIUS وتفويض؛ أجهزة غير متوافقة | قاعدة سياسات دخول ومصدر بصمات |
| [NetAlertX](https://github.com/netalertx/NetAlertX) | تنبيهات أجهزة جديدة أو اختفت ومزامنة مواقع مختلفة | ARP لا يعمل عبر الشبكات الفرعية دون حساسات/مصادر | طبقة تغيرات وعرض للأجهزة |
| [SNMP::Info](https://github.com/netdisco/snmp-info) | طبقة تجريد multi-vendor MIB/CDP/LLDP/ifIndex | اختلاف MIB والتطبيقات بين الإصدارات | محرك توحيد بيانات المنافذ |
| [Nmap](https://github.com/nmap/nmap) | فحص OS/خدمة عند تصريح وملاءمة جهاز | نشط؛ OS Fingerprinting تقديري ولا يرى الأجهزة غير المتاحة | فحص داعم لا أساسي |
| [Cisco ISE](https://www.cisco.com/c/en/us/td/docs/security/ise/cisco-ise-performance-scalability-and-best-practices.html) | Probes متعددة + Device Sensor + RADIUS | منتج تجاري؛ Requires infrastructure config | مرجع تصميم وظيفي |
| [Huawei iMaster Terminal Identification](https://info.support.huawei.com/info-finder/encyclopedia/en/detail?action=queryEntityDetail&keyword=Terminal+Identification) | Passive fingerprints + light probes + flow/AI profiling | تفاوت الميزات بحسب نوع الجهاز والإصدار والترخيص | مرجع أساسي للتصنيف متعدد الموردين |
| [lan-scan](https://github.com/jeremy-dolan/lan-scan) | mDNS/SSDP/WS-Discovery/ARP + IPP enrichment | مناسب لشبكة محلية أكثر من مؤسسة كبرى | نماذج لبروجيكتور/Printer |
| [NetBox](https://github.com/netbox-community/netbox) | مصدر بيانات معتمد للأصول والمواقع والكابلات | ليس أداة اكتشاف لحظي شاملة | ربط discovered vs expected |

## حالات الاستخدام المستهدفة (أمثلة لا نتائج حقيقية)

| السيناريو | مصادر اكتشاف محتملة | التفسير الآمن | ما يظهر للمسؤول |
|---|---|---|---|
| بروجيكتور جديد في قاعة | DHCP + FDB + mDNS/SSDP/UPnP | جهاز عرض محتمل يحتاج اعتمادًا | IP, MAC, Vendor/Model, Switch/Port/VLAN, Confidence |
| هاتف IP ومعه PC على منفذ واحد | LLDP-MED + Voice VLAN + MACs متعددة + PoE | منفذ مشترك؛ الإغلاق يؤثر على الصوت والكمبيوتر | تنبيه تأثير الإجراء |
| Mini-switch موصول بمنفذ مستخدم | MACs متعددة في access port بلا جار LLDP | احتمال bridge/unmanaged switch وليس إثبات اختراق | Need Review + Port + Evidence |
| نقطة اتصال Wi-Fi شخصية | WIDS/WLC + ربط MAC عند وجود حساس | قد تكون قريبة لا تتصل بالشبكة؛ لا تعني اختراقًا | SSID/BSSID + مدى الرؤية + اتصال الشبكة إن ثبت |
| هاتف يستخدم بيانات 4G/5G فقط | لا يوجد مصدر شبكة محلية | خارج رؤية شبكة LAN | لا يدعي النظام كشفه |
| جهاز اختفى من الشبكة | stale DHCP + FDB missing + failed probe | قد يكون سكونًا أو نقلًا أو فشل جمع | Last Seen + Confidence + Source Health |
| جهاز DHCP غير معتمد | DHCP snooping/PacketFence probe وRADIUS | Rogue DHCP محتمل بعد تأكيد | مصدر العروض + VLAN + port إن توفر |

## دروس صارمة قبل البروتوتايب

1. **لن نسمي أي طريقة أفضل بالمطلق**: الأجهزة المُدارة أفضل عبر controller/NAC/SNMP، وأجهزة LAN الصامتة عبر ARP أو FDB، وأجهزة الوسائط عبر mDNS/SSDP، والأجهزة البعيدة تحتاج حساسات أو ربط APIs.
2. **تتبّع MAC يحتاج VLAN وزمن**، وإذا ظهر MAC على uplink فقد تكون هناك شبكة أو سويتش أسفله؛ لا يجوز الحظر اعتمادًا على أول ظهور.
3. **نوع الجهاز بالاحتمال**: لا يكفي OUI/اسم DNS لتحديد البروجيكتور أو الهاتف، وMAC randomization يضعف مطابقة الشركة.
4. **تحديد المنفذ ليس اختراعًا جديدًا**: معيار Q-BRIDGE-MIB يحوي جداول MAC→Bridge Port؛ يلزم الربط الدقيق إلى ifIndex واسم الواجهة.
5. **الصلاحيات والتفويض**: امتلاك وصول تقني أو بيانات اعتماد لا يساوي إذن فحص جميع الشبكات؛ كل مصدر ونطاق يفصح عنه مسبقًا.
6. **حماية الشبكة من التطبيق نفسه**: حد معدلات، نطاق مصرح، Dry Run للتغييرات، منع تعطيل uplinks/VoIP/DC/management، ومسار رجوع.
7. **الهدف 20,000 جهاز مستقبليًا** يستلزم معالجة موزعة وتحديثات أحداث لا فحصًا كثيفًا من لابتوب واحد.
8. **البرومبت النهائي مؤجل**؛ هذا المستند متطلبات بحثية قابلة للتنفيذ بشروط وليست ميزات مُنجزة.

**نقطة الاستكمال:** CG-725؛ ينبغي دراسة دقة بصمات IoT مقابل الطرازات الحقيقية، Wi-Fi WIDS، وأمن DHCP/ARP/NAC وتوافق Cisco/Huawei بإصدارات محددة.


---

# إضافة البحث — v1.4: التعرّف على أنظمة IoT ورصد الشبكات اللاسلكية وحمايتها

**تاريخ الإضافة:** 10 نوفمبر 2026. **الحالة:** بحث ومتطلبات فقط؛ لا تطبيق ولا فحص لشبكات أو أجهزة. **نطاق الزيادة:** CG-725 إلى CG-796.

## الخلاصة المنهجية

- لا توجد طريقة واحدة لكشف جميع الأجهزة: نعتمد *Passive First, Multi-Source, Evidence-Based* وطبقة تحسين بمراجعة بشرية.
- معرفة نوع الجهاز ≠ معرفة هوية مالكه أو تصريح استخدامه؛ يفصل محرك الجرد بين Type وIdentity وAuthorization وLocation وConfidence.
- ظهور شبكة Wi-Fi في الهواء لا يثبت اتصالها بشبكتنا؛ لإثبات Rogue-on-wire نحتاج أدلة من الشبكة السلكية وWLC/NAC و/أو حساسات.
- كشف الأجهزة اللاسلكية يحتاج راديو/حساس مناسب وتغطية مكانية؛ PC بكرت Ethernet وحده لا يرصد كل Wi-Fi أو Bluetooth.
- الحماية المبنية على نوع الجهاز تكون بمبدأ أقل امتياز؛ أي تغيير ACL/Port/NAC يحتاج تقييم أثر وموافقة وتحقق.
- معيار MUD (RFC 8520) يخدم أجهزة IoT محددة الوظيفة؛ لا نفترض أن كل جهاز يدعم MUD أو أن ملف MUD من مورد غير متحقق منه آمن.

## المتطلبات الجديدة — معرّفات ثابتة

### 14-A — الهوية والجرد الموثوق للجهاز (CG-725–CG-732)
- **CG-725** مطلوب — إنشاء Unique Asset Identity مستقل عن IP وMAC المتغيرين؛ يدمج هوية AD/MDM والرقم التسلسلي والمعرّفات الموثوقة حيثما توجد.
- **CG-726** مطلوب — عرض نوع الجهاز (PC/Server/Printer/Projector/Camera/IP Phone/AP/IoT/Unknown) مع نوع نظام التشغيل وإصداره عندما تتوفر أدلة موثوقة.
- **CG-727** مطلوب — حقول Manufacturer, Model, Firmware, Lifecycle, Owner, Site, Building, Room، وتاريخ آخر مشاهدة مع مصدر كل حقل.
- **CG-728** مطلوب — حفظ تصنيف Unknown واضح؛ لا تحوّل أي OUI أو DHCP hostname منفرد إلى حقيقة مؤكدة.
- **CG-729** مطلوب — جدول الأدلة وأوزان الثقة: SNMP sysObjectID وLLDP/CDP وDHCP وRADIUS وmDNS/SSDP وIPP وAgent/MDM وWLC.
- **CG-730** مطلوب — تتبع هوية الجهاز عبر IPv4 وIPv6 وتغيّر DHCP Lease وVLAN والمنافذ والتبديل بين LAN وWLAN دون دمج خاطئ.
- **CG-731** مطلوب — رصد حالات الهوية المتعارضة مثل MAC واحد يظهر بنوعين أو أكثر مع ضرورة مراجعة MAC Randomization وNAT والشبكات الافتراضية.
- **CG-732** مطلوب — Device Approval Registry بحالة Authorized/Guest/Pending/Unknown/Blocked مرتبطة بسجل الموافقات والمالك وفترة الصلاحية.

### 14-B — بصمات الأجهزة والأنظمة متعددة المصادر (CG-733–CG-740)
- **CG-733** مطلوب — Fingerprint Fusion متعدد المصادر، مع إخراج درجة ثقة وتفسير للأدلة بدلاً من تصنيف AI بلا مصدر.
- **CG-734** مطلوب — DHCP Option 55/60 وVendor Class وHostname بوصفها إشارات تحليلية قابلة للخطأ/التزوير، لا هوية قاطعة.
- **CG-735** مطلوب — تصنيف الشبكات الطرفية باستخدام LLDP-MED وVoice VLAN وPoE وSNMP حيث يُدعم، مع التفريق بين الهاتف والكمبيوتر خلفه.
- **CG-736** مطلوب — تصنيف IPP/mDNS/SSDP/ONVIF للوسائط والطابعات والكاميرات عند توافرها وفي النطاق المصرح.
- **CG-737** مطلوب — تقييم OS Fingerprinting سلبيًا عند وجود SPAN/TAP/Flow أو PCAP، مع وضع أدلة p0f القديمة كبحث مرجعي لا اختيار إنتاج تلقائي.
- **CG-738** مطلوب — تفعيل Safe Active Verification فقط للأصول والنطاقات المرخصة وعندما لا تكفي المصادر السلبية، بحدود سرعة وأجهزة مستثناة.
- **CG-739** مطلوب — تعزيز التصنيف بإشارات Agent وIntune/MDM وHypervisor inventory وAD وVendor Controller عندما يكون لها ثقة أعلى.
- **CG-740** مطلوب — قياس Precision/Recall والتباس الأنواع بحسب الفئة والطراز؛ مراجعة بشرية للحالات منخفضة الثقة.

### 14-C — الكشف اللاسلكي WIDS/Rogue AP/Evil Twin (CG-741–CG-748)
- **CG-741** مطلوب — Wi-Fi Sensor Integration مع WLC/WIDS أو Kismet/Nzyme ضمن النطاق والتراخيص المعتمدة؛ لا يعتبر محول PC العادي كافيًا.
- **CG-742** مطلوب — سجل SSID وBSSID والقناة ونوع التشفير وPMF وFirstSeen/LastSeen وSensorID مع الحفاظ على الخصوصية.
- **CG-743** مطلوب — التمييز بين Authorized AP وNeighbor AP وUnknown AP وRogue-on-wire وSuspected Evil Twin، وعدم مساواة مجرد الظهور اللاسلكي بالاختراق.
- **CG-744** مطلوب — مقارنة SSID/BSSID والتكوين والإشارات والبصمة الفيزيائية مع Baseline مُعتمد لرصد الانتحال وتدهور التشفير.
- **CG-745** مطلوب — مراقبة ارتفاع deauthentication/disassociation كمؤشرات تحتاج ربطًا بالأدلة واستبعاد تغييرات القنوات الطبيعية.
- **CG-746** مطلوب — الربط بين الرصد اللاسلكي وMAC/FDB/NAC/Controller لتحديد هل Access Point غير المصرّح به متصل فعلًا بالشبكة السلكية.
- **CG-747** مطلوب — دعم حساسات موزعة للمباني والأدوار، مع خرائط تقريبية ومؤشرات تغطية وإنذار بأن عدم وجود حساس يعني نقص رؤية.
- **CG-748** مطلوب — عدم إيقاف أو التشويش على شبكات لاسلكية خارج صلاحيات المؤسسة؛ أدوات WIDS تراقب، وأي احتواء يتطلب صلاحية ومراجعة قانونية.

### 14-D — Hotspot، مشاركة الإنترنت، والأجهزة غير المعتمدة (CG-749–CG-756)
- **CG-749** مطلوب — كشف تشغيل Mobile Hotspot أو Internet Connection Sharing على Windows مُدار عبر Agent/MDM/السياسة حيث تدعمه المنصة.
- **CG-750** مطلوب — كشف Router/AP منزلي موصول بمنفذ سلكي بربط عدد MACs ونوع LLDP وبيانات DHCP/RADIUS مع استثناءات VoIP/VMs.
- **CG-751** مطلوب — معالجة NAT/USB tethering: قد لا يظهر وراء NAT سوى جهاز واحد؛ لا يُدّعى رؤية الهاتف أو أجهزته دون Sensor/Endpoint Evidence.
- **CG-752** مطلوب — كشف عرض DHCP غير مصرح به وتحديد مصدره المحتمل من DHCP Snooping وPacketFence وأحداث الشبكة قبل الحظر.
- **CG-753** مطلوب — رفض اعتبار Wi-Fi AP مجاور أو Hotspot خلوي غير متصل بالمؤسسة اختراقًا لمجرد ظهوره في الراديو.
- **CG-754** مطلوب — تعريف قوائم السماح المؤقتة لضيوف/مقاولين/معارض/أجهزة عرض بمدة وصلاحيات وموافقة واضحة.
- **CG-755** مطلوب — ربط سياق مخالفة السياسة بمكان المنفذ أو موقع الراديو والأصل المتأثر وحالة التشغيل، مع درجة ثقة.
- **CG-756** مطلوب — توثيق مصدر الأدلة، والاحتفاظ لفترة محددة، وتقليل البيانات الشخصية عند مراقبة SSIDs وProbe Requests وMACs.

### 14-E — سياسات الحماية المتخصصة لأجهزة IoT وMUD (CG-757–CG-764)
- **CG-757** مطلوب — دراسة تطبيق IETF RFC 8520 Manufacturer Usage Description (MUD) لقيود شبكة IoT، والتحقق من أصالة الوصف.
- **CG-758** مطلوب — إنشاء Policy Profiles للأجهزة غير الداعمة لـMUD محليًا بحسب الوظيفة، مع تأكيد المسؤول قبل التفعيل.
- **CG-759** مطلوب — سياسات حسب نوع الأصل: projector يسمح لشبكة العرض/DNS/NTP الضروري ويمنع الوصول غير اللازم إلى Domain Controller.
- **CG-760** مطلوب — سياسات printers وIP phones وcameras وsensors وفق مسارات الاتصال الفعلية وليس حجبًا شاملًا ثابتًا لكل نوع.
- **CG-761** مطلوب — كشف IoT Device Behavior Drift إذا تواصل الجهاز مع وجهات/منافذ خارج Baseline الموافق عليه.
- **CG-762** مطلوب — جرد عمر Firmware وEnd-of-Support وتوافر التحديث الأمني وبيانات المورّد مع حالة Unknown حين يغيب المصدر.
- **CG-763** مطلوب — Read-only Mode لأجهزة IoT/OT ذات حساسية عالية؛ تجنب الخدمات النشطة المسببة لتعطّل البرامج الثابتة.
- **CG-764** مطلوب — سياسات Segment/ACL/Quarantine مقترحة ومحدودة يمكن اختبار أثرها وتراجعها، دون تطبيق تلقائي من تصنيف منخفض الثقة.

### 14-F — الحماية السلكية واللاسلكية وIPv6 (CG-765–CG-772)
- **CG-765** مطلوب — فحص 802.1X/NAC/RADIUS وMAB fallback وEAP-TLS بحسب دور المنفذ ونوع الجهاز وموائمة سياسات الضيوف.
- **CG-766** مطلوب — فحص DHCP Snooping وDynamic ARP Inspection وIP Source Guard مع التحقق من قاعدة Binding وTrunk/Uplink exemptions.
- **CG-767** مطلوب — إضافة IPv6 RA Guard وDHCPv6 Guard وNeighbor Discovery/SISF ودعم IPv6 في جرد الأجهزة والأحداث.
- **CG-768** مطلوب — فحص سياسات WPA3 و802.11w Protected Management Frames وتوافق العملاء والهواتف والـIoT.
- **CG-769** مطلوب — مراقبة تغيّر الإعدادات الأمنية للـSSID من WPA3/Enterprise إلى إعداد أضعف مع التمييز عن تغيير اعتمده المشرف.
- **CG-770** مطلوب — ربط الأمن بسلامة شبكة الإدارة Management VLAN/AAA/TACACS+/SNMPv3/Syslog وقت التدقيق.
- **CG-771** مطلوب — كشف ارتفاع MAC counts وPort Flap وPoE anomalies بوصفها إشارات تشغيل وأمان مترابطة لا دليل هجوم منفرد.
- **CG-772** مطلوب — Change Impact Assessment وDry Run لكل تعديل VLAN أو إغلاق منفذ أو تغيير PoE أو NAC أو سياسات Wi-Fi.

### 14-G — التشغيل من PC وتحديد حدود الرؤية (CG-773–CG-780)
- **CG-773** مطلوب — عند التشغيل محليًا تظهر مصادر اكتشاف الجهاز الحالي (interfaces, routes, DNS, gateway) دون تغيير تلقائي للشبكة.
- **CG-774** مطلوب — شاشة طلب وصلاحيات تفصل Local Inventory وSNMPv3 Read-only وAD Read وDHCP/DNS وWLC/WIDS وNAC Read عن Write Actions.
- **CG-775** مطلوب — اختيار صريح لنطاقات الشبكات المصرح باستكشافها مع السماح بوضع اكتشاف سلبي افتراضي مناسب للجهات الحساسة.
- **CG-776** مطلوب — إظهار فجوات التغطية: VLAN غير مرئية، سويتش لا يرد، AP بلا Controller API، مبنى بلا حساس، شبكة خلف NAT.
- **CG-777** مطلوب — Discover Modes: One-PC Basic؛ Connected Network Infrastructure؛ Distributed Enterprise/Wireless Sensors.
- **CG-778** مطلوب — منع افتراض أن PC على VLAN واحدة يستطيع استكشاف الشبكات جميعها أو سماع كل حركة الأجهزة الأخرى.
- **CG-779** مطلوب — تخزين بيانات اعتماد قراءة الأجهزة في خزنة محلية/مؤسسية، وعدم إدراجها في سجلات الاكتشاف أو النصوص المرسلة إلى AI.
- **CG-780** مطلوب — دعم العمل Offline ثم مزامنة الأحداث مع واجهة HTTPS المحمية، دون رفع لقطات الحزم أو بيانات المستخدمين افتراضيًا.

### 14-H — معمارية الأدلة والتكاملات والحوكمة (CG-781–CG-788)
- **CG-781** مطلوب — Normalized Evidence Graph يربط IP/MAC/VLAN/SwitchPort/AP/SSID/AD/MDM/DHCP/Time/Source مع سجل انتقالات.
- **CG-782** مطلوب — Last-Seen Freshness وTTL لكل مصدر ومنع تأكيد Location أو Authorization اعتمادًا على معلومات قديمة.
- **CG-783** مطلوب — Correlation بين Wi-Fi وwired access عبر بصمة لا تعتمد حصريًا على MAC، مع مراعاة MAC randomization.
- **CG-784** مطلوب — مصفوفة Vendor Capability واقعية تشمل Cisco وHuawei وAruba وJuniper وMikroTik؛ دعم الإصدارات لا الشركات بالاسم فقط.
- **CG-785** مطلوب — التمييز في واجهة الإدارة بين Detect/Observe/Policy Suggest/Approve/Enforce/Verify/Rollback مع تدقيق لكل انتقال.
- **CG-786** مطلوب — مراجعة تراخيص الأدوات مثل Nzyme SSPL ومتطلبات استخدام/توزيع Fingerbank ومشاريع GitHub قبل دمجها تجاريًا.
- **CG-787** مطلوب — User Approval وRBAC وMFA عند قرارات العزل ومنع تغيير Uplink/Phone/DC/Management Ports دون موافقة خاصة.
- **CG-788** مطلوب — Data Minimization لبيانات الراديو والحركة وDHCP/MDM، وسياسة حفظ واضحة تمنع جمع بيانات غير ضرورية.

### 14-I — ضمان جودة الاكتشاف وقبول المشروع (CG-789–CG-796)
- **CG-789** مطلوب — اختبار اكتشاف Projector/Printer/VoIP Phone/Camera/AP/PC/Server ووسم Unknown دون ادعاء دقة مطلقة.
- **CG-790** مطلوب — التحقق من منفذ السويتش الحقيقي بمقارنتِه بالتوصيل المادي وتتبّع Uplink/Mini-switch/VoIP chained PC.
- **CG-791** مطلوب — مجموعة اختبارات Wi-Fi تفرق Neighbor وRogue-on-wire وSSID lookalike/Evil Twin المشتبه، دون تشويش.
- **CG-792** مطلوب — اختبار كشف Windows ICS/Hotspot وUSB tethering وفق بيانات Endpoint وعرض Missing Telemetry إذا لم تتوفر.
- **CG-793** مطلوب — اختبار آليات DHCP Rogue + IPv6 RA/DHCPv6 Rogue مع تأثيرها على الخدمات الأساسية ودون تعطيل إنتاج.
- **CG-794** مطلوب — قياس Precision/Recall/False Positive ووقت الاكتشاف ووقت ظهور المنفذ وفرق آخر مشاهدة، حسب كل مصدر.
- **CG-795** مطلوب — اختبار أثر الحظر/العزل على VoIP/Projector/Uplink/Guest ووجود آلية استرداد مؤكدة وFail-safe.
- **CG-796** مطلوب — معايير Gate قبل البروتوتايب: Verify APIs/Model Compat/License/Hardware Sensor/Privacy/Authorization/Performance، ولا إعلان جاهزية 100%.

## نتائج البحث والتحقق من مشاريع GitHub — جدول قرار

| المرجع | الوظيفة التي ندرسها | القيمة الحقيقية | القيود / ما لم نتحقق منه |
|---|---|---|---|
| [nzyme](https://github.com/nzymeorg/nzyme) و[القدرات](https://www.nzyme.org/capabilities/wireless) | Rogue AP/Evil Twin وارتباط الهواء بالسلك | اكتشاف BSSID/SSID وتغير صفاته وسلوك deauthentication، وربط نقطة الوصول بالشبكة السلكية | ترخيص SSPL؛ حالة الإصدارات والاعتمادية والأجهزة الموصى بها تحتاج مراجعة قبل دمج تجاري |
| [Kismet](https://github.com/kismetwireless/kismet) و[توثيق مصادر البيانات](https://kismetwireless.net/docs/readme/datasources/datasources/) | مراقبة Wi-Fi وBLE وZigbee عند توفر راديو مناسب | سلبي في معظم أوضاعه؛ دعم remote capture | لا يكفي Windows Ethernet؛ يحتاج حساس وعتاد وتغطية مناسبة، وقيود الخصوصية |
| [Kismet WIDS alerts](https://www.kismetwireless.net/docs/readme/alerts_and_wids/) | APSPOOF وCRYPTODROP وتنبيهات القنوات | إشارات للمقارنة | False positives، وبعض أنواع الانتحال قد تتجاوز بصمة MAC |
| [PacketFence](https://github.com/inverse-inc/packetfence) و[Fingerbank](https://github.com/inverse-inc/packetfence/blob/devel/docs/installation/fingerbank_integration.asciidoc) | DHCP fingerprinting وNAC وتصنيف جهاز | يمكن اكتشاف تغيير الجهاز من فئة إلى أخرى وفق قواعد | التحديثات السحابية للـfingerprints قد ترسل بيانات؛ لا نفترض تفعيل مشاركة بصمات دون موافقة |
| [Netdisco](https://github.com/netdisco/netdisco) | IP/MAC→Switch Port | تحديد موقع جهاز عند توافر FDB/SNMP/CLI/API | MAC على Uplink أو VoIP/VM لا يعني منفذ جهاز نهائيًا |
| [LibreNMS](https://github.com/librenms/librenms) | SNMP وLLDP/CDP واكتشاف أجهزة الشبكة | رؤية مكانية وتشغيلية للراوترات والسويتشات | ليس مصدرًا حاسمًا لكل IoT على جميع VLANs |
| [p0f](https://github.com/p0f/p0f) | OS fingerprinting سلبي من TCP | تجربة تعليمية لفهم بصمات نظم التشغيل وNAT | مستودع غير رسمي قديم؛ لا يوضع في Production دون تقييم صيانة/ترخيص/توافق |
| [osMUD](https://osmud.org/) و[RFC 8520](https://www.rfc-editor.org/rfc/rfc8520.html) | MUD لسياسات IoT | يصف شبكة الاتصالات الضرورية للجهاز | مرجع بحثي؛ قابلية الدمج متعددة الموردين تحتاج اختبارًا |
| [OpenWISP](https://openwisp.io/docs/dev/monitoring/user/intro.html) | إدارة ومراقبة الشبكات اللاسلكية المدارة | حالة العملاء وDHCP والواجهات والأماكن | ليس بديلًا عامًا لـWIDS أو NAC |

## حالات الاستخدام الدفاعية الإضافية

| الحدث | مصادر الرصد المطلوبة | القرار المدروس | التدخل المسموح بعد تحقق |
|---|---|---|---|
| بروجيكتور جديد | DHCP + mDNS/SSDP + MAC FDB + Model | تصنيف Projector بثقة مدعومة بالأدلة؛ Approval Pending | Guest/AV VLAN، والسماح للخدمات الضرورية فقط |
| نقطة Wi-Fi جارة ظهرت | WIDS Sensor + BSSID + Signal + WLC | Nearby/Neighbor وليس اختراقًا | تسجيل سياق أو تجاهل وفق السياسة |
| نقطة بث SSID مشابه للشركة | WIDS + Baseline + SSID/BSSID + channel/security | Suspected Evil Twin؛ لا هوية مهاجم مؤكدة | تنبيه وتحقيق، وإرشاد المستخدمين؛ بلا تشويش على الشبكات الخارجية |
| راوتر منزلي موصول بمنفذ السويتش | FDB + DHCP + LLDP + WLC correlation | Rogue-on-wire مرجح فقط إذا ثبت الربط السلكي | Network Quarantine بشروط، والتحقق من أثر VoIP/PC المشارك |
| Windows PC يفعل مشاركة إنترنت | Endpoint/MDM Policy + Interface State | Violation policy / يحتاج تحقق | سياسة إدارة Windows Intune/GPO إن مدعومة وبعد مراجعة |
| عدة MACs على منفذ واحد | FDB + VLAN + LLDP-MED + Phone/Hypervisor inventory | Mini-switch أو VoIP/VM؛ لا قرار تلقائي | تحقيق قبل تغييرات Port Security |
| جهاز كاميرا يصدر اتصالًا غير معتاد | Expected IoT Policy + Flow/DNS + Device Type | Behavior Drift مع مصدر دقيق | منع وجهة غير ضرورية أو تقليص Egress بعد تقييم |
| DHCPv6/RA غير معتمد | IPv6 FHS logs + network sensor + port binding | Rogue Router/Server محتمل | RA Guard/DHCPv6 Guard حسب الجهاز بعد تحقق توافق |

## خطة تحقق علمي وتطوير القرار

1. إنشاء مختبر ممثل: سويتش Cisco/Huawei إن توفر، Windows/Linux، IP phone، طابعة، بروجيكتور، AP، هاتف يعمل Hotspot، وجهاز IoT كاميرا.
2. تشغيل Discovery بصلاحيات قراءة فقط على نطاق مصرح؛ حفظ مقارنة Ground Truth لما هو موصول بالمنافذ فعلًا.
3. إثبات أمثلة Genuine Network vs Neighbor AP، Evil Twin في مختبر مرخّص دون استهداف شبكات خارجية، ودقة نسبة المنفذ النهائي.
4. اختبار أن تدهور Telemetry يقلل Confidence ولا ينتج هوية أو أمانًا مزيفًا.
5. قياس FPS/DHCP وسعة أحداث NAC وفترات التحديث، والخصوصية والتخزين والتكلفة.
6. مراجعة SSPL وحقوق دمج كل مكون، واختيار API/adapter بدل دمج الكود عند عدم مناسبة الترخيص.
7. إعطاء الأولوية للتفويض والحوكمة والأجهزة الحساسة قبل أي ميزة Write Control.

## مصادر موثوقة وأدلة رئيسية

- [Huawei — Terminal Identification](https://info.support.huawei.com/info-finder/encyclopedia/en/detail?action=queryEntityDetail&keyword=Terminal+Identification) — الجمع بين fingerprint وscan وflow وAI.
- [Huawei — Client Plug-and-Play](https://info.support.huawei.com/info-finder/encyclopedia/en/Client%2BPlug-and-Play.html) — اختلاف سياسات الأصول حسب النوع.
- [Cisco Catalyst 9800 — Rogue Classification](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/26-1/configuration-guide/wl-26-1-cg/g_classify_rogue_ap/information-about-classifying-rogue-access-points.html) — التفريق بين AP مرخّص/مجهول وعلى الشبكة السلكية.
- [Cisco IOS XE — IPv6 First-Hop Security](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/sec-crypto/fhs-sisf/fhs-and-sisf-configuration-guide/ipv6-first-hop-security.html) — RA Guard/DHCPv6 Guard وقيودها.
- [Microsoft — AllowInternetSharing Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-wifi) — سياسة مشاركة الإنترنت على الأجهزة المُدارة.
- [NIST IR 8259 Rev. 1, 2026](https://csrc.nist.gov/pubs/ir/8259/r1/final) — أمن دورة حياة أجهزة IoT.
- [NIST IR 8259A](https://csrc.nist.gov/pubs/ir/8259/a/final) — القدرات الأمنية الأساسية.
- [NIST SP 800-213](https://csrc.nist.gov/pubs/sp/800/213/final) — متطلبات أمان IoT.
- [IETF RFC 8520 — MUD](https://www.rfc-editor.org/rfc/rfc8520.html) — وصف سلوك اتصال الأجهزة.
- [ITU-T Q.4080 (Jan 2026)](https://www.itu.int/dms_pubrec/itu-t/rec/q/T-REC-Q.4080-202601-I%21%21SUM-HTM-E.htm) — اختبار ومراقبة MUD.
- [Nzyme — Wireless Capabilities](https://www.nzyme.org/capabilities/wireless) و[GitHub](https://github.com/nzymeorg/nzyme).
- [Kismet — WIDS](https://www.kismetwireless.net/docs/readme/alerts_and_wids/) و[Passive Capture](https://github.com/kismetwireless/kismet-docs/blob/master/readme/000-intro.md).
- [PacketFence — Fingerbank Integration](https://github.com/inverse-inc/packetfence/blob/devel/docs/installation/fingerbank_integration.asciidoc).
- [Netdisco — README](https://github.com/netdisco/netdisco).

**خلاصة:** هدف الإصدار v1.4 هو حماية منظومة الأصول المكتشفة وتصنيفها على أساس الأدلة، وليس ضمان اكتشاف كل جهاز أو إيقافه. **نقطة الاستكمال: CG-797.** ولم يبدأ أي تنفيذ برمجي أو فحص حقيقي.


---

# إضافة البحث — v1.5: أربعون فكرة جديدة للأيجنتات والهوية والدفاع المتصل
**تاريخ الإضافة:** 2026-11-10. **المرحلة:** البحث وتجميع الأفكار فقط. **النطاق:** CG-797 إلى CG-836 (40 فكرة).
**قاعدة الاستمرارية:** هذه إضافة هندسية مفصّلة للمتطلبات السابقة؛ بعض الأفكار توسّع ميزات سبق تسجيلها وتحدد شروط الاختبار والأدلة. ليست 40 وظيفة مثبتة أو مبرمجة.
**فلسفة التشغيل:** Local-first, passive-first, least-privilege, proof-driven, human approval for changes. التطبيق الأساسي لا يخترق الشبكات ولا يدّعي رؤية الأصول خلف العوائق دون مصادر معلومات.
## نموذج طبقات الأيجنت المقترح للدراسة
1. Endpoint Sensor: جرد وحالة Windows/Linux/macOS. 2. Network Collector: قراءة Cisco/Huawei/Firewall/WLC. 3. Wireless Sensor: حساسات Wi-Fi حسب التغطية. 4. Cloud Connector: واجهات قراءة AWS/Azure/GCP. 5. Forensic Collector: فحوص محدودة بوقت وموافقة. 6. AI Analyst: تفسير وتوصية بلا صلاحيات تنفيذ مباشرة.
**عدم المساواة بين أدوات البحث:** osquery/Fleet لإدارة حالة الأجهزة؛ Velociraptor للأدلة؛ OpenTelemetry للمراقبة والسجلات؛ Tetragon لمراقبة Linux؛ Zeek لتحليل حركة المرور من مصدر PCAP/SPAN مناسب. ليست أداة واحدة ولا تتطلب تثبيتها كلها.
## المتطلبات الجديدة المرقمة وتفاصيل قبولها
### 15-A — التعرف على الهوية والنظام والأصل
- **CG-797** بحث — **Device Trust Attestation**: ربط جرد Windows المُدار بإثبات سلامة الإقلاع الصادر من TPM/MDM، مع منع اعتبار DHCP أو MAC دليل هوية قوية. **معيار القبول:** دليل TPM/MDM موثوق أو حالة Unsupported؛ مقارنة الجهاز قبل وبعد تحديث Firmware. **حدود/مخاطر:** تحتاج أجهزة/إصدارات/سياسات داعمة؛ لا تعني سلامة جميع التطبيقات.
- **CG-798** بحث — **Operating-System Evidence Matrix**: فصل اسم النظام عن الإصدار والبنية والتحديث وKernel/Build/Edition، وتوثيق مصدر كل حقل ووقت قراءته. **معيار القبول:** تقرير لثلاثة أنظمة مع إظهار الإصدار Unknown حين لا يتوفر Agent أو API. **حدود/مخاطر:** OS fingerprint وحده قد يخطئ في تحديد الإصدار.
- **CG-799** بحث — **Device Arrival Timeline**: إنشاء تسلسل وصول الجهاز من DHCP/NAC/WLC والسويتش لتحديد هل ظهر للمرة الأولى أو نقل منفذه أو أعاد الاتصال. **معيار القبول:** سيناريو هاتف IP مع PC وآخر لجهاز جديد يفرّق بينهما زمنيًا. **حدود/مخاطر:** تحتاج مزامنة ساعات المصادر وجودة سجلاتها.
- **CG-800** بحث — **Service Dependency Proof**: إنتاج خريطة اعتماد حقيقية قبل اقتراح إطفاء سيرفر أو تعطيل منفذ: من يتصل بمن، وما الخدمات الحيوية؟ **معيار القبول:** إظهار اعتماد خدمة هاتف VoIP على السويتش والطاقة والإدارة. **حدود/مخاطر:** مشاهدات Flow لا تكشف كل الاعتمادات المخفية؛ تتطلب مراجعة.
- **CG-801** بحث — **Dual-Homed Endpoint Risk**: اكتشاف الجهاز المُدار الذي يجمع Ethernet مع Wi-Fi/USB tethering أو شبكة افتراضية أخرى، وربط الخطر بسياسة المؤسسة. **معيار القبول:** سجل محولات الجهاز وواجهة الشبكة الفعلية وعلاقة المشاركات. **حدود/مخاطر:** ليس كل اتصال ثانٍ مخالفًا؛ لا يتحقق ذلك من SNMP السويتش وحده.
- **CG-802** بحث — **Switch-Port Evidence Fusion**: احتساب موقع الجهاز بالجمع بين FDB وLLDP وRADIUS وPoE ووقت آخر مشاهدة، مع إظهار منفذ uplink مقابل access. **معيار القبول:** جهاز خلف Mini-Switch لا يعرض المنفذ على أنه اتصال مباشر مؤكد. **حدود/مخاطر:** جداول MAC قد تتقادم أو توجد أجهزة خلف NAT.
- **CG-803** بحث — **Wireless RF Identity Drift**: تسجيل تغير خصائص AP المعتمد: الأمان، القناة، قدرات 802.11، بصمة المراقبة ومصدر الحساس قبل إنذار انتحال. **معيار القبول:** اختبار تمييز AP جار من AP مؤسسي تغيّرت إعداداته. **حدود/مخاطر:** لا يمكن الجزم بالموقع أو الملكية من SSID أو BSSID وحده.
- **CG-804** بحث — **Shadow SaaS Discovery**: اكتشاف التطبيقات السحابية غير المسجلة من DNS/Proxy/IdP ومقارنة استخدام المؤسسة مع سجل التطبيقات المصرح بها. **معيار القبول:** لوحة تعرض اسم الخدمة ومصدر المعرفة وحالة الاعتماد بدون كشف محتوى المستخدم. **حدود/مخاطر:** لا يدعم كشف جميع الخدمات المشفرة أو الوصول عبر شبكات غير مراقبة.
### 15-B — طبقة الأيجنتات والحساسات الذكية
- **CG-805** بحث — **Agent Capability Negotiation**: قبل تفعيل أي وظيفة، يعلن Agent النظام والإصدار والأذونات والحساسات الممكنة، ويعطل غير المدعوم بوضوح. **معيار القبول:** صفحة Windows/Linux/macOS تميّز Read/Respond/Unavailable. **حدود/مخاطر:** لا يمكن فرض أدوات عميقة على أنظمة قديمة أو دون تفويض.
- **CG-806** بحث — **Sandboxed Agent Extensions**: كل إضافة للأيجنت لها Manifest صلاحيات وموارد وحدود وصول إلى البيانات، بدلاً من منح جميع الإضافات امتيازات مسؤول. **معيار القبول:** اختبار فشل إضافة واحدة دون تعطيل بقية الأيجنت أو الوصول لأسراره. **حدود/مخاطر:** العزل الحقيقي يعتمد على نظام التشغيل وتقنيات Sandboxing المتاحة.
- **CG-807** بحث — **On-Demand Investigation Lease**: فحوص التحقيق الثقيلة لا تعمل دائمًا؛ تُفعّل لهدف ومدة ونطاق محددين، ثم تتوقف وتنظّف مخرجاتها المؤقتة. **معيار القبول:** سيناريو جمع معلومات عمليات مشتبه بها لمدة 10 دقائق ثم إنهاء المهمة. **حدود/مخاطر:** جمع الذاكرة أو الملفات الحساسة يحتاج موافقة أعلى.
- **CG-808** بحث — **Windows Event-Driven Telemetry**: تصميم موصل Windows Event Logs وSysmon عبر مستقبل أحداث فعلي، مع كشف فقد القنوات وحماية السجلات من الاستبدال. **معيار القبول:** مقارنة استلام Security/Sysmon والوقت والفقد عند إعادة تشغيل Collector. **حدود/مخاطر:** الـSecurity Log قد يحتاج Administrator وبعض المكونات Alpha.
- **CG-809** بحث — **macOS EndpointSecurity Bridge**: بحث موصل macOS عبر إطار Apple Endpoint Security لعمليات التنفيذ والملفات، لا استخدام أوامر Windows على Mac. **معيار القبول:** قدرة القراءة المسموحة وموافقة المستخدم وentitlements موثقة لكل إصدار. **حدود/مخاطر:** يتطلب موافقات Apple/System Extension وقد لا يتوفر لكل ناشر.
- **CG-810** بحث — **Linux eBPF Collector**: بحث مراقبة محدودة المصدر للأحداث المهمة في Linux باستخدام eBPF/Tetragon مع بديل auditd/syslog عند عدم الدعم. **معيار القبول:** مقارنة event count والموارد قبل/بعد على Kernel مختلف. **حدود/مخاطر:** توافق Kernel والصلاحيات وeBPF ليس مضمونًا على كل خادم.
- **CG-811** بحث — **Encrypted Offline Event Spool**: يتحمل الأيجنت انقطاع الإنترنت، ويخزن الأحداث محليًا بصورة مشفرة وحد أقصى ثابت، ويرسلها بعد العودة دون تكرار. **معيار القبول:** اختبار انقطاع 24 ساعة ثم مزامنة مع كشف فقد الأحداث. **حدود/مخاطر:** قدرة التخزين وقيود البيانات الحساسة تحتاج سياسة الاحتفاظ.
- **CG-812** بحث — **Cryptographic Agent Enrollment**: ربط الأيجنت بهوية جهاز وشهادة لكل جهاز مع آلية تدوير وإبطال مفاتيح وانتهاء صلاحية الاتصالات. **معيار القبول:** اختبار إبطال شهادة جهاز مسروق دون التأثير على بقية الأجهزة. **حدود/مخاطر:** التسجيل الأول يحتاج مصادقة مصدر موثوقة؛ لا نضع أسرارًا ثابتة مشتركة.
### 15-C — قرارات الحماية والشبكة قبل التنفيذ
- **CG-813** بحث — **Posture-Aware Network Admission**: التحقق من سلامة الجهاز المُدار ونسخة نظامه والحماية قبل حصوله على صلاحية VLAN حساسة عبر تكامل NAC مدعوم. **معيار القبول:** موقف جهاز غير محدّث يحصل فقط على شبكة إصلاح محدودة. **حدود/مخاطر:** تقييم الصحة يجب أن يتوافق مع المستخدم والجهاز والمهمة.
- **CG-814** بحث — **Removable & USB Network Interface Policy**: تحديد مخاطر محولات Ethernet/USB والأقراص الخارجية ومشاركة الإنترنت عبر Agent وإعدادات MDM، مع استثناءات عمل معتمدة. **معيار القبول:** سيناريو محول USB لإنجاز عمل مشروع مقابل مشاركة شبكة غير مصرح بها. **حدود/مخاطر:** لا يُحظر USB تلقائيًا لأن أجهزة الوصول الطبية/التشغيلية قد تعتمد عليه.
- **CG-815** بحث — **Microsegmentation Candidate Simulator**: اقتراح قواعد اتصال دقيقة بين مجموعات الأجهزة استنادًا إلى الاتصالات المرصودة والسياسات، مع اختبار الأثر قبل النشر. **معيار القبول:** محاكاة منع طابعة من إدارة DC مع استمرار الطباعة. **حدود/مخاطر:** أيام المراقبة السابقة قد لا تغطي اتصالات نادرة أو نسخًا احتياطية.
- **CG-816** بحث — **Resolver Integrity Checker**: مقارنة DNS Resolver الفعلي على الأجهزة والخوادم بما هو معتمد، ورصد التبديل المحلي أو عبر DHCP/RA دون افتراض اختراق. **معيار القبول:** حالة تغيير DNS مع سجل إدارة معتمد وحالة غير معتمدة. **حدود/مخاطر:** DNS مشفر/DoH والـVPN قد يخفي بعض المسارات.
- **CG-817** بحث — **Critical Port Context Graph**: تصنيف منفذ السويتش هل هو Uplink/Trunk/VoIP/PoE/Hypervisor/DC قبل السماح بأي Shutdown أو تحريك VLAN. **معيار القبول:** تجربة منع إغلاق uplink بدون موافقة خاصة ومراجعة أثر. **حدود/مخاطر:** الكشف عن دور المنفذ احتمالي ويحتاج تحقق مدير الشبكة.
- **CG-818** بحث — **Rogue Wireless-to-Wired Evidence Gate**: تحويل إنذار Wireless Rogue إلى حالة مؤكد فقط بعد الربط مع إثبات اتصال فعلي في الشبكة السلكية أو وحدة التحكم. **معيار القبول:** اختبار شبكة جار مرئية بالراديو لا تتحول إلى Rogue-on-wire. **حدود/مخاطر:** يحتاج تغطية حساسات وبيانات WLC/FDB.
- **CG-819** بحث — **Policy TTL With Device-Side Verification**: الاستثناء المؤقت يجب أن تنتهي صلاحيته في المنفّذ أو الجدار الناري حيث يدعمه، مع تحقق مستقل من إزالة القاعدة. **معيار القبول:** تصريح ساعة ينتهي حتى لو أُغلقت لوحة التحكم على الجوال. **حدود/مخاطر:** بعض أجهزة الشبكة لا تدعم TTL أصليًا؛ يلزم تعويض موثوق.
- **CG-820** بحث — **End-to-End Security Control Canary**: اختبار دوري غير ضار يتحقق من وصول حدث اختباري من Sensor إلى محرك الكشف ثم لوحة الإنذارات. **معيار القبول:** يعرض إن الحساس كان متصلًا لكن التنبيه لا يصل بسبب قاعدة خاطئة. **حدود/مخاطر:** يجب تمييز أحداث الاختبار حتى لا تتسبب في استجابة حقيقية.
### 15-D — ذكاء الكشف والتحقيق والتحقق
- **CG-821** بحث — **JA4 Encrypted-Flow Intelligence**: استخدام بصمات JA4 من Zeek لتفسير تغيّر نوع عميل TLS وتكتلات اتصال مشبوهة دون فك تشفير محتوى المستخدمين. **معيار القبول:** عرض بصمة مع سياق التطبيق وبيانات الشبكة دون ادعاء هوية منفردة. **حدود/مخاطر:** JA4 TLS له رخصة مختلفة عن عائلة JA4+؛ استشارة الترخيص واجبة.
- **CG-822** بحث — **Behavioral Role Baselines**: مقارنة سلوك Projector/Printer/IP Phone بملفات الدور المعتمدة مع استثناء تحديثات Firmware والصيانة. **معيار القبول:** إنذار جهاز عرض بدأ إرسال بريد أو اتصالات إدارة غير معتادة. **حدود/مخاطر:** لا ينبغي اعتبار اختلاف إحصائي وحيد اختراقًا مؤكدًا.
- **CG-823** بحث — **Detector Data-Precondition Contract**: كل قاعدة كشف تصرّح أي سجلات تحتاجها وكيفية تمكينها ومدة الاحتفاظ والفشل المتوقع عند نقص الأحداث. **معيار القبول:** صفحة قاعدة DCSync تظهر Missing Telemetry بدل علامة أمان خادعة. **حدود/مخاطر:** قد تتعارض متطلبات السجلات مع سياسة الخصوصية والأداء.
- **CG-824** بحث — **Historical Detection Replay**: إعادة تحليل أحداث اختبار محفوظة بعد تحديث القواعد للتأكد من اكتشاف الحالات السابقة وعدم زيادة الإنذارات الخاطئة. **معيار القبول:** مقارنة نتيجة مجموعة سيناريوهات قبل وبعد تحديث حزمة قواعد. **حدود/مخاطر:** لا يُعاد تشغيل حمولة هجومية على الشبكة الحقيقية.
- **CG-825** بحث — **Threat Indicator Expiration Engine**: ربط IOC بالمصدر وتاريخ ظهوره ودرجة الثقة وفترة الصلاحية قبل إدخال عنوان IP في قائمة حظر. **معيار القبول:** اختبار IP قديم لم يعد ضارًا لا يستمر محظورًا بلا مراجعة. **حدود/مخاطر:** IP قد يعود لمستخدم مختلف؛ السمعة لا تثبت هوية شخص.
- **CG-826** بحث — **Explainable Multi-Signal Detection**: يشرح سبب التحذير بإظهار أحداث الدخول والعملية والاتصال وغياب الموافقة، بدل نتيجة صندوق أسود من AI. **معيار القبول:** حالتان مشروع/مشبوه مع تفسير سبب الفرق. **حدود/مخاطر:** الروابط السببية قد تكون غير مؤكدة وتحتاج عرض درجة ثقة.
- **CG-827** بحث — **Risk-Based Testing Coverage**: قياس جودة الكشف عبر سيناريوهات محددة مرتبطة بـMITRE ATT&CK مع نجاح/فشل وأثر التشويش على التشغيل. **معيار القبول:** نتيجة اختبار تقول missed/observed/prevented بدل درجة 100% عامة. **حدود/مخاطر:** اختبارات المحاكاة لا تثبت مقاومة كل هجمات المستقبل.
- **CG-828** بحث — **Secure Evidence & Attribution Boundary**: تثبيت أدلة التحقيق ببصمات وتوقيت ومصدر، مع فصل نسبة النشاط إلى جهة مهاجمة عن إثبات هوية شخص حقيقي. **معيار القبول:** تقرير IP عبر VPN يذكر وسيطًا محتملًا ولا يحدد شخصًا. **حدود/مخاطر:** لا Hack-back؛ التحقيق على شبكات الغير ليس ضمن الصلاحية.
### 15-E — السحابة والمنصة وسلامة التحديثات
- **CG-829** بحث — **Ephemeral Cloud Asset Continuity**: ربط حاوية أو VM قصيرة العمر بهوية الـCloud Resource وTags وخدمة التشغيل، وليس IP المؤقت فقط. **معيار القبول:** إزالة التكرار بين عناوين IP القديمة والجديدة لنفس عبء العمل. **حدود/مخاطر:** القيود تختلف بين CloudTrail وK8s Logs وموفر السحابة.
- **CG-830** بحث — **Cross-Account Privilege Graph**: فحص المسارات الفعلية لصلاحيات IAM بين حسابات AWS أو اشتراكات Azure مع قراءة فقط قبل اقتراح تضييق. **معيار القبول:** تمييز صلاحية ظاهرية عن صلاحية فعالة بعد Deny/SCP/Conditions. **حدود/مخاطر:** التقييم الحقيقي معقد ويحتاج محاكاة المورد الرسمية.
- **CG-831** بحث — **Kubernetes East-West Service Mapping**: دراسة الاستفادة من Hubble لإظهار اتصالات Pod-to-Pod والهوية الشبكية مع الاعتمادات بين الخدمات. **معيار القبول:** خريطة تبين خدمة تصل إلى قاعدة بيانات وقرار NetworkPolicy. **حدود/مخاطر:** خاص ببيئات Cilium/Kubernetes ولا ينطبق على LAN تقليدية.
- **CG-832** بحث — **Infrastructure Policy Gate**: فحص Terraform/Kubernetes وGitOps ضد سياسات وصول وخصوصية قبل النشر، مع إخراج سبب الرفض وخط الإصلاح. **معيار القبول:** رفض تكوين يعرّض واجهة إدارة للسماح العام في مختبر CI. **حدود/مخاطر:** قد تحتاج كل مؤسسة سياسات مختلفة وإدارة استثناءات.
- **CG-833** بحث — **Dependency Vulnerability Provenance**: ربط SBOM ومصادر حزم البرامج بقاعدة OSV واستثناء الإصدارات غير المتأثرة بدل CVE عامة. **معيار القبول:** قائمة مكونات تحدد أي إصدار متأثر وما الذي يجب تحديثه. **حدود/مخاطر:** نتائج قاعدة البيانات تتغير وتتطلب تحققًا من دقة المطابقة.
- **CG-834** بحث — **Signed Agent Update & Rollback**: تقييم TUF/Sigstore لتوقيع حزم الأيجنت ومراقبة مصدرها وتحديث دفعات صغيرة ثم التراجع عند الخلل. **معيار القبول:** نسخة معدّلة غير موقعة تُرفض؛ نسخة رسمية تجريبية تُجرّب على Pilot. **حدود/مخاطر:** تحديث خاطئ لأيجنت مسؤول قد يوقف المراقبة؛ يلزم مسار تعافٍ.
- **CG-835** بحث — **Secrets Without Raw Extraction**: ربط KMS/Vault/SOPS لمراجعة السياسات والدوران وتاريخ الاستخدام دون قراءة الأسرار الخام إلى قاعدة CyberGuard. **معيار القبول:** تقرير secret بدون إظهار قيمة مفتاح API في logs/AI. **حدود/مخاطر:** لا يمكن الجزم بأن السر لم يُنسخ خارج نظام الحفظ.
- **CG-836** بحث — **AI Action Approval Gateway**: المساعد الذكي يقترح إجراء من قائمة محددة فقط، تمر عبر تحقق سياسة وصلاحية وموافقة وسجل لا من تنفيذ أمر Shell حر. **معيار القبول:** اختبار نص سجل خبيث يحاول جعل AI يحذف قاعدة Firewall ويفشل. **حدود/مخاطر:** Prompt Injection لا يُحل بنموذج AI وحده؛ العزل والسياسات حاسمان.
## أسماء وهوية المشروع — بحث أولي لا يعني توفر العلامات
- **Cyber Guardian** — واضح، لكن مستخدم كاسم لمنصة أمن سيبراني تجارية؛ لا نوصي به دون مراجعة قانونية.
- **CyberGuard AI** — قريب من فكرتنا، لكنه مستخدم في مواقع أمنية أخرى؛ يظل اسمًا مؤقتًا.
- **Guardian of Security** — جيد كشعار توضيحي، لكنه طويل ومركّب قليلًا كاسم علامة.
- **GuardianOps** — قصير ويربط الأمن بالتشغيل، لكنه مستخدم ضمن ENIGMA GUARDIANOPS؛ ليس اسمًا متاحًا مفترضًا.
- **Guardian Nexus** — يعكس توحيد الشبكات والهوية والسحابة، لكن توجد شركة أمنية باسم Guardian Nexus/GuardianNex؛ مرشح ضعيف.
- **Guardian One** — سهل اللفظ لكنه عام؛ يحتاج بحث علامة ودومين.
- **GuardSphere** — مستخدم لمنصة حوكمة أجهزة؛ مرشح ضعيف للاسم التجاري.
- **SentinelGrid** — يعكس مراقبة الشبكات والأصول؛ يحتاج بحث علامة ودومين.
- **NADHIR X** — علامة عربية الهوية بمعنى الإنذار؛ يحتاج بحث علامة ودومين.
- **MIRSAD One** — مرصاد: رصد وتحقيق واستجابة؛ يحتاج بحث علامة ودومين.
**فحص أسماء مبدئي بتاريخ 2026-11-10:** Cyber Guardian مستخدم لمنصة من Santander Services Solutions: https://www.cyberguardian.tech/en/about-us ؛ CyberGuard AI مستخدم في https://cyberguard-ai.com/ ؛ وهناك استخدامات لـGuardianOps: https://www.hmenigma.com/platforms/enigma-guardianops ، وGuardian Nexus: https://www.guardiannex.us/ ، وGuardSphere: https://www.guardsphere.app/. لا يمكن تأكيد قانونية أو توافر الأسماء الأخرى دون فحص سجل العلامات والنطاقات ذات الصلة.
**الاقتراح اللغوي المحدّث:** MIRSAD One أو NADHIR X كأسماء عمل تحتاج فحص العلامة، و“Guardian of Security” كشعار فرعي أو اسم سلسلة ميزات. Cyber Guardian وCyberGuard AI وGuardianOps وGuardian Nexus وGuardSphere جميعها لديها استخدامات عامة مؤكدة؛ تجنب الادعاء بالتوفر.
## مصادر رسمية ومشاريع جرى الرجوع إليها
- [Fleet / osquery](https://github.com/fleetdm/fleet) — جرد وإدارة أجهزة عبر مصادر النظام الأصلية؛ مناسبة لاكتشاف الحالة وليس إثبات عدم الاختراق.
- [Velociraptor Artifacts](https://docs.velociraptor.app/docs/vql/artifacts/) — جمع أدلة موجهة مع preconditions لحماية الأجهزة أثناء التحقيق.
- [OpenTelemetry Windows Events](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/windowseventlogreceiver/README.md) — جمع أحداث Windows؛ ثبات المكون والتصاريح يجب اختبارها.
- [Apple EndpointSecurity](https://developer.apple.com/documentation/EndpointSecurity) — أحداث عمليات وملفات وتفويض على macOS مع متطلبات حقوق.
- [Tetragon eBPF](https://github.com/cilium/tetragon) — رؤية Linux/Kubernetes أثناء التشغيل ودعم سياسات في بيئات ملائمة.
- [Zeek JA4](https://zeek.org/2026/01/how-to-use-ja4-network-fingerprints-in-zeek/) — بصمات حركة مرور مشفرة؛ بعض أسرة JA4+ لها شروط ترخيص أخرى.
- [Hubble](https://github.com/cilium/hubble) — خرائط الاتصالات لـKubernetes مع Cilium.
- [OSV-Scanner](https://github.com/google/osv-scanner) — مطابقة تبعيات البرامج مع الثغرات المعروفة.
- [The Update Framework](https://github.com/theupdateframework/python-tuf) — مرجع للتحديثات الموقعة وتقليل مخاطر اختراق قناة التحديث.
- [SOPS](https://github.com/getsops/sops) — حفظ ملفات سرية مشفرة مع KMS/age/PGP.
- [OPA Gatekeeper](https://github.com/open-policy-agent/gatekeeper) — ضوابط وإثبات قبل نشر موارد Kubernetes.
- [StackStorm](https://github.com/StackStorm/st2) — مستشعرات وأحداث وتنفيذ workflows مع audit trail.
- [Microsoft TPM Health Attestation](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/trusted-platform-module-overview) — أدلة سلامة إقلاع Windows بحسب دعم الجهاز والإصدار.
- [BRSKI RFC 8995](https://www.rfc-editor.org/rfc/rfc8995.html) — تأسيس هوية أجهزة دعمها المصنّع بشكل موثوق.
- [Sigstore](https://openssf.org/projects/sigstore/) — توقيع والتحقق من حزم البرامج والتحديثات.
## قائمة التحليل قبل أي بروتوتايب
| محور | ما يجب إثباته |
|---|---|
| اكتشاف | Precision/Recall لأنواع الأجهزة ومنفذ السويتش مع ظهور Unknown بدل التخمين |
| الأيجنت | أداء CPU/RAM وامتيازات Min-Privilege والتوافق بين الإصدارات |
| المراقبة | تحقق وصول البيانات وتعامل مع فقد المصدر / انقطاع الشبكة |
| الاستجابة | Dry-run ثم موافقة وتحقق من تغيير الجهاز وتراجع مستقل |
| الأمن | إدارة هوية الأيجنت وتحديثاته وأسراره ومراجعة تراخيص GitHub |
| AI | عدم إعطاء AI قناة أوامر مفتوحة؛ توثيق الأدلة والشكوك |
| الاسم | بحث علامة تجارية ودومين وشبه صوتي بالعربية والإنجليزية |
**نقطة الاستكمال القادمة:** CG-837. **لا برمجة ولا بروتوتايب ولا نشر ولا فحص واقعي.**

---

# إضافة البحث — v1.6: ستون فكرة جديدة للأمن المتكامل

**تاريخ الجولة:** 2026-11-10. **الحالة:** تجميع أفكار وبحث فقط، دون تشغيل أدوات أو فحص شبكات أو كتابة كود المنتج. **معرّفات الإضافة:** CG-837 إلى CG-896.

**ملاحظة مهمة:** هذه متطلبات مرشحة وبعضها تفصيل لاحتياج موجود سابقًا، وليست 60 قدرة موجودة بالفعل. لا توجد منصة تؤكد أمان الشبكة 100% أو تكشف كل هجوم دون فجوات.

## ملخص الأدوات الجديدة والقرارات

- **أمن الشبكات العامة:** FastNetMon للاكتشاف عبر Flow، وBGPalerter للمؤسسات التي تملك ASN/Prefixes عامة؛ لا نفعّل RTBH أو BGP FlowSpec تلقائيًا.
- **الوصول المقيد:** NetBird مرشح لتصميم ربط موثوق بين PC والجوال والخادم. تراخيص عناصر المشروع ليست كلها متطابقة؛ راجعها قبل التوزيع.
- **الاستعادة:** Restic/Kopia يدعمان نسخًا مشفرة، لكن تحقق النسخة، واستعادة التطبيقات، والتخزين المقفل قضايا مختلفة.
- **Cloud Native:** Kyverno وkube-bench وTracee لأغراض سياسات/تدقيق/مراقبة وقت التشغيل؛ لا تُثبت جميعها على PC واحد.
- **البرمجيات:** Syft لإنتاج SBOM، وGrype لتطابق الثغرات، وGitleaks للأسرار، وDefectDojo لتقارير العلاج الموحدة.
- **قاعدة عامة:** اقرأ الوثائق الرسمية والرخصة والتوافق قبل الدمج التجاري، وافصل القراءة عن التنفيذ، وضع Review/Dry Run قبل أي إجراء على أجهزة الإنتاج.

### 16-A — الدفاع عن الشبكات ومنافذ الإنترنت

- **CG-837** **[بحث/متطلب مرشح] — DDoS Flow Exposure Monitor:** دمج NetFlow/IPFIX/sFlow وعدادات الواجهات لكشف القفزات المفاجئة في الحزم والتدفقات مع Baseline لكل خدمة. **اختبار القبول:** عرض التدفقات المصدرية والوجهات والمدة ومعدل الخطأ قبل تصعيد الحدث. **الحدود والمخاطر:** قد يتطلب تصدير Flow من الراوتر؛ لا يمنع هجومًا حجميًا يفوق سعة مزود الإنترنت.
- **CG-838** **[بحث/متطلب مرشح] — Provider Mitigation Handoff:** تجهيز طلب حماية DDoS للمزود مع بيانات Prefix وحجم الهجوم ونمطه، وتوثيق بدء وإيقاف الحماية. **اختبار القبول:** ملف حادث به Evidence ووقت إنشاء طلب المزود والنتيجة. **الحدود والمخاطر:** RTBH/FlowSpec تغييرات عالية الخطورة ولا تنفذ تلقائيًا.
- **CG-839** **[بحث/متطلب مرشح] — BGP Routing Integrity Watch:** مراقبة إعلانات Prefix العامة وRPKI/ROA وتغير AS Path والانقطاعات للأصول التي تملكها الجهة. **اختبار القبول:** التنبيه عند إعلان RPKI Invalid لا يتضمن اتهام صاحب AS باختراق. **الحدود والمخاطر:** مفيد فقط لجهات لديها عناوين عامة أو ارتباطات BGP؛ ليس لكل LAN.
- **CG-840** **[بحث/متطلب مرشح] — North-South vs East-West Guard:** تمييز حركة الإنترنت الخارجية عن الاتصالات الداخلية بين VLAN/Servers لتحديد مكان وضع الحساس المناسب. **اختبار القبول:** تعرض الخريطة مصادر Flow/SPAN وتكتب غير مرئي للمسارات بلا مصدر. **الحدود والمخاطر:** PC واحد لا يشاهد كل حركة شرق-غرب.
- **CG-841** **[بحث/متطلب مرشح] — DDoS / Service Failure Differentiation:** ربط امتلاء رابط الشبكة وأخطاء التطبيقات وCPU والخدمات لتفريق هجوم محتمل من عطل بنية. **اختبار القبول:** اختبار انقطاع مزود أو طفرة نسخ احتياطي دون تصنيف تلقائي DDoS مؤكد. **الحدود والمخاطر:** الارتباط لا يثبت سبب الانقطاع.
- **CG-842** **[بحث/متطلب مرشح] — IPv6 Policy Parity:** مراجعة قواعد الحجب والمنع والـNAC بين IPv4 وIPv6 لمنع فتح مسار غير محمي. **اختبار القبول:** جهاز اختبار لا يستطيع تجاوز سياسة IPv4 عبر IPv6. **الحدود والمخاطر:** يحتاج معرفة مواضع IPv6 الحقيقية ولا يعطلها عشوائيًا.
- **CG-843** **[بحث/متطلب مرشح] — NAT Path Context:** ربط NAT وDHCP وVPN وFirewall في Timeline يفصل بين عنوان الإنترنت وهوية الجهاز الداخلي. **اختبار القبول:** المحقق يرى أن IP عام قد يخص عدة مستخدمين ولا يحدد شخصًا دون أدلة. **الحدود والمخاطر:** قد تمنع سياسات الاحتفاظ حفظ بيانات إضافية.
- **CG-844** **[بحث/متطلب مرشح] — Secure Admin Overlay Access:** دراسة وصول الإدارة عبر شبكة WireGuard مقيدة الهوية مع MFA وسياسات جهاز بدل منافذ عامة. **اختبار القبول:** حساب مراقب لا يستطيع فتح جلسة إدارة إلا إلى أصوله المخولة. **الحدود والمخاطر:** الحل يتطلب قناة طوارئ منفصلة ومراجعة ترخيص NetBird.
- **CG-845** **[بحث/متطلب مرشح] — Control-Plane Protection Posture:** فحص دعم CoPP وAAA وSNMPv3 وACL إدارة الراوتر/السويتش وتقييم التغييرات. **اختبار القبول:** قائمة الإعدادات الناقصة حسب الطراز والإصدار دون إصلاح جماعي أعمى. **الحدود والمخاطر:** القواعد المختلفة قد تسبب حجب جلسة الإدارة.
- **CG-846** **[بحث/متطلب مرشح] — Encrypted Tunnel Inventory:** رصد قنوات VPN وSSH Tunnel وProxy المدعومة أو غير المعتمدة عبر الأدلة المحلية والسياسات. **اختبار القبول:** عرض مالك الاتصال والجهة والعميل بدل اعتبار كل اتصال مشفر خطرًا. **الحدود والمخاطر:** لا نفك تشفير المحتوى بغير أساس قانوني أو تصريح.

### 16-B — الهوية والصلاحيات والاعتماد

- **CG-847** **[بحث/متطلب مرشح] — Machine Identity Passport:** جرد شهادات وخدمات وحسابات التطبيقات وManaged Identities كأصول مستقلة عن المستخدمين. **اختبار القبول:** خدمة تتغير شهادتها تظهر كهوية خدمة واحدة مع سجل تبديل. **الحدود والمخاطر:** قد تختلف المعلومات بين AD وEntra وIAM.
- **CG-848** **[بحث/متطلب مرشح] — Service Account Privilege Expiry:** تحديد تاريخ مراجعة امتيازات حسابات الخدمة وربطها بمالك وتطبيق ومتطلبات فعلية. **اختبار القبول:** حساب خدمة بلا مالك أو مراجعة يظهر خطر حوكمة قابل للمعالجة. **الحدود والمخاطر:** لا نلغي صلاحيات إنتاجية بلا تحليل أثر.
- **CG-849** **[بحث/متطلب مرشح] — Emergency Access Drift Check:** مراقبة حسابات Break-glass واختبار سياسات التنبيه والاحتفاظ بالوصول الطارئ. **اختبار القبول:** يوثق إنذار تجريبي لا يلغي حساب الطوارئ أو يغلق وصوله. **الحدود والمخاطر:** سياسات الطوارئ تحتاج مراجعة رسمية.
- **CG-850** **[بحث/متطلب مرشح] — Admin Session Approval Chain:** ربط جلسة إدارية حساسة بطلب وموافقة وبداية ونهاية وسجل تغييرات. **اختبار القبول:** جلسة غير معتمدة تظهر مخالفة دون قطعها إذا كانت مهمة حرجة. **الحدود والمخاطر:** التسجيل الكامل للجلسات يمس الخصوصية وقد يحتاج سياسة مستقلة.
- **CG-851** **[بحث/متطلب مرشح] — Permission Effective-Rights Resolver:** محاكاة صلاحية فعالة بعد Deny وInheritance وGroups وSCP/Conditional Access. **اختبار القبول:** يعرض اختلاف الإذن المعلن عن الإذن الفعلي في حالة اختبار. **الحدود والمخاطر:** تقييم كل موفر مختلف وقد لا يكتمل بقراءة API.
- **CG-852** **[بحث/متطلب مرشح] — Third-Party Access Expiration:** إدارة تصاريح الموردين الخارجيين بخاصية انتهاء ومالك وسبب وMFA. **اختبار القبول:** انتهاء عقد المورد يطلق مراجعة ويعطّل فقط المسارات المخولة. **الحدود والمخاطر:** علاقات دعم وصيانة قد تحتاج استثناءات موثقة.
- **CG-853** **[بحث/متطلب مرشح] — Identity Attack Graph Review:** جمع نتائج AD/Cloud privilege graph للبحث عن سلسلة امتيازات غير مقصودة. **اختبار القبول:** تقرير يوضح Edge Evidence والحدود والفرق بين مسار نظري ومؤكد. **الحدود والمخاطر:** لا يمنح صلاحية تنفيذ هجمات على الدومين.
- **CG-854** **[بحث/متطلب مرشح] — Token Revocation Verification:** عقب بلاغ سرقة جلسة يتأكد من نجاح إبطالها لدى IdP وإغلاق جلسات التطبيق ذات الصلة. **اختبار القبول:** نتيجة إبطال موثقة أو Unsupported لكل مزود. **الحدود والمخاطر:** بعض التوكنات تبقى فعالة حتى انتهاء صلاحيتها.
- **CG-855** **[بحث/متطلب مرشح] — Authentication Downgrade Alarm:** كشف تراجع تطبيق من FIDO2 إلى عامل ضعيف أو تفعيل Legacy Authentication. **اختبار القبول:** تغيّر سياسة MFA يظهر مع صاحب التعديل وموعده. **الحدود والمخاطر:** قد تكون هناك تطبيقات قديمة تتطلب خطة ترحيل.
- **CG-856** **[بحث/متطلب مرشح] — Identity Recovery Runbook:** إجراءات اختبارية لاستعادة حسابات ومديري الدومين وموثوقية النسخ دون استخدام أسرار حقيقية. **اختبار القبول:** محاكاة فشل IdP تظهر مسار تحكم طارئ مستقل. **الحدود والمخاطر:** لا تخزن كلمات مرور الطوارئ داخل واجهة SOC.

### 16-C — سلامة البيانات والنسخ الاحتياطية

- **CG-857** **[بحث/متطلب مرشح] — Backup Repository Tamper Watch:** التنبيه عند حذف Snapshots أو تغيير صلاحيات مستودع النسخ أو فشل مهمة النسخ. **اختبار القبول:** يسجل التغيير ومن فعله وما إذا كان ضمن نافذة صيانة. **الحدود والمخاطر:** لا يضمن كشف كل تلاعب لو اخترق جهاز النسخ ذاته.
- **CG-858** **[بحث/متطلب مرشح] — Backup Integrity Sampling:** تنسيق فحص check/read-data دوري لنسخ Restic/Kopia وتحديد نسبة عينات التحقق. **اختبار القبول:** يُظهر آخر نجاح تحقق من المحتوى لا مجرد نجاح نسخ الملفات. **الحدود والمخاطر:** التحقق من السلامة غير اختبار استعادة تطبيق كامل.
- **CG-859** **[بحث/متطلب مرشح] — Clean-Room Restore Drill:** استعادة عينة في بيئة معزولة للتحقق من التشغيل دون إعادة تلوث الشبكة. **اختبار القبول:** نتيجة RTO/RPO واقعية مع تمييز تمرين عن حدث فعلي. **الحدود والمخاطر:** التدريب يستهلك موارد ويجب إخفاء البيانات الحساسة.
- **CG-860** **[بحث/متطلب مرشح] — Backup Destructive Permission Split:** فصل صلاحية إضافة نسخ عن حذفها وتعديل سياسات الاحتفاظ. **اختبار القبول:** حساب النسخ العادي يفشل في حذف آخر نسخة محمية. **الحدود والمخاطر:** يعتمد على خواص التخزين Lock/WORM ولا يكفي تشفير النسخ.
- **CG-861** **[بحث/متطلب مرشح] — Database Audit Coverage Ledger:** قياس تدقيق SELECT/ALTER/DROP/LOGIN وفشل المصادقة لكل محرك قاعدة بيانات. **اختبار القبول:** واجهة تقول أي أحداث متاحة في SQL Server/PostgreSQL/MySQL/Oracle. **الحدود والمخاطر:** قد تزيد السجلات الحمل وتحتوي بيانات شخصية.
- **CG-862** **[بحث/متطلب مرشح] — Schema Change Security Diff:** رصد تغيّر الصلاحيات والجداول والمخططات الحساسة وربطه بطلب تغيير. **اختبار القبول:** إضافة مستخدم DB عالي الصلاحية يظهر باسم المسؤول والطلب. **الحدود والمخاطر:** نسخ التطوير تختلف عن الإنتاج ويجب فصل الضوضاء.
- **CG-863** **[بحث/متطلب مرشح] — Database Exfiltration Context:** تحليل ارتفاع نقل البيانات عبر Connection/Query Metadata بدون قراءة النتائج الخام. **اختبار القبول:** إنذار يستخدم وقت الاتصال والحجم والمصدر دون نسخ محتوى الجداول. **الحدود والمخاطر:** السحب الكبير قد يكون نسخًا احتياطيًا مشروعًا.
- **CG-864** **[بحث/متطلب مرشح] — Sensitive Data Location Map:** جرد مواضع تخزين بيانات حساسة وربطها بمالك وتصنيف ونسخ احتياطية. **اختبار القبول:** البيانات الحساسة غير المملوكة تظهر للمراجعة. **الحدود والمخاطر:** يحتاج تفويضًا وحدود خصوصية ومنع قراءة المحتوى بلا ضرورة.
- **CG-865** **[بحث/متطلب مرشح] — Data Retention Policy Auditor:** تذكير بالفترات القانونية/المعتمدة لحفظ سجلات الأمن والنسخ والبيانات. **اختبار القبول:** تقرير احتفاظ منفصل لكل نوع بيانات مع استثناءات معللة. **الحدود والمخاطر:** لا نحدد مددًا قانونية ثابتة دون سياسة الجهة.
- **CG-866** **[بحث/متطلب مرشح] — Cross-Region Data Residency Review:** إظهار مكان تخزين السجلات والنسخ وواجهات AI السحابية ومخاطر نقل البيانات. **اختبار القبول:** مسار بيانات من LAN إلى خدمة أجنبية يظهر للمراجعة. **الحدود والمخاطر:** تصنيف البيانات والالتزامات القانونية يختلفان حسب الجهة.

### 16-D — أمان التطبيقات والحاويات وسلسلة التوريد

- **CG-867** **[بحث/متطلب مرشح] — Live SBOM Reconciliation:** إنشاء SBOM من الصور والملفات ثم ربطها بالتطبيق المثبت فعليًا بعد تحديثه. **اختبار القبول:** مقارنة Syft قبل وبعد الإصدار تظهر المكوّن المتغير. **الحدود والمخاطر:** لا نعتبر SBOM دليلًا على عدم وجود شيفرة خبيثة.
- **CG-868** **[بحث/متطلب مرشح] — Exploitability-Aware Finding Dedup:** ربط نتائج Grype/OSV/DAST في قضية واحدة مع VEX وحالة استغلال المكون. **اختبار القبول:** CVE واحدة في 4 نتائج تُدمج دون فقد الأدلة. **الحدود والمخاطر:** VEX استثناء معلّل يحتاج مراجعة.
- **CG-869** **[بحث/متطلب مرشح] — Source Secret Pre-Commit Gate:** كشف أسرار داخل المستودع قبل Commit عبر أدوات مناسبة ومراقبة دورانها بعد التسريب. **اختبار القبول:** مفتاح اختباري لا يدخل مسار النشر، ولا يُطبع في السجلات. **الحدود والمخاطر:** الحساس لا يضمن كشف كل نوع Secret.
- **CG-870** **[بحث/متطلب مرشح] — Kubernetes Admission Guard:** دراسة Kyverno للسياسات: صور موقعة وعدم تشغيل Privileged وحظر HostPath غير المصرح. **اختبار القبول:** Pod اختباري يخالف السياسة يُرفض مع شرح واضح. **الحدود والمخاطر:** سياسة عامة قد توقف تطبيقات شرعية، نبدأ Audit.
- **CG-871** **[بحث/متطلب مرشح] — Kubernetes CIS Drift Evidence:** تشغيل فحوص kube-bench وتخزين نسخة معيار CIS وإصدار العنقود كدليل. **اختبار القبول:** فحص يميّز NotApplicable من Fail. **الحدود والمخاطر:** الملفات الصحيحة لا تثبت حماية التطبيق من هجمات المنطق.
- **CG-872** **[بحث/متطلب مرشح] — Runtime eBPF Detection Profiles:** فحص تشغيل العمليات والوصول للملفات واتصالات Linux عند الحاجة عبر Tracee. **اختبار القبول:** تجربة مختبر تعرض الدليل من kernel دون استنتاج هوية مهاجم. **الحدود والمخاطر:** يتطلب امتيازات Kernel حساسة وتوافق إصدار Linux.
- **CG-873** **[بحث/متطلب مرشح] — Software Update Chain of Trust:** تأكيد توقيع ومصدر وتاريخ حزمة التحديث، ومنع Downgrade غير مصرح. **اختبار القبول:** ملف تحديث معدّل يرفضه نظام الاختبار. **الحدود والمخاطر:** التوقيع لا يعني عدم وجود ثغرة في النسخة الموقعة.
- **CG-874** **[بحث/متطلب مرشح] — Release Rollout Blast-Radius Limit:** توزيع تحديثات الأيجنت والسياسات على مجموعات تجريبية قبل المؤسسات بأكملها. **اختبار القبول:** فشل مجموعة صغيرة يوقف النشر قبل الوصول إلى الأجهزة الحرجة. **الحدود والمخاطر:** قد يتأخر تصحيح سريع بسبب مراحل الموافقة.
- **CG-875** **[بحث/متطلب مرشح] — Security Findings Workflow:** دمج نتائج SAST/DAST/Cloud/Containers في سجلات علاج مع مالك وموعد ودليل إغلاق. **اختبار القبول:** نتائج متكررة توحد، وإعادة فتح الثغرة تحفظ التاريخ. **الحدود والمخاطر:** إغلاق التذكرة دون إعادة فحص لا يعني علاجًا.
- **CG-876** **[بحث/متطلب مرشح] — Trusted Plugin / GitHub Health Gate:** فحص رخصة المشروع وتحديثاته والتنبيهات الأمنية قبل اعتماد إضافات CyberGuard. **اختبار القبول:** مشروع مؤرشف أو تغيّر ترخيصه يظهر كمخاطرة. **الحدود والمخاطر:** التراخيص تحتاج مراجعة قانونية وليست حكمًا آليًا.

### 16-E — التحقيق والرصد والإنذارات

- **CG-877** **[بحث/متطلب مرشح] — Dual-Signal Incident Threshold:** رفض تحويل مؤشر منفرد مثل MAC OUI أو IP reputation إلى تأكيد اختراق. **اختبار القبول:** حالة اختبار منخفضة الثقة تبقى بحاجة تحقيق. **الحدود والمخاطر:** بعض هجمات حقيقية لا تترك إلا مصدرًا واحدًا.
- **CG-878** **[بحث/متطلب مرشح] — Evidence Clock Quality Index:** تقييم مزامنة الساعات وNTP ومصدر المنطقة الزمنية قبل إنشاء Timeline. **اختبار القبول:** إذا اختلفت ساعة سويتش تظهر لافتة عدم دقة التسلسل. **الحدود والمخاطر:** قد تتعذر معرفة الوقت الحقيقي لأجهزة غير متصلة.
- **CG-879** **[بحث/متطلب مرشح] — Event Pipeline Loss Budget:** قياس فقد أحداث Windows/Syslog/Cloud أثناء ضغط الشبكة وعرض معدل الفقد. **اختبار القبول:** اختبار قطع اتصال الحساس ينتج Missing Events لا Green. **الحدود والمخاطر:** مقاييس فقد قد تكون تقديرية حسب مصدر السجل.
- **CG-880** **[بحث/متطلب مرشح] — Secure Raw Evidence Store:** خزن نسخة أصلية مختومة ونسخة قابلة للبحث مع بصمة وسلسلة حيازة. **اختبار القبول:** المحلل لا يستطيع تعديل نسخة المصدر، وكل قراءة تسجل. **الحدود والمخاطر:** لا نستطيع ضمان عدم تغيير المصدر قبل جمع الدليل.
- **CG-881** **[بحث/متطلب مرشح] — Response Evidence Checklist:** كل Playbook يحدد الأدلة التي يجب حفظها قبل إجراء قد يمحوها. **اختبار القبول:** خطة عزل جهاز تعرض خطوات الجمع العاجلة ومخاطر التأخير. **الحدود والمخاطر:** الأولوية لوقف الضرر عند حادث طارئ.
- **CG-882** **[بحث/متطلب مرشح] — Alert Quality Feedback:** تسجيل تحليل True Positive / False Positive / Benign Positive مع قرار القاعدة. **اختبار القبول:** انخفاض جودة قاعدة معينة يطلق مراجعة بدل تعطيل فوري. **الحدود والمخاطر:** التقييم البشري نفسه قد يخطئ.
- **CG-883** **[بحث/متطلب مرشح] — Advanced Sensor Capability State:** عرض لكل حساس: Agent health + privileges + last event + limitations. **اختبار القبول:** الحساس المتصل بلا Event Stream لا يظهر حالة سليمة. **الحدود والمخاطر:** معلومات بعض الحساسات لا تعطي Heartbeat أصلي.
- **CG-884** **[بحث/متطلب مرشح] — Deception Egress Safety:** بيئات Honeypot يجب أن تعزل الاتصالات الخارجة وتحصر ما يجمع منها. **اختبار القبول:** تجربة تحاول خروجًا غير مسموح فتُرفض في المختبر. **الحدود والمخاطر:** التفاعل مع مهاجم حقيقي يحمل مخاطر تشغيلية وقانونية.
- **CG-885** **[بحث/متطلب مرشح] — SOC Service Degradation Mode:** عند سقوط محرك AI أو محرك البحث تستمر إنذارات حرجة عبر مسار مستقل. **اختبار القبول:** محاكاة انقطاع AI لا تمنع تسجيل الحادث أو طلب العزل. **الحدود والمخاطر:** يحتاج بنية إضافية وميزانية.
- **CG-886** **[بحث/متطلب مرشح] — Local Incident Offline Kit:** إتاحة أدوات قراءة أدلة وتقارير محلية متوقعة عند انقطاع الإنترنت ضمن صلاحية المسؤول. **اختبار القبول:** في مختبر غير متصل يمكن استخراج ملخص حادث من البيانات المخزنة. **الحدود والمخاطر:** تحديث معلومات التهديدات قد يتأخر دون اتصال.

### 16-F — أمان الذكاء الاصطناعي ونضج التشغيل

- **CG-887** **[بحث/متطلب مرشح] — Shadow AI Endpoint Inventory:** كشف استخدام برامج وأدوات AI المحلية في الأجهزة المُدارة عبر جرد osquery مع تقييد الصلاحية. **اختبار القبول:** يظهر برنامج AI غير معروف دون نسخ محادثات المستخدمين. **الحدود والمخاطر:** ليس دليلًا على تسريب بيانات ولا مراقبة الأجهزة غير المُدارة.
- **CG-888** **[بحث/متطلب مرشح] — LLM Retrieval Evidence Chain:** كل إجابة AI أمنية ترتبط بأحداث وشروط كشف ومرجع زمني بدل أوامر مباشرة. **اختبار القبول:** سؤال عن حادث يعطي رقم الأدلة أو يقول غير كافٍ. **الحدود والمخاطر:** قد يعطي AI استنتاجًا خاطئًا رغم وجود مراجع.
- **CG-889** **[بحث/متطلب مرشح] — AI Prompt Injection Test Set:** اختبار مستندات وسجلات خبيثة تحاول طلب تغيير إعداد Firewalls داخل بيئة اختبار. **اختبار القبول:** الاختبار يفشل في تجاوز بوابة الموافقة حتى لو وافق النموذج. **الحدود والمخاطر:** لا توجد حماية نموذجية تضمن منع كل Prompt Injection.
- **CG-890** **[بحث/متطلب مرشح] — AI Data Classification Router:** تحديد ما يجوز إرساله للنموذج السحابي وما يبقى محليًا، بناءً على حساسية الحقول. **اختبار القبول:** توكن اختباري لا يصل إلى AI خارجي أو سجل Debug. **الحدود والمخاطر:** التصنيف قد يخطئ ويحتاج مراجعة سياسة الخصوصية.
- **CG-891** **[بحث/متطلب مرشح] — Plugin Action Manifest:** تعريف صلاحية لكل تكامل: Read / Propose / Execute، مع شروط وقيود الصلاحية. **اختبار القبول:** تكامل يقرأ السويتش لا يمكنه تعطيل منفذ ولو طلب AI. **الحدود والمخاطر:** صلاحيات واجهة الشبكة الخارجية قد تكون أوسع من المطلوب.
- **CG-892** **[بحث/متطلب مرشح] — Security Architecture Threat Model:** تحليل مخاطر اختراق CyberGuard نفسه خصوصًا Collector وAgent وAPI ومخزن الأسرار. **اختبار القبول:** مراجعة دورية لتصميم الثقة وقنوات الإدارة وتعافي الاختراق. **الحدود والمخاطر:** التصميم الآمن يتطلب اختبارًا لاحقًا وليس مستندًا فقط.
- **CG-893** **[بحث/متطلب مرشح] — Audit Trail Independence:** حفظ سجلات القرارات الحساسة بنسخ منفصلة وصلاحيات كتابة مقيدة. **اختبار القبول:** مدير تطبيق عادي لا يستطيع مسح تاريخ الإجراءات. **الحدود والمخاطر:** أي سجل يعتمد على نفس خادم واحد قد يفقد أثناء حادث.
- **CG-894** **[بحث/متطلب مرشح] — Cost Per Protected Asset:** ربط التخزين والحساسات والسحابة وحجم الأحداث بتكلفة تقديرية لكل أصل. **اختبار القبول:** سيناريو 500 و5000 و20000 أصل مع اختلاف معدلات الأحداث. **الحدود والمخاطر:** تقديرات التكلفة تتغير حسب الترخيص وحجم السجلات.
- **CG-895** **[بحث/متطلب مرشح] — Detection Coverage Acceptance Gate:** لا نعتمد ميزة اكتشاف حتى تحدد Detection Preconditions ونتائج سيناريوهات صح/خطأ. **اختبار القبول:** يظهر معدل التجارب الفاشلة وأسباب غياب الأحداث. **الحدود والمخاطر:** الاختبارات المختبرية لا تضمن كشف كل الهجمات الواقعية.
- **CG-896** **[بحث/متطلب مرشح] — Governed Feature Registry:** تسجيل حالة كل ميزة: فكرة/بحث/مثبت مختبرًا/جاهز/مؤجل/مرفوض، مع قرار مكتوب. **اختبار القبول:** أي ميزة في سجل CG لا توصف بأنها شغالة دون اختبار إثبات. **الحدود والمخاطر:** عدد الميزات ليس مقياس جودة أمني.

## عشرة أسماء إضافية — لم يتم حجزها ولا التحقق قانونيًا من توفرها

| بالعربي | بالإنجليزي | الاختصار |
|---|---|---|
| سياج الأمن | Siyaj Security | **SYJ** |
| حصين كور | Haseen Core | **HSC** |
| مرقاب الحماية | Mirqab Sentinel | **MQS** |
| يقظة السيبراني | Yaqzah Cyber | **YCB** |
| ركن الدرع | Rukn Shield | **RKS** |
| درع المدار | Madar Shield | **MDS** |
| نبض الدفاع | Defense Pulse | **DFP** |
| عين الأطلس | Atlas Watch | **ATW** |
| حارس النواة | Core Guardian | **CGN** |
| بوابة الحصن | Bastion Gate | **BTG** |

**الاسم النهائي مؤجل إلى قرار المستخدم.** الأسماء السابقة من v1.5 تبقى مرشحة؛ هذه إضافة وليست بديلًا عنها.

## مستودعات ومراجع بحث هذه الجولة

- [FastNetMon DDoS / Flows](https://github.com/pavel-odintsov/fastnetmon) — نقطة انطلاق للدراسة، لا قرار دمج نهائي.
- [BGPalerter BGP/RPKI](https://github.com/nttgin/BGPalerter) — نقطة انطلاق للدراسة، لا قرار دمج نهائي.
- [NetBird Zero Trust WireGuard](https://github.com/netbirdio/netbird) — نقطة انطلاق للدراسة، لا قرار دمج نهائي.
- [Restic encrypted backups](https://github.com/restic/restic) — نقطة انطلاق للدراسة، لا قرار دمج نهائي.
- [Kopia snapshots](https://github.com/kopia/kopia) — نقطة انطلاق للدراسة، لا قرار دمج نهائي.
- [Kyverno policy as code](https://github.com/kyverno/kyverno) — نقطة انطلاق للدراسة، لا قرار دمج نهائي.
- [kube-bench CIS](https://github.com/aquasecurity/kube-bench) — نقطة انطلاق للدراسة، لا قرار دمج نهائي.
- [Tracee Linux runtime](https://github.com/aquasecurity/tracee) — نقطة انطلاق للدراسة، لا قرار دمج نهائي.
- [Anchore Syft](https://github.com/anchore/syft) — نقطة انطلاق للدراسة، لا قرار دمج نهائي.
- [Anchore Grype](https://github.com/anchore/grype) — نقطة انطلاق للدراسة، لا قرار دمج نهائي.
- [Gitleaks secrets](https://github.com/gitleaks/gitleaks) — نقطة انطلاق للدراسة، لا قرار دمج نهائي.
- [DefectDojo vulnerability operations](https://github.com/DefectDojo/django-DefectDojo) — نقطة انطلاق للدراسة، لا قرار دمج نهائي.
- [Cortex analyzers](https://github.com/TheHive-Project/Cortex-Analyzers) — نقطة انطلاق للدراسة، لا قرار دمج نهائي.
- [MITRE Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — نقطة انطلاق للدراسة، لا قرار دمج نهائي.
- [osquery endpoint inventory](https://github.com/osquery/osquery) — نقطة انطلاق للدراسة، لا قرار دمج نهائي.

## شروط اعتماد كل متطلب لاحقًا

1. تحديد التهديد وسياق المنتج والشبكة المشمولة.
2. الدليل المتوقع، ومصدره، وحدود الرؤية ومدى دقة التصنيف.
3. إثبات الأداة في المختبر، ودعم المورد والنسخة والترخيص.
4. صلاحيات القراءة والتنفيذ، وتأثير الإجراء والتراجع وحماية الأصول الحرجة.
5. أثر الأداء والتخزين والخصوصية والصيانة والتكلفة.
6. توثيق القرار: اعتمد / مؤجل / يلزم تحقيق / مرفوض، مع السبب.

**نقطة الاستكمال التالية بعد هذه الإضافة: CG-937.**


---

## الجولة السابعة عشرة — دمج الأمن مع التشغيل: خيارات مدروسة وجاهزية إصدار متكامل

**حالة هذه الجولة:** أفكار بحثية جديدة، لا برمجة ولا تنفيذ. **اسم CyberGuard AI مؤقت** حتى قرار المستخدم. كما أن عدد الأفكار لا يساوي عدد الوظائف المؤهلة للإنتاج.

### القرار المعماري المرشح

- **الهوية الأساسية المرشحة:** Unified Security + Network Operations (SOC + NOC) مع طبقة Digital Twin لتحديد أثر التغيير، تتوسع إلى ITSM وCyber Resilience وAIOps وDevSecOps على شكل وحدات مستقلة.
- **التشغيل من PC:** يكون PC بوابة إدارة/مجمعًا محليًا عند النطاق الصغير؛ لا يستطيع بمفرده اكتشاف الحركة غير المرئية أو تجاوز الصلاحيات أو تشغيل الأنظمة السحابية دون تكامل مناسب.
- **الإطلاق الموحّد:** لا نسلم وظائف ناقصة على أنها مكتملة، لكن نجتاز اختبارات داخلية متعددة المراحل قبل إصدار موحد؛ لا يوجد ضمان كوني 100% كشف أو 100% توافق مع كل جهاز.
- **مبدأ الأمان:** اكتشاف وقراءة أولًا، استجابة محددة الصلاحية مع تقييم أثر وموافقة وتحقيق النتيجة وإمكانية استرجاع.

### 17 — البنية الموحدة

- **CG-897** **[بحث/متطلب مرشح] — Unified Asset Identity Graph:** إنشاء معرّف مستقل عن IP/MAC لكل أصل، يجمع أدلة Agent وAD وDHCP وSNMP وCloud مع سجل المصدر. **اختبار القبول:** تغير IP في سيناريو اختبار دون إنشاء أصل مكرر؛ تُعرض درجة الثقة. **الحدود والمخاطر:** قد تتطابق بصمات أجهزة مختلفة؛ يمنع الدمج التلقائي عند الشك.
- **CG-898** **[بحث/متطلب مرشح] — Source Authority Matrix:** تحديد المصدر المرجعي لكل نوع بيانات: DHCP للمنح، Network FDB للمنفذ، CMDB للمالك، Cloud API لمعرف المورد. **اختبار القبول:** عند تعارض MAC/المالك بين مصدرين يظهر سبب التعارض دون اختيار عشوائي. **الحدود والمخاطر:** لا توجد سلطة مطلقة لمصدر واحد على كل الحقول.
- **CG-899** **[بحث/متطلب مرشح] — Time-Aware Topology Graph:** تتبع شبكة التوصيلات والمنفذ وVLAN والسيرفر والخدمة ضمن نسخ زمنية. **اختبار القبول:** عرض اتصال جهاز قبل وبعد نقله بين منفذين بدقة الزمن المتاح. **الحدود والمخاطر:** قد تفوت حركة قصيرة بسبب معدل جمع البيانات.
- **CG-900** **[بحث/متطلب مرشح] — Business Service Ownership:** ربط التطبيقات والخدمات بمالك وSLA ومستوى أهمية وبيئة Production أو Lab. **اختبار القبول:** عزل تجريبي يظهر تأثيره المحتمل على الخدمات المرتبطة. **الحدود والمخاطر:** قد لا تكون علاقات التطبيقات معروفة دون تعريف بشري.
- **CG-901** **[بحث/متطلب مرشح] — Cross-Domain Evidence Provenance:** توثيق مصدر كل علاقة بين الأصل والخدمة والمستخدم والمنفذ وتاريخ آخر تحقق. **اختبار القبول:** علاقة غير موثقة تظهر Unknown لا Confirmed. **الحدود والمخاطر:** جمع الأدلة لا يثبت جميع الاعتمادات المخفية.
- **CG-902** **[بحث/متطلب مرشح] — Observed vs Intended State:** فصل حالة الشبكة المكتشفة Live عن التصميم المعتمد Source of Truth. **اختبار القبول:** تغيير VLAN غير معتمد يظهر كفرق بمرجع الحالة المعتمدة. **الحدود والمخاطر:** لا يجوز نسخ كل تغيير مكتشف إلى المرجع المعتمد تلقائيًا.
- **CG-903** **[بحث/متطلب مرشح] — Asset Context Freshness:** درجة صلاحية زمنية مستقلة لكل حقل من IP والمنفذ والمالك ونوع الجهاز. **اختبار القبول:** معلومة منفذ قديمة لا تستخدم لاتخاذ قرار عزل دون إعادة تحقق. **الحدود والمخاطر:** اختلاف معدلات تحديث الأجهزة.
- **CG-904** **[بحث/متطلب مرشح] — Multi-Site Boundary Model:** عزل نطاقات المباني والمواقع والجهات والأذونات وتحديد من يملك اكتشاف كل شبكة. **اختبار القبول:** مسؤول موقع 1 لا يستطيع رؤية أسرار أو تنفيذ على موقع 2 دون تفويض. **الحدود والمخاطر:** الربط بين الفروع لا يضمن اكتشاف كل الأجهزة.

### 17 — NOC و AIOps

- **CG-905** **[بحث/متطلب مرشح] — Service-Level Objectives:** مراقبة توافر الشبكة والخدمات بزمن استجابة ونسبة نجاح مقيّدة بنوع الخدمة. **اختبار القبول:** يتحقق إنذار عن انخفاض التوافر من قياسات صالحة ويبيّن نافذة الحساب. **الحدود والمخاطر:** قد تكون الخدمة متاحة تقنيًا لكن غير صالحة وظيفيًا.
- **CG-906** **[بحث/متطلب مرشح] — Security-to-Outage Correlation:** ربط أعطال DNS وDHCP وSwitch وFirewall مع التنبيهات الأمنية في خط زمني واحد. **اختبار القبول:** اختبار سويتش منقطع ينتج مشكلة جذرية واحدة بدل عشرات الإنذارات المستقلة. **الحدود والمخاطر:** الترابط إحصائي ولا يثبت السببية دون أدلة.
- **CG-907** **[بحث/متطلب مرشح] — Maintenance-Aware Alerts:** تعليق تنبيهات محددة بموافقة أثناء نافذة صيانة مع الحفاظ على كشف الحوادث الحرجة. **اختبار القبول:** تنتهي نافذة الصيانة آليًا وتعود التنبيهات دون تدخل. **الحدود والمخاطر:** إساءة استخدام الصيانة قد تخفي هجومًا إذا لم تُراجع.
- **CG-908** **[بحث/متطلب مرشح] — Early Saturation Risk:** رصد مؤشرات امتلاء منافذ وروابط وطاقة PoE وCPU وMemory قبل انقطاع الخدمة. **اختبار القبول:** تنبيه سعة يظهر دليل الاتجاه الزمني والحد وإطار القياس. **الحدود والمخاطر:** ليس كل ارتفاع مؤقت مشكلة تشغيلية.
- **CG-909** **[بحث/متطلب مرشح] — Network Incident Root Cause Hypotheses:** اقتراح قائمة أسباب مدعومة بأدلة بدل إعلان سبب قطعي للانقطاع. **اختبار القبول:** تشير الواجهة إلى أسباب محتملة مع الأدلة والفجوات، ولا تخترع السبب. **الحدود والمخاطر:** أدوات RUM والسجلات قد تكون مفقودة.
- **CG-910** **[بحث/متطلب مرشح] — Edge Collector Store and Forward:** جامع أحداث عند الموقع يحتفظ بالأحداث محليًا أثناء انقطاع WAN ثم يزامنها بإشارات فقد. **اختبار القبول:** اختبار فصل WAN لا يفقد الأحداث ضمن سعة التخزين المحددة. **الحدود والمخاطر:** عند امتلاء التخزين يجب الإبلاغ بفقد البيانات.
- **CG-911** **[بحث/متطلب مرشح] — Monitoring Blast Radius Estimation:** تقدير كم خدمة أو أصلًا متأثرًا بخطأ Uplink أو DNS أو DC. **اختبار القبول:** اختبار رابط تجميعي يظهر الأصول المحتمل تأثرها مع مدى الثقة. **الحدود والمخاطر:** تعتمد النتيجة على اكتمال خريطة الاعتمادات.
- **CG-912** **[بحث/متطلب مرشح] — Service Health != Security Health:** لوحة منفصلة لصحة الخدمة عن درجة خطرها، مع ربط السياق. **اختبار القبول:** خدمة متاحة مع ثغرة حرجة لا تظهر آمنة فقط لأنها تعمل. **الحدود والمخاطر:** لا قيمة واحدة تلخص كل المخاطر.

### 17 — عمليات الدعم والحوكمة

- **CG-913** **[بحث/متطلب مرشح] — Incident-to-Ticket Workflow:** تحويل الحوادث المؤكدة والمشكلات التشغيلية إلى تذاكر ذات مالك وأولوية وأدلة دون تكرار. **اختبار القبول:** تنبيهات مترابطة تنتج تذكرة واحدة مع تاريخها. **الحدود والمخاطر:** المزامنة مع ITSM تعتمد على API متاح.
- **CG-914** **[بحث/متطلب مرشح] — Approved Change Ticket Link:** ربط كل تغيير منفذ أو سياسة أو خدمة برقم موافقة وخطة اختبار وموعد انتهاء. **اختبار القبول:** لا ينفذ تغيير عالي الأثر دون مرجع موافقة مناسب. **الحدود والمخاطر:** حالات الاستجابة الطارئة تحتاج إجراء استثنائي موثق.
- **CG-915** **[بحث/متطلب مرشح] — Ownership and Escalation Matrix:** تحديد المسؤول عن Switch وAD وCloud وخدمات الأعمال ومسار التصعيد. **اختبار القبول:** تنبيه خطير يصل للفريق الصحيح دون نسخ أسرار الأطراف غير المعنية. **الحدود والمخاطر:** الحصول على مالكي الأنظمة يحتاج بيانات مؤسسية صحيحة.
- **CG-916** **[بحث/متطلب مرشح] — Configuration Change Calendar:** عرض نوافذ التغيير والاختبارات المستحقة والانتهاء الآلي للتصاريح المؤقتة. **اختبار القبول:** يمنع جدولة تغييرين متعارضين على نفس الخدمة أو يطلب مراجعة. **الحدود والمخاطر:** لا يمنع التغيير خارج المنصة ما لم تقيد الامتيازات.
- **CG-917** **[بحث/متطلب مرشح] — IT Asset Lifecycle Security:** ربط شراء الجهاز وتكوينه واعتماده ونقله وإخراجه من الخدمة ومسح بياناته. **اختبار القبول:** أصل متقاعد يعود للشبكة يظهر كحدث أمني لا كجهاز جديد عادي. **الحدود والمخاطر:** المخزون المعتمد قد يكون ناقصًا.
- **CG-918** **[بحث/متطلب مرشح] — Exception Owner and Expiry:** كل استثناء أمني له مالك وسبب وموعد انتهاء ومسار مراجعة. **اختبار القبول:** استثناء مختبر ينتهي ولا يظل مؤثرًا بعد انتهاء سببه. **الحدود والمخاطر:** إزالة استثناء تحتاج تحقق من التنفيذ في الجدار الناري.
- **CG-919** **[بحث/متطلب مرشح] — Incident Communications Playbook:** نصوص ومعلومات معتمدة لتواصل الفرق المتأثرة أثناء انقطاع أو اختراق. **اختبار القبول:** رسالة تجريبية لا تكشف أسرار الحادث لأطراف غير مخولة. **الحدود والمخاطر:** لا يُرسل تقرير خارجي دون موافقة مفوضة.
- **CG-920** **[بحث/متطلب مرشح] — Audit Evidence Pack Generator:** جمع سجلات التدقيق وتغييرات السياسة ودليل الاستجابة كحزمة مراجعة مترابطة. **اختبار القبول:** الحزمة تتحقق من بصمات ملفاتها وتذكر أحداثًا مفقودة. **الحدود والمخاطر:** الحزمة لا تثبت الامتثال وحدها.

### 17 — التوأم الرقمي

- **CG-921** **[بحث/متطلب مرشح] — Port Shutdown What-if:** محاكاة تعطيل منفذ وصول أو Uplink باستخدام معلومات التوصيلات والاعتمادات قبل طلب التنفيذ. **اختبار القبول:** يحذر من قطع هاتف VoIP أو عدة MAC أو رابط Uplink. **الحدود والمخاطر:** قد لا يرى أجهزة خلف Switch غير مُدار.
- **CG-922** **[بحث/متطلب مرشح] — ACL and VLAN Policy What-if:** تحليل وصول الخدمات قبل وبعد تغييرات ACL وVLAN ضمن دعم الطراز ومصادر التكوين. **اختبار القبول:** اختبار حالة يبرز خدمة كانت مسموحة وستُحجب. **الحدود والمخاطر:** التحليل الثابت لا يغطي كل السلوكيات وقت التشغيل.
- **CG-923** **[بحث/متطلب مرشح] — Identity Outage What-if:** تقييم تأثير تعطل Domain Controller أو DNS أو RADIUS على المستخدمين والخدمات. **اختبار القبول:** يوضح الاعتمادات المعروفة واحتمال فقد المصادقة دون تجربة على الإنتاج. **الحدود والمخاطر:** قد توجد مسارات فشل بديلة غير موثقة.
- **CG-924** **[بحث/متطلب مرشح] — VM and Cluster Failover Map:** إظهار ارتباطات Hyper-V/VMware/Cloud VMs بالمضيف والتخزين والشبكة عند تصور عطل. **اختبار القبول:** سقوط مضيف في سيناريو افتراضي يظهر خدمات VMs المتأثرة. **الحدود والمخاطر:** يتطلب APIs أو بيانات دقيقة عن الـcluster.
- **CG-925** **[بحث/متطلب مرشح] — Simulation Confidence Boundaries:** إظهار القيود والفجوات قبل اعتماد نتيجة أي محاكاة. **اختبار القبول:** محاكاة ناقصة تسجل Unknown ولا تزعم ضمان عدم الانقطاع. **الحدود والمخاطر:** جودة النموذج تعتمد على تحديث الجرد.
- **CG-926** **[بحث/متطلب مرشح] — Recovery Path Validation Model:** تحديد قناة إدارة احتياطية ومسار استعادة قبل تغيير يمكن أن يقطع التحكم. **اختبار القبول:** لا يقبل تغييرًا خطرًا عند غياب قناة استرداد مصرح بها. **الحدود والمخاطر:** القنوات الاحتياطية قد تفشل أيضًا وتحتاج اختبارًا.

### 17 — الجاهزية والتسليم

- **CG-927** **[بحث/متطلب مرشح] — Supported Environment Matrix:** إعلان نسخ Windows/Linux وأجهزة Cisco/Huawei والسحب المدعومة ومستوى الوظائف في كل نسخة. **اختبار القبول:** كل تركيبة مدعومة لها اختبار توافقي ومحددات منشورة. **الحدود والمخاطر:** لا يمكن ضمان عمل جميع الميزات على كل موديل في العالم.
- **CG-928** **[بحث/متطلب مرشح] — Real Integration Contract Tests:** اختبارات API/CLI/Agent تكشف تغيّر مخططات أو صلاحيات مزودي الخدمة. **اختبار القبول:** فشل تكامل يعطله بأمان ويعرض السبب، لا نجاحًا وهميًا. **الحدود والمخاطر:** خدمات المورد قد تتغير دون إعلان.
- **CG-929** **[بحث/متطلب مرشح] — Release Feature Acceptance Gate:** لا توصف أي ميزة بأنها جاهزة حتى تنجح حالاتها الإيجابية والسلبية وحدود الصلاحيات والتراجع. **اختبار القبول:** 100% من اختبارات القبول المتفق عليها للوظائف المعلنة ناجحة، مع صفر أخطاء حرجة غير معالجة. **الحدود والمخاطر:** نجاح الاختبارات لا يضمن كشف جميع الهجمات في الواقع.
- **CG-930** **[بحث/متطلب مرشح] — One-Click Readiness Preflight:** فحص مسبق لصلاحيات الاتصال والشهادات والمنافذ والتراخيص وأجهزة الاستشعار قبل عرض الحالة. **اختبار القبول:** يمنع أخطاء خفية عند غياب SNMP/AD/Cloud/Agent ويشرح ما ينقص. **الحدود والمخاطر:** أذونات المسؤول لا تعني بالضرورة سماح المؤسسة بالفحص.
- **CG-931** **[بحث/متطلب مرشح] — Idempotent Verified Responses:** تنفيذ استجابة مرة واحدة وتحقق من نتيجتها وحالة التراجع حتى مع إعادة المحاولة أو انقطاع الاتصال. **اختبار القبول:** إرسال طلب عزل مرتين لا يضاعف تغييرات الشبكة، وعودة الوصلة تحسم الحالة. **الحدود والمخاطر:** الحالة الوسيطة تحتاج تدخلاً بشريًا أحيانًا.
- **CG-932** **[بحث/متطلب مرشح] — Production Launch Evidence Dossier:** توثيق اختبارات الأداء والأمان والمراقبة والنسخ والتعافي والتوافق وتوقيع الإصدارات قبل الإعلان عن الجاهزية. **اختبار القبول:** تقرير تسليم يذكر المتطلبات المعلنة والدليل والنسخة والقيود وأسباب رفض الإطلاق إن وجدت. **الحدود والمخاطر:** لا يمكن جعل نظام مفتوح الأطراف آمنًا بنسبة مطلقة.
- **CG-933** **[بحث/متطلب مرشح] — No-Deceptive-Control UI:** أي زر غير مدعوم يعرض Not Supported أو Needs Integration بدل إيهام المستخدم بالتنفيذ. **اختبار القبول:** واجهات الجوال والكمبيوتر تعكس الحالة الحقيقية ولا تغيرها دون صلاحية. **الحدود والمخاطر:** الدقة مشروطة بتحديث حالة التكامل.
- **CG-934** **[بحث/متطلب مرشح] — Safe Default and Staged Internal QA:** الوظائف الحساسة تبدأ Read Only؛ تؤهّل داخل المختبر وعلى أجهزة معتمدة قبل طرحها ضمن إصدار متكامل. **اختبار القبول:** عرض تقرير اختبارات وظيفية وتكاملية وأمنية لكل ميزة معلنة. **الحدود والمخاطر:** الاختبار المسبق إلزامي حتى لو لم ير المستخدم النسخ التجريبية.
- **CG-935** **[بحث/متطلب مرشح] — Independent Post-Launch Health Watchdog:** مراقبة مستقلة لصحة CyberGuard نفسه وأحداث فقد الحساسات وتوقف قاعدة البيانات وسجل التدقيق. **اختبار القبول:** اختبار تعطل محرك أمان يطلق تنبيهًا عبر قناة مستقلة ويمنع إظهار الحالة آمنة. **الحدود والمخاطر:** المراقب المستقل يحتاج بنية أخرى ولا يوفر توافرًا مطلقًا.
- **CG-936** **[بحث/متطلب مرشح] — Operations SLO and Recovery Contract:** توثيق وقت الاستعادة المقصود وتوفر المسارات الحرجة (كشف، بحث، تدقيق، استجابة) في حالات انقطاع مكونات فرعية. **اختبار القبول:** تعطل AI لا يعطل تخزين إنذار حرج، ويظهر مستوى التدهور. **الحدود والمخاطر:** الاعتمادية تتطلب مراقبة مستمرة بعد الإطلاق.

### خيارات الدمج ذات الأولوية — أرشيف v1.7 (تم تجاوزه بقرار النطاق في v1.8)

> **تنبيه:** هذه مقارنة تاريخية محفوظة للأثر البحثي فقط؛ لا تعني إدخال NCC أو Digital Twin أو ITSM داخل CyberGuard. القرار الحالي في قسم «أ-1» هو المرجع الملزم.

| الخيار | القيمة | الملاحظة |
|---|---|---|
| SOC + NOC | ربط التهديد بالعطل والبنية التحتية | أفضل خيار أساس للمشروع |
| SOC + Digital Twin | رؤية الأجهزة والتوصيلات ومحاكاة أثر التغيير | لا تغني المحاكاة عن اختبار التكوين فعليًا |
| SOC + AIOps | تجميع التنبيهات وتفسير أسباب الأعطال المحتملة | AI لا ينفذ أوامر دون بوابة موافقة |
| SOC + ITSM | ربط الحوادث والأجهزة والتذاكر والصيانة | يحتاج مالكي أصول وعمليات معتمدة |
| SOC + Cyber Resilience | التعافي والنسخ والاعتمادات الحرجة | نجاح النسخ لا يثبت سلامة الاستعادة |
| SOC + DevSecOps | حماية التطبيقات والتحديثات قبل النشر | وحدة متخصصة ليست ضرورية لكل منشأة |

### شروط الجاهزية قبل الإصدار الأول

1. تعيين **Scope مصرح** ومصفوفة أنظمة/إصدارات/معدات مدعومة؛ غير المدعوم يظهر بصراحة.
2. لكل ميزة معلنة: اختبار إيجابي وسلبي وأخطاء صلاحيات وحالات انقطاع وRollback إن كانت تغير شيئًا.
3. يجب نجاح **كل اختبارات القبول المتفق عليها** مع عدم وجود أعطال حرجة معروفة؛ لا نعني ضمان كشف 100% من التهديدات.
4. مراجعات أمنية مستقلة: نمذجة تهديدات، اختبار اختراق دفاعي مصرح، عزل بيانات، مراجعة أسرار وحقوق إدارة.
5. اختبار أداء واستهلاك وتخزين مع نطاقات 100/1000/20000 أصل، وتحديد الحد الرسمي للنسخة.
6. التحقق من سجلات الأدلة، موافقات التنفيذ، فشل التنفيذ، التعافي، والكفاءة التشغيلية.
7. مستند قبول نهائي يوضح جاهز/غير مدعوم/يحتاج تهيئة، ولا تُقدَّم الوظائف المؤجلة للمستخدم على أنها شغالة.

### مصادر جديدة من GitHub وNIST (راجعناها في هذه الجولة)

- [Nautobot — Network Source of Truth & Automation](https://github.com/nautobot/nautobot) — أمثلة نمذجة روابط وأصول وجداول التغيير، لا محرك رصد كامل.
- [NetBox — Intended Network State](https://github.com/netbox-community/netbox) — مرجع بنية الشبكة والحالة المعتمدة، ليس أداة استكشاف مباشر.
- [Zabbix — Network/Server Monitoring](https://github.com/zabbix/zabbix) — عمليات ومؤشرات وRCA، يخضع لترخيص AGPL.
- [GLPI — IT Asset & Service Desk](https://github.com/glpi-project/glpi) — إدارة الأصول والتذاكر، يخضع لترخيص GPL.
- [StackStorm — Event-driven Automation](https://github.com/StackStorm/st2) — workflows وإجراءات؛ تحتاج مراجعة سماح التنفيذ.
- [OpenTelemetry Collector](https://github.com/open-telemetry/opentelemetry-collector) — تجميع بيانات مراقبة موحد.
- [Wazuh — Security XDR/SIEM](https://github.com/wazuh/wazuh) — محرك أمن مرشح، يحتاج اختبارات تكامل.
- [OpenCost — Cloud and Kubernetes Costs](https://github.com/opencost/opencost) — تحليل تكلفة وحدة السحابة إذا اخترنا إضافة FinOps لاحقًا.
- [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) — إطار لتطوير برمجيات آمنة.
- [NIST DevSecOps Release Guidance](https://pages.nist.gov/nccoe-devsecops/notational-reference-model.html) — تحقق وتوثيق وتراجع قبل النشر.

**نقطة الاستكمال التالية بعد تحديث v1.8: CG-997.**

## ز. إضافات الجولة الثامنة عشرة (v1.8) — نطاق معتمد وثلاث وحدات إضافية

### 18 — نطاق التكامل والحوكمة

- **CG-937** **[بحث/متطلب مرشح] — NCC Exclusive Control Plane:** فصل أوامر إدارة أجهزة الشبكة وتكوينها عن CyberGuard؛ لوحة الحماية تقرأ وتبلّغ فقط، وأي تغيير تنفيذي بالشبكة يتجه إلى NCC. **اختبار القبول:** لا يُرسل CyberGuard أمر VLAN أو Switch-Port عبر قناة إدارة مستقلة.
- **CG-938** **[بحث/متطلب مرشح] — NCC Security Handoff Contract:** واجهة طلبات أمنية موثقة: asset_id، الإجراء، النطاق، السبب، صلاحية الموافقة، TTL، وrollback_ref إلى NCC. **اختبار القبول:** طلب معلّق بلا موافقة لا يغيّر أي منفذ.
- **CG-939** **[بحث/متطلب مرشح] — Separate IT Twin Boundary:** إزالة محاكاة Digital Twin البصرية من النطاق مع الحفاظ على سياق التبعيات الأمنية الخفيف. **اختبار القبول:** لا تنشأ بيئة محاكاة كاملة داخل CyberGuard.
- **CG-940** **[بحث/متطلب مرشح] — Tickets Scope Exclusion:** فصل البلاغات الفنية عن سجلات الحوادث الأمنية؛ رابط إلى Tickets لاحقًا فقط. **اختبار القبول:** حادث أمني لا ينشئ تذكرة صيانة تلقائيًا داخل CyberGuard.
- **CG-941** **[بحث/متطلب مرشح] — Four-Pillar Product Definition:** تحديد الوحدات المعتمدة: Security Core، AIOps/SOAR، DevSecOps، Cyber Resilience. **اختبار القبول:** كل شاشة وAPI مصنفة داخل عمود واحد أو تكامل عابر.
- **CG-942** **[بحث/متطلب مرشح] — Integration Ownership Map:** تعيين مالك كل إجراء ومخزن بيانات: الحماية للمخاطر، NCC للشبكات، أدوات النسخ للاستعادة. **اختبار القبول:** كل إجراء إداري له مكوّن واحد مسؤول ولا يحدث تضارب.
- **CG-943** **[بحث/متطلب مرشح] — Vendor Capability Ledger:** توثيق نسخ الأدوات والتراخيص والتصاريح والأنظمة المدعومة (Windows/Linux/Cloud/Containers). **اختبار القبول:** إجراء غير مدعوم يُرفض مع بيان سبب فني.
- **CG-944** **[بحث/متطلب مرشح] — Action Permission Manifest:** تحديد scopes من نوع read/inspect/approve/execute/restore لكل موصل وخدمة. **اختبار القبول:** المستخدم ذو صلاحية القراءة لا يرسل أوامر تشغيل.
- **CG-945** **[بحث/متطلب مرشح] — Design-Only Research Status:** فصل الأفكار البحثية عن القدرات المختبرة والمنفذة؛ لا يُعرض تصميم كنظام جاهز. **اختبار القبول:** حالات متطلبات واضحة: بحث/معتمد/منقول/مؤجل/مرفوض.
- **CG-946** **[بحث/متطلب مرشح] — Unified Evidence and Audit Interface:** مخطط أحداث للحوادث الأمنية وللعمليات الثلاث الجديدة دون جرد تشغيلي مكرر. **اختبار القبول:** المستخدم يستطيع التحقق من مصدر كل دليل وآخر تحديث له.

### 19 — الأتمتة الذكية AIOps/SOAR

- **CG-947** **[بحث/متطلب مرشح] — Evidence-Based Root Cause Hypotheses:** تقديم عدة احتمالات لسبب الحادث مع أدلة مؤيدة ومعارضة، ولا يدعي السبب القطعي من تزامن حدثين. **اختبار القبول:** يظهر Unknown عند نقص البيانات.
- **CG-948** **[بحث/متطلب مرشح] — Causal Change Correlation:** ربط الأعطال الأمنية بالتحديثات وإيقاف الخدمات وتغير الصلاحيات والتوقيت، دون تنفيذ معالجة قبل التحقق. **اختبار القبول:** يمكن تتبع حدث لطلب تغيير معروف.
- **CG-949** **[بحث/متطلب مرشح] — Baseline Comparison for Anomalies:** مقارنة نشاط الخدمة بعد تحديث مع نافذة مرجعية معتمدة مع استثناء الصيانة المخطط لها. **اختبار القبول:** انذار الاختبار يظهر الاستثناء والفرق العددي.
- **CG-950** **[بحث/متطلب مرشح] — Alert Clustering and Deduplication:** تجميع آلاف التنبيهات المتصلة في قضية واحدة مع حفظ كل حدث أصلي. **اختبار القبول:** لا تُفقد أحداث أصلية عند التجميع.
- **CG-951** **[بحث/متطلب مرشح] — Read-Only Investigation Mode:** تحليل مشكلات وتحقيقات دون أي أوامر تغير الحالة الافتراضية. **اختبار القبول:** يفشل طلب التنفيذ عند اعتماد حساب قراءة فقط.
- **CG-952** **[بحث/متطلب مرشح] — Policy-Based Action Catalog:** كتالوج إجراءات مُعرَّف بمخططات مُوقعة، معاملات محددة، أجهزة مسموحة، زمن تنفيذ ومخاطر؛ لا أوامر Shell من AI. **اختبار القبول:** فشل الطلب ذي المعلمات غير المعروفة آمنًا.
- **CG-953** **[بحث/متطلب مرشح] — Just-in-Time Execution Tokens:** تفويض التنفيذ قصير العمر لجهاز وإجراء واحد بعد تحقق الهوية، بدل كلمة مرور مشتركة دائمة. **اختبار القبول:** تستخدم صلاحية منتهية فلا تُقبل.
- **CG-954** **[بحث/متطلب مرشح] — Two-Person High Impact Approval:** موافقة منفصلة للإيقاف أو الاستعادة أو الحذف أو الحظر الذي يؤثر على الأصول الحرجة. **اختبار القبول:** لا يجتمع المنفذ والموافق في جلسة واحدة للإجراء الحساس.
- **CG-955** **[بحث/متطلب مرشح] — Impact and Recovery Preflight:** فحص اعتماد الخدمات والتوافر وقنوات الإدارة ونقاط الاستعادة قبل أي إجراء عالي التأثير. **اختبار القبول:** عند غياب قناة تعافٍ يُعرض حظر التنفيذ.
- **CG-956** **[بحث/متطلب مرشح] — Event-to-Workflow Engine:** خط Trigger -> Enrichment -> Policy -> Approval -> Execute -> Verify -> Audit؛ دراسة StackStorm. **اختبار القبول:** مسار اختبار يسجل كل انتقال وحالة.
- **CG-957** **[بحث/متطلب مرشح] — Idempotent Action Execution:** مفاتيح Idempotency ومحاولة إعادة آمنة تمنع تنفيذ نفس القرار مرتين عند انقطاع الاتصال. **اختبار القبول:** إرسال الحدث مرتين لا ينفذ أمرين.
- **CG-958** **[بحث/متطلب مرشح] — Timeouts and Circuit Breakers:** مهلات وتنبيه وتعطيل مؤقت للتكامل الفاشل، ومنع حلقات إعادة التشغيل. **اختبار القبول:** فشل موصل لا يستهلك موارد النظام بلا حد.
- **CG-959** **[بحث/متطلب مرشح] — Post-Action Verification:** التحقق من نتيجة العلاج من مصدر مستقل أو نفس المورد واعتبار العملية غير محسومة عند غياب التأكيد. **اختبار القبول:** لا تظهر علامة نجاح إذا لم تتغير الحالة في الواقع.
- **CG-960** **[بحث/متطلب مرشح] — Compensation and Rollback Records:** إجراءات تعويض وعكس معتمدة مسبقًا لكل Action، ومعالجة الحالات التي يتعذر فيها التراجع. **اختبار القبول:** اختبار فشل في منتصف سير العمل يوضح حالة النظام.
- **CG-961** **[بحث/متطلب مرشح] — Safe Alert Flood Control:** تجميع وتقييد التنبيهات مع حماية الحوادث الحرجة من الإسقاط. **اختبار القبول:** ضغط 10 آلاف تنبيه يظل يحتفظ بالأدلة الحرجة.
- **CG-962** **[بحث/متطلب مرشح] — Dry Run Policy Evaluation:** محاكاة قرار السياسة والأوامر التي *كان* سيطلبها، من دون الاتصال بقنوات تنفيذ. **اختبار القبول:** تقرير معاينة يختلف صراحة عن تقرير التنفيذ.
- **CG-963** **[بحث/متطلب مرشح] — AI Prompt Injection Boundary:** اعتبار سجلات الشبكة ونصوص التذاكر ونتائج البحث بيانات غير موثوقة، ومنعها من تعديل قواعد الموافقة. **اختبار القبول:** تعليمة خبيثة داخل Log لا تطلق Action.
- **CG-964** **[بحث/متطلب مرشح] — SLO Aware Incident Prioritization:** دمج أثر الحادث على وظائف الأمن وRTO/RPO الخاصة بالخدمات المحمية، دون التحول إلى NOC عام. **اختبار القبول:** حماية مصدر التنبيهات تسبق تجميل التقرير.
- **CG-965** **[بحث/متطلب مرشح] — Runbook Registry and Versioning:** كتالوج Runbooks مُوقّع ومدقق، مع مالك وتاريخ وتراجع واختبارات قبل الاعتماد. **اختبار القبول:** لا يعمل Runbook معدل دون موافقة واعتماد نسخة.
- **CG-966** **[بحث/متطلب مرشح] — AIOps Evaluation Benchmark:** مجموعة حالات اختبار لقياس دقة السبب والتوصية وصحة تنفيذ السياسة وتكلفة AI. **اختبار القبول:** كل إصدار يحافظ على معايير جودة محددة دون تراجع كبير.

### 20 — حماية البرمجيات DevSecOps

- **CG-967** **[بحث/متطلب مرشح] — SAST Source Scan:** دراسة Semgrep لتحليل أخطاء الكود والثغرات أثناء PR دون الادعاء بكشف كامل. **اختبار القبول:** نتيجة قابلة للربط بالملف والسطر والإصدار.
- **CG-968** **[بحث/متطلب مرشح] — Secrets and Token Detection:** فحص Git والمستودعات بGitleaks قبل الدمج وفتح مهمة لتدوير السر دون كشف قيمته. **اختبار القبول:** التقرير يخفي السر نفسه ويحدد مكانه.
- **CG-969** **[بحث/متطلب مرشح] — Dependency Intelligence:** استخدام OSV-Scanner لملفات Lock وSBOM وتحديد التبعيات المصابة. **اختبار القبول:** لا يُعتمد إصدار ذو ثغرة حرجة معلومة دون استثناء موثق.
- **CG-970** **[بحث/متطلب مرشح] — SBOM Production:** إنشاء CycloneDX/SPDX بواسطة Syft لكل إصدار أو حاوية وتوقيته مع artifact. **اختبار القبول:** يمكن إعادة الوصول إلى SBOM المنتج نفسه.
- **CG-971** **[بحث/متطلب مرشح] — Container Vulnerability Risk:** دراسة Grype/Trivy مع EPSS وKEV وVEX لتجنب تضخيم الثغرات غير القابلة للاستغلال. **اختبار القبول:** نتائج مرتبطة بـdigest وليس latest فقط.
- **CG-972** **[بحث/متطلب مرشح] — Infrastructure as Code Policy:** استخدام Checkov أو OPA لفحص Terraform/Kubernetes وGitHub Actions قبل التنفيذ. **اختبار القبول:** تكوين عام مفتوح لخدمة حساسة يوقف الدمج.
- **CG-973** **[بحث/متطلب مرشح] — DAST Staging Safety Gate:** تجارب ZAP على بيئة اختبار مع تفويض؛ النشاط المؤثر لا يعمل على الإنتاج تلقائيًا. **اختبار القبول:** يفشل اختبار Active Scan خارج allowlist.
- **CG-974** **[بحث/متطلب مرشح] — Image and Artifact Provenance:** التحقق من توقيع صور الحاويات والإصدارات بـCosign/Sigstore. **اختبار القبول:** نسخة غير موقعة أو بتوقيع غير موثوق تُرفض.
- **CG-975** **[بحث/متطلب مرشح] — Software Supply Chain Posture:** OpenSSF Scorecard لمراجعة مشاريع GitHub المستوردة؛ لا تعتمد الشعبية وحدها. **اختبار القبول:** مكوّن مهجور أو مرخّص بشكل غير ملائم يُحظر/يراجع.
- **CG-976** **[بحث/متطلب مرشح] — CI Release Security Gate:** شروط اختبار قبل النشر: فحص أمن، اختبار وظائف، تحليل أسرار، SBOM، توقيع، صلاحيات مفوضة. **اختبار القبول:** لا يُعطى Release حالة Ready عند فشل شرط إلزامي.
- **CG-977** **[بحث/متطلب مرشح] — DevSecOps Remediation Queue:** تجميع وإزالة تكرار نتائج الفحص وإسناد مسؤول إصلاح ضمن لوحة أمن البرمجيات، لا نظام تذاكر صيانة عام. **اختبار القبول:** ثغرة متكررة من أداتين تُحسب مرة مع مصدرين.
- **CG-978** **[بحث/متطلب مرشح] — Safe Dependency Update Proposal:** اقتراح PR تحديث تبعية مع ChangeLog واختبارات، وعدم تعديل production دون مراجعة مطور. **اختبار القبول:** فشل الاختبار يمنع النشر لا يكرر تحديثًا آليًا.
- **CG-979** **[بحث/متطلب مرشح] — Runtime Drift Versus Deployment:** مقارنة حالة الخدمة المنشورة والنسخة المعتمدة وكشف انحراف البرامج غير المصرح به. **اختبار القبول:** تغيير صورة حاوية خارج CI يظهر حادثًا.
- **CG-980** **[بحث/متطلب مرشح] — Policy Exception Expiry:** استثناءات موثقة لنتائج الفحص مع مالك ومدة انتهاء ومراجعة آلية. **اختبار القبول:** استثناء منتهي يعيد نتيجة الفحص للتقييم.
- **CG-981** **[بحث/متطلب مرشح] — Secure Update Channel:** توقيع تحديثات CyberGuard Agents والتحقق من سلسلة المصدر والتراجع عند الفشل. **اختبار القبول:** تحديث غير موقع لا يُثبت على أيجنت.
- **CG-982** **[بحث/متطلب مرشح] — App Security Coverage Matrix:** إظهار الفحص الذي تم/لم يتم لكل لغة ونوع مشروع ومسار نشر، وعدم تصوير النتائج الناقصة آمنة. **اختبار القبول:** مشروع بلا Lockfile يظهر تغطية ناقصة.

### 21 — الاستمرارية والتعافي Cyber Resilience

- **CG-983** **[بحث/متطلب مرشح] — Backup Asset Inventory:** جرد مهمات النسخ وأهدافها ومالكيها ومدة الاحتفاظ وحالة المصدر لكل Windows/AD/DB/VM/Cloud. **اختبار القبول:** الحساب يميّز أصلًا غير محمي عن أصل لم يفحص.
- **CG-984** **[بحث/متطلب مرشح] — Backup Job Telemetry and Alerts:** قراءة نجاح/فشل النسخ وآخر نجاح وحجم التغيير والتنبيه على توقف النسخ أو انخفاض حجمه بشكل شاذ. **اختبار القبول:** يظهر سبب فشل وظيفي بدل اعتبار آخر جدولة نجاحًا.
- **CG-985** **[بحث/متطلب مرشح] — Immutable and Offline Coverage:** قياس نسخة محمية من الحذف/تعديل المدة أو منفصلة؛ التحقق من WORM/locked vault عند توفرها. **اختبار القبول:** المستودع القابل للحذف لا يُعرض غير قابل للتغيير.
- **CG-986** **[بحث/متطلب مرشح] — Backup Admin Separation:** فصل مالك البيانات عن مخوّل حذف نسخها، وموافقة إضافية على الإجراء التدميري. **اختبار القبول:** اختبار حساب مخترق بصلاحية backup-only لا يستطيع محو الاسترداد.
- **CG-987** **[بحث/متطلب مرشح] — Clean Room Recovery Workflow:** بيئة استعادة معزولة وفحص صحة الملفات والبرامج وIndicators قبل ربطها بالشبكة الأصلية. **اختبار القبول:** حالة اختبار توفر دليل Restore لا مجرد Snapshot.
- **CG-988** **[بحث/متطلب مرشح] — Cloud Automated Restore Testing:** دراسة AWS Backup Restore Testing وAzure Backup MUA/immutability لتقييم استعادة دورية. **اختبار القبول:** تقرير يتضمن نجاح الاستعادة ومدتها ومعايير التطبيق.
- **CG-989** **[بحث/متطلب مرشح] — Windows Backup Readiness:** قراءة نسخ Windows المتاحة عبر wbadmin get versions؛ لمراقبة System State ونسخ سيرفرات AD عند الدعم. **اختبار القبول:** يظهر آخر استرداد ممكن وليس آخر مهمة فقط.
- **CG-990** **[بحث/متطلب مرشح] — AD Forest Recovery Readiness:** تدقيق وجود نسخ سليمة لـDomain Controllers وDNS/GPO/AD CS مع خطة استعادة آمنة وموافقات. **اختبار القبول:** تمرين معزول لإعادة Domain دون المساس بالإنتاج.
- **CG-991** **[بحث/متطلب مرشح] — Database PITR Coverage:** التحقق من WAL وPoint-in-Time Recovery في PostgreSQL أو ما يماثله حسب قاعدة البيانات، وترابط نسخ البيانات والسجلات. **اختبار القبول:** اختبار استعادة لنقطة زمنية محددة.
- **CG-992** **[بحث/متطلب مرشح] — Application Consistent Backups:** التمييز بين Disk Snapshot والنسخة المتسقة تطبيقياً (قواعد بيانات/VM/AD) وتوثيق حالة Quiesce. **اختبار القبول:** لا تُعلن النسخة متسقة دون دليل من التطبيق.
- **CG-993** **[بحث/متطلب مرشح] — RPO/RTO Verified Metrics:** حساب نقطة الاستعادة الفعلية والزمن المُقاس لعودة الخدمة من الاختبار وليس من تقدير يدوي. **اختبار القبول:** عرض فرق الهدف عن المنجز بالأرقام.
- **CG-994** **[بحث/متطلب مرشح] — Ransomware Recovery Sequence:** سيناريو فصل مصادر الهجوم، حماية الأدلة، اختيار نسخة نظيفة، إعادة هويات النظام، ثم العودة التدريجية. **اختبار القبول:** لا يسمح بالاستعادة إلى شبكة نشطة قبل إتمام خطوات السلامة.
- **CG-995** **[بحث/متطلب مرشح] — Backup Vault Policy Monitor:** رصد أي محاولة تقليل الاحتفاظ أو تعطيل immutability أو حذف السجل مع موافقة متعددة حسب الإمكانية. **اختبار القبول:** تغيير السياسة يولد إنذارًا مستقلاً.
- **CG-996** **[بحث/متطلب مرشح] — Restore Evidence Report:** حزمة تقارير موقعة ببصمات: نسخة/موقع/تاريخ/صحة البيانات/وقت الاختبار/القيود. **اختبار القبول:** يمكن للمراجع التحقق من مصدر التقرير ونتيجة الاختبار.

## ح. أنظمة التنفيذ المقترحة — فصل المراقبة عن التشغيل

| الطبقة | مصادر / موصلات أو خدمات | مثال مخرجات | ضوابط |
|---|---|---|---|
| Intake | Windows Event Logs / Sysmon / Linux journald / Wazuh / OpenTelemetry / Webhooks | حدث موقّع + asset_id + source_id + timestamp | قراءة فقط، استبعاد أسرار، مراقبة فقد البيانات |
| AIOps Analysis | Coroot / HolmesGPT / قواعد ربط / RunWhen وRunbooks | فرضيات متعددة، درجة ثقة، بيانات ناقصة | AI لا يرسل تنفيذًا مباشرًا |
| Workflow | StackStorm / AWX / Ansible Runner | Trigger / Policy / Approval / Job / Verify / Evidence | RBAC/MFA، Allowlist، مهلة، Idempotency |
| Application Scans | Semgrep / Gitleaks / OSV / Syft / Grype / Trivy / Checkov | SAST/SCA/Secrets/IaC/SBOM | على كود مصرح، لا نشر تلقائي ولا رفع أسرار |
| Software Release | Cosign / Sigstore / GitHub CI / TUF | توقيع/مصدر Artifact/قبول إصدار | رفض المصدر غير موثوق، صلاحيات CI محدودة |
| Backups | Windows Server Backup / restic / Velero / AWS Backup / Azure Backup | Recovery points / restore tests / RTO / RPO | أدوار منفصلة، MFA، نسخ غير قابلة للعبث |
| NCC integration | Security Incident -> NCC controlled API -> Authorized network action | طلب حظر منفذ أو سياسة NAC | NCC وحده يملك تنفيذ أوامر الشبكة العامة |

### أوامر مرجعية للبحث والتدقيق (لا نُنفّذ أيًا منها الآن)

> **حدود الاستخدام:** الأمثلة التالية قراءة/فحص فقط على بيئات ومشاريع يملك المستخدم صلاحية فحصها. ينبغي اختبار الأوامر وإصداراتها والتأثير على I/O قبل تشغيلها لاحقًا؛ بعض الأوامر تحتاج صلاحيات إضافية أو قد تقرأ بيانات حساسة. لا توجد هنا أوامر تعديل Firewall أو محو بيانات أو تعطيل خدمات.

| النوع | مثال أمر للمختبر المستقبلي | الدليل الناتج |
|---|---|---|
| Windows PowerShell | `Get-Service | Where-Object Status -eq 'Stopped'` | خدمات متوقفة (ليس دليلًا على الاختراق بحد ذاته) |
| Windows logs | `Get-WinEvent -ListLog *Security*` | اكتشاف قنوات سجلات متاحة؛ الوصول حسب الصلاحيات |
| Windows backup | `wbadmin get versions` | نسخ Windows المتاحة؛ يتطلب حسابًا مخولًا ونافذة CMD مرتفعة |
| Linux services | `systemctl --failed` | وحدات Systemd الفاشلة |
| Linux logs | `journalctl -p err -n 50` | آخر أخطاء النظام |
| Restic | `restic snapshots` | نقاط نسخ موجودة إذا توفرت الأسرار والمستودع |
| Restic | `restic check --read-data` | تحقق أعمق من بيانات المستودع؛ كثيف القراءة؛ يختلف حسب النسخة |
| Source code | `semgrep scan --config auto .` | نتائج SAST محلية على المشروع وفق إعدادات النسخة |
| Git secrets | `gitleaks git .` | مؤشرات أسرار ضمن Git؛ يجب إخفاؤها من التقارير |
| Dependencies | `osv-scanner scan source -r .` | ثغرات معلومة في التبعيات |
| SBOM | `syft . -o cyclonedx-json` | قائمة مكونات برنامج ومكتباته |
| IaC | `checkov -d .` | مراجعة قوالب البنية السحابية |

**أوامر تنفيذ عالية الأثر غير مدرجة:** تشغيل `wbadmin start recovery`، عزل مضيف، تغيير GPO أو إغلاق منفذ سويتش، تعديل سياسات Firewall، أو نشر مخرجات CI. هذه تتطلب موافقات منفصلة وخطة تراجع عند مرحلة التنفيذ المستقبلية.

## ط. ثلاث حالات عمل تفصيلية للدراسة

### CASE-30: خدمة مراقبة أمنية توقفت بعد تحديث
1. تستقبل المنصة حدث توقف خدمة من Windows Agent أو مراقب مستقل.
2. تربط الحدث بإصدار التحديث وإشارات الموارد والسجلات وتُنشئ فرضيتين بديلتين على الأقل.
3. تتحقق من احتمال محاولة تعطيل حماية متعمدة، وتُظهر الأدلة الناقصة.
4. تقترح Runbook مراجعة الخدمة، ولا تنفذ Restart دون Policy/Approval مناسبين.
5. تُقاس نتيجة العملية؛ إن استمر العطل لا تُعلن المعالجة ناجحة.

### CASE-31: تحديث تطبيق يضيف ثغرة خطيرة
1. Pipeline يفحص PR باستخدام Semgrep وGitleaks وOSV وCheckov بحسب الملفات.
2. يصدر Syft ملف SBOM؛ يربطه Grype أو Trivy بالتبعيات والثغرات والأصل المتأثر.
3. تُراجع النتيجة حسب ثبوت الاستغلال والتأثير والتوافق والاستثناءات.
4. تمنع بوابة الإصدار النشر عند فشل شرط أساسي، وتوثق توقيع الإصدار عن طريق Cosign.
5. بعد النشر يراقب AIOps التراجع في حالة التطبيق، ويقترح rollback معتمداً إذا لزم.

### CASE-32: فدية استهدفت النسخ الاحتياطية
1. يُعزل نطاق الحادث بعد تقييم أثر القرار؛ يحتفظ النظام بالأدلة ويمنع نشر الحادث عبر قنوات الاستعادة.
2. يفحص CyberGuard سجلات محاولات حذف Recovery Points أو تخفيض الاحتفاظ أو تغيير سياسات المخزن.
3. يحدد آخر نسخة *مرشحة* للنظافة ولا يدّعي نظافتها بلا فحص.
4. تُستعاد البيانات إلى بيئة معزولة ثم تختبر التطبيقات وصلاحياتها من جديد.
5. يقيّم RPO/RTO الفعلي مقابل الأهداف، ثم يُصدر تقريرًا مع أدلة وتوقيعات.

## ي. مصادر موثوقة جديدة — مراجع البحث الحالية

**AIOps / SOAR**
- [StackStorm](https://github.com/StackStorm/st2) — قواعد أحداث، Actions، Workflows وتدقيق؛ دراسة محرك تنفيذ خاضع للسياسة.
- [Ansible Runner](https://github.com/ansible/ansible-runner) — تشغيل وظائف موثقة وإرجاع Events/Artifacts.
- [AWX Workflows](https://github.com/ansible/awx/blob/devel/docs/workflow.md) — موافقات ووظائف متعددة المراحل.
- [HolmesGPT](https://github.com/HolmesGPT/holmesgpt) — تحليل السبب الجذري متعدد المصادر؛ بعض أوضاع Operator تجريبية.
- [Coroot](https://github.com/coroot/coroot) — مراقبة Metrics/Logs/Traces وتحليل خدمة حسب مصادر البيانات.

**DevSecOps**
- [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) — الحوكمة والتطوير والتحقق من الإصدار.
- [Semgrep](https://github.com/semgrep/semgrep) — Static Analysis مع حدود نسخة المجتمع.
- [Gitleaks](https://github.com/gitleaks/gitleaks) — Secrets Scanning.
- [OSV-Scanner](https://github.com/google/osv-scanner) — ثغرات Dependencies وSBOM.
- [Syft](https://github.com/anchore/syft) + [Grype](https://github.com/anchore/grype) — SBOM وفحص ثغرات.
- [Trivy](https://github.com/aquasecurity/trivy) + [Checkov](https://github.com/bridgecrewio/checkov) — حاويات وأسرار وإعدادات IaC.
- [Sigstore Cosign](https://github.com/sigstore/cosign) — توقيع الإصدارات والتحقق.
- [OpenSSF Scorecard](https://github.com/ossf/scorecard) — تقييم ممارسات سلامة المشاريع المفتوحة.

**Resilience & Recovery**
- [restic](https://github.com/restic/restic) — نسخ مشفرة وفحص سلامة مستودع؛ ليس بديلًا عن الاستعادة التجريبية.
- [Velero](https://github.com/vmware-tanzu/velero) — يرجى استخدام المستودع الحالي [velero-io/velero](https://github.com/velero-io/velero) للنسخ والاستعادة في Kubernetes.
- [Gardener etcd-backup-restore](https://github.com/gardener/etcd-backup-restore) — دعم نسخ واستعادة etcd.
- [AWS Backup Restore Testing](https://docs.aws.amazon.com/aws-backup/latest/devguide/restore-testing.html) — اختبارات استعادة مجدولة.
- [Azure Backup Security](https://learn.microsoft.com/en-us/azure/backup/security-overview) — MUA، Soft Delete، Immutability.
- [Microsoft wbadmin get versions](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin-get-versions) — جرد نقاط الاستعادة.
- [CISA Ransomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide) — فصل النسخ والاختبار والتعافي.

**مبدأ القرار النهائي:** كود المشروع نفسه لم يُنشأ؛ جميع الاقتراحات هنا للدراسة وليست وظائف مُختبرة أو جاهزة، ويُختبر لاحقًا دعمها والتكامل وترخيصها وموارد التشغيل قبل اعتماد الإصدار.

**نقطة الاستكمال التالية: CG-997.**


---

# ملحق v1.9 — تنظيف نطاق المشروع وسياسة السجلات والإثبات

**حالة هذا الملحق:** متطلبات بحثية وليست خصائص منفذة. تم تدقيق أرقام معرفات السجل السابق: 996 معرفًا فريدًا دون فجوات. لا يعني ذلك أن كل البنود خالية من التكرار الدلالي أو صالحة للتنفيذ؛ يلزم تقييمها وتصنيفها قبل التطوير.

## القرار: لا تجمع جميع الـ Logs أو PCAP بشكل دائم

- **الافتراضي:** اجمع الأحداث الأمنية المهمة فقط من كل مصدر وفق ملف سياسة قابل للتعديل؛ لا تنسخ كل سجلات كل جهاز إلى قاعدة البحث بصورة عمياء.
- **المصادر عالية القيمة:** Domain Controllers وEntra/IAM، VPN وFirewalls وNAC، Agents على الأجهزة المُدارة، تغييرات Cloud control-plane، خوادم التطبيقات الحساسة، أنظمة النسخ الاحتياطي، Git/CI/CD، ومنصة CyberGuard نفسها.
- **جمع موسع عند الحوادث:** احفظ أدلة أوسع مؤقتًا عندما توجد موافقة وصلاحية وسبب واضح ونطاق وزمن وتخزين محددان. التقاط PCAP الكامل منفصل عن Logs وقد يحتوي بيانات شخصية/حساسة؛ لا يُفعّل تلقائيًا لكل شبكة.
- **الأولوية للنوعية:** يجب أن تبقى أحداث الدخول الحساسة وتغييرات الصلاحيات والعمليات الحرجة وتوقف السجلات وتغييرات قواعد الحماية قابلة للبحث والتجميع؛ تجنب إسقاط أحداث تدعم كشفًا معتمدًا بسبب ضغط التخزين.
- **النظافة:** تطبيع الحقول، توحيد UTC، إزالة التكرار مع الاحتفاظ بدليل المصدر، تقليل البيانات الحساسة، والتحقق من اكتمال تدفق السجلات.

## متطلبات إضافية مرقمة (CG-997 إلى CG-1010)

- **CG-997** مطلوب — **Log Source Coverage Matrix:** مصفوفة لكل أصل/نوع نظام تربط مصادر الأحداث اللازمة بقواعد الكشف، وحالة التفعيل، وصلاحية الجمع، ونسبة التغطية، والفجوات المعروفة.
- **CG-998** مطلوب — **Security-First Log Collection Profiles:** مستويات `Baseline / Critical Asset / Incident` قابلة للمراجعة والتعديل؛ جمع حد أدنى ذي قيمة عالية افتراضيًا دون التقاط شامل لكل الأحداث.
- **CG-999** مطلوب — **Detection-Aware Filtering:** منع إسقاط حدث تستخدمه قاعدة كشف معتمدة بصمت؛ اختبارات توضح أثر كل فلتر على الاكتشاف والمراجعة الجنائية.
- **CG-1000** مطلوب — **Sensitive Data Minimization:** تنقيح كلمات المرور والتوكنات والمعلومات الشخصية قبل التخزين أو التحليل السحابي؛ مع حفظ الأدلة الأصلية المرخصة في مخزن محمي منفصل عند الحاجة القانونية.
- **CG-1001** مطلوب — **Retention by Risk and Law:** سياسات احتفاظ منفصلة Hot/Archive حسب حساسية المصدر ومتطلبات المؤسسة والأنظمة المطبقة والتكلفة، من دون تثبيت مدة عامة لكل البيانات.
- **CG-1002** مطلوب — **Clock Integrity and Event Correlation:** استخدام وقت UTC وNTP موثوق، وتوثيق انحراف الساعة، وإضافة معرفات جلسات/أجهزة/طلبات لربط الحوادث بين Windows وAD والشبكة والسحابة.
- **CG-1003** مطلوب — **Telemetry Pipeline Health:** كشف توقف المصدر أو الـAgent أو ازدحام الطوابير وفقد الأحداث وتأخر النقل، مع إعادة إرسال مضبوطة وإظهار حالة التغطية بوضوح.
- **CG-1004** مطلوب — **Scoped Forensic Escalation:** جمع موسع مؤقت داخل أصول مصرّح بها وبموافقة صريحة، وحد حجم ومدة وتاريخ حذف وخط توثيق الأدلة. لا جمع شامل غير محدود.
- **CG-1005** مطلوب — **Tamper-Resistant Audit Trail:** صلاحيات منفصلة لقراءة السجلات وتعديل السياسات وإجراءات الاستجابة، مع تخزين أدلة التدقيق بصورة مقاومة للتعديل وبصمات سلامة وتحقيق دوري.
- **CG-1006** مطلوب — **Separate Packet Capture Policy:** لا تعامل PCAP كمرادف للسجل؛ يدار ضمن صلاحيات وحساسات ومدة قصيرة وموقع تخزين منفصل، وقد يتطلب SPAN/TAP أو صلاحيات خاصة.
- **CG-1007** مطلوب — **Normalized Event Catalog:** قاموس أنواع أحداث موحد وتطبيع بيانات Vendor مختلف إلى مخطط OCSF/Schema مماثل مع الاحتفاظ بالحدث الخام المحمي ورابط المصدر.
- **CG-1008** مطلوب — **Data Quality Acceptance Tests:** اختبارات عينات مصرح بها تتحقق أن حدثًا معروفًا من AD أو Firewall أو Endpoint يظهر مرة واحدة، وبالتوقيت والحقول الصحيحة، وأن التنبيه الملائم يعمل.
- **CG-1009** مطلوب — **Feature Duplication and Project Boundary Review:** مرجع واحد لكل وظيفة؛ الإدارة التشغيلية العامة للشبكات في NCC، التوأم في IT Twin، التذاكر في Tickets، وCyberGuard للأمن وSOAR/AIOps الأمني وDevSecOps والتعافي فقط. التاريخ محفوظ لكن البنود المنقولة لا تتحول إلى وظائف مكررة.
- **CG-1010** مطلوب — **Lean Security UI and Honest Status:** أقسام رئيسية أربعة مع وحدات فرعية واضحة، بدون أزرار شكلية أو تكرار؛ كل ميزة تعرض Supported/Requires Connector/Permission Missing/Not Verified، ولا تعرض نتيجة «آمن 100%».

## أولويات التنظيف قبل أي مرحلة تطوير

| المجال | نفعل | لا نفعل |
|---|---|---|
| Security Core | جمع أحداث عالية القيمة، كشف، ثغرات، هوية، تحقيق، استجابة معتمدة | لا نسخ كل سجلات المؤسسة دون سياسة |
| AIOps/SOAR | تحليل أسباب التهديدات وأعطال الحماية، تشغيل Playbooks محددة بعد الموافقة | لا إدارة شبكات عامة أو تنفيذ أوامر حرّة عبر AI |
| DevSecOps | فحص المستودعات والتبعيات والحاويات والتوقيع وRelease Gates | لا نسخ بيانات المستودعات الخاصة إلى سحابة تلقائيًا |
| Cyber Resilience | فحص النسخ والاستعادة والتعافي، وقياس RPO/RTO | لا تنفيذ استعادة مدمرة بلا خطة واختبار وإذن |
| NCC / Twin / Tickets | تكاملات اختيارية وأحداث وأذونات تفويض | لا إعادة بناء وظائف هذه المشاريع داخل CyberGuard |

## مراجعة اكتمال الدراسة

توصية المراجعة ليست جمع عدد أكبر من المزايا، بل لكل متطلب: 1) فائدة أمنية قابلة للقياس، 2) مصدر أحداث أو API متاح، 3) ترخيص وصلاحيات، 4) حدود الدعم، 5) أدلة اختبار وتراجع، 6) أثر تكلفة وخصوصية، 7) هل يكرر متطلبًا أو يقع خارج النطاق؟ ولا يُعتمد تنفيذ الوظيفة قبل توفر هذه الإجابات.

## مراجع مباشرة

1. ASD/ACSC + CISA + FBI + NSA وآخرون، Best practices for event logging and threat detection (2024): https://www.cyber.gov.au/publication/best-practices-for-event-logging-and-threat-detection
2. ASD/ACSC، Priority logs for SIEM ingestion (2025): https://www.cyber.gov.au/publication/priority-logs-for-siem-ingestion-practitioner-guidance
3. Microsoft، Audit Policy Recommendations: https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations
4. NIST SP 800-92، Guide to Computer Security Log Management: https://csrc.nist.gov/pubs/sp/800/92/final
5. OWASP، Logging and Monitoring: https://owasp.github.io/DevSecOpsGuideline/2-Process/2-7-Operate/2-7-2-Logging-and-Monitoring/
6. OpenTelemetry Collector Redaction Processor (مكوّن يحتاج تقييمًا للاستقرار): https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/processor/redactionprocessor/README.md


---

# إضافة v2.0 — دراسة أفكار Microsoft Security Copilot وGoogle Gemini ومزوّدي AI (2026-11-10)

**حالة الإضافة:** نتائج بحث ومقترحات تنفيذ مستقبلية فقط؛ لم يُربط Copilot أو Gemini فعليًا، ولم يُستشر أي نموذج خارجي بصورة مباشرة أو تُرسل له بيانات. لا يوجد فحص شبكة أو برمجة.

**قرار النطاق الساري:** CyberGuard = Security Core + AIOps/SOAR الأمني + DevSecOps + Cyber Resilience. إدارة السويتشات والشبكات في NCC، والتوأم الرقمي في IT Twin، وتذاكر الصيانة في مشروع مستقل. AI لا ينفّذ أوامر شبكة عامة بل يرفع طلبًا محميًا إلى النظام المخوّل.

## خلاصات موثقة من الشركات

- **Microsoft Security Copilot:** دعم التحقيقات وتوليد KQL وتحليل السكربتات وPromptbooks وعوامل متخصصة للفرز والكشف الديناميكي. بعض الخدمات Preview، والإجابات تحتاج تحققًا بشريًا. المصدر: https://learn.microsoft.com/en-us/copilot/security/rai-faqs-security-copilot-agents
- **Google Security Operations + Gemini:** بحث بلغة طبيعية، إنشاء قواعد YARA-L/Playbooks، دمج سياق الحوادث، وتحسين عمليات الكشف عن حملات جديدة. المصدر: https://cloud.google.com/security/products/security-operations
- **Google Emerging Threats Center:** التحقق من تأثر البيئة بحملة جديدة ووجود قواعد كشف لها. المصدر: https://cloud.google.com/blog/products/identity-security/introducing-the-emerging-threats-center-in-google-security-operations
- **Gemini Cloud Assist:** تحليل السجلات والمقاييس والتتبعات والإعدادات وفحص الفرضيات؛ بعض قدراته Private Preview. المصدر: https://cloud.google.com/products/gemini/cloud-assist
- **الأمن والخصوصية:** Security Copilot يلتزم بدور المستخدم وRBAC وخيارات مشاركة البيانات، في حين تختلف شروط Gemini Enterprise عن تطبيق Gemini الاستهلاكي؛ لا نفترض سياسة موحدة لكل APIs أو المناطق. https://learn.microsoft.com/en-us/security-copilot/privacy-data-security و https://docs.cloud.google.com/gemini/enterprise/docs/security-overview

## معمارية AI المقترحة للدراسة

`Source telemetry → Normalization & DLP → Security Evidence Store → Policy/Identity Gate → Local model or authorized Cloud model → Evidence-grounded recommendation → Human approval + read/write separation → Verified action (or request to NCC) → Audit and rollback`

هذا ليس مخطط تشغيل نهائيًا؛ يحتاج مراجعة المعمارية والخصوصية والتوافق والأداء.

## متطلبات جديدة مرقمة (CG-1011 إلى CG-1040)
- **CG-1011** — **Evidence-Linked Incident Copilot:** مساعد تحقيق يربط الإجابة بالمصدر ووقت الحدث ورابط السجل الأصلي بدل إنشاء رواية بلا أدلة. **الاعتماد/الحد:** سجلات EDR/SIEM، هوية أصل، صلاحية قراءة؛ لا قرارات تنفيذية. **اختبار القبول:** تقرير حادث يشمل ادعاءات قابلة للرجوع إلى أحداث المصدر، ويضع «غير معروف» عند غياب المصدر. **مرجع الدراسة:** https://learn.microsoft.com/en-us/defender-xdr/security-copilot-in-microsoft-365-defender.
- **CG-1012** — **Natural-Language Threat Hunting Translator:** تحويل طلب عربي إلى استعلام KQL أو صيغة البحث المدعومة، ثم عرض الاستعلام للمراجعة قبل تشغيله. **الاعتماد/الحد:** مخططات مصادر البيانات واستعلامات read-only ونطاق زمني وحد تكلفة. **اختبار القبول:** استعلام صحيح من حيث الحقول والنطاق، واختبار يمنع الاستعلامات غير المرخصة أو المكلفة بلا حد. **مرجع الدراسة:** https://learn.microsoft.com/en-us/azure/sentinel/sentinel-security-copilot.
- **CG-1013** — **AI Alert Triage with Justified Verdicts:** فرز تنبيهات كثيرة إلى حادث واحد أو إنذار خاطئ مع مبررات وأدلة ودرجة ثقة. **الاعتماد/الحد:** محرك قواعد، أحداث مترابطة، مراجعة بشرية؛ لا إغلاق تلقائي للحوادث عالية الخطورة. **اختبار القبول:** تجربة بقياسات false positive / false negative على بيانات اختبار مرجعية. **مرجع الدراسة:** https://learn.microsoft.com/en-us/copilot/security/rai-faqs-security-copilot-agents.
- **CG-1014** — **Detection Gap Discovery:** البحث عن سلاسل أحداث غير مكتشفة بقواعد تقليدية وإبراز فجوات الرؤية المعروفة. **الاعتماد/الحد:** مصادر سياقية وقواعد موجودة؛ قد تكون المخرجات مجرد فرضيات. **اختبار القبول:** كشف حالات اختبار متعددة الأحداث مع شرح لماذا لم تتطابق معها قواعد سابقة. **مرجع الدراسة:** https://learn.microsoft.com/en-us/defender-xdr/dynamic-threat-detection-agent.
- **CG-1015** — **Script and Command-Line Explanation:** شرح سلوك الأوامر والسجلات والسكربتات المشبوهة من دون تشغيل عينات أو أسرار. **الاعتماد/الحد:** مدخلات منقّحة، بيئة تحليل بلا تنفيذ، سياسة حماية للمحتوى النصي غير الموثوق. **اختبار القبول:** شرح يستند إلى عناصر الأمر المرصود وتحذير إذا كانت الأدلة غير كافية. **مرجع الدراسة:** https://learn.microsoft.com/en-us/copilot/security/responsible-ai-overview-security-copilot.
- **CG-1016** — **Identity Policy Optimization Assistant:** تحليل سياسات الوصول المشروط للحسابات الحساسة وتحديد التداخل والأثر المحتمل. **الاعتماد/الحد:** Microsoft Entra APIs بصلاحيات قراءة وحالة تراخيص؛ تغيير عبر اعتماد منفصل. **اختبار القبول:** يقترح تقريرًا قابلاً للمراجعة ويكشف تضارب السياقات قبل أي تعديل. **مرجع الدراسة:** https://learn.microsoft.com/en-us/copilot/security/rai-faqs-security-copilot-agents.
- **CG-1017** — **Security Promptbook Library:** تسلسل تحقيقات ثابتة وموثقة مثل دخول غير معتاد أو ransomware، مع مدخلات ونتائج متوقعة. **الاعتماد/الحد:** نسخ معتمدة قابلة للتدقيق ومرجع مصدر للخطوات والتحديثات. **اختبار القبول:** تشغيل promptbook على حالة مرجعية يعيد الأقسام المطلوبة ويذكر الخطوات التي فشلت. **مرجع الدراسة:** https://learn.microsoft.com/en-us/copilot/security/responsible-ai-overview-security-copilot.
- **CG-1018** — **External Security Data Connectors:** تصميم موصلات سجلات وهوية وثغرات مستقلة عن مزود AI عبر API/OpenAPI/MCP بضبط أذونات كل مصدر. **الاعتماد/الحد:** موصلات معتمدة، سياسة scopes وتوثيق الملكية؛ ليس الوصول لجميع المصادر تلقائيًا. **اختبار القبول:** اختبار أن المستخدم غير المخول لا يستطيع جلب بيانات مصدر متصل. **مرجع الدراسة:** https://learn.microsoft.com/en-us/copilot/security/developer/agent-components.
- **CG-1019** — **Campaign Exposure Answer Engine:** عند ظهور حملة تهديد جديدة: تحديد الأجهزة المتأثرة، الوجود التاريخي لمؤشرات الاستغلال، وتوفر قواعد الكشف. **الاعتماد/الحد:** CVE/KEV/TI، جرد أصول، قواعد كشف وتاريخ سجلات؛ النتائج مشروطة بالتغطية. **اختبار القبول:** تقرير «متأثر/غير مؤكد/لا دليل» مع فصل غياب الأحداث عن إثبات السلامة. **مرجع الدراسة:** https://cloud.google.com/blog/products/identity-security/introducing-the-emerging-threats-center-in-google-security-operations.
- **CG-1020** — **Retrohunt New Threat Indicators:** إعادة البحث بأثر رجعي في السجلات المحمية بعد ظهور IOC/TTP جديد. **الاعتماد/الحد:** مدة الاحتفاظ المعلنة ومخزون المؤشرات ومنع الاستعلامات المفرطة. **اختبار القبول:** بحث مؤرخ يحدد نطاق البيانات الذي شمله والفجوة التي لم يفحصها. **مرجع الدراسة:** https://cloud.google.com/security/products/security-operations/investigate.
- **CG-1021** — **Detection Rule Draft and Validation:** مقترحات Sigma/YARA-L/KQL تتحول إلى مسودة خاضعة لlint وunit tests وshadow mode. **الاعتماد/الحد:** محوّل قواعد مدعوم، اختبارات توليد أحداث، مراجعة بشرية. **اختبار القبول:** القاعدة لا تُنشر حتى تنجح اختبارات الدقة والأداء وتحديد المصادر الضرورية. **مرجع الدراسة:** https://cloud.google.com/security/products/security-operations.
- **CG-1022** — **Natural Language Playbook Drafting:** كتابة تسلسل استجابة مقترح بلغة طبيعية ثم تحويله إلى خطوات مقيدة بموافقة ونسخة معاينة. **الاعتماد/الحد:** قالب Playbook وسجلات تنفيذ؛ لا تشغيل أوامر حرة من النص. **اختبار القبول:** يظهر diff واضح قبل الحفظ، ويطلب اعتماد كل إجراء ذي أثر حقيقي. **مرجع الدراسة:** https://docs.cloud.google.com/chronicle/docs/soar/respond/working-with-playbooks/create-edit-playbook-with-gemini.
- **CG-1023** — **Threat-Centric Case Stitching:** دمج أحداث IP والحساب والجهاز والعملية ضمن حادث واحد مع خريطة علاقات. **الاعتماد/الحد:** منظومة هوية موحدة وtimestamps وحفظ provenance. **اختبار القبول:** تقليل التكرار دون دمج حادثين منفصلين خطأً في عينات الاختبار. **مرجع الدراسة:** https://cloud.google.com/security/products/security-operations/investigate.
- **CG-1024** — **Multi-Hypothesis Root Cause Analyzer:** اختبار فرضيات متوازية لعطل أمني/تشغيلي: فشل Agent أو DNS أو صلاحية أو تغيير سياسة. **الاعتماد/الحد:** logs, metrics, traces, change events؛ قراءة فقط. **اختبار القبول:** كل فرضية معها دليل مؤيد/مناقض واستنتاج قابل للمراجعة. **مرجع الدراسة:** https://cloud.google.com/products/gemini/cloud-assist.
- **CG-1025** — **Telemetry Ingestion Privacy Router:** مسار جمع وتصفية وإخفاء بيانات وحجب أسرار قبل إدخال بيانات SOC إلى محركات AI. **الاعتماد/الحد:** تصنيف البيانات وخط معالجة بحدود الاحتفاظ والمناطق. **اختبار القبول:** اختبار يمنع خروج سر خام إلى مزود AI حتى لو طلبه تقرير حادث. **مرجع الدراسة:** https://cloud.google.com/security/products/security-operations.
- **CG-1026** — **Analyst Feedback and Detection Tuning Loop:** تغذية راجعة من المحلل حول إنذارات صحيحة وخاطئة لتحسين الأولويات مع سجل إصدار. **الاعتماد/الحد:** مراجعة بشرية وتقييم مرجعي قبل تغيير العتبات. **اختبار القبول:** تظهر مؤشرات precision/recall وتأثير تغيير الإصدار على الحالات القديمة. **مرجع الدراسة:** https://cloud.google.com/solutions/security/agentic-soc.
- **CG-1027** — **Model Provider Abstraction:** واجهة موحدة لأنواع النماذج المحلية وواجهات Azure/OpenAI/Gemini بحسب الخدمة والسياسة. **الاعتماد/الحد:** عقود API مستقلة وتحقق مخرجات structured schema. **اختبار القبول:** اختبار تبديل المزود دون تغيير نتيجة تفويض أو منفذ التنفيذ الأمني. **مرجع الدراسة:** https://docs.cloud.google.com/gemini/enterprise/docs/security-overview.
- **CG-1028** — **Sensitive Data Local-First Routing:** إبقاء سجلات الهوية والبيانات الحساسة المحلية في التحليل المحلي افتراضيًا والانتقال للسحابة فقط بتصريح. **الاعتماد/الحد:** حساسية البيانات وموقع التخزين وDLP قبل الإرسال. **اختبار القبول:** رفض تلقائي لإرسال RAW log سري مع إثبات سياسة المنع. **مرجع الدراسة:** https://learn.microsoft.com/en-us/security-copilot/privacy-data-security.
- **CG-1029** — **AI Provider Privacy Contract Registry:** تسجيل سياسة كل مزود حول الاحتفاظ والتدريب والولاية القضائية والتكلفة بدل افتراض أن الكل متشابه. **الاعتماد/الحد:** شروط المؤسسات الرسمية وتحديثاتها وقيود المناطق. **اختبار القبول:** جدول اعتماد مزود/منطقة/نوع بيانات مع تاريخ آخر مراجعة. **مرجع الدراسة:** https://docs.cloud.google.com/gemini/enterprise/docs/compliance-security-controls.
- **CG-1030** — **Model Cost and Latency Budgets:** حدود توكنات وزمن وتكلفة لكل نوع مهمة وتوجيه للمعالجة القائمة على القواعد إذا لم يلزم AI. **الاعتماد/الحد:** سجل استخدام model API والموازنة والأولوية. **اختبار القبول:** إيقاف المهام غير الحرجة عند تجاوز الميزانية بلا تعطيل الكشف الأمني. **مرجع الدراسة:** https://learn.microsoft.com/en-us/defender-xdr/dynamic-threat-detection-agent.
- **CG-1031** — **Least-Privilege AI Tool Broker:** الأيجنت لا يملك credentials شبكة؛ وسيط يُصدر وظائف محددة بسياسة RBAC وABAC ونطاق مورد مؤقت. **الاعتماد/الحد:** تفويض المستخدم، resource scope، policy engine، واجهة NCC لطلبات التحكم. **اختبار القبول:** أمر غير مخول مرفوض حتى لو خرج من نموذج ذكي موثوق. **مرجع الدراسة:** https://learn.microsoft.com/en-us/copilot/security/authentication.
- **CG-1032** — **Prompt Injection Trust Boundary:** تمييز نص log أو صفحة ويب أو commit كبيانات غير موثوقة ومنعها من تغيير تعليمات النظام أو طلب استدعاء أدوات. **الاعتماد/الحد:** سياسات تصنيف وعزل سياق الأدلة وtool allowlist. **اختبار القبول:** اختبار سجل يحتوي تعليمات خبيثة لا ينفذ أمرًا أو يقرأ سرًا. **مرجع الدراسة:** https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-detection-protection.
- **CG-1033** — **Evidence Source Attestation for AI:** كل ادعاء يولده AI يربط إلى حدث أصلي وبصمته ووقت جمعه، مع تحذير عند ضعف نسبة الثقة. **الاعتماد/الحد:** hash chain, timestamp, source identifiers، سياسات العرض. **اختبار القبول:** يستطيع المحلل فتح أدلة كل جملة مؤثرة في التوصية. **مرجع الدراسة:** https://learn.microsoft.com/en-us/copilot/security/responsible-ai-overview-security-copilot.
- **CG-1034** — **AI Runtime Threat Monitoring:** تنبيهات عن سلوك أداة AI نفسها: تسريب أسرار، استعمال أدوات غير معتاد، prompt injection، نشاط مجاوز لصلاحيتها. **الاعتماد/الحد:** telemetry للـagent، حجب raw prompts الحساسة، مصدر أحداث مستقل. **اختبار القبول:** محاولة jailbreak في عينة اختبار تلتقط دون تسجيل أسرار صريحة. **مرجع الدراسة:** https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-detection-protection.
- **CG-1035** — **Specialist Agent Separation:** وحدات AI منفصلة للمحقق، intelligence، cloud posture، malware analysis، DevSecOps، recovery؛ لا تمنح صلاحيات موحدة. **الاعتماد/الحد:** مهارات مقيدة لكل عامل ووثائق صلاحيات. **اختبار القبول:** يفشل أي وكيل متخصص عند طلب وظيفة خارج حدوده. **مرجع الدراسة:** https://docs.cloud.google.com/architecture/agentic-ai-orchestrate-security-ops-workflows.
- **CG-1036** — **Durable Case Workflows:** تخزين نقاط تقدم التحقيق والأوامر المعتمدة بحيث تستأنف بعد تعطل الخادم بلا إعادة تنفيذ إجراء ضار. **الاعتماد/الحد:** checkpoint + idempotency key + retries + audit. **اختبار القبول:** إعادة تشغيل خدمة خلال اختبار لا ينتج عنه تنفيذ الأمر مرتين. **مرجع الدراسة:** https://github.com/langchain-ai/langgraph.
- **CG-1037** — **Tool-Level Guardrails:** تطبيق فحص قبل/بعد كل استدعاء API حساس، وليس فقط فحص نص السؤال أو المخرجات النهائية. **الاعتماد/الحد:** Schema validation, scopes, policy engine. **اختبار القبول:** طلب تعطيل منفذ uplink من مصدر غير موثوق يُرفض قبل التنفيذ. **مرجع الدراسة:** https://github.com/openai/openai-agents-python/blob/main/docs/guardrails.md.
- **CG-1038** — **Human Approval Before Security Changes:** عزل أو إبطال حساب أو تغيير firewall يطلب أثر وتفويض وموافقة وإظهار تراجع وإثبات نجاح. **الاعتماد/الحد:** Approval store وMFA وزمن موافقة مع انتهاء. **اختبار القبول:** اختبار أن غياب الموافقة يمنع التنفيذ ولا يوهم بالنجاح. **مرجع الدراسة:** https://docs.cloud.google.com/architecture/agentic-ai-orchestrate-security-ops-workflows.
- **CG-1039** — **Cross-Model Consensus Only as Advisory:** اختياريًا مقارنة تحليل مزودين مختلفين لملف تهديد مهم؛ الخلاف يزيد المراجعة ولا يصبح إذن تنفيذ. **الاعتماد/الحد:** بيانات منقحة وموافقة وأثر تكلفة. **اختبار القبول:** تسجيل مواضع الخلاف وعدم اعتبار إجماع النماذج إثباتًا تقنيًا. **مرجع الدراسة:** https://learn.microsoft.com/en-us/copilot/security/responsible-ai-overview-security-copilot.
- **CG-1040** — **Cloud Connector Capability Matrix:** حالة واضحة لكل موصل: Read-only/Write/License/Region/Permission/Not configured، مع اختبارات صلاحيات. **الاعتماد/الحد:** موصل AWS/Azure/GCP ومصادر محلية ومراجعة الترخيص. **اختبار القبول:** واجهة لا تعرض زر تنفيذ إلا إن أكد التكامل الصلاحية ودعم الوظيفة. **مرجع الدراسة:** https://cloud.google.com/security/products/security-operations.

## مقارنة الخيارات السحابية والمحلية

| الخيار | ما الذي يصلح له؟ | ما الذي لا نفترضه؟ |
|---|---|---|
| Local only | تحليل سجلات حساسة وتقليل خروج البيانات؛ يستمر دون إنترنت بعد تهيئة الأدوات | لا يعني تحليلاً أقوى من النماذج الكبيرة أو تغطية تلقائية |
| Microsoft Security Copilot integration | Microsoft Defender/Sentinel/Entra عند وجود الترخيص والأدوار والواجهات المدعومة | لا يعني أن Microsoft 365 Copilot العادي يملك سجلات SOC أو امتيازات أوسع |
| Google SecOps / Gemini for Security | بحث وتحقيق وإنشاء Playbooks وقواعد ضمن Google SecOps وإمكانيات Multi-Cloud | Google SecOps منتج سحابي متخصص، لا يعمل من LAN بدون تغذية بيانات واشتراك |
| Azure/OpenAI/Gemini API via broker | نموذج لغوي لتحليل سياق منقح عبر HTTPS ومنطقة معتمدة عند الحاجة | لا يُرسل كل الـPCAP والـAD logs الخام، ولا تعطى Keys التحكم للـLLM |
| Hybrid multi-provider | توجيه المهمة للمحرك المناسب وفق حساسية البيانات والتكلفة والمهلة | ليس كل مزود يقدم إقامة بيانات أو أمنًا أو API متطابقًا |

## مستودعات GitHub للدراسة المستقبلية (لا تعني اعتماد المكتبات)

- OpenAI Agents SDK: https://github.com/openai/openai-agents-python — Guardrails, tool calling, tracing, handoff, human-in-loop. تحقق من التوافق والخصوصية وسياسات الاحتفاظ بالتتبعات.
- LangGraph: https://github.com/langchain-ai/langgraph — استئناف عمليات التحقيق بعد الفشل، checkpoints، موافقات بشرية؛ لا يعني سلامة إجراء جانبي دون Idempotency.
- Microsoft Security Copilot custom agents/plugins: https://learn.microsoft.com/en-us/copilot/security/developer/ — أدوات API/KQL/MCP بتوثيق منفصل ومتطلبات ترخيص.
- Google SecOps YARA-L وPlaybooks: https://docs.cloud.google.com/chronicle/docs/soar/respond/working-with-playbooks/create-edit-playbook-with-gemini — إنشاء مسودة واستعراضها قبل تفعيلها.

## معايير تقييم نضج الفكرة قبل اعتمادها

1. توثيق المصدر وتاريخ آخر مراجعة لكل تكامل؛ إثبات أن المنتج/الواجهة يدعم الميزة في إصدار محدد.
2. حماية البيانات: تحكم في المرسل إلى السحابة، ترشيح أسرار، تصنيف وتوثيق المنطقة وسياسة مزود النموذج.
3. الاستجابة: لا يُنفذ AI أوامر حرة؛ سياسة صلاحيات محدودة وواجهة موحدة للموافقات والأثر والتراجع.
4. الجودة: بيانات اختبار مرجعية، تحاليل false positives/false negatives، مقارنة ناتج AI بالأدلة لا مجرد ثقة النموذج.
5. التشغيل: حدود وقت وتكلفة وتوكنات، مراقبة pipeline، تسجيل فشل الموديل/موصلات البيانات، fallback واضح.
6. الفصل: لا تحويل CyberGuard إلى نسخة أخرى من NCC أو IT Twin أو Tickets.

**نقطة الاستكمال التالية:** CG-1041؛ الاسم CyberGuard AI مؤقت والدراسة مستمرة.
