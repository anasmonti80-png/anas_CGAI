# CyberGuard AI — السجل التراكمي للبحث والمتطلبات

**الإصدار:** v0.3 (مسودة بحث)  
**تاريخ التحديث:** 2026-11-09  
**الحالة:** دراسة وتوثيق فقط؛ **لا برمجة، ولا بروتوتايب، ولا نشر، ولا فحص لأجهزة فعلية**.  
**الاسم:** CyberGuard AI اسم عمل مؤقت؛ يجب إجراء فحص علامة تجارية ونطاق قبل اعتماده.  
**المرجع البصري:** لقطة لوحة SOC الكحلية/الرمادية/البرتقالية التي قدمها المستخدم؛ نحتفظ باتجاهها وتوزيعها دون نسخ أصول مملوكة لطرف آخر حرفيًا.

> مبدأ السجل: لا تُحذف أي فكرة سابقة دون تسجيل سبب القرار؛ نسجل كل متطلب بحالة (مطلوب/بحث/قابل للتنفيذ بشروط/مؤجل/مرفوض). هذه **أهداف تصميم** وليست قدرات منفذة أو مضمونة.

## أ. تعريف المنتج

منصة أمنية دفاعية تجمع SIEM وEDR/XDR وNDR وVulnerability Management وSecurity Posture وSOAR وAI Analyst، وتعمل بدءًا من جهاز PC محلي مع واجهة Windows ولوحة ويب آمنة للجوال والتابلت، وتتوسع لاحقًا إلى خوادم وحساسات موزعة وبيئات Multi-Vendor وMulti-Cloud وMulti-Tenant.

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
