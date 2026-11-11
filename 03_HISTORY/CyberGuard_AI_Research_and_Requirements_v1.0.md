# CyberGuard AI — السجل التراكمي للبحث والمتطلبات

**الإصدار:** v1.0 (سجل تراكمي كامل من v0.3 إلى v1.0؛ بحث دفاعي دون تنفيذ)  
**تاريخ التحديث:** 2026-11-10 — الجولة العاشرة: التشفير وحماية المفاتيح وCrypto Agility  
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

**حالة التسليم في نهاية v0.5:** دراسة فقط. بدأت جولة v0.6 من **CG-181** دون استبدال متطلبات النسخ السابقة.


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