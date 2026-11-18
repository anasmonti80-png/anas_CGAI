# موصلات أجهزة الشبكة والجدران النارية — CG-041 إلى CG-043

حالة كل مورّد كما هي في الكود، دون ادعاء تشغيل حي لم يحدث. كل الموصلات تقرأ فقط ما لم يُذكر غير ذلك، ولا تخزّن بيانات الدخول، وتأخذها من متغيرات البيئة عند التشغيل الحي.

| المورّد | واجهة القراءة الموثقة | المصادقة | ما نُفّذ | ما لم يُنفّذ |
|---|---|---|---|---|
| Cisco Catalyst Center | Intent API: `network-device`، `topology/physical-topology`، `device-health` | `X-Auth-Token` | جرد الأجهزة، الطوبولوجيا، صحة الأجهزة وتنبيه CG-NET-HEALTH-041 (`scripts/cisco-connector.js`) | واجهات العملاء والمشكلات في Assurance |
| Cisco Secure Firewall FMC | `policy/accesspolicies/{id}/accessrules?expanded=true` | `X-auth-access-token` | قواعد الوصول إلى محلل الجدار الناري CG-020 | حل الكائنات المسماة (تُعلَّم غير مقروءة) |
| Cisco IOS XE | RESTCONF `Cisco-IOS-XE-native:native` | Basic | الإصدار وDNS وNTP وبروتوكولات الإدارة وقيود access-class | NETCONF؛ CLI عبر CG-021 |
| Cisco ISE | ERS `ancendpoint/apply` و`clear` (كتابة) | Basic (ERS) | عزل/فك عزل نقطة نهاية كإجراء محكوم CG-029 ينفذه الموصل لمهام معتمدة فقط | قراءة سياسات ANC |
| Huawei iMaster NCE-Campus | `controller/campus/v3/devices` | `X-ACCESS-TOKEN` | الأجهزة وحالتها وتنبيه عدم الاتصال (`scripts/huawei-connector.js`) | واجهات الطوبولوجيا والتهيئة في NCE |
| Huawei VRP | `display version`، `display current-configuration`، `display lldp neighbor brief` | جلسة الجهاز | التهيئة دون أسرار، وجيران LLDP بصيغتي الإصدارات | التهيئة عبر NETCONF |
| Palo Alto PAN-OS / Panorama | REST `Policies/SecurityRules` | `X-PAN-KEY` | قواعد الأمان (`scripts/firewall-policy-to-telemetry.js panos`) | قواعد Panorama المشتركة (pre/post) |
| Fortinet FortiOS / FortiManager | REST `cmdb/firewall/policy` | Bearer API token | السياسات مع الخدمات المعروفة | كائنات العناوين والخدمات المخصصة؛ FortiManager JSON-RPC |
| Juniper SRX | `show configuration security policies \| display set` | جلسة الجهاز | السياسات بين المناطق والتطبيقات المعرّفة مسبقًا | address-book وتطبيقات مخصصة |
| MikroTik RouterOS v7 | REST `ip/firewall/filter` | Basic | سلاسل input وforward وoutput | قوائم العناوين (تُعلَّم غير مقروءة) |
| OPNsense | `api/firewall/filter/searchRule` | مفتاح وسر API | قواعد التصفية | الأسماء المستعارة (aliases) |
| pfSense | لا توجد واجهة REST رسمية في الإصدار المجتمعي | — | سجلات filterlog عبر CG-018 | قراءة القواعد (تصدير config.xml أو حزمة REST غير رسمية) |
| Aruba (AOS-CX) | REST `rest/v10.x` | جلسة REST | — | لم يُنفّذ: يحتاج جهازًا لتحديد الحقول حسب الإصدار |
| Linux routers | `iptables-save` | محلي (root) | جدول filter مع السياسات الافتراضية، ويُختبر على جهاز CI حقيقي | nftables وقواعد ipset |

## قواعد مشتركة

- أي كائن مسمّى (مجموعة عناوين، alias، address-list، خدمة مخصصة) لا تُعرف قيمته من المدخل تُعلَّم قاعدته `filters_readable=false` ولا تُحلَّل، بدل التخمين.
- كلمات المرور المشفرة والمفاتيح ومجتمعات SNMP لا تُنسخ من أي تهيئة.
- لم يُجرَ تشغيل حي ضد أجهزة حقيقية لهذه المورّدين لعدم توفرها، ولأن الوكلاء لا يُدخلون بيانات دخول. صيغ المدخلات مطابقة لوثائق المورّدين، والتشغيل الحي يتطلب بيانات دخول المالك.

## AWS للقراءة فقط (CG-046)

| المصدر | واجهة القراءة الموثقة | ما يصل إلى CyberGuard |
|---|---|---|
| Organizations | `organizations list-accounts` | `cloud.account_inventory` بالحسابات وحالتها |
| أدوار عبر الحسابات | `sts assume-role` لدور `CyberGuardReadOnly` (قالب `deploy/aws/cyberguard-readonly-role.yaml`) | نتيجة التولي لكل حساب: إدارة، مُتولّى، مرفوض |
| CloudTrail وGuardDuty وSecurity Hub CSPM وInspector وConfig وVPC Flow Logs وNetwork Firewall ومجموعات الأمان وEventBridge | استدعاء قراءة واحد لكل خدمة وإقليم (`describe-trails`، `list-detectors`، `describe-hub`، `batch-get-account-status`، `describe-configuration-recorder-status`، `describe-flow-logs`، `list-firewalls`، `describe-security-groups`، `list-rules`) | حالة كل خدمة: مفعلة، غير مفعلة، مرفوض الوصول، غير متاحة، لم تُفحص |
| النتائج | `securityhub get-findings` (ASFF) و`guardduty get-findings` وأحداث EventBridge | `cloud.finding` بآخر حالة لكل نتيجة |
| CloudTrail | ملفات السجل `{"Records":[...]}` أو EventBridge | `log.batch` بصيغة `aws-cloudtrail-json` |
| VPC Flow Logs | الصيغة الافتراضية v2 أو ترويسة الحقول في S3 | `log.batch` بصيغة `aws-vpc-flow` |
| Network Firewall | سجلات alert وflow (EVE) | `log.batch` بصيغة `aws-network-firewall-json` |
| مجموعات الأمان | `ec2 describe-security-groups` | `firewall.ruleset` بالمورّد `aws-security-group` ويحللها CG-020 |

- الدور يمنح SecurityAudit وقراءة النتائج فقط، ويمنع صراحة أي كتابة على الخدمات المقروءة، ويتطلب ExternalId، ومدة الجلسة ساعة واحدة. لا يُطلب Root.
- الاعتمادات المؤقتة تبقى في بيئة العملية الفرعية فقط ولا تُكتب في أي ملف.
- مجموعة الأمان تصل فقط إلى واجهات أعضائها، لذلك لا تُعد قاعدة "أي إلى أي"؛ ويُعلَّم الكشف الواسع للمنافذ الإدارية. القواعد التي تشير إلى مجموعة أخرى أو prefix list تُعلَّم غير مقروءة ولا تُحلَّل.
- الحساب المعلق فجوة واحدة، والدور المرفوض فجوة تشمل كل الخدمات، ولا تُعرض خدمة لم تُفحص على أنها مغطاة.
- التنبيهات: `CG-CLOUD-FINDING-046` للنتائج النشطة العالية والحرجة، و`CG-CLOUD-GAP-046` لتعطيل CloudTrail أو GuardDuty أو رفض الدور، و`CG-CLOUD-TRAIL-046` لاستدعاءات تعطيل الرؤية أو توسيع الوصول الناجحة واستخدام root وتكرار فشل دخول الكونسول، وتعيد سجلات Network Firewall استخدام `CG-LOG-IDS-014`.
- لم يُجرَ تشغيل حي ضد حساب AWS لأن الوكلاء لا يُدخلون بيانات دخول. المدخلات بصيغ AWS الموثقة بأرقام حسابات التوثيق، والتشغيل الحي يتم بملف تعريف AWS CLI الخاص بالمالك: `node scripts/aws-connector.js live --profile <name> --regions us-east-1,eu-west-1 --output <file>`.
