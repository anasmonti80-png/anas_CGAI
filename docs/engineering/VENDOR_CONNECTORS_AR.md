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
