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

## Azure وMicrosoft Entra للقراءة فقط (CG-047)

| المصدر | واجهة القراءة الموثقة | ما يصل إلى CyberGuard |
|---|---|---|
| الاشتراكات | `az account list` (ARM `/subscriptions`) | `cloud.account_inventory` بالمزود `azure` والاشتراكات وحالتها |
| Azure Resource Graph | `az graph query` على VNet وNetwork Watcher وflowLogs وAzure Firewall وNSG وASG وحلول Sentinel | حالة Network Watcher لكل إقليم فيه VNet، وسجلات تدفق VNet، وAzure Firewall، وNSG/ASG |
| Defender for Cloud | `az security pricing list` والتنبيهات (`Microsoft.Security/alerts`) والتوصيات (`assessments`) | حالة الخطط و`cloud.finding` بالمنتج `defender-for-cloud` |
| Microsoft Sentinel | `Microsoft.SecurityInsights/incidents` لكل مساحة مفعّل فيها Sentinel | `cloud.finding` بالمنتج `sentinel` |
| Azure Monitor | `az monitor diagnostic-settings subscription list` وسجل النشاط | حالة تصدير سجل النشاط، و`log.batch` بصيغة `azure-activity-json` |
| Microsoft Entra | Graph `auditLogs/signIns` و`auditLogs/directoryAudits` | `identity.signin_activity` و`identity.idp_change` (الوصول المشروط، الاتحاد، سياسة MFA، ...) فتعمل قواعد تهديدات الهوية CG-015 |
| VNet flow logs | ملف التدفق الإصدار 4 `{"records":[...]}` | `log.batch` بصيغة `azure-vnet-flow-json` |
| Azure Firewall | السجلات المنظمة AZFWNetworkRule وAZFWApplicationRule وAZFWIdpsSignature وAZFWThreatIntel | `log.batch` بصيغة `azure-firewall-json` |
| NSG وسياسة Azure Firewall | `az network nsg list` و`az network firewall policy rule-collection-group list` | `firewall.ruleset` بالمورّدين `azure-nsg` و`azure-firewall` ويحللها CG-020 |

- الدور المخصص `deploy/azure/cyberguard-reader-role.json` يحتوي عمليات `/read` فقط ولا DataActions؛ ويكفي بديلًا عنه Reader وSecurity Reader وMicrosoft Sentinel Reader، مع صلاحية Graph `AuditLog.Read.All` لسجلات Entra. لا يُطلب Global Admin أو Owner.
- الاشتراك الذي لا يوجد عليه دور قراءة فجوة تشمل كل الخدمات، والاشتراك المعطل فجوة واحدة، ولا تُكتب له صفوف خدمات حتى لا يبدو مغطى.
- الاشتراك الذي فيه سجلات تدفق NSG فقط يظهر بفجوة «تتقاعد في 2027-09-30؛ يلزم تفعيل سجلات تدفق VNet» (تمهيدًا لـCG-051).
- قواعد NSG تشمل القواعد الافتراضية بترتيب الأولوية؛ وما يشير إلى ASG أو وسوم خدمة مثل VirtualNetwork وAzureLoadBalancer أو IP Groups يُعلَّم غير مقروء ولا يُحلَّل. سياسة Azure Firewall تُحلَّل دون قيد نطاق لأنها تمر عليها كل الحركة الموجهة إليها، لذلك «أي إلى أي» فيها حرجة.
- التنبيهات: `CG-CLOUD-FINDING-046` للنتائج النشطة العالية والحرجة، و`CG-CLOUD-GAP-046` لتعطيل Defender for Cloud أو عدم تصدير سجل النشاط أو تعذر قراءة سجلات Entra أو غياب دور القراءة، و`CG-CLOUD-ACTIVITY-047` للعمليات الحساسة الناجحة في سجل النشاط (حذف إعدادات التشخيص أو سجلات التدفق، كتابة قواعد NSG أو سياسة الجدار، إسناد الأدوار)، وتعيد تنبيهات IDPS استخدام `CG-LOG-IDS-014`.
- لم يُجرَ تشغيل حي ضد مستأجر Azure لأن الوكلاء لا يُدخلون بيانات دخول. المدخلات بصيغ Microsoft الموثقة بمعرّفات بديلة، والتشغيل الحي يتم بجلسة `az login` الخاصة بالمالك: `node scripts/azure-connector.js live --output <file>`.

## Google Cloud للقراءة فقط (CG-048)

| المصدر | واجهة القراءة الموثقة | ما يصل إلى CyberGuard |
|---|---|---|
| المشاريع | `gcloud projects list` | `cloud.account_inventory` بالمزود `gcp` والمشاريع وحالتها |
| Security Command Center | `gcloud scc findings list organizations/<id>` (ListFindingsResult) | `cloud.finding` بالمنتج `scc` مع الفئة والخطورة والامتثال وحالة الكتم |
| IAM | `gcloud projects get-iam-policy` | `identity.directory_snapshot` من نوع `gcp-iam` بالأدوار المميزة والشروط، ونتيجة مشتقة لكل ربط علني (`allUsers`/`allAuthenticatedUsers`) |
| Cloud Audit Logs | `gcloud logging read` لسجلات `cloudaudit.googleapis.com` | `log.batch` بصيغة `gcp-audit-json`، وحالة سجلات Data Access من `auditConfigs` |
| VPC Flow Logs | `logConfig.enable` لكل شبكة فرعية، وسجلات `vpc_flows` | حالة كل إقليم، و`log.batch` بصيغة `gcp-vpc-flow-json` |
| قواعد جدار VPC وتسجيلها | `gcloud compute firewall-rules list` وسجلات `firewall` | `firewall.ruleset` بالمورّد `gcp-vpc-firewall`، و`log.batch` بصيغة `gcp-firewall-json` |
| Cloud Armor | `gcloud compute security-policies describe` وسجلات موازن التحميل | `firewall.ruleset` بالمورّد `gcp-cloud-armor`، و`log.batch` بصيغة `gcp-armor-json` (فئة WAF) |

- الأدوار في `deploy/gcp/cyberguard-viewer-roles.json` أدوار عرض ومراجعة فقط (`roles/viewer` و`roles/iam.securityReviewer` و`roles/securitycenter.findingsViewer` و`roles/logging.viewer` و`roles/cloudasset.viewer`)، ولا يُطلب Owner أو Editor أو Organization Admin.
- ترتيب قواعد جدار VPC: الأولوية الأدنى رقمًا أولًا، والرفض قبل السماح عند تساوي الأولوية، ثم القاعدتان الضمنيتان (رفض الوارد وسماح الصادر). القاعدة التي تستهدف وسومًا أو حسابات خدمة مقيدة النطاق، والمصدر بالوسوم أو حسابات الخدمة لا يُحلَّل. قاعدة سماح كاملة من `0.0.0.0/0` بلا هدف تشمل كل الأجهزة في الشبكة فتُعد «أي إلى أي».
- قواعد Cloud Armor مقيدة بالخدمة الخلفية التي تحميها السياسة، والقاعدة في وضع المعاينة تُعلَّم غير مطبقة، وقواعد التعبيرات (مثل `evaluatePreconfiguredExpr`) لا تُقيّم.
- التنبيهات: `CG-CLOUD-FINDING-046` للنتائج النشطة العالية والحرجة (ومنها الربط العلني)، و`CG-CLOUD-GAP-046` لتعطيل SCC أو تعذر قراءة IAM أو غياب دور العرض، و`CG-CLOUD-AUDIT-048` لاستدعاءات ناجحة تحذف أو تعدّل مصارف السجلات أو تغيّر IAM أو تنشئ مفاتيح حسابات خدمة أو تعدّل قواعد الجدار وسياسات Cloud Armor، وتعيد حظرات Cloud Armor استخدام `CG-WAF-025`.
- لم يُجرَ تشغيل حي ضد مؤسسة Google Cloud لأن الوكلاء لا يُدخلون بيانات دخول. المدخلات بصيغ Google الموثقة بمعرّفات أمثلة، والتشغيل الحي يتم بجلسة `gcloud auth login` الخاصة بالمالك: `node scripts/gcp-connector.js live --projects <ids> --organization-id <id> --output <file>`.

### بحث لاحق: Kubernetes (EKS وAKS وGKE)

- مصادر القراءة الموثقة: سجل تدقيق خادم Kubernetes API (`audit.k8s.io/v1` Event) عبر CloudWatch Logs لـEKS، وفئة `kube-audit` في إعدادات التشخيص لـAKS، وCloud Audit Logs لـGKE؛ وقائمة العناقيد عبر `eks list-clusters` و`az aks list` و`gcloud container clusters list`؛ وسياسات الشبكة `networking.k8s.io/v1 NetworkPolicy` وأدوار RBAC (`ClusterRoleBinding`) بالقراءة عبر `kubectl get -o json`.
- كشف الحماية المدارة: GuardDuty EKS Protection، وDefender for Containers، وGKE Security Posture/SCC، وتُستورد نتائجها بالموصلات الحالية لأنها تصل عبر Security Hub وDefender for Cloud وSCC.
- ما يلزم قبل التنفيذ: نوع حدث لسجل تدقيق Kubernetes، ومحلل لـ`NetworkPolicy` (غيابها يعني السماح الكامل داخل مساحة الأسماء)، وربط ClusterRoleBinding بلقطة الهوية؛ ودور قراءة فقط بـ`get/list/watch` دون `secrets`.

## صلاحيات سحابية مؤقتة ومحدودة (CG-049)

- كل وصول إلى حساب أو اشتراك أو مشروع يُسجَّل كـ`cloud.access_grant`: الأدوار ومستوى الصلاحية (قراءة، كتابة، مسؤول) والآلية ومدة الجلسة ووقت الانتهاء والشروط.
- المصادر: AWS `iam get-role` و`iam list-attached-role-policies` و`iam get-account-summary` (مفاتيح root)؛ Azure `roleAssignmentScheduleInstances` و`roleEligibilityScheduleInstances` (PIM)؛ Entra `roleManagement/directory/roleAssignmentScheduleInstances` والأهلية؛ Google Cloud `getIamPolicy` مع شروط `request.time < timestamp(...)`.
- مخالفة: مفاتيح root، أو صلاحية مسؤول دائمة (مثل Global Administrator أو Owner أو roles/owner دون PIM)، أو صلاحية مسؤول بلا وقت انتهاء، أو كتابة دائمة، أو كتابة على مؤسسة أو مجموعة إدارة أو مجلد كامل. تحذير: جلسة أطول من ساعة، أو قراءة دائمة غير مؤقتة، أو قراءة على مستوى المؤسسة. أهلية PIM غير المفعلة والتفعيل المحدد بوقت وانتحال الهوية القصير والشرط الزمني تُعد وصولًا مؤقتًا.
- الموصلات: جلسة AWS افتراضيًا 15 دقيقة وحدّها ساعة (`--session-seconds`)، ودور Azure يُسند لكل اشتراك على حدة ويفضّل كإسناد مؤهل في PIM، وموصل Google Cloud يقبل `--impersonate-service-account` لرموز قصيرة العمر لحساب خدمة قراءة فقط. الوضع live لكل موصل يضيف مراجعة الصلاحيات للهوية التي يعمل بها.
- التنبيه `CG-CLOUD-ACCESS-049`: حرج لمفاتيح root والمسؤول الدائم، وعالٍ لبقية المخالفات.

## الجرد السحابي الموحد والرسوم (CG-050)

- مصادر الجرد: AWS Resource Explorer (`resource-explorer-2 search` على عرض مجمّع لكل الحسابات والأقاليم)، وAzure Resource Graph (`resources`)، وGoogle Cloud Asset Inventory (`asset search-all-resources`)؛ وتصل كـ`cloud.resource_inventory` بفئات موحدة: حوسبة، حاويات، تخزين، قواعد بيانات، شبكة، هوية ومفاتيح، خدمات أمن، بلا خادم، أخرى. مناطق GCP (مثل europe-west1-b) تُجمع في إقليمها.
- العرض الموحد يجمع لكل مزود: الحسابات والأقاليم والموارد والموارد العامة كما يذكرها المصدر، والنتائج النشطة، والتنبيهات المفتوحة، وسياسات جدار السحابة وWAF مع نتائج المحلل، ومراجعة الصلاحيات (CG-049)، وفجوات الخدمات.
- الفجوة الإقليمية: إقليم فيه موارد بلا CloudTrail وسجلات تدفق VPC مفعلة (AWS)، أو بلا Network Watcher (Azure)، أو بلا سجلات تدفق VPC (Google Cloud)؛ والموارد العامة (global) لا تُعد فجوة إقليمية.
- الرسوم: لكل خدمة يقرؤها CyberGuard ما يحتسبه مزودها (مدفوعة، جزئيًا، بلا رسوم) وصفحة الأسعار الرسمية وعدد الحسابات المفعلة فيها. لا تُذكر أرقام أسعار لأنها تتغير؛ الصفحة الرسمية هي المرجع، ولا يفعّل CyberGuard أي خدمة مدفوعة.

## ترحيل سجلات تدفق NSG إلى VNet (CG-051)

- أوقفت Azure إنشاء سجلات تدفق NSG الجديدة، وتتقاعد في 2027-09-30؛ البديل سجلات تدفق VNet.
- مع `--graph` يكتب الوضع inventory (والوضع live) خطة `cloud.nsg_flow_migration`: كل سجل تدفق NSG يُطابق مع شبكات VNet للشبكات الفرعية المرتبطة بالمجموعة (`properties.subnets`). الحالات: ترحيل (VNet بلا سجل تدفق VNet)، مغطى (عطّل سجل NSG لتجنب الدفع مرتين)، مرتبط ببطاقات شبكة فقط، غير مرتبط.
- تُحسب الأيام المتبقية عند القراءة لا عند الجمع، والتنبيه `CG-AZURE-NSGFLOW-051` متوسط ويصبح عاليًا في آخر 90 يومًا.
- ملفات سجلات NSG الحالية (الإصدار 1 و2) تبقى مقروءة بالوضع `nsg-flow` وصيغة `azure-nsg-flow-json` حتى التقاعد.
