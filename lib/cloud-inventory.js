// CG-050 Unified cloud asset inventory across providers, accounts and regions, with the billing model of every
// security service CyberGuard reads. Inputs are the documented read outputs of AWS Resource Explorer
// (resource-explorer-2 search), Azure Resource Graph and Google Cloud Asset Inventory (search-all-resources).
const short = (v, max = 300) => (v === null || v === undefined || v === '' ? null : String(v).replace(/[\x00-\x1f\x7f]/g, ' ').trim().slice(0, max) || null);
const obj = v => (typeof v === 'string' ? JSON.parse(v) : v);
export const resourceCategories = ['compute', 'container', 'storage', 'database', 'network', 'identity', 'security', 'serverless', 'other'];
const rules = [
  ['container', /eks|ecs|containerservice|managedclusters|container\.googleapis|containerinstance|kubernetes|ecr|containerregistry|artifactregistry/i],
  ['serverless', /lambda|functionapp|\/sites|cloudfunctions|run\.googleapis|appengine/i],
  ['database', /rds|dynamodb|redshift|docdb|elasticache|sql|cosmos|spanner|bigtable|firestore|database|bigquery/i],
  ['storage', /s3|bucket|storageaccount|storage\.googleapis|efs|fsx|disk|volume|snapshot|backup/i],
  ['identity', /iam|role|user|serviceaccount|managedidentit|userassignedidentit|kms|keyvault|secret/i],
  ['security', /guardduty|securityhub|inspector|wafv2|waf|firewallpolic|networkfirewall|securitypolic|defender|sentinel|securitycenter|cloudarmor|azurefirewall/i],
  ['network', /vpc|subnet|security-?group|networksecuritygroup|applicationsecuritygroup|networkinterface|elasticloadbalancing|loadbalancer|publicip|address|route|gateway|virtualnetwork|networkwatcher|compute\.googleapis\.com\/(firewall|network|subnetwork|address|forwardingrule|router)|dns/i],
  ['compute', /ec2:instance|instance|virtualmachine|compute\.googleapis\.com\/instance|autoscaling|scaleset/i]];
export const categoryOf = type => (rules.find(([, re]) => re.test(String(type || ''))) || ['other'])[0];
const tagsOf = list => Object.fromEntries((list || []).slice(0, 50).map(t => [short(t.Key ?? t.key, 128), short(t.Value ?? t.value ?? '', 256)]).filter(([k]) => k));

// aws resource-explorer-2 search --query-string "*" (aggregator index, all accounts and regions in the view)
export function awsResources(json) {
  const v = obj(json); if (!Array.isArray(v?.Resources)) throw new Error('not a Resource Explorer search response (Resources[] missing)');
  return v.Resources.slice(0, 20000).map(r => { const tags = tagsOf((r.Properties || []).find(p => p.Name === 'tags')?.Data); return { resource_id: short(r.Arn, 500), name: short(tags.Name || String(r.Arn).split(/[/:]/).pop(), 200), account_id: String(r.OwningAccountId || ''), region: short(r.Region || 'global', 40), type: short(r.ResourceType, 200), category: categoryOf(r.ResourceType), tags, public: null }; }).filter(r => r.resource_id && /^\d{12}$/.test(r.account_id));
}
// az graph query -q "resources | project id,name,type,location,subscriptionId,tags,properties"
export function azureResources(json) {
  const v = obj(json), l = Array.isArray(v) ? v : v?.data || v?.value; if (!Array.isArray(l)) throw new Error('not a Resource Graph response (data[] missing)');
  return l.slice(0, 20000).map(r => ({ resource_id: short(r.id, 500), name: short(r.name, 200), account_id: String(r.subscriptionId || String(r.id).split('/')[2] || '').toLowerCase(), region: short(r.location || 'global', 40), type: short(String(r.type).toLowerCase(), 200), category: categoryOf(r.type), tags: Object.fromEntries(Object.entries(r.tags || {}).slice(0, 50).map(([k, val]) => [short(k, 128), short(val, 256)])), public: String(r.type).toLowerCase() === 'microsoft.network/publicipaddresses' ? true : r.properties?.publicNetworkAccess ? r.properties.publicNetworkAccess === 'Enabled' : null })).filter(r => r.resource_id && /^[0-9a-f-]{36}$/.test(r.account_id));
}
// gcloud asset search-all-resources --scope=organizations/<id> --format=json ; projects map number -> id from projects list
export function gcpResources(json, projectNumbers = {}) {
  const v = obj(json), l = Array.isArray(v) ? v : v?.results; if (!Array.isArray(l)) throw new Error('not a Cloud Asset search-all-resources response');
  return l.slice(0, 20000).map(r => { const fromName = String(r.name || '').match(/\/projects\/([a-z][a-z0-9-]{4,28}[a-z0-9])\//)?.[1], num = String(r.project || '').replace('projects/', '');
    return { resource_id: short(r.name, 500), name: short(r.displayName || String(r.name).split('/').pop(), 200), account_id: projectNumbers[num] || fromName || '', region: short(String(r.location || 'global').replace(/^([a-z]+-[a-z]+\d+)-[a-z]$/, '$1'), 40), type: short(r.assetType, 200), category: categoryOf(r.assetType), tags: Object.fromEntries(Object.entries(r.labels || {}).slice(0, 50).map(([k, val]) => [short(k, 128), short(val, 256)])), public: null }; }).filter(r => r.resource_id && /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(r.account_id));
}

// Billing model of every service CyberGuard reads. Prices change: the page is the source; this states what is charged for.
export const serviceCharges = {
  aws: {
    cloudtrail: { billed: 'partial', en: 'First copy of management events per region is free; additional trails, data events and CloudTrail Lake are charged.', ar: 'النسخة الأولى من أحداث الإدارة لكل إقليم مجانية؛ المسارات الإضافية وأحداث البيانات وCloudTrail Lake مدفوعة.', url: 'https://aws.amazon.com/cloudtrail/pricing/' },
    guardduty: { billed: 'yes', en: 'Charged by volume of events and logs analysed per account and region; 30-day trial.', ar: 'تُحتسب بحجم الأحداث والسجلات المحللة لكل حساب وإقليم؛ مع تجربة 30 يومًا.', url: 'https://aws.amazon.com/guardduty/pricing/' },
    'security-hub': { billed: 'yes', en: 'Charged per security check and per finding ingested, per account and region.', ar: 'تُحتسب لكل فحص أمني ولكل نتيجة مستوردة، لكل حساب وإقليم.', url: 'https://aws.amazon.com/security-hub/pricing/' },
    inspector: { billed: 'yes', en: 'Charged per instance, container image and Lambda function scanned.', ar: 'تُحتسب لكل جهاز وصورة حاوية ودالة Lambda تُفحص.', url: 'https://aws.amazon.com/inspector/pricing/' },
    config: { billed: 'yes', en: 'Charged per configuration item recorded and per rule evaluation.', ar: 'تُحتسب لكل عنصر تهيئة مسجل ولكل تقييم قاعدة.', url: 'https://aws.amazon.com/config/pricing/' },
    'vpc-flow-logs': { billed: 'yes', en: 'Charged as vended logs delivered to CloudWatch Logs, S3 or Firehose, plus storage.', ar: 'تُحتسب كسجلات مُسلَّمة إلى CloudWatch Logs أو S3 أو Firehose، إضافة إلى التخزين.', url: 'https://aws.amazon.com/cloudwatch/pricing/' },
    'network-firewall': { billed: 'yes', en: 'Charged per firewall endpoint hour and per GB processed.', ar: 'تُحتسب لكل ساعة نقطة جدار ولكل GB معالج.', url: 'https://aws.amazon.com/network-firewall/pricing/' },
    'security-groups': { billed: 'no', en: 'No charge.', ar: 'بلا رسوم.', url: 'https://aws.amazon.com/vpc/pricing/' },
    eventbridge: { billed: 'partial', en: 'Events from AWS services are free; custom and cross-account events are charged.', ar: 'أحداث خدمات AWS مجانية؛ الأحداث المخصصة وعبر الحسابات مدفوعة.', url: 'https://aws.amazon.com/eventbridge/pricing/' },
  },
  azure: {
    'resource-graph': { billed: 'no', en: 'No charge (requests are throttled).', ar: 'بلا رسوم (مع حدود للطلبات).', url: 'https://learn.microsoft.com/azure/governance/resource-graph/overview' },
    'entra-logs': { billed: 'partial', en: 'Sign-in logs need Microsoft Entra ID P1 or P2; exporting them to Log Analytics is charged per GB ingested.', ar: 'سجلات الدخول تتطلب Microsoft Entra ID P1 أو P2؛ وتصديرها إلى Log Analytics يُحتسب لكل GB.', url: 'https://www.microsoft.com/security/business/microsoft-entra-pricing' },
    'defender-for-cloud': { billed: 'yes', en: 'Foundational CSPM is free; each Defender plan is charged per protected resource.', ar: 'CSPM الأساسي مجاني؛ وكل خطة Defender تُحتسب لكل مورد محمي.', url: 'https://azure.microsoft.com/pricing/details/defender-for-cloud/' },
    sentinel: { billed: 'yes', en: 'Charged per GB analysed (pay-as-you-go or commitment tiers) on top of Log Analytics.', ar: 'تُحتسب لكل GB محلل (حسب الاستخدام أو الالتزام) إضافة إلى Log Analytics.', url: 'https://azure.microsoft.com/pricing/details/microsoft-sentinel/' },
    'azure-monitor': { billed: 'partial', en: 'The activity log is free; exporting it to Log Analytics or storage is charged by ingestion and retention.', ar: 'سجل النشاط مجاني؛ وتصديره إلى Log Analytics أو التخزين يُحتسب بالاستيعاب والاحتفاظ.', url: 'https://azure.microsoft.com/pricing/details/monitor/' },
    'vnet-flow-logs': { billed: 'yes', en: 'Charged per GB of flow logs collected, plus storage and optional traffic analytics.', ar: 'تُحتسب لكل GB من سجلات التدفق المجمعة، إضافة إلى التخزين وتحليلات الحركة الاختيارية.', url: 'https://azure.microsoft.com/pricing/details/network-watcher/' },
    'azure-firewall': { billed: 'yes', en: 'Charged per deployment hour and per GB processed.', ar: 'تُحتسب لكل ساعة نشر ولكل GB معالج.', url: 'https://azure.microsoft.com/pricing/details/azure-firewall/' },
    nsg: { billed: 'no', en: 'No charge.', ar: 'بلا رسوم.', url: 'https://azure.microsoft.com/pricing/details/virtual-network/' },
    'network-watcher': { billed: 'partial', en: 'Enabling Network Watcher is free; diagnostics, connection monitor and flow logs are charged.', ar: 'تفعيل Network Watcher مجاني؛ والتشخيصات ومراقبة الاتصال وسجلات التدفق مدفوعة.', url: 'https://azure.microsoft.com/pricing/details/network-watcher/' },
  },
  gcp: {
    'asset-inventory': { billed: 'no', en: 'No charge; exports to BigQuery or Cloud Storage are charged by those services.', ar: 'بلا رسوم؛ والتصدير إلى BigQuery أو Cloud Storage يُحتسب لديهما.', url: 'https://cloud.google.com/asset-inventory/pricing' },
    scc: { billed: 'partial', en: 'The Standard tier is free; Premium and Enterprise tiers are charged.', ar: 'المستوى Standard مجاني؛ ومستويا Premium وEnterprise مدفوعان.', url: 'https://cloud.google.com/security-command-center/pricing' },
    'cloud-audit-logs': { billed: 'partial', en: 'Admin Activity and System Event logs are free; Data Access logs are charged as Cloud Logging ingestion.', ar: 'سجلات Admin Activity وSystem Event مجانية؛ وسجلات Data Access تُحتسب كاستيعاب في Cloud Logging.', url: 'https://cloud.google.com/logging/pricing' },
    'vpc-flow-logs': { billed: 'yes', en: 'Charged for log generation, plus Cloud Logging ingestion if stored there.', ar: 'تُحتسب على توليد السجلات، إضافة إلى الاستيعاب في Cloud Logging إن خُزنت فيه.', url: 'https://cloud.google.com/vpc/network-pricing' },
    'firewall-rules-logging': { billed: 'yes', en: 'Charged as Cloud Logging ingestion.', ar: 'تُحتسب كاستيعاب في Cloud Logging.', url: 'https://cloud.google.com/logging/pricing' },
    'vpc-firewall': { billed: 'no', en: 'VPC firewall rules are free; Cloud NGFW Enterprise features are charged.', ar: 'قواعد جدار VPC مجانية؛ وميزات Cloud NGFW Enterprise مدفوعة.', url: 'https://cloud.google.com/firewall/pricing' },
    'cloud-armor': { billed: 'yes', en: 'Charged per policy, per rule and per million requests (Standard), or by subscription (Enterprise).', ar: 'تُحتسب لكل سياسة ولكل قاعدة ولكل مليون طلب (Standard)، أو باشتراك (Enterprise).', url: 'https://cloud.google.com/armor/pricing' },
    iam: { billed: 'no', en: 'No charge.', ar: 'بلا رسوم.', url: 'https://cloud.google.com/iam/pricing' },
  },
};
// Services whose evidence covers resources in a region (used to find regions holding resources without that coverage).
export const regionalLogging = { aws: ['cloudtrail', 'vpc-flow-logs'], azure: ['network-watcher'], gcp: ['vpc-flow-logs'] };
