// CG-160 Cloud cost and API permissions preview. Before a cloud log source is enabled the owner sees, per source:
// the expected data volume (from a measured sample or declared rates), the billed components (ingestion, API requests,
// storage, egress, analysis) with their official pricing units and free allowances, the permissions needed to enable it
// and for CyberGuard to read it, and the regional scope. Unit prices are never assumed: a cost is computed only from
// prices the owner enters for their contract and region (as in the CG-129 capacity model).
// Stopping collection never deletes evidence: it revokes the source credential, records who stopped it and why, and
// reports what stays protected. Events linked to unresolved alerts are already exempt from retention purge (tenancy.js),
// an open case blocks the stop unless the incident owner is named, and each provider keeps its own free record
// (CloudTrail Event history 90 days, Azure Activity log 90 days, Google Admin Activity audit logs 400 days).
import { randomUUID } from 'node:crypto';
import { fail, object, text, integer } from './common.js';

const P = { aws: 'AWS', azure: 'Azure', gcp: 'Google Cloud' };
const EGRESS = {
  aws: { component: 'egress', unit: 'GB', free: 100, free_note: '100 GB per month free to the internet, aggregated across AWS services and Regions', url: 'https://aws.amazon.com/ec2/pricing/on-demand/' },
  azure: { component: 'egress', unit: 'GB', free: 0, free_note: 'Per the Azure bandwidth price list for the route', url: 'https://azure.microsoft.com/pricing/details/bandwidth/' },
  gcp: { component: 'egress', unit: 'GB', free: 0, free_note: 'Per the Google Cloud network pricing for the route', url: 'https://cloud.google.com/vpc/network-pricing' },
};
// Official billing structure only; amounts come from the owner.
export const CATALOG = [
  { id: 'aws-cloudtrail-management', provider: 'aws', title: 'CloudTrail management events (trail to S3)', title_ar: 'أحداث الإدارة في CloudTrail (مسار إلى S3)', default_state: 'free-record',
    provider_record: 'CloudTrail Event history keeps 90 days of management events at no charge, with or without a trail.', provider_record_ar: 'يحفظ CloudTrail Event history أحداث الإدارة 90 يومًا دون رسوم، بمسار أو دونه.',
    billing: [{ component: 'ingest', unit: '100k events', driver: 'events', free_first_copy: true, note: 'The first copy of management events delivered to S3 is free; additional copies are billed per 100,000 events.' }, { component: 'storage', unit: 'GB-month', driver: 'gb', note: 'S3 storage of the log files.' }, { component: 'api', unit: '1,000 requests', driver: 'requests', note: 'S3 LIST and GET requests made by the collector.' }],
    enable: ['cloudtrail:CreateTrail', 'cloudtrail:StartLogging', 's3:PutBucketPolicy'], read: ['s3:ListBucket', 's3:GetObject', 'kms:Decrypt (only with SSE-KMS)'],
    regions: 'Create one multi-Region trail; a single-Region trail misses activity in other Regions.', regions_ar: 'أنشئ مسارًا واحدًا متعدد المناطق؛ المسار أحادي المنطقة يفوته نشاط المناطق الأخرى.', multi_region: true, url: 'https://aws.amazon.com/cloudtrail/pricing/' },
  { id: 'aws-cloudtrail-data', provider: 'aws', title: 'CloudTrail data events (S3 object, Lambda)', title_ar: 'أحداث البيانات في CloudTrail (كائنات S3 وLambda)', default_state: 'off',
    provider_record: 'Not recorded unless enabled on a trail or event data store.', provider_record_ar: 'لا تُسجل إلا إذا فُعّلت على مسار أو مخزن أحداث.',
    billing: [{ component: 'ingest', unit: '100k events', driver: 'events', note: 'Billed per 100,000 data events delivered.' }, { component: 'storage', unit: 'GB-month', driver: 'gb', note: 'S3 storage.' }, { component: 'api', unit: '1,000 requests', driver: 'requests', note: 'S3 requests by the collector.' }],
    enable: ['cloudtrail:PutEventSelectors'], read: ['s3:ListBucket', 's3:GetObject'], regions: 'Selectors apply per trail; scope them to the buckets and functions that matter.', regions_ar: 'المحددات لكل مسار؛ احصرها في الحاويات والدوال المهمة.', multi_region: true, url: 'https://aws.amazon.com/cloudtrail/pricing/' },
  { id: 'aws-vpc-flow', provider: 'aws', title: 'VPC Flow Logs', title_ar: 'سجلات تدفق VPC', default_state: 'off', provider_record: 'Not recorded unless enabled.', provider_record_ar: 'لا تُسجل إلا إذا فُعّلت.',
    billing: [{ component: 'ingest', unit: 'GB', driver: 'gb', note: 'Vended logs: data ingestion and archival charges per GB, tiered per month (CloudWatch Logs or S3 delivery).' }, { component: 'storage', unit: 'GB-month', driver: 'gb', note: 'Destination storage.' }, { component: 'api', unit: '1,000 requests', driver: 'requests', note: 'Collector reads.' }],
    enable: ['ec2:CreateFlowLogs', 'logs:CreateLogDelivery', 'iam:PassRole (CloudWatch Logs destination)'], read: ['s3:GetObject or logs:FilterLogEvents'], regions: 'Per VPC, subnet or interface in each Region.', regions_ar: 'لكل VPC أو شبكة فرعية أو واجهة في كل منطقة.', multi_region: false, url: 'https://aws.amazon.com/cloudwatch/pricing/' },
  { id: 'aws-guardduty', provider: 'aws', title: 'GuardDuty findings', title_ar: 'نتائج GuardDuty', default_state: 'off', provider_record: 'Findings only exist after a detector is enabled.', provider_record_ar: 'لا توجد نتائج قبل تفعيل الكاشف.',
    billing: [{ component: 'analysis', unit: '1M events', driver: 'events', note: 'Priced on volume analyzed: CloudTrail management events per million, VPC Flow and DNS logs per GB; a 30-day free trial per account and Region.' }],
    enable: ['guardduty:CreateDetector'], read: ['guardduty:ListFindings', 'guardduty:GetFindings'], regions: 'Enable in every Region; GuardDuty is Regional.', regions_ar: 'فعّله في كل منطقة؛ GuardDuty خدمة إقليمية.', multi_region: false, url: 'https://aws.amazon.com/guardduty/pricing/' },
  { id: 'azure-activity-log', provider: 'azure', title: 'Azure Activity log (diagnostic setting)', title_ar: 'سجل نشاط Azure (إعداد تشخيص)', default_state: 'free-record',
    provider_record: 'Azure keeps Activity log events 90 days at no charge; ingestion into Log Analytics is free and only retention beyond 90 days is billed.', provider_record_ar: 'يحفظ Azure أحداث سجل النشاط 90 يومًا دون رسوم؛ واستيعابها في Log Analytics مجاني، ولا يُحاسب إلا الاحتفاظ بعد 90 يومًا.',
    billing: [{ component: 'storage', unit: 'GB-month', driver: 'gb', note: 'Only retention past 90 days, or the storage account or Event Hubs destination.' }, { component: 'api', unit: '1,000 requests', driver: 'requests', note: 'Collector reads.' }],
    enable: ['Microsoft.Insights/diagnosticSettings/write'], read: ['Reader or Log Analytics Reader'], regions: 'Subscription scope; one setting per subscription.', regions_ar: 'على مستوى الاشتراك؛ إعداد واحد لكل اشتراك.', multi_region: false, url: 'https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/activity-log' },
  { id: 'azure-vnet-flow', provider: 'azure', title: 'VNet flow logs', title_ar: 'سجلات تدفق VNet', default_state: 'off', provider_record: 'Not recorded unless enabled.', provider_record_ar: 'لا تُسجل إلا إذا فُعّلت.',
    billing: [{ component: 'ingest', unit: 'GB', driver: 'gb', free_gb_month: 5, note: 'Charged per GB of network flow logs collected, 5 GB per month per subscription free; traffic analytics is extra with no free tier.' }, { component: 'storage', unit: 'GB-month', driver: 'gb', note: 'Blob storage billed separately.' }, { component: 'api', unit: '10,000 operations', driver: 'requests', note: 'Blob reads by the collector.' }],
    enable: ['Network Contributor on Network Watcher', 'Storage account write'], read: ['Storage Blob Data Reader'], regions: 'Per virtual network, in each region with a Network Watcher.', regions_ar: 'لكل شبكة افتراضية، في كل منطقة فيها Network Watcher.', multi_region: false, url: 'https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview' },
  { id: 'gcp-admin-activity', provider: 'gcp', title: 'Admin Activity audit logs', title_ar: 'سجلات تدقيق Admin Activity', default_state: 'always-on',
    provider_record: 'Always written and cannot be disabled; kept 400 days in the _Required bucket with no charge.', provider_record_ar: 'تُكتب دائمًا ولا يمكن تعطيلها؛ وتُحفظ 400 يوم في حاوية _Required دون رسوم.',
    billing: [{ component: 'api', unit: '1,000 requests', driver: 'requests', note: 'Logging API reads by the collector (subject to quotas).' }], enable: [], read: ['roles/logging.viewer'], regions: 'Per project; an organization sink covers all projects.', regions_ar: 'لكل مشروع؛ والمصرف على مستوى المؤسسة يغطي كل المشاريع.', multi_region: false, url: 'https://cloud.google.com/logging/docs/audit' },
  { id: 'gcp-data-access', provider: 'gcp', title: 'Data Access audit logs', title_ar: 'سجلات تدقيق Data Access', default_state: 'off',
    provider_record: 'Disabled by default except BigQuery, because they can be very large.', provider_record_ar: 'معطلة افتراضيًا عدا BigQuery، لأن حجمها قد يكون كبيرًا جدًا.',
    billing: [{ component: 'ingest', unit: 'GiB', driver: 'gb', free_gb_month: 50, note: 'Cloud Logging storage per GiB, first 50 GiB per project per month free, includes 30 days.' }, { component: 'storage', unit: 'GiB-month', driver: 'gb', note: 'Retention beyond 30 days per GiB per month.' }],
    enable: ['resourcemanager.projects.setIamPolicy (audit config)'], read: ['roles/logging.privateLogViewer'], regions: 'Per project and service; enable only the services that matter.', regions_ar: 'لكل مشروع وخدمة؛ فعّل الخدمات المهمة فقط.', multi_region: false, url: 'https://cloud.google.com/logging/pricing' },
  { id: 'gcp-vpc-flow', provider: 'gcp', title: 'VPC Flow Logs', title_ar: 'سجلات تدفق VPC', default_state: 'off', provider_record: 'Not recorded unless enabled.', provider_record_ar: 'لا تُسجل إلا إذا فُعّلت.',
    billing: [{ component: 'ingest', unit: 'GiB', driver: 'gb', note: 'Sent to Logging, generation charges are waived and vended network log storage is billed per GiB with no free allotment; sampling and the aggregation interval reduce volume.' }, { component: 'storage', unit: 'GiB-month', driver: 'gb', note: 'Retention beyond 30 days.' }],
    enable: ['compute.subnetworks.update'], read: ['roles/logging.viewer'], regions: 'Per subnet in each region; billed to the project of the resource.', regions_ar: 'لكل شبكة فرعية في كل منطقة؛ ويُحاسب مشروع المورد.', multi_region: false, url: 'https://cloud.google.com/logging/pricing' },
];
export const STOP_GUIDANCE = { aws: 'Stop CyberGuard first (revoke the source); keep the trail and its first free management copy so the account record continues.', azure: 'Stop CyberGuard first; the Activity log keeps 90 days at no charge whether or not the diagnostic setting stays.', gcp: 'Stop CyberGuard first; Admin Activity logs keep 400 days in _Required regardless.' };
export const STOP_GUIDANCE_AR = { aws: 'أوقف CyberGuard أولًا (إلغاء المصدر)، وأبقِ المسار ونسخته المجانية لأحداث الإدارة ليستمر سجل الحساب.', azure: 'أوقف CyberGuard أولًا؛ يحفظ سجل النشاط 90 يومًا دون رسوم سواء بقي إعداد التشخيص أم لا.', gcp: 'أوقف CyberGuard أولًا؛ تبقى سجلات Admin Activity 400 يوم في _Required في كل الأحوال.' };

const num = (v, name, min, max, optional = true) => { if ((v === undefined || v === null || v === '') && optional) return null; const n = Number(v); fail(Number.isFinite(n) && n >= min && n <= max, 400, `invalid_${name}`); return n; };
const r2 = n => n === null ? null : Math.round(n * 100) / 100;

export function preview(input) {
  object(input, ['source', 'sample_events', 'sample_bytes', 'sample_hours', 'events_per_day', 'avg_event_bytes', 'regions', 'trail_multi_region', 'retention_days', 'poll_seconds', 'prices'], 'collection_preview');
  const src = CATALOG.find(c => c.id === input.source); fail(src, 400, 'unknown_collection_source');
  // Volume: a measured sample wins over declared rates.
  let events, bytes, basis;
  if (input.sample_events !== undefined && input.sample_events !== null) { const e = num(input.sample_events, 'sample_events', 1, 1e12, false), b = num(input.sample_bytes, 'sample_bytes', 1, 1e15, false), h = num(input.sample_hours, 'sample_hours', 1, 720, false); events = e * 24 / h; bytes = b / e; basis = 'measured-sample'; }
  else { events = num(input.events_per_day, 'events_per_day', 0, 1e12, false); bytes = num(input.avg_event_bytes, 'avg_event_bytes', 50, 100000, false); basis = 'declared'; }
  const regions = num(input.regions, 'regions', 1, 40) ?? 1, retention = num(input.retention_days, 'retention_days', 1, 3650) ?? 30, poll = num(input.poll_seconds, 'poll_seconds', 60, 86400) ?? 300;
  const eventsMonth = events * 30, gbMonth = events * bytes * 30 / 1024 ** 3, requestsMonth = Math.ceil(30 * 86400 / poll) * regions * 2;
  const prices = input.prices || {}; fail(typeof prices === 'object' && !Array.isArray(prices), 400, 'invalid_prices');
  const price = k => num(prices[k], `price_${k}`, 0, 1e6);
  const units = { events: { '100k events': eventsMonth / 1e5, '1M events': eventsMonth / 1e6 }, gb: gbMonth, requests: { '1,000 requests': requestsMonth / 1000, '10,000 operations': requestsMonth / 10000 } };
  const lines = [...src.billing, EGRESS[src.provider]].map(b => {
    let qty = b.component === 'egress' ? gbMonth : b.driver === 'gb' ? (b.unit.includes('month') ? gbMonth * Math.min(retention, 3650) / 30 : gbMonth) : units[b.driver][b.unit];
    let free = b.component === 'egress' ? b.free : b.free_gb_month || 0;
    if (b.free_first_copy) free = qty; // first trail copy of management events is free
    if (b.unit.includes('month') && src.id === 'azure-activity-log') qty = gbMonth * Math.max(0, retention - 90) / 30;
    if (b.unit.includes('month') && src.provider === 'gcp' && b.component === 'storage') qty = gbMonth * Math.max(0, retention - 30) / 30;
    const billed = Math.max(0, qty - free), p = price(b.component);
    return { component: b.component, unit: b.unit, quantity: r2(qty), free_allowance: r2(Math.min(free, qty)), billed_quantity: r2(billed), unit_price: p, cost: p === null ? null : r2(billed * p), note: b.note || b.free_note, url: b.url || src.url };
  });
  const warnings = [];
  if (src.multi_region && regions > 1 && input.trail_multi_region === false) warnings.push({ code: 'single-region-trail', en: 'A single-Region trail would miss activity in the other Regions.', ar: 'مسار أحادي المنطقة سيفوته نشاط المناطق الأخرى.' });
  if (src.default_state === 'off' && gbMonth > 50) warnings.push({ code: 'high-volume', en: `About ${r2(gbMonth)} GB per month: start with a filter, sampling or a narrower scope.`, ar: `قرابة ${r2(gbMonth)} GB شهريًا: ابدأ بمرشح أو أخذ عينات أو نطاق أضيق.` });
  if (lines.every(l => l.unit_price === null)) warnings.push({ code: 'no-prices', en: 'No unit prices entered: costs are not computed. Enter the prices of your contract and Region.', ar: 'لم تُدخل أسعار وحدات، فلم تُحسب التكاليف. أدخل أسعار عقدك ومنطقتك.' });
  const priced = lines.filter(l => l.cost !== null);
  return { source: src.id, provider: src.provider, title: src.title, title_ar: src.title_ar, basis, volume: { events_per_day: Math.round(events), avg_event_bytes: Math.round(bytes), events_per_month: Math.round(eventsMonth), gb_per_month: r2(gbMonth), api_requests_per_month: requestsMonth, regions, retention_days: retention },
    lines, total: priced.length ? r2(priced.reduce((a, l) => a + l.cost, 0)) : null, total_complete: priced.length === lines.length, warnings, permissions: { enable: src.enable, read: src.read }, regions: src.regions, regions_ar: src.regions_ar,
    provider_record: src.provider_record, provider_record_ar: src.provider_record_ar, stop: STOP_GUIDANCE[src.provider], stop_ar: STOP_GUIDANCE_AR[src.provider] };
}

export class CollectionControl {
  constructor(store, { clock, retentionDays } = {}) { Object.assign(this, { s: store, clock: clock || (() => Date.now()), retentionDays: retentionDays || (() => 365) }); }
  now() { return new Date(this.clock()).toISOString(); }
  stopPreview(sourceId) {
    const src = this.s.require('SELECT id,name,kind,revoked,last_received FROM sources WHERE id=?', [sourceId]);
    const open = this.s.all("SELECT id,severity,evidence_ids FROM alerts WHERE source_id=? AND status!='resolved'", sourceId), openIds = new Set(open.map(a => a.id));
    const cases = this.s.all("SELECT id,title,status,alert_ids FROM cases WHERE status!='closed'").filter(c => JSON.parse(c.alert_ids).some(a => openIds.has(a)) || JSON.parse(c.alert_ids).some(a => this.s.get('SELECT 1 x FROM alerts WHERE id=? AND source_id=?', a, sourceId)));
    const protectedIds = new Set(open.flatMap(a => JSON.parse(a.evidence_ids || '[]'))), total = this.s.get('SELECT COUNT(*) n FROM events WHERE source_id=?', sourceId).n;
    const cutoff = new Date(this.clock() - this.retentionDays() * 86400000).toISOString(), soon = new Date(this.clock() - (this.retentionDays() - 30) * 86400000).toISOString();
    const expiring = this.s.get('SELECT COUNT(*) n FROM events WHERE source_id=? AND received_at<?', sourceId, soon).n;
    return { source: { id: src.id, name: src.name, revoked: !!src.revoked, last_received: src.last_received }, events_total: total, protected_events: protectedIds.size, open_alerts: open.length, open_cases: cases.map(c => ({ id: c.id, title: c.title, status: c.status })),
      retention_days: this.retentionDays(), events_reaching_retention_within_30_days: expiring, retention_cutoff: cutoff, blocked: cases.length > 0,
      statement: 'Stopping revokes the source credential only. No event is deleted: events linked to unresolved alerts stay exempt from retention purge, and everything else follows the retention policy already in force.',
      statement_ar: 'الإيقاف يلغي بيانات اعتماد المصدر فقط، ولا يُحذف أي حدث: الأحداث المرتبطة بتنبيهات غير محلولة تبقى مستثناة من حذف الاحتفاظ، والباقي يتبع سياسة الاحتفاظ السارية.' };
  }
  stop(actor, sourceId, input) {
    object(input, ['reason', 'authorization_ref', 'incident_owner_ref', 'confirm_no_deletion'], 'collection_stop'); fail(input.confirm_no_deletion === true, 400, 'confirm_no_deletion_required');
    const pre = this.stopPreview(sourceId); fail(!pre.source.revoked, 409, 'source_already_stopped');
    const reason = text(input.reason, 'stop_reason', 1000), authorization_ref = text(input.authorization_ref, 'stop_authorization_ref', 200), owner = text(input.incident_owner_ref, 'incident_owner_ref', 200, true) || null;
    fail(!pre.blocked || owner, 409, 'open_incident_from_source_requires_incident_owner');
    const id = randomUUID(), at = this.now();
    this.s.transaction(() => {
      this.s.run('UPDATE sources SET token_hash=NULL,revoked=1 WHERE id=?', sourceId);
      this.s.run('INSERT INTO collection_stops(id,source_id,stopped_by,stopped_at,reason,authorization_ref,incident_owner_ref,events_total,protected_events,open_alerts,open_cases) VALUES (?,?,?,?,?,?,?,?,?,?,?)', id, sourceId, actor, at, reason, authorization_ref, owner, pre.events_total, pre.protected_events, pre.open_alerts, pre.open_cases.length);
      this.s.audit(actor, 'source.collection-stopped', sourceId, { stop_id: id, authorization_ref, incident_owner_ref: owner, events_total: pre.events_total, protected_events: pre.protected_events, open_cases: pre.open_cases.length, deleted_events: 0 }, at);
    });
    return { id, source_id: sourceId, stopped_at: at, deleted_events: 0, ...pre, source: { ...pre.source, revoked: true } };
  }
  view() {
    return { catalog: CATALOG.map(({ billing, ...c }) => ({ ...c, billing: billing.map(b => ({ component: b.component, unit: b.unit, note: b.note })) })), egress: EGRESS,
      sources: this.s.all('SELECT id,name,kind,revoked,last_received FROM sources ORDER BY name').map(s => ({ ...s, revoked: !!s.revoked, ...(() => { const p = this.stopPreview(s.id); return { events_total: p.events_total, protected_events: p.protected_events, open_alerts: p.open_alerts, open_cases: p.open_cases.length }; })() })),
      stops: this.s.all('SELECT c.*,s.name source_name FROM collection_stops c JOIN sources s ON s.id=c.source_id ORDER BY stopped_at DESC LIMIT 100'),
      claim: 'Before a cloud source is enabled, CyberGuard shows its expected volume, billed components with their official units and free allowances, the permissions to enable and to read it, and its regional scope. Costs are computed only from unit prices the owner enters. Stopping collection revokes the source and deletes nothing.',
      claim_ar: 'قبل تفعيل مصدر سحابي يعرض CyberGuard حجمه المتوقع، ومكونات الفوترة بوحداتها الرسمية وحصصها المجانية، والصلاحيات اللازمة لتفعيله ولقراءته، ونطاقه الإقليمي. ولا تُحسب التكاليف إلا من أسعار وحدات يدخلها المالك. وإيقاف الجمع يلغي المصدر ولا يحذف شيئًا.' };
  }
}
