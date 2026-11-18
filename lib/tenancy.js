// CG-059 Multi-tenant operation. Each tenant (customer) runs as its own CyberGuard instance with its own data
// directory, database, secret-store key, audit chain, users, sessions and service account (deploy/linux/cyberguard@.service,
// scripts/tenants.js), so no query, cache or key is shared between tenants. Inside an instance this module enforces the
// tenant's own resource limits and retention policy, both changed only by an administrator with recent MFA and audited.
import fs from 'node:fs';
import { fail, object, integer } from './common.js';

export const POLICY_DEFAULTS = { retention_days: 365, max_events_per_day: 500000, max_sources: 100, max_assets: 20000, max_db_mb: 10240 };
const BOUNDS = { retention_days: [7, 3650], max_events_per_day: [100, 50000000], max_sources: [1, 100], max_assets: [1, 1000000], max_db_mb: [64, 1048576] };
// Activity streams that age out. State records (asset context, risks, plans, inventories, snapshots) are kept: each is the
// latest known state of something, not a log line, and removing it would silently change what CyberGuard reports.
export const RETENTION_KINDS = ['log.batch', 'auth.failed', 'identity.signin_activity', 'remote.attempt', 'remote.authenticated', 'remote.active', 'remote.ended', 'discovery.observed'];
export const TENANT_ID = /^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$/;

export class TenantPolicy {
  constructor(store, { clock, tenant, dbFile, domain }) { this.s = store; this.clock = clock || (() => Date.now()); this.tenant = tenant; this.dbFile = dbFile; this.domain = domain; this.lastRetention = 0; }
  now() { return new Date(this.clock()).toISOString(); }
  get() {
    const row = this.s.get('SELECT * FROM tenant_policy WHERE id=1');
    const values = Object.fromEntries(Object.keys(POLICY_DEFAULTS).map(k => [k, row ? row[k] : POLICY_DEFAULTS[k]]));
    return { tenant: this.tenant, ...values, source: row ? 'administrator' : 'default', updated_by: row?.updated_by || null, updated_at: row?.updated_at || null, retention_kinds: RETENTION_KINDS };
  }
  set(actor, input) {
    object(input, Object.keys(POLICY_DEFAULTS), 'tenant_policy');
    const next = { ...this.get() };
    for (const [k, [min, max]] of Object.entries(BOUNDS)) if (input[k] !== undefined) next[k] = integer(input[k], min, max, k);
    const usage = this.usage();
    fail(next.max_sources >= usage.sources, 409, 'tenant_limit_below_current_sources');
    fail(next.max_assets >= usage.assets, 409, 'tenant_limit_below_current_assets');
    this.s.transaction(() => {
      this.s.run('INSERT INTO tenant_policy(id,retention_days,max_events_per_day,max_sources,max_assets,max_db_mb,updated_by,updated_at) VALUES (1,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET retention_days=excluded.retention_days,max_events_per_day=excluded.max_events_per_day,max_sources=excluded.max_sources,max_assets=excluded.max_assets,max_db_mb=excluded.max_db_mb,updated_by=excluded.updated_by,updated_at=excluded.updated_at', next.retention_days, next.max_events_per_day, next.max_sources, next.max_assets, next.max_db_mb, actor, this.now());
      this.s.audit(actor, 'tenant.policy_changed', this.tenant, Object.fromEntries(Object.keys(POLICY_DEFAULTS).map(k => [k, next[k]])), this.now());
    });
    return this.get();
  }
  dbMegabytes() {
    if (!this.dbFile || this.dbFile === ':memory:') return 0;
    let bytes = 0; for (const f of [this.dbFile, `${this.dbFile}-wal`]) { try { bytes += fs.statSync(f).size; } catch {} }
    return Math.round(bytes / 1048576 * 100) / 100;
  }
  usage() {
    const day = this.now().slice(0, 10) + 'T00:00:00.000Z';
    return { events_today: this.s.get('SELECT COUNT(*) n FROM events WHERE received_at>=?', day).n, sources: this.s.get('SELECT COUNT(*) n FROM sources WHERE revoked=0').n, assets: this.s.get('SELECT COUNT(*) n FROM assets').n, events_total: this.s.get('SELECT COUNT(*) n FROM events').n, db_mb: this.dbMegabytes() };
  }
  // Called by the domain: before a batch (storage), inside the batch transaction (daily events and assets) and before a source.
  beforeIngest() { const p = this.get(); fail(this.dbMegabytes() < p.max_db_mb, 507, 'tenant_storage_limit_exceeded'); }
  afterIngest() { const p = this.get(), u = this.usage(); fail(u.events_today <= p.max_events_per_day, 429, 'tenant_event_quota_exceeded'); fail(u.assets <= p.max_assets, 429, 'tenant_asset_limit_exceeded'); }
  beforeSource() { const p = this.get(); fail(this.usage().sources < p.max_sources, 409, 'tenant_source_limit_exceeded'); }
  limitHit(code, sourceId) {
    const day = this.now().slice(0, 10), label = { tenant_event_quota_exceeded: 'daily event quota', tenant_asset_limit_exceeded: 'asset limit', tenant_storage_limit_exceeded: 'storage limit' }[code] || code;
    const labelAr = { tenant_event_quota_exceeded: 'حصة الأحداث اليومية', tenant_asset_limit_exceeded: 'حد الأصول', tenant_storage_limit_exceeded: 'حد التخزين' }[code] || code;
    this.domain?.alert({ key: `CG-TENANT-LIMIT-059:${code}:${day}`, sourceId, rule: 'CG-TENANT-LIMIT-059', severity: 'high', title: `Tenant ${label} reached; telemetry refused / بلغ المستأجر ${labelAr}؛ رُفضت البيانات: ${this.tenant}` });
    this.s.audit('tenant-policy', 'tenant.limit_reached', this.tenant, { code, source_id: sourceId || null }, this.now());
  }
  applyRetention(actor = 'retention-service') {
    const p = this.get(), cutoff = new Date(this.clock() - p.retention_days * 86400000).toISOString();
    const result = this.s.transaction(() => {
      const r = this.s.run(`DELETE FROM events WHERE kind IN (${RETENTION_KINDS.map(() => '?').join(',')}) AND received_at<? AND id NOT IN (SELECT j.value FROM alerts a, json_each(a.evidence_ids) j WHERE a.status!='resolved')`, ...RETENTION_KINDS, cutoff);
      const deleted = Number(r.changes);
      if (deleted) this.s.audit(actor, 'retention.applied', this.tenant, { deleted_events: deleted, cutoff, retention_days: p.retention_days }, this.now());
      return { deleted_events: deleted, cutoff, retention_days: p.retention_days, kept: 'state records, evidence of unresolved alerts and the audit chain' };
    });
    this.lastRetention = this.clock(); return result;
  }
  maybeRetention() { if (this.clock() - this.lastRetention >= 3600000) return this.applyRetention(); return null; }
  status() {
    const policy = this.get(), usage = this.usage(), pct = (a, b) => Math.round(a / b * 1000) / 10;
    return { policy, usage, utilisation: { events_today: pct(usage.events_today, policy.max_events_per_day), sources: pct(usage.sources, policy.max_sources), assets: pct(usage.assets, policy.max_assets), storage: pct(usage.db_mb, policy.max_db_mb) },
      isolation: { model: 'one instance per tenant', data_directory: 'own database, secret-store key, setup token and TLS material', audit_chain: 'own hash chain', identities: 'own users, sessions, MFA and SSO configuration', service_account: 'systemd DynamicUser per tenant (cyberguard@<tenant>.service)', cross_tenant_users: 'refused (tenant_scope_mismatch)' },
      claim: 'Each tenant runs as a separate CyberGuard instance with its own data directory, database, keys, audit chain, users and service account; nothing is shared between tenants. Within the instance, the tenant administrator sets resource limits and retention; telemetry over a limit is refused with an alert instead of being dropped silently, and only activity streams age out while state records, evidence of unresolved alerts and the audit chain are kept.',
      claim_ar: 'يعمل كل مستأجر كنسخة CyberGuard مستقلة بمجلد بيانات وقاعدة بيانات ومفاتيح وسلسلة تدقيق ومستخدمين وحساب خدمة خاصة به؛ ولا يُشارك شيء بين المستأجرين. داخل النسخة يحدد مسؤول المستأجر حدود الموارد ومدة الاحتفاظ؛ والبيانات فوق الحد تُرفض مع تنبيه بدل إسقاطها بصمت، ولا يُحذف بانتهاء المدة إلا سجلات النشاط، وتبقى سجلات الحالة وأدلة التنبيهات المفتوحة وسلسلة التدقيق.' };
  }
}
