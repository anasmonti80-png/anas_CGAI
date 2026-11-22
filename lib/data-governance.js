// CG-126 Multi-tenant isolation and data residency. Builds on CG-059 (one instance, data directory, database, keys and
// service account per tenant):
//  - the database is bound to its tenant on first start; an instance started for another tenant refuses to open it,
//    so a misconfigured path can never mix two customers' data;
//  - a residency map lists where each class of data actually lives (database, evidence, encryption keys, signing key,
//    backups) with its size, whether it stays inside the tenant data directory, and the region declared for it;
//  - the right to export: a complete, hashed and audited export of the tenant data;
//  - the right to delete: erasure of one person's records requested by one administrator and approved by another, who
//    re-enters the identifier (only its hash is stored); records linked to open cases are kept under legal hold.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fail, text, choice } from './common.js';

const sha = v => createHash('sha256').update(v).digest('hex'), REGIONS = ['saudi-arabia', 'gcc', 'outside-gcc', 'undeclared'];
export const DATA_CLASSES = ['database', 'evidence', 'secret-key', 'mfa-key', 'rule-signing-key', 'backups'];

export function bindTenant(store, tenant) {
  const row = store.get('SELECT tenant FROM instance_identity WHERE id=1');
  if (!row) { store.run('INSERT INTO instance_identity(id,tenant,bound_at) VALUES (1,?,?)', tenant, new Date().toISOString()); return tenant; }
  if (row.tenant !== tenant) throw new Error(`tenant_data_mismatch: this database belongs to tenant ${row.tenant}, not ${tenant}`);
  return tenant;
}
const sizeOf = p => { if (!fs.existsSync(p)) return null; const st = fs.statSync(p); if (!st.isDirectory()) return st.size; return fs.readdirSync(p).reduce((n, f) => n + (sizeOf(path.join(p, f)) || 0), 0); };
const inside = (dir, p) => { const r = path.relative(path.resolve(dir), path.resolve(p)); return Boolean(r) && !r.startsWith('..') && !path.isAbsolute(r); };

export class DataGovernance {
  constructor(store, { clock, tenant, dataDir, dbFile }) { Object.assign(this, { s: store, clock: clock || (() => Date.now()), tenant, dataDir, dbFile }); }
  now() { return new Date(this.clock()).toISOString(); }
  locations() {
    const declared = Object.fromEntries(this.s.all('SELECT data_class,region FROM data_residency').map(r => [r.data_class, r.region]));
    const paths = { database: this.dbFile, evidence: path.join(this.dataDir, 'evidence'), 'secret-key': `${this.dbFile}.secret-key`, 'mfa-key': `${this.dbFile}.mfa-key`, 'rule-signing-key': path.join(this.dataDir, 'rule-signing-key.pem'), backups: process.env.CG_BACKUP_DIR || path.join(this.dataDir, 'backups') };
    return DATA_CLASSES.map(c => ({ data_class: c, path: path.relative(this.dataDir, paths[c]) || '.', exists: fs.existsSync(paths[c]), bytes: sizeOf(paths[c]), inside_tenant_directory: inside(this.dataDir, paths[c]), region: declared[c] || 'undeclared' }));
  }
  declareRegion(actor, input) {
    const data_class = choice(input.data_class, DATA_CLASSES, 'data_class'), region = choice(input.region, REGIONS.filter(r => r !== 'undeclared'), 'region');
    this.s.run('INSERT INTO data_residency(data_class,region,declared_by,declared_at) VALUES (?,?,?,?) ON CONFLICT(data_class) DO UPDATE SET region=excluded.region,declared_by=excluded.declared_by,declared_at=excluded.declared_at', data_class, region, actor, this.now());
    this.s.audit(actor, 'residency.declared', data_class, { region }, this.now()); return this.view();
  }
  // Complete export of the tenant data: one JSON object per line, ending with a manifest of counts and hashes.
  exportAll(actor) {
    const tables = ['assets', 'sources', 'events', 'alerts', 'cases', 'actions', 'evidence_items', 'evidence_custody', 'audit'], lines = [], counts = {}, hash = createHash('sha256');
    const push = o => { const l = JSON.stringify(o); lines.push(l); hash.update(l + '\n'); };
    for (const t of tables) { const rows = this.s.all(`SELECT * FROM ${t}`); counts[t] = rows.length; for (const r of rows) push({ table: t, row: t === 'sources' ? { ...r, token_hash: undefined } : r }); }
    const manifest = { schema_version: 'cg.tenant-export/1', tenant: this.tenant, exported_at: this.now(), exported_by: actor, counts, sha256: hash.digest('hex'), audit_chain: this.s.verifyAudit(), evidence_files: 'evidence bytes are exported with /api/evidence/<id>/content per item' };
    lines.push(JSON.stringify({ manifest })); this.s.audit(actor, 'tenant.exported', this.tenant, { counts, sha256: manifest.sha256 }, this.now());
    return { body: lines.join('\n') + '\n', manifest };
  }
  matches(identifier) {
    const id = identifier.toLowerCase(), hit = v => typeof v === 'string' ? v.toLowerCase() === id : Array.isArray(v) ? v.some(hit) : v && typeof v === 'object' ? Object.values(v).some(hit) : false;
    const held = new Set(this.s.all("SELECT alert_ids FROM cases WHERE status<>'closed'").flatMap(c => JSON.parse(c.alert_ids)).flatMap(a => JSON.parse(this.s.get('SELECT evidence_ids FROM alerts WHERE id=?', a)?.evidence_ids || '[]')));
    const like = `%${identifier.replace(/[%_]/g, '')}%`, rows = this.s.all('SELECT id,payload FROM events WHERE payload LIKE ? COLLATE NOCASE', like).filter(r => hit(JSON.parse(r.payload).details));
    return { erasable: rows.filter(r => !held.has(r.id)).map(r => r.id), held: rows.filter(r => held.has(r.id)).map(r => r.id) };
  }
  requestErasure(actor, input) {
    const identifier = text(input.identifier, 'erasure_identifier', 300), reason = text(input.reason, 'erasure_reason', 1000), m = this.matches(identifier), id = randomUUID();
    fail(identifier.length >= 3, 400, 'erasure_identifier_too_short');
    this.s.run('INSERT INTO erasure_requests(id,identifier_sha256,reason,requested_by,requested_at,status,matched,held) VALUES (?,?,?,?,?,?,?,?)', id, sha(identifier.toLowerCase()), reason, actor, this.now(), 'pending-approval', m.erasable.length, m.held.length);
    this.s.audit(actor, 'erasure.requested', id, { identifier_sha256: sha(identifier.toLowerCase()), matched: m.erasable.length, held: m.held.length }, this.now());
    return this.erasure(id);
  }
  approveErasure(actor, id, input) {
    const r = this.s.get('SELECT * FROM erasure_requests WHERE id=?', id); fail(r, 404, 'erasure_request_not_found'); fail(r.status === 'pending-approval', 409, 'erasure_not_pending');
    fail(actor !== r.requested_by, 403, 'independent_approver_required'); const identifier = text(input.identifier, 'erasure_identifier', 300); fail(sha(identifier.toLowerCase()) === r.identifier_sha256, 400, 'erasure_identifier_does_not_match_request');
    const m = this.matches(identifier);
    this.s.transaction(() => { for (const e of m.erasable) this.s.run('DELETE FROM events WHERE id=?', e); this.s.run("UPDATE erasure_requests SET status='completed',approved_by=?,completed_at=?,erased=?,held=? WHERE id=?", actor, this.now(), m.erasable.length, m.held.length, id); });
    this.s.audit(actor, 'erasure.completed', id, { identifier_sha256: r.identifier_sha256, erased: m.erasable.length, held: m.held.length }, this.now()); return this.erasure(id);
  }
  erasure(id) { return this.s.get('SELECT id,identifier_sha256,reason,requested_by,requested_at,status,approved_by,completed_at,matched,erased,held FROM erasure_requests WHERE id=?', id); }
  view() {
    const loc = this.locations();
    return { tenant: this.tenant, bound: this.s.get('SELECT tenant,bound_at FROM instance_identity WHERE id=1') || null, locations: loc, all_inside_tenant_directory: loc.filter(l => l.data_class !== 'backups' || l.exists).every(l => l.inside_tenant_directory), undeclared_regions: loc.filter(l => l.region === 'undeclared').map(l => l.data_class),
      retention: this.s.get('SELECT retention_days FROM tenant_policy WHERE id=1')?.retention_days ?? 365, erasures: this.s.all('SELECT id,status,requested_at,completed_at,matched,erased,held FROM erasure_requests ORDER BY requested_at DESC LIMIT 50'),
      claim: 'Each tenant has its own instance and data directory; the database is bound to its tenant and refuses another one. The map shows where each class of data lives and its declared region; data can be exported in full, and one person\'s records can be erased with two administrators while records in open cases stay under legal hold.',
      claim_ar: 'لكل عميل نسخة ومجلد بيانات خاص؛ وقاعدة البيانات مربوطة بعميلها وترفض غيره. الخريطة تبين مكان كل فئة بيانات ومنطقتها المعلنة؛ ويمكن تصدير البيانات كاملة، وحذف سجلات شخص بموافقة مسؤولين اثنين مع إبقاء سجلات الحالات المفتوحة تحت الحفظ القانوني.' };
  }
}
