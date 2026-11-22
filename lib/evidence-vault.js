// CG-114 Evidence integrity and chain of custody. Original evidence (a log export, a pcap, a memory or disk extract, a
// vendor report) is attached to a case byte for byte: content-addressed by SHA-256, written read-only once, with its
// original time, source, acquisition method and collector. Items are never changed: a redacted or extracted copy is a
// new derived item linked to its parent with the transformation stated. Every collection, access (with a stated
// purpose), export, derivation and verification is appended to a per-item SHA-256 hash chain that the database refuses
// to update or delete, and exported custody bundles are signed with the installation Ed25519 key.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fail, text, choice, timestamp, digest } from './common.js';
import { canonical } from './rule-signing.js';

export const MAX_EVIDENCE_BYTES = 50 * 1024 * 1024;
export const ACQUISITIONS = ['analyst-upload', 'collector-export', 'agent-collection', 'vendor-export', 'derived'];
const sha = b => createHash('sha256').update(b).digest('hex');
const recordHash = r => sha(canonical({ item_id: r.item_id, at: r.at, actor: r.actor, action: r.action, purpose: r.purpose, details: r.details, previous_hash: r.previous_hash }));

export class EvidenceVault {
  constructor(store, { dataDir, clock, signer, domain }) { Object.assign(this, { s: store, dir: path.join(dataDir, 'evidence'), clock: clock || (() => Date.now()), signer, domain }); }
  now() { return new Date(this.clock()).toISOString(); }
  file(hash) { return path.join(this.dir, hash); }
  custody(itemId) { return this.s.all('SELECT seq,item_id,at,actor,action,purpose,details,previous_hash,hash FROM evidence_custody WHERE item_id=? ORDER BY seq', itemId).map(r => ({ ...r, details: JSON.parse(r.details) })); }
  append(itemId, actor, action, purpose = null, details = {}) {
    const last = this.s.get('SELECT hash FROM evidence_custody WHERE item_id=? ORDER BY seq DESC LIMIT 1', itemId), r = { item_id: itemId, at: this.now(), actor, action, purpose, details, previous_hash: last?.hash || '0'.repeat(64) };
    r.hash = recordHash(r); this.s.run('INSERT INTO evidence_custody(item_id,at,actor,action,purpose,details,previous_hash,hash) VALUES (?,?,?,?,?,?,?,?)', itemId, r.at, actor, action, purpose, JSON.stringify(details), r.previous_hash, r.hash);
    this.s.audit(actor, `evidence.${action}`, itemId, { purpose, ...details }, r.at); return r;
  }
  store(bytes) { fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 }); const hash = sha(bytes), f = this.file(hash); if (!fs.existsSync(f)) { fs.writeFileSync(f, bytes, { mode: 0o400, flag: 'wx' }); } fail(sha(fs.readFileSync(f)) === hash, 500, 'evidence_write_verification_failed'); return hash; }
  get(id) { const r = this.s.get('SELECT * FROM evidence_items WHERE id=?', id); fail(r, 404, 'evidence_not_found'); return r; }
  // Collect original evidence for a case.
  collect(actor, caseId, meta, bytes) {
    fail(this.s.get('SELECT id FROM cases WHERE id=?', caseId), 404, 'case_not_found'); fail(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= MAX_EVIDENCE_BYTES, 400, 'evidence_size_out_of_range');
    const m = { name: text(meta.name, 'evidence_name', 260), media_type: text(meta.media_type || 'application/octet-stream', 'evidence_media_type', 100), source_ref: text(meta.source_ref, 'evidence_source_ref', 300), acquisition: choice(meta.acquisition, ACQUISITIONS.filter(a => a !== 'derived'), 'evidence_acquisition'), collected_at: timestamp(meta.collected_at, 'evidence_collected_at', this.clock()), collected_by: text(meta.collected_by || this.s.get('SELECT username FROM users WHERE id=?', actor)?.username || actor, 'evidence_collected_by', 200) };
    fail(/^[^\\/]+$/.test(m.name), 400, 'evidence_name_must_not_contain_paths');
    if (meta.expected_sha256 !== undefined && meta.expected_sha256 !== null && meta.expected_sha256 !== '') fail(String(meta.expected_sha256).toLowerCase() === sha(bytes), 409, 'evidence_hash_mismatch_with_source');
    return this.s.transaction(() => { const hash = this.store(bytes), id = randomUUID();
      this.s.run('INSERT INTO evidence_items(id,case_id,parent_id,name,media_type,size,sha256,source_ref,acquisition,collected_at,collected_by,received_at,received_by,transform) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', id, caseId, null, m.name, m.media_type, bytes.length, hash, m.source_ref, m.acquisition, m.collected_at, m.collected_by, this.now(), actor, null);
      this.append(id, actor, 'collected', null, { sha256: hash, size: bytes.length, source_ref: m.source_ref, acquisition: m.acquisition, collected_at: m.collected_at, collected_by: m.collected_by, source_hash_confirmed: Boolean(meta.expected_sha256) });
      return this.item(id); });
  }
  // A redacted, filtered or extracted copy: a new item tied to its parent; the original is never modified.
  derive(actor, parentId, meta, bytes) {
    const p = this.get(parentId); fail(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= MAX_EVIDENCE_BYTES, 400, 'evidence_size_out_of_range');
    const transform = text(meta.transform, 'evidence_transform', 500), name = text(meta.name, 'evidence_name', 260); fail(/^[^\\/]+$/.test(name), 400, 'evidence_name_must_not_contain_paths');
    return this.s.transaction(() => { const hash = this.store(bytes), id = randomUUID(); fail(hash !== p.sha256, 400, 'derived_copy_is_identical_to_parent');
      this.s.run('INSERT INTO evidence_items(id,case_id,parent_id,name,media_type,size,sha256,source_ref,acquisition,collected_at,collected_by,received_at,received_by,transform) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', id, p.case_id, p.id, name, text(meta.media_type || p.media_type, 'evidence_media_type', 100), bytes.length, hash, p.source_ref, 'derived', p.collected_at, p.collected_by, this.now(), actor, transform);
      this.append(id, actor, 'derived', null, { parent_id: p.id, parent_sha256: p.sha256, sha256: hash, transform }); this.append(p.id, actor, 'copy-derived', null, { child_id: id, transform });
      return this.item(id); });
  }
  // Reading the bytes needs a stated purpose and is recorded before the content is released.
  read(actor, id, purpose) {
    const p = text(purpose, 'access_purpose', 300); fail(p.length >= 5, 400, 'access_purpose_required'); const r = this.get(id), v = this.verify(actor, id, { record: false });
    fail(v.content_valid, 409, 'evidence_integrity_failure'); this.append(id, actor, 'accessed', p, { sha256: r.sha256 }); return { item: this.item(id), bytes: fs.readFileSync(this.file(r.sha256)) };
  }
  verify(actor, id, { record = true } = {}) {
    const r = this.get(id), f = this.file(r.sha256), exists = fs.existsSync(f), actual = exists ? sha(fs.readFileSync(f)) : null, chain = this.verifyChain(id), result = { item_id: id, expected_sha256: r.sha256, actual_sha256: actual, content_valid: actual === r.sha256, chain_valid: chain.valid, chain_records: chain.records, broken_at: chain.broken_at, checked_at: this.now() };
    if (record) { this.append(id, actor, result.content_valid && result.chain_valid ? 'verified' : 'integrity-failure', null, { content_valid: result.content_valid, chain_valid: result.chain_valid });
      if (!(result.content_valid && result.chain_valid)) this.domain?.alert({ key: `CG-EVIDENCE-TAMPER-114:${id}:${actual || 'missing'}`, assetId: null, rule: 'CG-EVIDENCE-TAMPER-114', severity: 'critical', title: `Evidence integrity failure: ${r.name} (${result.content_valid ? 'custody chain broken' : exists ? 'content hash differs' : 'content missing'}) / فشل سلامة الدليل: ${r.name}` }); }
    return result;
  }
  verifyChain(id) { let previous = '0'.repeat(64), n = 0; for (const r of this.custody(id)) { n++; if (r.previous_hash !== previous || recordHash(r) !== r.hash) return { valid: false, records: n, broken_at: r.seq }; previous = r.hash; } return { valid: n > 0, records: n, broken_at: null }; }
  item(id) { const r = this.get(id); return { ...r, custody: this.custody(id), derived: this.s.all('SELECT id,name,sha256,transform FROM evidence_items WHERE parent_id=?', id) }; }
  list(caseId) { return this.s.all(`SELECT * FROM evidence_items ${caseId ? 'WHERE case_id=?' : ''} ORDER BY received_at DESC LIMIT 500`, ...(caseId ? [caseId] : [])).map(r => ({ ...r, custody_records: this.s.get('SELECT COUNT(*) n FROM evidence_custody WHERE item_id=?', r.id).n, last_access: this.s.get("SELECT c.at,COALESCE(u.username,c.actor) actor,c.purpose FROM evidence_custody c LEFT JOIN users u ON u.id=c.actor WHERE c.item_id=? AND c.action='accessed' ORDER BY c.seq DESC LIMIT 1", r.id) || null })); }
  // Signed custody bundle for legal or external review; recorded as an export.
  exportCustody(actor, id, purpose) {
    const p = text(purpose, 'export_purpose', 300); fail(p.length >= 5, 400, 'export_purpose_required'); const v = this.verify(actor, id, { record: false }); fail(v.content_valid && v.chain_valid, 409, 'evidence_integrity_failure');
    this.append(id, actor, 'exported', p, {}); const { custody, derived, ...item } = this.item(id), bundle = { schema_version: 'cg.evidence-custody/1', exported_at: this.now(), exported_by: actor, item, custody, derived, verification: { ...v, chain_records: custody.length } };
    return { bundle, signature: this.signer.sign(bundle), signer_fingerprint: this.signer.fingerprint, public_key: this.signer.publicKeyPem };
  }
  // Integrity across the stored records: evidence items, event payloads against their stored hash, and the audit chain.
  integrity(actor) {
    const items = this.s.all('SELECT id FROM evidence_items').map(r => this.verify(actor, r.id, { record: false }));
    let checked = 0; const tampered = []; for (const e of this.s.all('SELECT id,kind,sanitized_sha256,payload FROM events ORDER BY received_at DESC LIMIT 20000')) { checked++; if (digest(e.payload) !== e.sanitized_sha256) tampered.push({ id: e.id, kind: e.kind }); }
    for (const t of tampered.slice(0, 50)) this.domain?.alert({ key: `CG-EVIDENCE-TAMPER-114:event:${t.id}`, assetId: null, rule: 'CG-EVIDENCE-TAMPER-114', severity: 'critical', title: `Stored event payload does not match its hash: ${t.kind} / سجل حدث مخزن لا يطابق بصمته` });
    const audit = this.s.verifyAudit();
    return { evidence: { items: items.length, valid: items.filter(i => i.content_valid && i.chain_valid).length, failures: items.filter(i => !(i.content_valid && i.chain_valid)) }, events: { checked, tampered }, audit_chain: audit,
      protections: ['evidence files written once, read-only, named by SHA-256', 'evidence items and custody records cannot be updated or deleted (database triggers)', 'stored events cannot be updated (database trigger)', 'per-item SHA-256 custody chain and global audit chain', 'custody exports signed with Ed25519'],
      claim: 'Original evidence is kept unchanged with its time, source, collector and SHA-256; derived copies are separate items; every access needs a purpose and is recorded in a hash chain, and records are protected against change.', claim_ar: 'يُحفظ الدليل الأصلي دون تغيير مع وقته ومصدره وجامعه وبصمة SHA-256؛ والنسخ المشتقة عناصر منفصلة؛ وكل اطلاع يحتاج غرضًا ويُسجل في سلسلة بصمات، والسجلات محمية من التعديل.' };
  }
}
