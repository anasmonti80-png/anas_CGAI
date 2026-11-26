// CG-138 Vendor adapter validation registry. Support is recorded per function (inventory read, firewall policy read,
// endpoint quarantine, ...) with the product, API, models, minimum firmware, licence, read/write/undo operations, the
// tests that exercise the adapter and the date it was last verified. A function is "lab-validated" only when the owner
// records a passing lab test on a model and firmware; otherwise it is "fixture-verified" (tested on the vendor's
// documented response shape) and never presented as tested on hardware. Nothing is claimed from a vendor name alone.
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { fail, text, choice } from './common.js';
import { compareVersions } from './device-config.js';

const FILE = 'docs/adapters/registry.json', DATE = /^\d{4}-\d{2}-\d{2}$/;
export const FUNCTIONS = ['inventory-read', 'topology-read', 'health-read', 'config-read', 'config-audit', 'firewall-policy-read', 'l2-security-read', 'bgp-read', 'wireless-read', 'endpoint-quarantine', 'port-shutdown', 'block-ip'];
export const FUNCTION_AR = { 'inventory-read': 'قراءة الجرد', 'topology-read': 'قراءة الطوبولوجيا', 'health-read': 'قراءة الصحة', 'config-read': 'قراءة الإعداد', 'config-audit': 'تدقيق الإعداد', 'firewall-policy-read': 'قراءة سياسة الجدار الناري', 'l2-security-read': 'قراءة أمن الطبقة الثانية', 'bgp-read': 'قراءة BGP', 'wireless-read': 'قراءة الشبكة اللاسلكية', 'endpoint-quarantine': 'حجر نقطة طرفية', 'port-shutdown': 'إغلاق منفذ', 'block-ip': 'حظر عنوان IP' };
export const loadRegistry = root => JSON.parse(fs.readFileSync(path.join(root, FILE), 'utf8'));

export function validateRegistry(reg, root) {
  const errors = [], ids = new Set(), err = (id, m) => errors.push(`${id}: ${m}`), testCache = new Map();
  const hasTest = (file, name) => { if (!testCache.has(file)) testCache.set(file, fs.existsSync(path.join(root, file)) ? fs.readFileSync(path.join(root, file), 'utf8') : null); const src = testCache.get(file); return !!src && (src.includes(`test('${name}'`) || src.includes(`test("${name}"`)); };
  if (reg?.schema_version !== 'cg.adapter-registry/1') errors.push('schema_version');
  for (const e of reg?.entries || []) {
    if (!/^A-\d{3}$/.test(e.id) || ids.has(e.id)) err(e.id, 'id must be unique A-NNN'); ids.add(e.id);
    for (const k of ['vendor', 'product', 'api', 'adapter_file']) if (typeof e[k] !== 'string' || e[k].length < 2) err(e.id, `${k} required`);
    if (!FUNCTIONS.includes(e.function)) err(e.id, 'function must be a known function, not a vendor-wide claim');
    if (!fs.existsSync(path.join(root, e.adapter_file || ''))) err(e.id, 'adapter_file missing');
    const ops = e.operations || {}; if (![ops.read, ops.write, ops.undo].every(x => typeof x === 'boolean')) err(e.id, 'operations read/write/undo required');
    if (ops.write && !ops.undo) err(e.id, 'a write operation must have an undo');
    if (!Array.isArray(e.models) || typeof e.firmware !== 'object' || typeof e.license !== 'object') err(e.id, 'models, firmware and license required');
    if (e.firmware?.min && !e.firmware.basis) err(e.id, 'a minimum firmware needs its basis');
    if (!['fixture', 'device-lab'].includes(e.evidence?.kind) || !e.evidence.tests?.length) err(e.id, 'evidence kind and tests required');
    for (const t of e.evidence?.tests || []) if (!hasTest(t.file, t.name)) err(e.id, `test not found: ${t.file}: ${t.name}`);
    if (!DATE.test(e.last_verified || '')) err(e.id, 'last_verified must be YYYY-MM-DD');
  }
  return errors;
}

export class AdapterRegistry {
  constructor(store, { root, clock }) { Object.assign(this, { s: store, root, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  labs(id) { return this.s.all('SELECT * FROM adapter_lab_validations WHERE adapter_id=? ORDER BY tested_at DESC', id); }
  status(e, reg) {
    const days = (this.clock() - Date.parse(`${e.last_verified}T00:00:00Z`)) / 86400000, stale = days > (reg.policy?.stale_after_days || 180);
    const passed = this.labs(e.id).filter(l => l.result === 'pass' && (this.clock() - Date.parse(l.tested_at)) / 86400000 <= (reg.policy?.stale_after_days || 180));
    return { status: passed.length ? 'lab-validated' : stale ? 'stale' : 'fixture-verified', lab: passed.map(l => ({ model: l.model, firmware: l.firmware, tested_at: l.tested_at, lab_ref: l.lab_ref })), days_since_verified: Math.floor(days) };
  }
  view() {
    const reg = loadRegistry(this.root), errors = validateRegistry(reg, this.root);
    const entries = reg.entries.map(e => ({ ...e, ...this.status(e, reg), function_ar: FUNCTION_AR[e.function], failed_labs: this.labs(e.id).filter(l => l.result === 'fail').length }));
    return { entries, valid: !errors.length, errors, policy: reg.policy, functions: FUNCTIONS.map(f => ({ function: f, function_ar: FUNCTION_AR[f] })),
      summary: { entries: entries.length, lab_validated: entries.filter(e => e.status === 'lab-validated').length, fixture_verified: entries.filter(e => e.status === 'fixture-verified').length, stale: entries.filter(e => e.status === 'stale').length, write_capable: entries.filter(e => e.operations.write).length },
      claim: reg.policy?.claim, claim_ar: 'الدعم يُعلن لكل وظيفة وطراز وإصدار مع مستوى الدليل، لا باسم الشركة. «متحقق بالعينات» يعني أن المحوّل اختُبر على شكل الاستجابة الموثق من المورّد لا على جهاز؛ ولا تصبح الوظيفة «متحققة في المختبر» إلا باختبار مسجل على طراز وإصدار.' };
  }
  // Is this function supported for this vendor, model and firmware, and on what evidence?
  supports(q) {
    const vendor = text(q?.vendor, 'adapter_vendor', 60).toLowerCase(), fn = choice(q.function, FUNCTIONS, 'adapter_function'), model = text(q.model, 'adapter_model', 120, true), firmware = text(q.firmware, 'adapter_firmware', 60, true);
    const reg = loadRegistry(this.root), list = reg.entries.filter(e => e.vendor === vendor && e.function === fn);
    if (!list.length) return { vendor, function: fn, answer: 'no-adapter', reasons: [reg.entries.some(e => e.vendor === vendor) ? `No adapter for ${fn} on ${vendor}; other functions exist, which is not support for this one` : `No adapter for ${vendor}`], reasons_ar: [reg.entries.some(e => e.vendor === vendor) ? `لا يوجد محوّل لهذه الوظيفة لدى ${vendor}؛ وجود وظائف أخرى لا يعني دعم هذه` : `لا يوجد محوّل للمورّد ${vendor}`], entries: [] };
    const out = list.map(e => { const st = this.status(e, reg), reasons = [], reasons_ar = [];
      if (e.firmware?.min && firmware && compareVersions(firmware, e.firmware.min) < 0) { reasons.push(`Firmware ${firmware} is older than ${e.firmware.min} (${e.firmware.basis})`); reasons_ar.push(`الإصدار ${firmware} أقدم من ${e.firmware.min}`); }
      if (e.firmware?.min && !firmware) { reasons.push(`Firmware not given; at least ${e.firmware.min} is needed`); reasons_ar.push(`الإصدار غير محدد؛ المطلوب ${e.firmware.min} على الأقل`); }
      const labHit = st.lab.find(l => (!model || l.model.toLowerCase() === model.toLowerCase()) && (!firmware || l.firmware === firmware));
      const level = reasons.length ? 'unsupported-firmware' : labHit ? 'lab-validated' : st.status === 'stale' ? 'stale' : 'fixture-verified';
      if (level === 'fixture-verified') { reasons.push(st.lab.length ? `Lab-validated on ${st.lab.map(l => `${l.model} ${l.firmware}`).join(', ')}, not on this model or firmware` : 'Tested on the documented response shape only, not on a device'); reasons_ar.push(st.lab.length ? 'متحقق في المختبر على طراز أو إصدار آخر' : 'مختبر على شكل الاستجابة الموثق فقط، لا على جهاز'); }
      return { id: e.id, product: e.product, api: e.api, operations: e.operations, license: e.license, level, reasons, reasons_ar, last_verified: e.last_verified }; });
    const rank = ['lab-validated', 'fixture-verified', 'stale', 'unsupported-firmware'], best = out.sort((a, b) => rank.indexOf(a.level) - rank.indexOf(b.level))[0];
    return { vendor, function: fn, model, firmware, answer: best.level, reasons: best.reasons, reasons_ar: best.reasons_ar, entries: out };
  }
  recordLab(actor, id, input) {
    const reg = loadRegistry(this.root), e = reg.entries.find(x => x.id === id); fail(e, 404, 'adapter_not_found');
    const row = { id: randomUUID(), adapter_id: id, model: text(input?.model, 'lab_model', 120), firmware: text(input.firmware, 'lab_firmware', 60), result: choice(input.result, ['pass', 'fail'], 'lab_result'), lab_ref: text(input.lab_ref, 'lab_ref', 200), notes: text(input.notes, 'lab_notes', 1000, true) || null, tested_at: input.tested_at ? (fail(Number.isFinite(Date.parse(input.tested_at)), 400, 'invalid_lab_tested_at'), new Date(Date.parse(input.tested_at)).toISOString()) : this.now(), recorded_by: actor, recorded_at: this.now() };
    fail(Number.isFinite(Date.parse(row.tested_at)) && Date.parse(row.tested_at) <= this.clock() + 300000, 400, 'invalid_lab_tested_at');
    if (e.operations.write) fail(input.undo_verified === true || row.result === 'fail', 400, 'write_adapter_lab_requires_verified_undo');
    this.s.transaction(() => { this.s.run('INSERT INTO adapter_lab_validations(id,adapter_id,model,firmware,result,lab_ref,notes,tested_at,recorded_by,recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?)', row.id, row.adapter_id, row.model, row.firmware, row.result, row.lab_ref, row.notes, row.tested_at, actor, row.recorded_at); this.s.audit(actor, 'adapter.lab_recorded', id, { model: row.model, firmware: row.firmware, result: row.result }, row.recorded_at); });
    return row;
  }
}
