// CG-125 Regulatory readiness before CyberGuard is offered as a managed SOC (MSOC) service in Saudi Arabia.
// Based on NCA NPMSOC-1:2024 and RFMSOC-1:2024 (see docs/research/MSOC_REGULATION_AR.md). The gate records what the
// provider declares (licence, tier, residency, qualified analysts, subcontracting, notifications, national integration)
// and refuses to register an external customer while a mandatory item is missing, expired or does not fit the customer.
// It does not decide that the provider is licensed: that is the NCA's decision.
import { randomUUID } from 'node:crypto';
import { fail, text, choice, timestamp } from './common.js';

const RESIDENCY = ['storage', 'processing', 'backups', 'encryption_keys'];
export const ITEMS = [
  ['licence', 'NCA MSOC licence recorded and valid', 'ترخيص خدمات المركز المُدار من الهيئة مسجل وساري'],
  ['tier-fit', 'Licence tier covers every customer (Tier 1 for government and CNI)', 'مستوى الترخيص يغطي كل العملاء (المستوى الأول للحكومة والبنية الحساسة)'],
  ['residency', 'Service, storage, processing, backups and encryption keys inside the Kingdom', 'الخدمة والتخزين والمعالجة والنسخ الاحتياطية ومفاتيح التشفير داخل المملكة'],
  ['analysts', 'NCA-qualified MSOC analysts employed', 'محللون حاصلون على شهادة تأهيل من الهيئة'],
  ['subcontracting', 'Subcontracting declared (none, or approved under the framework conditions)', 'التعاقد من الباطن معلن (لا يوجد أو وفق شروط الإطار)'],
  ['ownership-notice', 'Contact for notifying the NCA of ownership changes', 'جهة إبلاغ الهيئة بتغييرات الملكية'],
  ['national-integration', 'Integration with the national security operations centre', 'التكامل مع المركز الوطني لعمليات الأمن السيبراني'],
  ['pdpl', 'Personal data processing agreement per customer (PDPL)', 'اتفاقية معالجة بيانات شخصية لكل عميل (نظام حماية البيانات الشخصية)'],
];

export class MsocReadiness {
  constructor(store, { clock }) { Object.assign(this, { s: store, clock: clock || (() => Date.now()) }); }
  now() { return new Date(this.clock()).toISOString(); }
  provider() { const r = this.s.get('SELECT profile,saved_at,saved_by FROM msoc_provider ORDER BY id DESC LIMIT 1'); return r ? { ...JSON.parse(r.profile), saved_at: r.saved_at, saved_by: r.saved_by } : null; }
  saveProvider(actor, input) {
    const p = {
      licence_number: text(input.licence_number, 'licence_number', 100, true), licence_tier: input.licence_tier ? choice(input.licence_tier, ['tier-1', 'tier-2'], 'licence_tier') : null,
      licence_valid_until: input.licence_valid_until ? timestamp(input.licence_valid_until, 'licence_valid_until', this.clock() + 20 * 365 * 86400000) : null,
      residency: Object.fromEntries(RESIDENCY.map(k => [k, input.residency?.[k] ? choice(input.residency[k], ['saudi-arabia', 'outside-saudi-arabia'], `residency_${k}`) : null])),
      qualified_analysts: Number.isInteger(input.qualified_analysts) && input.qualified_analysts >= 0 ? input.qualified_analysts : 0,
      subcontracting: choice(input.subcontracting || 'undeclared', ['none', 'approved-under-framework', 'undeclared'], 'subcontracting'),
      ownership_notice_contact: text(input.ownership_notice_contact, 'ownership_notice_contact', 200, true), national_integration_ref: text(input.national_integration_ref, 'national_integration_ref', 200, true),
    };
    this.s.run('INSERT INTO msoc_provider(saved_at,saved_by,profile) VALUES (?,?,?)', this.now(), actor, JSON.stringify(p)); this.s.audit(actor, 'msoc.provider.saved', 'msoc', { licence_tier: p.licence_tier, residency: p.residency }, this.now()); return this.readiness();
  }
  customers() { return this.s.all('SELECT * FROM msoc_customers ORDER BY created_at').map(c => ({ ...c, pdpl_agreement: Boolean(c.pdpl_agreement_ref) })); }
  check(p, customers) {
    const st = (ok, reason, reason_ar) => ({ passed: Boolean(ok), reason, reason_ar }), now = this.now(), r = {};
    r.licence = !p?.licence_number || !p.licence_tier ? st(false, 'No licence number and tier recorded', 'لا يوجد رقم ترخيص ومستوى مسجل') : !p.licence_valid_until || p.licence_valid_until <= now ? st(false, 'The licence has expired or has no validity date', 'الترخيص منتهٍ أو بلا تاريخ صلاحية') : st(true, `Licence ${p.licence_number} (${p.licence_tier}) valid until ${p.licence_valid_until.slice(0, 10)}`, `الترخيص ${p.licence_number} (${p.licence_tier}) ساري حتى ${p.licence_valid_until.slice(0, 10)}`);
    const needTier1 = customers.filter(c => ['government', 'cni'].includes(c.sector)); r['tier-fit'] = needTier1.length && p?.licence_tier !== 'tier-1' ? st(false, `${needTier1.length} government or CNI customer(s) need a Tier 1 licence`, `${needTier1.length} عميل حكومي أو بنية حساسة يحتاج ترخيص المستوى الأول`) : st(true, 'The licence tier covers the registered customers', 'مستوى الترخيص يغطي العملاء المسجلين');
    const outside = RESIDENCY.filter(k => p?.residency?.[k] !== 'saudi-arabia'); r.residency = outside.length ? st(false, `Not declared inside the Kingdom: ${outside.join(', ')}`, `غير معلن داخل المملكة: ${outside.join('، ')}`) : st(true, 'All declared inside the Kingdom', 'كلها معلنة داخل المملكة');
    r.analysts = (p?.qualified_analysts || 0) > 0 ? st(true, `${p.qualified_analysts} qualified analyst(s)`, `${p.qualified_analysts} محلل مؤهل`) : st(false, 'No NCA-qualified analyst recorded', 'لا يوجد محلل مؤهل مسجل');
    r.subcontracting = p?.subcontracting && p.subcontracting !== 'undeclared' ? st(true, p.subcontracting, p.subcontracting === 'none' ? 'لا يوجد تعاقد من الباطن' : 'تعاقد من الباطن وفق شروط الإطار') : st(false, 'Subcontracting not declared', 'التعاقد من الباطن غير معلن');
    r['ownership-notice'] = p?.ownership_notice_contact ? st(true, 'Contact recorded', 'جهة الإبلاغ مسجلة') : st(false, 'No contact for ownership-change notices', 'لا توجد جهة لإبلاغ تغييرات الملكية');
    r['national-integration'] = p?.national_integration_ref ? st(true, `Reference ${p.national_integration_ref}`, `المرجع ${p.national_integration_ref}`) : st(false, 'No national SOC integration reference', 'لا يوجد مرجع للتكامل الوطني');
    const noPdpl = customers.filter(c => !c.pdpl_agreement_ref); r.pdpl = noPdpl.length ? st(false, `${noPdpl.length} customer(s) without a data processing agreement`, `${noPdpl.length} عميل دون اتفاقية معالجة بيانات`) : st(true, 'Every customer has a data processing agreement', 'لكل عميل اتفاقية معالجة بيانات');
    return ITEMS.map(([id, en, ar]) => ({ id, title: en, title_ar: ar, ...r[id] }));
  }
  readiness() {
    const p = this.provider(), customers = this.customers(), items = this.check(p, customers);
    return { provider: p, customers, items, may_offer_service: items.every(i => i.passed), research: 'docs/research/MSOC_REGULATION_AR.md', frameworks: ['NPMSOC-1:2024', 'RFMSOC-1:2024'],
      claim: 'Readiness gate, not a licence: it records what the provider declares against the NCA MSOC policy and licensing framework and blocks external customers while a mandatory item is missing. The NCA decides licensing.',
      claim_ar: 'بوابة جاهزية وليست ترخيصًا: تسجل ما يعلنه المزود مقابل السياسة الوطنية لمراكز العمليات المُدارة وإطار ترخيصها، وتمنع العملاء الخارجيين ما دام بند إلزامي ناقصًا. الترخيص قرار الهيئة.' };
  }
  addCustomer(actor, input) {
    const c = { id: randomUUID(), name: text(input.name, 'customer_name', 200), sector: choice(input.sector, ['government', 'cni', 'other'], 'customer_sector'), pdpl_agreement_ref: text(input.pdpl_agreement_ref, 'pdpl_agreement_ref', 200, true) };
    // The customer must fit the licence (tier) and every other mandatory item must already pass.
    const items = this.check(this.provider(), [...this.customers(), c]), missing = items.filter(i => !i.passed);
    fail(!missing.length, 409, `msoc_not_ready:${missing.map(i => i.id).join(',')}`);
    this.s.run('INSERT INTO msoc_customers(id,name,sector,pdpl_agreement_ref,created_by,created_at) VALUES (?,?,?,?,?,?)', c.id, c.name, c.sector, c.pdpl_agreement_ref, actor, this.now());
    this.s.audit(actor, 'msoc.customer.registered', c.id, { sector: c.sector }, this.now()); return this.readiness();
  }
}
