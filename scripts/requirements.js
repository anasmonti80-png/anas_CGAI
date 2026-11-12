import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {sourceFingerprint} from './source-fingerprint.js';

export const ROOT = fileURLToPath(new URL('../', import.meta.url));
const hash = s => createHash('sha256').update(s).digest('hex');
const read = p => fs.readFileSync(path.join(ROOT, p), 'utf8').replace(/\r\n/g, '\n');
const paths = {
  'requirements_v2.9': '01_SOURCE/Research_and_Requirements_v2.9.md',
  'gap_closure_v2.9': '01_SOURCE/Gap_Closure_Audit_v2.9.md',
  v3_master_prompt: '00_START_HERE/CyberGuard_AI_V3.0_MASTER_PROMPT_COMPLETE.md',
  v3_execution_prompt_only: '00_START_HERE/CyberGuard_AI_V3.0_EXECUTION_PROMPT_ONLY.md',
  v3_jsonl: '02_REQUIREMENTS/CG_Requirements_1440.jsonl',
};
export function sourceInventory() {
  const manifest = JSON.parse(read('00_START_HERE/Manifest_V3.0.json'));
  const files = Object.entries(paths).map(([key, p]) => ({ path: p, expected: manifest.sha256[key], actual: hash(read(p)) }));
  for (const f of files) if (f.expected !== f.actual) throw new Error(`Source checksum mismatch: ${f.path}`);
  const requirements = read(paths.v3_jsonl).trim().split('\n').map(JSON.parse);
  if (requirements.length !== 1440 || new Set(requirements.map(r => r.id)).size !== 1440) throw new Error('Expected 1440 unique requirements');
  const sourceLines = read(paths['requirements_v2.9']).split('\n');
  const master = read(paths.v3_master_prompt);
  for (const p of [paths['requirements_v2.9'], paths['gap_closure_v2.9']]) if (!master.includes(read(p))) throw new Error(`Master is missing verbatim source: ${p}`);
  const chunkNames = fs.readdirSync(path.join(ROOT, '02_REQUIREMENTS/CHUNKS')).filter(n => n.endsWith('.md')).sort();
  if (chunkNames.length !== 12) throw new Error('Expected 12 source chunks');
  const chunks = chunkNames.map(name => ({ name, text: read(`02_REQUIREMENTS/CHUNKS/${name}`) }));
  for (const [i, r] of requirements.entries()) {
    if (r.number !== i + 1 || Number(r.id.slice(3)) !== r.number) throw new Error(`Non-contiguous ID: ${r.id}`);
    if (sourceLines[r.source_line - 1] !== r.text_verbatim) throw new Error(`Source text mismatch: ${r.id}`);
    if (!chunks[Math.floor(i / 120)].text.includes(r.text_verbatim)) throw new Error(`Chunk text mismatch: ${r.id}`);
  }
  const history = fs.readdirSync(path.join(ROOT, '03_HISTORY')).filter(n => n.endsWith('.md')).sort().map(n => ({ path: `03_HISTORY/${n}`, sha256: hash(read(`03_HISTORY/${n}`)) }));
  return { requirements, files, chunks: chunks.map(c => ({ name: c.name, sha256: hash(c.text) })), history };
}

// Routing suggestions are deliberately not a semantic review or implementation claim.
const routes = [
  ['remote-access', /جلسات|Remote Access|إسناد الهويات|وصول.*بعيد/i, 'M2'],
  ['resilience', /تعافي|النسخ|استمرارية|Restore|Backup|Resilience/i, 'M6'],
  ['devsecops', /DevSecOps|سلسلة التوريد|حماية البرمجيات|توقيع البرمجيات|أمان التطبيقات/i, 'M6'],
  ['ai-policy', /ذكاء|الذكاء|AI|الأيجنتات الذكية|الوكلاء الذكي|القرارات/i, 'M5'],
  ['response', /استجابة|الاستجابة|إصلاح|الإصلاح|الأتمتة|الاحتواء|تغييرات|المنع والعزل/i, 'M3'],
  ['alerts', /إنذار|الإنذار|إنذارات|الإنذارات|صفارات|الصفارات|إشعارات|الإشعارات|التصعيد/i, 'M2'],
  ['assets', /اكتشاف|الاكتشاف|الجرد|جرد|التعرّف|التعرف|بصمات|هوية الجهاز|الأجهزة الجديدة|الرؤية|نوع الجهاز/i, 'M1'],
  ['identity', /الهوية|الهوي|Kerberos|Active Directory|AD CS|الوصول/i, 'M4'],
  ['endpoint', /Windows|Linux|macOS|الحماية|الأجهزة|الفدية|البرمجيات الضارة|محرك الحماية/i, 'M4'],
  ['vulnerability', /ثغرات|الثغرة|تقييم|الاختبارات والصلاحيات/i, 'M4'],
  ['cloud', /السحاب|السحابة|SaaS/i, 'M6'],
  ['network', /الشبك|السويتش|اللاسلك|المنافذ|DNS|NDR|OT\/ICS/i, 'M4'],
  ['detection', /الكشف|سجلات|السجلات|الأدلة|التحقيق|Threat|تهديد/i, 'M2'],
  ['ui', /التصميم|تجربة الاستخدام/i, 'M1'],
  ['platform', /الحوكمة|المنصة|البنية|المعمارية|التشفير|مفاتيح|الشهادات|الجاهزية|جودة|التوافق/i, 'M1'],
];
const refines = {1415:[1245],1418:[802],1419:[1264],1425:[1408],1429:[1270],1431:[1122],1433:[859,1296],1434:[860]};
export function classify(requirements) {
  const seen = new Map();
  return requirements.map(r => {
    const route = routes.find(([, regex]) => regex.test(r.section)) || ['platform', null, 'M4'];
    const normalized = r.text_verbatim.replace(/CG-\d+/g, 'CG-ID').replace(/\s+/g, ' ').trim();
    const prior = seen.get(normalized);
    seen.set(normalized, prior || r.id);
    let scope = 'CyberGuard', reason = 'V3-02; section-based routing requires semantic review';
    if (r.number >= 921 && r.number <= 924) { scope = 'IT-Twin'; reason = 'V3-02 and CG-939 transfer what-if simulation; NCC owns network execution. Retain CyberGuard security context.'; }
    const evidence = Object.hasOwn(refines, r.number) ? refines[r.number].map(n => `CG-${String(n).padStart(3,'0')}`) : [];
    return {
      id:r.id, number:r.number, raw_requirement:r.text_verbatim, source_section:r.section,
      source_line:r.source_line, source_sha256:hash(r.text_verbatim), area:route[0], status:'planned',
      current_scope:scope, review_status:'needs-semantic-review', classification_method:'section-routing-v1',
      duplicate_of:prior || null, refines:evidence, decision_reason:reason,
      dependencies:['M0'], milestone:route[2], connector_or_engine:null,
      platform_coverage:{windows:'not-tested',macos:'not-tested',linux:'not-tested'},
      permissions:['read-only-default','explicit-scope-for-sensitive-actions'],
      implementation_owner:`CyberGuard/${route[0]}`, code_reference:[], test_id:[], test_result:'not-run',
      last_verified:null, evidence:[], restrictions:['No full acceptance claim without platform-specific evidence'],
    };
  });
}
export function applyReview(rows,review,verification=null,fingerprint=null) {
  const fresh=verification?.passed===true&&verification.source?.sha256===fingerprint?.sha256;
  const ids=new Set(rows.map(r=>r.id));
  for(const id of Object.keys(review)) if(!ids.has(id)) throw new Error(`Unknown reviewed requirement ${id}`);
  return rows.map(row=>{
    const item=review[row.id];if(!item)return row;
    return {...row,...(item.scope?{current_scope:item.scope}:{}),review_status:'reviewed-subset-boundaries',classification_method:'manual-scope-and-subset-v1',
      decision_reason:item.reason,code_reference:item.code||[],test_id:item.tests||[],
      status:item.code?.length?'partially-implemented':'planned',
      test_result:item.tests?.length&&fresh?'passed-for-subset':'not-run-for-this-source',
      last_verified:item.tests?.length&&fresh?verification.at:null,
      platform_coverage:{...row.platform_coverage,...(item.tests?.length&&fresh&&verification.environment.platform==='win32'?{windows:'unit-tested-subset'}:{})},
      evidence:item.tests?.length&&fresh?['artifacts/verification.json','artifacts/tests.tap']:[],restrictions:[...row.restrictions,...item.remaining]};
  });
}
export function applyBatchReview(rows,batch) {
  if (!batch || !Array.isArray(batch.ranges)) return rows;
  const used=new Set();
  for (const range of batch.ranges) {
    if (!Number.isInteger(range.start)||!Number.isInteger(range.end)||range.start<1||range.end<range.start||range.end>1440) throw new Error('Invalid review batch range');
    for(let number=range.start;number<=range.end;number++) {
      if(used.has(number)) throw new Error(`Overlapping review batch range: CG-${String(number).padStart(3,'0')}`);
      used.add(number);
    }
  }
  return rows.map(row=>{
    const range=batch.ranges.find(r=>row.number>=r.start&&row.number<=r.end);
    if(!range)return row;
    return {...row,
      review_status:'reviewed-semantic-triage',
      classification_method:batch.batch_id,
      current_scope:range.scope||row.current_scope,
      area:range.area||row.area,
      milestone:range.milestone||row.milestone,
      decision_reason:range.reason,
      restrictions:[...row.restrictions,...range.restrictions],
    };
  });
}
export function generate() {
  const inventory = sourceInventory();
  const reviewed=JSON.parse(read('docs/engineering/REVIEWED_SUBSETS.json'));
  const batches=['docs/engineering/REVIEW_BATCH_001_300.json','docs/engineering/REVIEW_BATCH_301_600.json'].map(p=>JSON.parse(read(p)));
  const verification=fs.existsSync(path.join(ROOT,'artifacts/verification.json'))?JSON.parse(read('artifacts/verification.json')):null;
  const triaged=batches.reduce((rows,batch)=>applyBatchReview(rows,batch),classify(inventory.requirements));
  const rows = applyReview(triaged,reviewed,verification,sourceFingerprint());
  const group = key => Object.fromEntries([...new Set(rows.map(r => r[key]))].sort().map(k => [k, rows.filter(r => r[key] === k).length]));
  const coverage = {
    schema_version:1, registered:1440, tracked:rows.length, verified:0, production_ready:false,
    semantic_review_complete:false, by_area:group('area'), by_scope:group('current_scope'),
    by_status:group('status'), reviewed_subset_boundaries:Object.keys(reviewed).length,
    semantic_triage:{batch_ids:batches.map(b=>b.batch_id),reviewed_ids:batches.reduce((total,b)=>total+b.ranges.reduce((n,r)=>n+r.end-r.start+1,0),0),methods:batches.map(b=>b.method)},
    by_milestone:group('milestone'), source_integrity:'pass-normalized-lf',
    files:inventory.files, chunks:inventory.chunks, history:inventory.history,
    caveats:['CG-001..CG-600 received scope and delivery semantic triage by domain. This is not a full acceptance review or implementation claim.', 'Remaining routing is an initial automated classification, not a completed manual semantic review.', 'No requirement is fully verified by inventory or a unit test of a subset.'],
  };
  fs.mkdirSync(path.join(ROOT,'docs/engineering'), {recursive:true});
  fs.writeFileSync(path.join(ROOT,'docs/engineering/TRACEABILITY.jsonl'), rows.map(r => JSON.stringify(r)).join('\n')+'\n');
  fs.writeFileSync(path.join(ROOT,'docs/engineering/COVERAGE.json'), JSON.stringify(coverage,null,2)+'\n');
  console.log(JSON.stringify({tracked:rows.length,verified:0,source_integrity:'pass',chunks:inventory.chunks.length,history:inventory.history.length,semantic_review_complete:false,semantic_triage_reviewed:coverage.semantic_triage.reviewed_ids}));
  return {rows,coverage};
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) generate();
