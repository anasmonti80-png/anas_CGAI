import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const root=new URL('../',import.meta.url);
const read=name=>fs.readFileSync(new URL(name,root),'utf8');

test('the current distributable has no undeclared npm dependency or accidental publish path',()=>{
  const pkg=JSON.parse(read('package.json'));
  assert.equal(pkg.private,true);
  assert.deepEqual(pkg.dependencies??{},{});
  assert.deepEqual(pkg.devDependencies??{},{});
  const policy=read('docs/engineering/DEPENDENCIES_AR.md');
  assert.match(policy,/لا تبعيات تشغيل npm/);
  assert.match(policy,/Node يحمل ترخيصًا رئيسيًا من نوع MIT/);
  assert.match(policy,/SQLite مضمّنة في Node/);
  assert.match(policy,/مراجعة إصدار وترخيص وكل تبعية/);
  assert.match(policy,/SBOM/);
  assert.match(policy,/فشل أي بند يمنع الدمج أو التوزيع/);
  assert.match(policy,/ليست فتوى قانونية أو شهادة امتثال/);
});
