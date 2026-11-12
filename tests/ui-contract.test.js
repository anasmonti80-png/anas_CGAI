import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const read=name=>fs.readFileSync(new URL(`../public/${name}`,import.meta.url),'utf8');

test('SOC shell exposes every required navigation destination as an operable view',()=>{
  const app=read('app.js');
  const required=['Overview','Discover','Assets','Network Map','Threats','Incidents','Vulnerabilities','Identity','Cloud','Policies','Response','AI Analyst','Reports','Settings'];
  let cursor=-1;
  for(const label of required){const next=app.indexOf(`'${label}'`,cursor+1);assert.ok(next>cursor,`${label} is present in the required order`);cursor=next;}
  for(const id of ['network-map','vulnerabilities','identity','cloud','policies','ai-analyst','reports']) assert.ok(app.includes(`${id}:`)||app.includes(`'${id}':`),`${id} has a rendered capability view`);
  assert.match(app,/No full acceptance evidence/);
});

test('bilingual RTL and responsive contracts cover desktop, tablet and mobile layouts',()=>{
  const app=read('app.js'),styles=read('styles.css'),soc=read('soc.css'),html=read('index.html');
  assert.match(app,/document\.documentElement\.lang=state\.lang/);
  assert.match(app,/document\.documentElement\.dir=state\.lang==='ar'\?'rtl':'ltr'/);
  assert.match(styles,/@media\(max-width:1100px\)/);
  assert.match(styles,/@media\(max-width:760px\)/);
  assert.match(soc,/@media\(max-width:390px\)/);
  assert.match(html,/styles\.css/);assert.match(html,/soc\.css/);
});

test('security posture UI keeps unknown, not configured and unverified evidence explicit',()=>{
  const app=read('app.js'),dashboard=read('dashboard.js');
  for(const marker of ['غير معروف','Unknown','لم تُضبط المصادر','Not configured','المنع الأمني غير متحقق','Prevention not verified']) assert.ok(app.includes(marker)||dashboard.includes(marker),marker);
  assert.match(app,/Missing data is never converted into a safe result/);
  assert.match(dashboard,/Insufficient evidence for assessment/);
  assert.match(dashboard,/not a security guarantee or an environment coverage percentage/);
});

test('discovery view exposes authorization, evidence boundaries and central asset observations',()=>{
  const app=read('app.js');
  assert.match(app,/\/api\/discovery/);
  assert.match(app,/Public discovery addresses are rejected/);
  assert.match(app,/this path performs no network probe/);
  assert.match(app,/authorization_ref:'SYNTHETIC-AUTHORIZATION-REFERENCE'/);
  for(const field of ['networks','routes','vlans','interfaces','services']) assert.ok(app.includes(field),field);
});
