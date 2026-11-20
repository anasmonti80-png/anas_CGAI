import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {spawnSync,execFileSync} from 'node:child_process';
import {DatabaseSync} from 'node:sqlite';
import {ROOT,sourceInventory} from './requirements.js';
import {sourceFingerprint} from './source-fingerprint.js';
sourceInventory();
const syntax=spawnSync(process.execPath,['scripts/check.js'],{cwd:ROOT,encoding:'utf8',windowsHide:true});
process.stdout.write(syntax.stdout);if(syntax.status!==0){process.stderr.write(syntax.stderr);process.exit(1);}
const tests=fs.readdirSync(path.join(ROOT,'tests')).filter(n=>n.endsWith('.test.js')).sort().map(n=>`tests/${n}`);
const run=spawnSync(process.execPath,['--test','--test-reporter=tap',...tests],{cwd:ROOT,encoding:'utf8',windowsHide:true,maxBuffer:16*1024*1024});
const db=new DatabaseSync(':memory:');const sqlite=db.prepare('SELECT sqlite_version() version').get().version;db.close();
const count=name=>Number(run.stdout.match(new RegExp(`^# ${name} (\\d+)`,'m'))?.[1]||0);
let commit=null;try{commit=execFileSync('git',['rev-parse','HEAD'],{cwd:ROOT,encoding:'utf8',windowsHide:true}).trim();}catch{}
const report={at:new Date().toISOString(),level:'Unit Tested',environment:{platform:os.platform(),arch:os.arch(),os_release:os.release(),node:process.version,sqlite},base_commit:commit,source:sourceFingerprint(),includes_uncommitted_work:true,command:'node scripts/verify.js',passed:run.status===0,tests:count('tests'),pass:count('pass'),fail:count('fail'),skipped:count('skipped'),coverage_scope:'Synthetic unit/integration/HTTP and pagination tests; not production or real endpoint validation'};
fs.mkdirSync(path.join(ROOT,'artifacts'),{recursive:true});
fs.writeFileSync(path.join(ROOT,'artifacts/tests.tap'),run.stdout);
fs.writeFileSync(path.join(ROOT,'artifacts/verification.json'),JSON.stringify(report,null,2)+'\n');
process.stdout.write(run.stdout);if(run.stderr)process.stderr.write(run.stderr);
// In GitHub Actions, failing tests become annotations (readable from the public checks API without signing in).
if(process.env.GITHUB_ACTIONS==='true'&&run.status!==0){const out=run.stdout.split('\n');out.forEach((line,i)=>{const m=/^\s*not ok \d+ - (.*)$/.exec(line);if(!m)return;const detail=out.slice(i+1,i+40).filter(l=>/error:|message:|expected:|actual:|code:|location:/.test(l)).slice(0,6).map(l=>l.trim()).join(' | ');console.log(`::error title=${m[1].replace(/[\r\n:,]/g,' ').slice(0,180)}::${detail.replace(/[\r\n]/g,' ').slice(0,900)||'see test output'}`);});}
console.log(JSON.stringify(report));process.exitCode=run.status===0?0:1;
