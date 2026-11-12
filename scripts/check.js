import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {ROOT} from './requirements.js';
function files(dir){return fs.readdirSync(path.join(ROOT,dir),{withFileTypes:true}).flatMap(e=>e.isDirectory()?files(path.join(dir,e.name)):[path.join(dir,e.name)]);}
const js=['server.js',...['lib','scripts','public','tests'].flatMap(files).filter(p=>p.endsWith('.js'))];
for(const file of js){const r=spawnSync(process.execPath,['--check',file],{cwd:ROOT,encoding:'utf8',windowsHide:true});if(r.status!==0){process.stderr.write(r.stderr);process.exit(r.status||1);}}
console.log(`Syntax checks passed: ${js.length} JavaScript files`);
