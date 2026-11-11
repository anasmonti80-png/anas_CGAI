import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('../',import.meta.url));
export function sourceFingerprint() {
  const files=[];
  function visit(relative) {
    const absolute=path.join(root,relative);
    if(fs.statSync(absolute).isDirectory()) {
      for(const name of fs.readdirSync(absolute).sort()) visit(`${relative}/${name}`);
    } else files.push(relative);
  }
  for(const entry of ['lib','public','scripts','tests','server.js','package.json','START_CYBERGUARD.cmd']) visit(entry);
  const hash=createHash('sha256');
  for(const name of files.sort()) hash.update(name+'\0').update(fs.readFileSync(path.join(root,name),'utf8').replace(/\r\n/g,'\n')).update('\0');
  return {sha256:hash.digest('hex'),files:files.length,normalization:'UTF-8 text with LF'};
}
