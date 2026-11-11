// Disposable browser-validation fixture. No personal or production data.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createApp} from '../server.js';
const dataDir=fs.mkdtempSync(path.join(os.tmpdir(),'cg-ui-lab-'));
const app=createApp({dataDir,setupToken:'synthetic-lab-setup-only'});
const source=app.domain.createSource('synthetic-fixture',{name:'SYNTHETIC LAB — not live telemetry',stale_seconds:86400});
const now=new Date().toISOString();
const asset={external_id:'SYNTHETIC-001',hostname:'SYNTHETIC-WORKSTATION',os_family:'windows',device_type:'workstation',addresses:['192.0.2.10']};
const events=[{event_id:'lab-inventory',kind:'asset.observed',observed_at:now,asset,details:{}},{event_id:'lab-exposure',kind:'remote.port_open',observed_at:now,asset,details:{session_id:'lab-rdp',protocol:'rdp',source_a:{ip:'192.0.2.20'},target_b:{ip:'192.0.2.10',account:'synthetic-target'},evidence_type:'port_observation'}},{event_id:'lab-finding',kind:'security.finding',observed_at:now,asset,details:{severity:'high',title:'SYNTHETIC LAB — review endpoint policy',description:'Synthetic evidence for browser validation only.'}}];
app.domain.ingest('synthetic-fixture',source.id,{schema_version:'cg.telemetry/1',events});
await app.listen(4311);
console.log('Disposable synthetic browser fixture: http://127.0.0.1:4311');
async function stop(){await app.close();const target=path.resolve(dataDir);if(!target.startsWith(path.resolve(os.tmpdir())+path.sep)||!path.basename(target).startsWith('cg-ui-lab-'))throw new Error('Invalid cleanup target');fs.rmSync(target,{recursive:true,force:true});process.exit(0);}
for(const signal of ['SIGINT','SIGTERM'])process.once(signal,stop);
