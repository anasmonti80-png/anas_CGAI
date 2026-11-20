import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Domain } from '../lib/domain.js';
import { correlateSignals, signalFamily } from '../lib/network-correlation.js';

const AT='2026-11-20T12:00:00.000Z',ASSET='11111111-1111-4111-8111-111111111111',SOURCE='22222222-2222-4222-8222-222222222222';
const signal=(id,family,rule,severity,title='same signal')=>({id,asset_id:ASSET,family,rule_id:rule,severity,title,occurrences:1,evidence_ids:[`event-${id}`],first_seen:AT,last_seen:AT});

test('multi-signal correlation compacts duplicate copies while preserving important alerts and evidence (CG-113)',()=>{
  const rows=[signal('e1','endpoint','CG-DET-001','medium'),signal('i1','identity','CG-IDENT-001','high'),signal('n1','network','CG-NET-001','medium'),signal('n2','network','CG-NET-001','medium'),signal('c1','cloud','CG-CLOUD-001','critical')];
  const result=correlateSignals(rows),item=result.correlations[0];
  assert.deepEqual(item.families,['cloud','endpoint','identity','network']);
  assert.equal(item.raw_alerts,5); assert.equal(item.deduplicated_signals,4); assert.equal(item.reduced_noise,1);
  assert.equal(item.signals.find(x=>x.family==='network').alert_ids.length,2); assert.equal(item.signals.find(x=>x.family==='network').evidence_ids.length,2);
  assert.deepEqual(item.important_alerts.map(x=>x.id).sort(),['c1','i1']); assert.equal(item.important_alerts_preserved,2); assert.equal(item.suppressed_alerts,0); assert.equal(item.severity,'critical');
});

test('signal family classification covers endpoint, identity, network and cloud (CG-113)',()=>{
  assert.equal(signalFamily({rule_id:'CG-DET-001'}),'endpoint'); assert.equal(signalFamily({rule_id:'CG-IDENT-001'}),'identity');
  assert.equal(signalFamily({rule_id:'CG-NET-001'}),'network'); assert.equal(signalFamily({rule_id:'CG-CLOUD-001'}),'cloud');
  assert.equal(signalFamily({rule_id:'OTHER',evidence_kinds:['endpoint.process_causality']}),'endpoint');
});

test('domain correlation adds central asset context and never changes source alerts (CG-113)',t=>{
  const store=new Store(':memory:');t.after(()=>store.close());const domain=new Domain(store,{clock:()=>Date.parse(AT)});
  store.run('INSERT INTO sources(id,name,kind,created_at,stale_seconds) VALUES (?,?,?,?,?)',SOURCE,'Synthetic CG-113','api',AT,3600);
  store.run('INSERT INTO assets(id,source_id,external_id,hostname,os_family,device_type,addresses,first_seen,last_seen,received_at,criticality,protection) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',ASSET,SOURCE,'asset-113','soc-host','windows','server','["192.0.2.113"]',AT,AT,AT,'high','{}');
  store.run('INSERT INTO events(id,source_id,external_id,asset_id,kind,observed_at,received_at,schema_version,parser_version,original_sha256,sanitized_sha256,payload) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)','context-113',SOURCE,'context-113',ASSET,'asset.context',AT,AT,'cg.telemetry/1','test','a'.repeat(64),'b'.repeat(64),JSON.stringify({details:{owner:'SOC',business_service:'Payments',service_name:'Payments API',site:'Riyadh',data_sensitivity:'restricted',maintenance_windows:[],service_criticality:'critical'}}));
  const ids=[domain.alert({key:'ep',assetId:ASSET,sourceId:SOURCE,rule:'CG-DET-001',severity:'medium',title:'Endpoint signal'}),domain.alert({key:'id',assetId:ASSET,sourceId:SOURCE,rule:'CG-IDENT-001',severity:'high',title:'Identity signal'}),domain.alert({key:'net-a',assetId:ASSET,sourceId:SOURCE,rule:'CG-NET-001',severity:'medium',title:'Repeated network signal'}),domain.alert({key:'net-b',assetId:ASSET,sourceId:SOURCE,rule:'CG-NET-001',severity:'medium',title:'Repeated network signal'}),domain.alert({key:'cloud',assetId:ASSET,sourceId:SOURCE,rule:'CG-CLOUD-001',severity:'critical',title:'Cloud signal'})];
  const before=store.all('SELECT id,status,severity FROM alerts ORDER BY id'),result=domain.multiSignalCorrelation(),item=result.correlations[0];
  assert.equal(result.total,1); assert.equal(item.asset.hostname,'soc-host'); assert.equal(item.asset_context.business_service,'Payments'); assert.equal(item.asset_context.service_criticality,'critical');
  assert.equal(item.raw_alerts,5); assert.equal(item.deduplicated_signals,4); assert.equal(item.important_alerts_preserved,2); assert.equal(result.suppressed_alerts,0);
  assert.deepEqual(store.all('SELECT id,status,severity FROM alerts ORDER BY id'),before); assert.ok(ids.every(id=>item.signals.some(x=>x.alert_ids.includes(id))));
});

