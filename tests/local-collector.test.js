import test from 'node:test';
import assert from 'node:assert/strict';
import {localObservation} from '../lib/local-collector.js';
import {validateEvent} from '../lib/domain.js';

test('local collection requires no shell and records only available identity without inferring prevention',()=>{
  const fixture={platform:()=> 'win32',hostname:()=> 'SYNTHETIC-HOST',arch:()=> 'x64',networkInterfaces:()=>({Loopback:[{address:'127.0.0.1',internal:true}],Ethernet:[{address:'192.0.2.4',internal:false},{address:'192.0.2.4',internal:false}]})};
  const now=new Date('2026-11-11T10:00:00.000Z'),batch=localObservation(fixture,now);
  assert.equal(batch.events[0].asset.os_family,'windows');
  assert.equal(batch.events[0].asset.device_type,'unknown');
  assert.deepEqual(batch.events[0].asset.addresses,['192.0.2.4']);
  assert.deepEqual(batch.events[0].details,{});
  validateEvent(batch.events[0],now.getTime());
  assert.equal(batch.events[0].asset.external_id,localObservation(fixture,now).events[0].asset.external_id);
  assert.notEqual(batch.events[0].event_id,localObservation(fixture,now).events[0].event_id);
});
