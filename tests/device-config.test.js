import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { parseCiscoIos, analyseDeviceConfig, compareVersions } from '../lib/device-config.js';
const read=name=>fs.readFileSync(new URL('./fixtures/'+name,import.meta.url),'utf8');
test('Cisco IOS-XE show version and running-config parse into version, model, DNS, NTP, VPN peers and management flags without secrets',()=>{
  const p=parseCiscoIos(read('cisco-show-version.txt'),read('cisco-running-config.txt'));
  assert.equal(p.firmware_version,'17.03.04a');assert.equal(p.model,'ISR4331/K9');assert.equal(p.hostname,'edge-rtr-01');assert.deepEqual(p.dns_servers,['10.0.0.53','10.0.0.54']);assert.deepEqual(p.ntp_servers,['10.0.0.123']);
  assert.ok(p.vpn_profiles.some(v=>v.peer==='203.0.113.10'&&v.protocol==='ipsec-ikev1'));const m=Object.fromEntries(p.management.map(x=>[x.protocol,x]));assert.equal(m.telnet.enabled,true);assert.equal(m.ssh.enabled,true);assert.equal(m.telnet.restricted_sources,false);assert.equal(m.http.enabled,true);assert.equal(m.snmpv2c.enabled,true);assert.equal(m.snmpv3.enabled,false);
  const text=JSON.stringify(p);for(const secret of ['SuperSecretKey123','PublicRO','PrivateRW'])assert.ok(!text.includes(secret),secret);
});
test('device analysis flags insecure or exposed management, vulnerable firmware and DNS/VPN/management/firmware changes',()=>{
  const base={vendor:'cisco',model:'ISR4331/K9',firmware_version:'17.3.4a',dns_servers:['10.0.0.53'],ntp_servers:[],vpn_profiles:[{name:'a',peer:'203.0.113.10',protocol:'ipsec'}],management:[{protocol:'ssh',enabled:true,exposed_to:'internal',restricted_sources:true},{protocol:'telnet',enabled:false,exposed_to:'unknown',restricted_sources:false}]};
  const now={...base,firmware_version:'16.9.1',dns_servers:['198.51.100.53'],vpn_profiles:[],management:[{protocol:'ssh',enabled:true,exposed_to:'internal',restricted_sources:true},{protocol:'telnet',enabled:true,exposed_to:'external',restricted_sources:false}]};
  const r=analyseDeviceConfig(now,base,[{vuln_id:'SYN-IOSXE-1',vendor:'cisco',product:'ISR4331/K9',affected:{min_version:'16.0',max_version_exclusive:'17.0'},fixed_version:'17.3.1',cvss:9.8,kev:true}]);
  const types=r.findings.map(f=>f.type);assert.ok(types.includes('insecure-management-protocol'));assert.ok(types.includes('management-exposed'));assert.equal(r.findings.find(f=>f.type==='firmware-vulnerable').severity,'critical');
  const changes=Object.fromEntries(r.changes.map(c=>[c.type,c]));assert.equal(changes['dns-changed'].severity,'high');assert.ok(changes['vpn-changed']);assert.equal(changes['management-changed'].severity,'high');assert.equal(changes['firmware-downgraded'].before,'17.3.4a');
  assert.equal(compareVersions('17.3.4a','17.03.04a'),0);assert.equal(compareVersions('16.9.1','17.3.4'),-1);
});
