import test from 'node:test';
import assert from 'node:assert/strict';
import { analyseRuleset, ruleCovers } from '../lib/firewall-analyzer.js';
const rule=(rule_id,position,action,extra={})=>({rule_id,name:rule_id,position,enabled:true,direction:'in',action,protocol:'tcp',src:['any'],dst:['10.0.0.0/24'],src_ports:['any'],dst_ports:['443'],application:null,profile:null,last_hit_at:null,hit_count:null,expires_at:null,owner:null,created_at:null,filters_readable:true,...extra});
const now=Date.parse('2026-11-11T10:00:00.000Z');
test('coverage understands CIDR containment, port ranges, protocol any and direction',()=>{
  assert.ok(ruleCovers(rule('a',1,'deny',{dst:['10.0.0.0/16'],dst_ports:['1-1024']}),rule('b',2,'allow',{dst:['10.0.0.5/32'],dst_ports:['443']})));
  assert.ok(!ruleCovers(rule('a',1,'deny',{dst:['10.0.1.0/24']}),rule('b',2,'allow')));assert.ok(!ruleCovers(rule('a',1,'deny',{protocol:'udp'}),rule('b',2,'allow')));assert.ok(ruleCovers(rule('a',1,'deny',{protocol:'any',dst:['any'],dst_ports:['any']}),rule('b',2,'allow')));assert.ok(!ruleCovers(rule('a',1,'deny',{direction:'out'}),rule('b',2,'allow')));
});
test('first-match rulesets report duplicates, shadowed and redundant rules; broad, stale and expiring rules are flagged',()=>{
  const r=analyseRuleset({ruleset_id:'R',evaluation:'first-match',rules:[rule('deny-web',1,'deny',{dst:['10.0.0.0/16']}),rule('allow-web',2,'allow'),rule('allow-web-copy',3,'allow'),rule('any-any',4,'allow',{protocol:'any',dst:['any'],dst_ports:['any']}),rule('rdp-any',5,'allow',{dst_ports:['3389']}),rule('old',6,'allow',{dst_ports:['8080'],src:['192.168.1.0/24'],last_hit_at:'2026-01-01T00:00:00.000Z'}),rule('temp',7,'allow',{dst_ports:['8443'],src:['192.168.2.0/24'],expires_at:'2026-11-01T00:00:00.000Z'}),rule('soon',8,'allow',{dst_ports:['9443'],src:['192.168.3.0/24'],expires_at:'2026-11-15T00:00:00.000Z'}),rule('off',9,'allow',{enabled:false,protocol:'any',dst:['any'],dst_ports:['any']})]},now);
  const of=t=>r.findings.filter(f=>f.type===t).map(f=>f.rule_id);
  assert.ok(of('shadowed').includes('allow-web'));assert.ok(of('duplicate').includes('allow-web-copy'));assert.deepEqual(of('any-any-allow'),['any-any']);assert.ok(of('broad-admin-exposure').includes('rdp-any'));assert.deepEqual(of('stale'),['old']);assert.deepEqual(of('expired-exception'),['temp']);assert.deepEqual(of('exception-expiring'),['soon']);assert.ok(!r.findings.some(f=>f.rule_id==='off'));
});
test('deny-overrides rulesets flag allow rules overridden by a covering block, skip unreadable rules, and change impact detects new admin exposure',()=>{
  const before={ruleset_id:'A',evaluation:'deny-overrides',rules:[rule('block-smb',1,'deny',{dst:['any'],dst_ports:['445']}),rule('allow-smb',2,'allow',{dst_ports:['445']}),rule('web',3,'allow')]};
  const after={ruleset_id:'B',evaluation:'deny-overrides',rules:[...before.rules,rule('new-rdp',4,'allow',{dst_ports:['3389']}),rule('hidden',5,'allow',{protocol:'any',dst:['any'],dst_ports:['any'],filters_readable:false})]};
  const r=analyseRuleset(after,now,before);assert.ok(r.findings.some(f=>f.type==='conflict'&&f.rule_id==='allow-smb'&&f.related_rule_id==='block-smb'));assert.ok(!r.findings.some(f=>f.rule_id==='hidden'));assert.equal(r.rules_unreadable,1);assert.deepEqual(r.change.added,['new-rdp','hidden']);assert.equal(r.change.impact,'increases-exposure');assert.deepEqual(r.change.new_admin_exposure.map(x=>x.rule_id),['new-rdp']);
});

test('scope constraints (user, package, service, owner) stop false conflicts and false any-any findings',()=>{
  const r=analyseRuleset({ruleset_id:'S',evaluation:'deny-overrides',rules:[rule('sandbox-block',1,'deny',{direction:'out',protocol:'any',dst:['any'],dst_ports:['any'],scope_constraints:['local-user:O:LSD:(A;;CC;;;S-1-5-21-1-2-3-1006)']}),rule('app-out',2,'allow',{direction:'out'}),rule('store-app',3,'allow',{direction:'out',protocol:'any',dst:['any'],dst_ports:['any'],scope_constraints:['owner:S-1-5-21-1-2-3-1000','package:S-1-15-2-1']}),rule('svc-block',4,'deny',{dst_ports:['445'],dst:['any'],scope_constraints:['service:lanmanserver']}),rule('svc-allow',5,'allow',{dst_ports:['445'],scope_constraints:['service:lanmanserver']})]},now);
  assert.ok(!r.findings.some(f=>f.rule_id==='app-out'&&f.type==='conflict'));assert.ok(!r.findings.some(f=>f.rule_id==='store-app'&&f.type==='any-any-allow'));assert.ok(r.findings.some(f=>f.rule_id==='svc-allow'&&f.type==='conflict'&&f.related_rule_id==='svc-block'));
});

test('administrative exposure needs explicit admin ports, or any port on TCP/UDP without an application, service or keyword scope',()=>{
  const r=analyseRuleset({ruleset_id:'E',evaluation:'deny-overrides',rules:[rule('rdp',1,'allow',{dst_ports:['3389']}),rule('ipv6',2,'allow',{protocol:'41',dst_ports:['any']}),rule('app-any',3,'allow',{dst_ports:['any'],application:'C:\\\\app.exe'}),rule('teredo',4,'allow',{protocol:'udp',dst_ports:['any'],scope_constraints:['port-keyword:Teredo']}),rule('open-tcp',5,'allow',{dst_ports:['any']})]},now);
  const exposed=r.findings.filter(f=>f.type==='broad-admin-exposure').map(f=>f.rule_id).sort();assert.deepEqual(exposed,['open-tcp','rdp']);
});
