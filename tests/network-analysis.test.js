import test from 'node:test';
import assert from 'node:assert/strict';
import { analyseNetwork } from '../lib/network-analysis.js';
const flow=(src_ip,dst_ip,dst_port,extra={})=>({category:'flow',time:'2026-11-11T09:00:00.000Z',action:'observed',src_ip,dst_ip,src_port:50000,dst_port,protocol:'tcp',bytes:100,...extra});
test('connections are grouped by zone and Internet exposure flags allowed inbound administrative services',()=>{
  const r=analyseNetwork([flow('10.0.0.5','198.51.100.7',443),flow('10.0.0.5','10.0.0.9',80),flow('203.0.113.5','10.0.0.20',3389),flow('203.0.113.6','10.0.0.20',3389),flow('203.0.113.7','10.0.0.21',8443),{...flow('203.0.113.8','10.0.0.22',22),category:'firewall',action:'blocked'}]);
  assert.equal(r.zones['internal->external'],1);assert.equal(r.zones['internal->internal'],1);assert.equal(r.zones['external->internal'],4);
  const rdp=r.exposure.find(x=>x.port===3389);assert.equal(rdp.service,'RDP');assert.equal(rdp.external_sources,2);assert.equal(rdp.severity,'high');assert.equal(r.exposure.find(x=>x.port===8443).severity,'medium');assert.ok(!r.exposure.some(x=>x.port===22));
});
test('lateral movement needs one internal host reaching five or more internal hosts on administrative ports',()=>{
  const spread=Array.from({length:6},(_,i)=>flow('10.0.0.50',`10.0.1.${i+1}`,i%2?445:5985));const normal=Array.from({length:6},(_,i)=>flow('10.0.0.60',`10.0.1.${i+1}`,443));
  const r=analyseNetwork([...spread,...normal]);assert.equal(r.lateral_movement.length,1);assert.equal(r.lateral_movement[0].src_ip,'10.0.0.50');assert.equal(r.lateral_movement[0].targets,6);assert.ok(r.lateral_movement[0].ports.includes('445/SMB'));
});
test('unusual DNS flags random-looking labels, very long names, TXT queries and many unique subdomains, but not ordinary names',()=>{
  const dns=(query,outcome='A')=>({category:'dns',time:'2026-11-11T09:00:00.000Z',query,outcome,src_ip:'10.0.0.5'});
  const tunnel=Array.from({length:35},(_,i)=>dns(`c${i}x${i*7}.exfil.example`));
  const r=analyseNetwork([dns('www.example.com'),dns('mail.google.com'),dns('xk3q9zp2vw8m4ty7lr6nc0b.example'),dns('a'.repeat(60)+'.long.example'),dns('cfg.example','TXT'),...tunnel]);
  const names=r.unusual_dns.map(q=>q.query);assert.ok(names.includes('xk3q9zp2vw8m4ty7lr6nc0b.example'));assert.ok(names.includes('cfg.example'));assert.ok(names.includes('exfil.example'));assert.ok(r.unusual_dns.some(q=>q.reasons.includes('very-long-name')));assert.ok(!names.includes('www.example.com'));assert.ok(!names.includes('mail.google.com'));
});
