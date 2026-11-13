import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeLogLines } from '../lib/log-normalizer.js';
test('ModSecurity and AWS WAF logs normalise to WAF records with block decisions and rule signatures',()=>{
  const ms=normalizeLogLines('modsecurity-json',[JSON.stringify({transaction:{client_ip:'203.0.113.9',client_port:51000,host_ip:'10.0.0.80',host_port:443,time_stamp:'Wed Nov 11 09:00:00 2026',request:{method:'GET',uri:'/login.php?id=1%27%20OR%201=1'},response:{http_code:403},messages:[{message:'SQL Injection Attack Detected via libinjection',details:{ruleId:'942100',severity:'2'}}]}})]);
  assert.equal(ms.records.length,1);assert.equal(ms.records[0].category,'waf');assert.equal(ms.records[0].action,'blocked');assert.equal(ms.records[0].severity,2);assert.match(ms.records[0].signature,/SQL Injection/);assert.equal(ms.records[0].time,'2026-11-11T09:00:00.000Z');
  const aws=normalizeLogLines('aws-waf-json',[JSON.stringify({timestamp:1794301200000,action:'BLOCK',terminatingRuleId:'AWS-AWSManagedRulesCommonRuleSet',httpRequest:{clientIp:'198.51.100.4',country:'NL',uri:'/wp-login.php',httpMethod:'POST'}})]);
  assert.equal(aws.records[0].action,'blocked');assert.equal(aws.records[0].src_ip,'198.51.100.4');assert.match(aws.records[0].query,/wp-login/);
});
test('dnsmasq/Pi-hole, Zeek conn, FreeRADIUS and Cloudflare Access logs normalise to DNS security, NDR, NAC and ZTNA records',()=>{
  const dns=normalizeLogLines('dnsmasq',['Nov 11 09:00:00 pihole dnsmasq[321]: query[A] malware.example from 10.0.0.5','Nov 11 09:00:00 pihole dnsmasq[321]: gravity blocked malware.example is 0.0.0.0','Nov 11 09:00:01 pihole dnsmasq[321]: reply www.example.com is 93.184.216.34'],{year:2026});
  assert.equal(dns.records.length,3);assert.equal(dns.records[1].action,'blocked');assert.equal(dns.records[0].src_ip,'10.0.0.5');
  const zeek=normalizeLogLines('zeek-conn',['#separator \\x09','#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state','1794301200.5\tC1\t10.0.0.5\t51000\t10.0.0.9\t445\ttcp\tsmb\t1.2\t300\t900\tSF']);
  assert.equal(zeek.records.length,1);assert.equal(zeek.records[0].dst_port,445);assert.equal(zeek.records[0].bytes,1200);assert.equal(zeek.records[0].signature,'smb');
  const radius=normalizeLogLines('freeradius',['Wed Nov 11 09:00:00 2026 : Auth: (12) Login OK: [alice/<via Auth-Type = eap>] (from client switch01 port 3 cli aa-bb-cc-dd-ee-ff)','Wed Nov 11 09:00:05 2026 : Auth: (13) Login incorrect (mschap: MS-CHAP2-Response is incorrect): [bob/<via Auth-Type = eap>] (from client switch01 port 7 cli 11-22-33-44-55-66)']);
  assert.equal(radius.records.length,2);assert.equal(radius.records[0].category,'nac');assert.equal(radius.records[0].outcome,'success');assert.equal(radius.records[0].mac,'aa:bb:cc:dd:ee:ff');assert.equal(radius.records[1].outcome,'failure');assert.equal(radius.records[1].user,'bob');assert.equal(radius.records[1].host,'switch01');
  const access=normalizeLogLines('cloudflare-access-json',[JSON.stringify({CreatedAt:'2026-11-11T09:00:00Z',Action:'login',Allowed:false,AppDomain:'wiki.example.invalid',UserEmail:'carol@example.invalid',IPAddress:'203.0.113.77',Country:'us'})]);
  assert.equal(access.records[0].category,'ztna');assert.equal(access.records[0].outcome,'failure');assert.equal(access.records[0].query,'wiki.example.invalid');
});
