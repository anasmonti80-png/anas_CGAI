import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeLogLines } from '../lib/log-normalizer.js';

test('syslog RFC 5424, RFC 3164 and journald lines normalise with host, program and severity',()=>{
  const {records,rejected}=normalizeLogLines('syslog',['<34>1 2026-11-11T09:00:00.000Z fw01 sshd 123 ID47 - Failed password for root from 203.0.113.9 port 2201','<38>Nov 11 09:01:02 web01 nginx[77]: upstream timed out','2026-11-11T09:02:00+0300 db01 postgres[9]: checkpoint complete','not a syslog line'],{year:2026});
  assert.equal(records.length,3);assert.deepEqual(rejected,[{line:4,reason:'unparsed'}]);assert.equal(records[0].host,'fw01');assert.equal(records[0].severity,2);assert.match(records[0].message,/Failed password/);assert.equal(records[1].time,'2026-11-11T09:01:02.000Z');assert.equal(records[1].signature,'nginx');assert.equal(records[2].time,'2026-11-11T06:02:00.000Z');
});
test('NetFlow/IPFIX exports from nfdump CSV and goflow2 JSON become flow records with bytes and packets',()=>{
  const csv=normalizeLogLines('nfdump-csv',['ts,te,td,sa,da,sp,dp,pr,flg,fwd,stos,ipkt,ibyt','2026-11-11 09:00:00,2026-11-11 09:00:05,5.0,10.0.0.5,198.51.100.7,51000,443,TCP,.AP.SF,0,0,12,9000']);assert.equal(csv.records.length,1);assert.equal(csv.records[0].dst_port,443);assert.equal(csv.records[0].protocol,'tcp');assert.equal(csv.records[0].bytes,9000);
  const gf=normalizeLogLines('goflow-json',[JSON.stringify({TimeFlowStart:1794301200,SrcAddr:'10.0.0.6',DstAddr:'10.0.0.9',SrcPort:3389,DstPort:50000,Proto:6,Bytes:123,Packets:3})]);assert.equal(gf.records[0].protocol,'tcp');assert.equal(gf.records[0].src_port,3389);
});
test('Suricata EVE alerts, DNS and flows; BIND queries; ISC dhcpd leases; OpenVPN logins normalise to their categories',()=>{
  const eve=normalizeLogLines('suricata-eve',[JSON.stringify({timestamp:'2026-11-11T09:00:00.000000+0000',event_type:'alert',src_ip:'203.0.113.5',src_port:4444,dest_ip:'10.0.0.5',dest_port:445,proto:'TCP',alert:{action:'allowed',signature:'ET EXPLOIT SMB',category:'Attempted Admin',severity:1}}),JSON.stringify({timestamp:'2026-11-11T09:00:01.000000+0000',event_type:'dns',src_ip:'10.0.0.5',dest_ip:'10.0.0.1',proto:'UDP',dns:{type:'query',rrname:'example.invalid'}}),JSON.stringify({timestamp:'2026-11-11T09:00:02Z',event_type:'stats'})]);
  assert.equal(eve.records.length,2);assert.equal(eve.records[0].category,'ids');assert.equal(eve.records[0].severity,1);assert.equal(eve.records[1].category,'dns');assert.equal(eve.records[1].query,'example.invalid');assert.equal(eve.rejected.length,1);
  const bind=normalizeLogLines('bind-query',['11-Nov-2026 09:00:00.123 client @0x7f 10.0.0.5#53123 (Example.Invalid): query: Example.Invalid IN A +E(0) (10.0.0.1)']);assert.equal(bind.records[0].query,'example.invalid');assert.equal(bind.records[0].src_ip,'10.0.0.5');
  const dhcp=normalizeLogLines('isc-dhcpd',['Nov 11 09:00:00 dhcp01 dhcpd[5]: DHCPACK on 10.0.0.20 to aa:bb:cc:dd:ee:ff (laptop-7) via eth0'],{year:2026});assert.equal(dhcp.records[0].action,'dhcpack');assert.equal(dhcp.records[0].mac,'aa:bb:cc:dd:ee:ff');assert.equal(dhcp.records[0].host,'laptop-7');
  const vpn=normalizeLogLines('openvpn',['Nov 11 09:00:00 vpn01 openvpn[9]: 203.0.113.50:51000 TLS: Username/Password authentication failed for username \'alice\'','Nov 11 09:01:00 vpn01 openvpn[9]: 203.0.113.50:51000 Peer Connection Initiated with [AF_INET]203.0.113.50:51000'],{year:2026});assert.equal(vpn.records[0].outcome,'failure');assert.equal(vpn.records[0].user,'alice');assert.equal(vpn.records[1].action,'connect');
});
test('iptables, Windows Firewall and pfSense filterlog lines normalise allow/block decisions with five-tuples and redact secrets',()=>{
  const ipt=normalizeLogLines('iptables',['Nov 11 09:00:00 gw kernel: [123.4] UFW BLOCK IN=eth0 OUT= MAC=00 SRC=203.0.113.7 DST=10.0.0.2 LEN=60 PROTO=TCP SPT=40000 DPT=22 WINDOW=1'],{year:2026});assert.equal(ipt.records[0].action,'blocked');assert.equal(ipt.records[0].dst_port,22);
  const win=normalizeLogLines('windows-firewall',['#Version: 1.5','#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path','2026-11-11 09:00:00 DROP TCP 203.0.113.8 10.0.0.3 51515 3389 52 S 1 0 64240 - - - RECEIVE']);assert.equal(win.records.length,1);assert.equal(win.records[0].action,'blocked');assert.equal(win.records[0].dst_port,3389);assert.equal(win.records[0].outcome,'RECEIVE');
  const pf=normalizeLogLines('pfsense-filterlog',['Nov 11 09:00:00 pfsense filterlog[1]: 5,,,1000000103,igb0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,203.0.113.9,10.0.0.4,40000,443,0,S,1,,64240,,'],{year:2026});assert.equal(pf.records[0].action,'blocked');assert.equal(pf.records[0].dst_port,443);
  const red=normalizeLogLines('syslog',['<38>Nov 11 09:00:00 app01 app[1]: login password=hunter2 ok'],{year:2026});assert.ok(!JSON.stringify(red.records).includes('hunter2'));
});
