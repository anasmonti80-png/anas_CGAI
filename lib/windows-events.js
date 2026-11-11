import {isIP} from 'node:net';
import {object,text,integer,timestamp,fail,digest} from './common.js';

const allowedData=['LogonType','TargetLogonId','TargetUserName','TargetDomainName','IpAddress','WorkstationName'];
const clean=value=>typeof value==='string'&&value.trim()&&value!=='-'?value.trim():null;
export function normalizeWindowsExport(input,now=Date.now()) {
  object(input,['schema_version','computer','boot_time','events'],'windows_export');
  fail(input.schema_version==='cg.windows-export/1',400,'unsupported_windows_export');
  const computer=text(input.computer,'computer',200), boot=timestamp(input.boot_time,'boot_time',now);
  fail(Array.isArray(input.events)&&input.events.length>=1&&input.events.length<=250,400,'windows_export_requires_1_to_250_events');
  const events=[],skipped=[];
  for(const raw of input.events) {
    object(raw,['event_id','record_id','time_created','provider','channel','data'],'windows_record');
    integer(raw.event_id,0,65535,'windows_event_id');
    integer(raw.record_id,1,Number.MAX_SAFE_INTEGER,'windows_record_id');
    fail(raw.provider==='Microsoft-Windows-Security-Auditing'&&raw.channel==='Security',400,'unsupported_windows_provider');
    const observed=timestamp(raw.time_created,'time_created',now);
    fail(observed>=boot,400,'event_precedes_declared_boot');
    const fields=object(raw.data,allowedData,'windows_data');
    for(const v of Object.values(fields)) fail(typeof v==='string'&&v.length<=256,400,'invalid_windows_data_value');
    const type=Number(fields.LogonType);
    if(![4624,4625,4634].includes(raw.event_id)||(raw.event_id!==4625&&type!==10)) {skipped.push({record_id:raw.record_id,reason:'unsupported-event-or-not-remote-interactive'});continue;}
    const account=clean(fields.TargetUserName)?[clean(fields.TargetDomainName),clean(fields.TargetUserName)].filter(Boolean).join('\\'):null;
    const ip=clean(fields.IpAddress);const sourceIp=ip&&isIP(ip)?ip:null;
    let kind,details;
    if(raw.event_id===4625) {kind='auth.failed';details={account,source_ip:sourceIp,protocol:type===10?'rdp':'unknown'};}
    else {
      const logonId=text(fields.TargetLogonId,'target_logon_id',40);fail(/^0x[0-9a-f]+$/i.test(logonId),400,'invalid_target_logon_id');
      kind=raw.event_id===4624?'remote.authenticated':'remote.ended';
      details={session_id:`winlogon:${digest([computer.toLowerCase(),boot]).slice(0,16)}:${logonId.toLowerCase()}`,protocol:'rdp',source_a:{ip:sourceIp,hostname:clean(fields.WorkstationName),account:null},target_b:{hostname:computer,account},relay:false,evidence_type:raw.event_id===4624?'authentication_log':'session_log'};
    }
    events.push({event_id:`winsec:${digest([computer.toLowerCase(),boot,raw.record_id,observed]).slice(0,40)}`,kind,observed_at:observed,asset:{external_id:`windows:${computer.toLowerCase()}`,hostname:computer,os_family:'windows',device_type:'unknown',addresses:[]},details,origin:{parser:'windows-security/1',record_id:String(raw.record_id),raw_sha256:digest(raw)}});
  }
  fail(events.length>0,400,'no_supported_windows_events');
  return {batch:{schema_version:'cg.telemetry/1',events},report:{parser:'windows-security/1',received:input.events.length,accepted:events.length,skipped,limitations:['4624 type 10 proves reported remote authentication, not active control.','Subject account is not attributed to source A.','Computer naming is source-scoped identity, not hardware attestation.']}};
}
