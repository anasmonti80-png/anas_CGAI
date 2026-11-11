import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { digest } from './common.js';

// Explicit, one-shot inventory of the control-plane host. No process inventory,
// user names, credential access, shell commands, network probes or prevention claims.
export function localObservation(provider=os,now=new Date()) {
  const family={win32:'windows',darwin:'macos',linux:'linux'}[provider.platform()]||'unknown';
  const hostname=provider.hostname();
  const addresses=[...new Set(Object.values(provider.networkInterfaces()).flat().filter(n=>n&&!n.internal).map(n=>n.address.split('%')[0]))].slice(0,32);
  return {schema_version:'cg.telemetry/1',events:[{
    event_id:`local-${randomUUID()}`,kind:'asset.observed',observed_at:now.toISOString(),
    asset:{external_id:`control-plane-${digest([hostname,provider.platform(),provider.arch()]).slice(0,24)}`,hostname,os_family:family,device_type:'unknown',addresses},details:{},
  }]};
}
