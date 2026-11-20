// CG-112 threat intelligence quality: every indicator keeps its source, dates, confidence,
// expiry and redistribution rights. A match is investigation context only and never creates
// a response action or an automatic block.
import { isIP } from 'node:net';
import { choice, digest, fail, integer, object, text } from './common.js';

const TYPES=['ipv4','ipv6','domain','url','sha256'];
const RIGHTS=['permitted','restricted','prohibited','unknown'];
const iso=(value,name)=>{fail(typeof value==='string'&&Number.isFinite(Date.parse(value))&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value),400,`invalid_${name}`);return new Date(value).toISOString();};
function indicator(type,value){
  const raw=text(value,'indicator_value',2048);
  if(type==='ipv4'||type==='ipv6'){fail(isIP(raw)===(type==='ipv4'?4:6),400,'invalid_indicator_value');return raw.toLowerCase();}
  if(type==='domain'){const v=raw.toLowerCase().replace(/\.$/,'');fail(v.length<=253&&/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(v),400,'invalid_indicator_value');return v;}
  if(type==='url'){let u;try{u=new URL(raw);}catch{}fail(u&&['http:','https:'].includes(u.protocol)&&!u.username&&!u.password,400,'invalid_indicator_value');u.hash='';return u.toString();}
  const v=raw.toLowerCase();fail(/^[a-f0-9]{64}$/.test(v),400,'invalid_indicator_value');return v;
}

export class ThreatIntelligence {
  constructor(store,{clock}={}){this.s=store;this.clock=clock||(()=>Date.now());}
  now(){return new Date(this.clock()).toISOString();}
  add(actor,input){
    object(input,['type','value','source_name','source_ref','published_at','expires_at','confidence','redistribution_rights','source_verified'],'threat_indicator');
    const type=choice(input.type,TYPES,'indicator_type'),value=indicator(type,input.value),source_name=text(input.source_name,'indicator_source_name',200),source_ref=text(input.source_ref,'indicator_source_ref',1000);
    fail(/^https:\/\/[^\s]+$/.test(source_ref),400,'indicator_source_must_be_https');
    const published_at=iso(input.published_at,'indicator_published_at'),expires_at=iso(input.expires_at,'indicator_expires_at');
    fail(Date.parse(published_at)<=this.clock()+300000&&Date.parse(expires_at)>Date.parse(published_at),400,'invalid_indicator_lifetime');
    const confidence=integer(input.confidence,0,100,'indicator_confidence'),redistribution_rights=choice(input.redistribution_rights,RIGHTS,'indicator_redistribution_rights');
    fail(typeof input.source_verified==='boolean',400,'invalid_indicator_source_verified');
    const id=digest({type,value,source_ref,published_at});
    this.s.run('INSERT INTO threat_indicators(id,type,value,source_name,source_ref,published_at,expires_at,confidence,redistribution_rights,source_verified,added_by,added_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET expires_at=excluded.expires_at,confidence=excluded.confidence,redistribution_rights=excluded.redistribution_rights,source_verified=excluded.source_verified',id,type,value,source_name,source_ref,published_at,expires_at,confidence,redistribution_rights,input.source_verified?1:0,actor,this.now());
    this.s.audit(actor,'threat_indicator.recorded',id,{type,source_name,confidence,redistribution_rights,source_verified:input.source_verified},this.now());return this.get(id);
  }
  row(r){if(!r)return null;const current=Date.parse(r.expires_at)>this.clock(),trusted=Boolean(r.source_verified)&&r.confidence>=70&&current;return {...r,source_verified:Boolean(r.source_verified),current,trusted,quality_state:!current?'expired':trusted?'trusted':'untrusted',enforcement:'manual-review-only',auto_block_allowed:false};}
  get(id){return this.row(this.s.get('SELECT * FROM threat_indicators WHERE id=?',id));}
  list(){return this.s.all('SELECT * FROM threat_indicators ORDER BY published_at DESC,id LIMIT 500').map(r=>this.row(r));}
  check(input){object(input,['type','value'],'indicator_check');const type=choice(input.type,TYPES,'indicator_type'),value=indicator(type,input.value),matches=this.s.all('SELECT * FROM threat_indicators WHERE type=? AND value=? ORDER BY confidence DESC',type,value).map(r=>this.row(r));return {type,value,matches,classification:matches.some(x=>x.trusted)?'trusted-match-requires-investigation':matches.length?'untrusted-context-only':'no-match',can_raise_alert:matches.some(x=>x.trusted),auto_block_allowed:false,action_created:false,claim:'An indicator match is investigation context, not proof. No indicator creates an automatic block.'};}
  exportable(){return {schema_version:'cg.threat-intelligence/1',generated_at:this.now(),items:this.list().filter(x=>x.current&&x.redistribution_rights==='permitted').map(({added_by,added_at,enforcement,auto_block_allowed,...x})=>x)};}
}
