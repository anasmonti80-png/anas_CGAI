import { randomBytes, randomUUID, scrypt as scryptCallback, createCipheriv, createDecipheriv, createHmac } from 'node:crypto';
import { promisify } from 'node:util';
import fs from 'node:fs';
import { AppError, fail, token, digest, equal, text, choice } from './common.js';
const scrypt = promisify(scryptCallback);
const cost = { N:32768, r:8, p:3, maxmem:64*1024*1024 };
const base32Alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(buffer){let bits=0,value=0,out='';for(const byte of buffer){value=(value<<8)|byte;bits+=8;while(bits>=5){out+=base32Alphabet[(value>>>(bits-5))&31];bits-=5;}}if(bits)out+=base32Alphabet[(value<<(5-bits))&31];return out;}
function base32Decode(value){let bits=0,acc=0,bytes=[];for(const char of String(value).replace(/=+$/,'').toUpperCase()){const n=base32Alphabet.indexOf(char);if(n<0)throw new AppError(400,'invalid_mfa_seed');acc=(acc<<5)|n;bits+=5;if(bits>=8){bytes.push((acc>>>(bits-8))&255);bits-=8;}}return Buffer.from(bytes);}
export function totpCode(seed,at=Date.now()){const counter=Math.floor(at/30000),buffer=Buffer.alloc(8);buffer.writeBigUInt64BE(BigInt(counter));const mac=createHmac('sha1',base32Decode(seed)).update(buffer).digest(),offset=mac[19]&15,value=(mac.readUInt32BE(offset)&0x7fffffff)%1000000;return String(value).padStart(6,'0');}
export async function hashPassword(password, salt = randomBytes(16).toString('hex')) {
  const key = await scrypt(password,salt,64,cost);
  return `scrypt$32768$8$3$${salt}$${key.toString('hex')}`;
}
export async function verifyPassword(password, encoded) {
  const parts = encoded.split('$');
  if (parts.length !== 6 || parts.slice(0,4).join('$') !== 'scrypt$32768$8$3') return false;
  return equal(await hashPassword(password,parts[4]),encoded);
}
export function passwordInput(password) {
  fail(typeof password === 'string' && password.length >= 14 && password.length <= 256,400,'password_requires_14_to_256_characters');
  return password;
}
export class Auth {
  constructor(store, {clock = () => Date.now()} = {}) { this.store=store; this.clock=clock; this.attempts=new Map(); this.inFlight=0; this.mfaKey=this.loadMfaKey(); }
  loadMfaKey(){if(this.store.filename===':memory:')return randomBytes(32);const file=`${this.store.filename}.mfa-key`;if(fs.existsSync(file)){const key=fs.readFileSync(file);fail(key.length===32,500,'invalid_local_mfa_key');return key;}const key=randomBytes(32);fs.writeFileSync(file,key,{mode:0o600,flag:'wx'});return key;}
  encryptSeed(seed){const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',this.mfaKey,iv),encrypted=Buffer.concat([cipher.update(seed,'utf8'),cipher.final()]),tag=cipher.getAuthTag();return Buffer.concat([iv,tag,encrypted]).toString('base64url');}
  decryptSeed(value){const packed=Buffer.from(value,'base64url');fail(packed.length>28,500,'invalid_mfa_record');const decipher=createDecipheriv('aes-256-gcm',this.mfaKey,packed.subarray(0,12));decipher.setAuthTag(packed.subarray(12,28));return Buffer.concat([decipher.update(packed.subarray(28)),decipher.final()]).toString('utf8');}
  limit(key) {
    const now=this.clock();
    for (const [k,v] of this.attempts) if (v.until<=now) this.attempts.delete(k);
    const current=this.attempts.get(key) || {count:0,until:now+15*60*1000};
    if (current.count>=10 || this.inFlight>=4) throw new AppError(429,'too_many_attempts');
    current.count++; this.attempts.set(key,current);
  }
  async createUser(actor, input, first = false) {
    const username = text(input.username,'username',64);
    fail(/^[A-Za-z0-9_.-]{3,64}$/.test(username),400,'invalid_username');
    const role=choice(input.role || (first?'admin':'viewer'),['admin','analyst','viewer'],'role');
    const password= passwordInput(input.password);
    if (first) fail(!this.store.get('SELECT id FROM users LIMIT 1'),409,'setup_complete');
    const passwordHash=await hashPassword(password);
    return this.store.transaction(() => {
      if (first) fail(!this.store.get('SELECT id FROM users LIMIT 1'),409,'setup_complete');
      fail(this.store.get('SELECT COUNT(*) n FROM users').n<100,409,'user_limit');
      fail(!this.store.get('SELECT id FROM users WHERE username=?',username),409,'username_exists');
      const id=randomUUID(), created_at=new Date(this.clock()).toISOString();
      this.store.run('INSERT INTO users VALUES (?,?,?,?,?)',id,username,passwordHash,role,created_at);
      this.store.audit(actor,'user.created',id,{role},created_at);
      return {id,username,role,created_at};
    });
  }
  async login(input, address) {
    this.limit(address);
    const username=text(input.username,'username',64), password=passwordInput(input.password);
    const user=this.store.get('SELECT * FROM users WHERE username=?',username);
    this.inFlight++;
    let valid;
    try { valid=await verifyPassword(password,user?.password_hash || `scrypt$32768$8$3$${'0'.repeat(32)}$${'0'.repeat(128)}`); }
    finally { this.inFlight--; }
    if (!user || !valid) { this.store.audit('anonymous','login.denied','session',{}); throw new AppError(401,'invalid_credentials'); }
    const mfa=this.store.get('SELECT * FROM user_mfa WHERE user_id=? AND enabled_at IS NOT NULL',user.id),mfaCode=typeof input.mfa_code==='string'?input.mfa_code:null;
    if(mfa){fail(mfaCode&&this.validTotp(this.decryptSeed(mfa.seed_cipher),mfaCode),401,'mfa_required_or_invalid');}
    const session=token(), csrf=token(), now=this.clock();
    this.store.run('DELETE FROM sessions WHERE expires_at < ? OR last_seen < ?',now,now-30*60*1000);
    const sessionHash=digest(session),mfaAt=mfa?now:null;
    this.store.run('INSERT INTO sessions(token_hash,user_id,csrf,created_at,last_seen,expires_at,mfa_at) VALUES (?,?,?,?,?,?,?)',sessionHash,user.id,csrf,now,now,now+8*60*60*1000,mfaAt);
    if(mfa)this.recordMfa(user.id,sessionHash,'totp');
    this.store.audit(user.id,'login.succeeded','session',{});
    return {token:session,csrf,user:{id:user.id,username:user.username,role:user.role}};
  }
  session(cookie) {
    const value=String(cookie || '').split(';').map(x=>x.trim()).find(x=>x.startsWith('cg_session='))?.slice(11);
    if (!value || value.length>100) throw new AppError(401,'authentication_required');
    const row=this.store.get('SELECT s.*,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE token_hash=?',digest(value));
    const now=this.clock();
    if (!row || row.expires_at<=now || row.last_seen+30*60*1000<=now) throw new AppError(401,'session_expired');
    this.store.run('UPDATE sessions SET last_seen=? WHERE token_hash=?',now,row.token_hash);
    const emergency=this.activeBreakGlass(row.user_id,now),jit=emergency?null:this.activeJit(row.user_id,now),mfaEnabled=Boolean(this.store.get('SELECT user_id FROM user_mfa WHERE user_id=? AND enabled_at IS NOT NULL',row.user_id)),mfaRecent=Number.isInteger(row.mfa_at)&&row.mfa_at>=now-5*60000;
    return {id:row.user_id,username:row.username,role:emergency?'admin':jit?jit.requested_role:row.role,base_role:row.role,jit:jit?{id:jit.id,role:jit.requested_role,scope:jit.scope,expires_at:jit.expires_at,actions_left:jit.max_actions-jit.used_actions}:null,break_glass:emergency?{id:emergency.id,scope:emergency.scope,expires_at:emergency.expires_at,actions_left:emergency.max_actions-emergency.used_actions}:null,mfa:{enabled:mfaEnabled,recent:mfaRecent,verified_at:mfaRecent?new Date(row.mfa_at).toISOString():null,expires_at:mfaRecent?new Date(row.mfa_at+5*60000).toISOString():null},csrf:row.csrf,session_hash:row.token_hash};
  }
  validTotp(seed,code){if(!/^\d{6}$/.test(String(code||'')))return false;return [-1,0,1].some(step=>equal(totpCode(seed,this.clock()+step*30000),String(code)));}
  enrollMfa(user){fail(!this.store.get('SELECT user_id FROM user_mfa WHERE user_id=? AND enabled_at IS NOT NULL',user.id),409,'mfa_already_enabled');const seed=base32Encode(randomBytes(20)),at=new Date(this.clock()).toISOString();this.store.run('INSERT INTO user_mfa(user_id,seed_cipher,enrolled_at,enabled_at) VALUES (?,?,?,NULL) ON CONFLICT(user_id) DO UPDATE SET seed_cipher=excluded.seed_cipher,enrolled_at=excluded.enrolled_at,enabled_at=NULL',user.id,this.encryptSeed(seed),at);this.store.audit(user.id,'mfa.enrollment.started',user.id,{method:'totp'},at);return {method:'totp',seed,uri:`otpauth://totp/CyberGuard:${encodeURIComponent(user.username)}?secret=${seed}&issuer=CyberGuard&digits=6&period=30`,claim:'The seed is shown once for local authenticator enrollment. It is encrypted at rest with a local device key and is never written to audit or logs.'};}
  confirmMfa(user,code){const row=this.store.require('SELECT * FROM user_mfa WHERE user_id=?',[user.id]);fail(this.validTotp(this.decryptSeed(row.seed_cipher),code),401,'invalid_mfa_code');const at=new Date(this.clock()).toISOString();this.store.transaction(()=>{this.store.run('UPDATE user_mfa SET enabled_at=? WHERE user_id=?',at,user.id);this.store.run('UPDATE sessions SET mfa_at=? WHERE token_hash=?',this.clock(),user.session_hash);this.recordMfa(user.id,user.session_hash,'totp');this.store.audit(user.id,'mfa.enabled',user.id,{method:'totp'},at);});return this.mfaStatus({...user,mfa:{enabled:true,recent:true}});}
  verifyMfa(user,code){const row=this.store.require('SELECT * FROM user_mfa WHERE user_id=? AND enabled_at IS NOT NULL',[user.id]);fail(this.validTotp(this.decryptSeed(row.seed_cipher),code),401,'invalid_mfa_code');this.store.transaction(()=>{this.store.run('UPDATE sessions SET mfa_at=? WHERE token_hash=?',this.clock(),user.session_hash);this.recordMfa(user.id,user.session_hash,'totp');});return this.mfaStatus({...user,mfa:{enabled:true,recent:true}});}
  recordMfa(userId,sessionHash,method){const verifiedAt=new Date(this.clock()).toISOString(),expiresAt=new Date(this.clock()+5*60000).toISOString(),id=randomUUID(),evidenceHash=digest({id,userId,sessionHash,method,verifiedAt,expiresAt});this.store.run('INSERT INTO mfa_assertions VALUES (?,?,?,?,?,?,?)',id,userId,sessionHash,method,verifiedAt,expiresAt,evidenceHash);this.store.audit(userId,'mfa.verified',id,{method,expires_at:expiresAt,evidence_hash:evidenceHash},verifiedAt);return {id,verified_at:verifiedAt,expires_at:expiresAt,evidence_hash:evidenceHash};}
  mfaStatus(user){const enabled=Boolean(this.store.get('SELECT user_id FROM user_mfa WHERE user_id=? AND enabled_at IS NOT NULL',user.id)),session=this.store.get('SELECT mfa_at FROM sessions WHERE token_hash=?',user.session_hash),recent=Number.isInteger(session?.mfa_at)&&session.mfa_at>=this.clock()-5*60000;return {enabled,recent,verified_at:recent?new Date(session.mfa_at).toISOString():null,expires_at:recent?new Date(session.mfa_at+5*60000).toISOString():null,window_minutes:5};}
  requireRecentMfa(user){const session=this.store.get('SELECT mfa_at FROM sessions WHERE token_hash=? AND user_id=?',user.session_hash,user.id);fail(Number.isInteger(session?.mfa_at)&&session.mfa_at>=this.clock()-5*60000,403,'recent_mfa_required');}
  require(user, roles) { fail(roles.includes(user.role),403,'insufficient_role'); }
  activeJit(userId,now=this.clock()) {
    const iso=new Date(now).toISOString();
    return this.store.get("SELECT * FROM jit_grants WHERE user_id=? AND status='approved' AND starts_at<=? AND expires_at>? AND used_actions<max_actions ORDER BY expires_at DESC LIMIT 1",userId,iso,iso)||null;
  }
  requestJit(user,input) {
    this.requireRecentMfa(user);
    const rank={viewer:0,analyst:1,admin:2},requested_role=choice(input.role,['analyst','admin'],'jit_role');
    fail(rank[requested_role]>rank[user.base_role||user.role],400,'jit_role_must_exceed_current_role');
    const reason=text(input.reason,'jit_reason',500);fail(reason.length>=10,400,'jit_reason_too_short');
    const duration=Number(input.duration_minutes),maxActions=Number(input.max_actions);fail(Number.isInteger(duration)&&duration>=5&&duration<=480,400,'invalid_jit_duration');fail(Number.isInteger(maxActions)&&maxActions>=1&&maxActions<=500,400,'invalid_jit_max_actions');
    const now=new Date(this.clock()).toISOString();
    return this.store.transaction(()=>{
      fail(!this.store.get("SELECT id FROM jit_grants WHERE user_id=? AND (status='pending' OR (status='approved' AND expires_at>? AND used_actions<max_actions))",user.id,now),409,'jit_request_already_open');
      const id=randomUUID();
      this.store.run("INSERT INTO jit_grants(id,user_id,base_role,requested_role,scope,reason,duration_minutes,max_actions,status,requested_at) VALUES (?,?,?,?,?,?,?,?,'pending',?)",id,user.id,user.base_role||user.role,requested_role,text(input.scope,'jit_scope',300),reason,duration,maxActions,now);
      this.store.audit(user.id,'jit.requested',id,{requested_role,duration_minutes:duration,max_actions:maxActions},now);
      return this.jitGrant(id);
    });
  }
  decideJit(approver,id,decision,note=null) {
    this.requireRecentMfa(approver);
    fail((approver.base_role||approver.role)==='admin',403,'jit_approver_must_be_standing_admin');
    const grant=this.store.require('SELECT * FROM jit_grants WHERE id=?',[id]);fail(grant.status==='pending',409,'jit_not_pending');fail(grant.user_id!==approver.id,403,'jit_self_approval_forbidden');
    const now=this.clock(),iso=new Date(now).toISOString(),status=decision==='approve'?'approved':'denied';
    this.store.transaction(()=>{
      if(status==='approved')this.store.run("UPDATE jit_grants SET status='approved',decided_by=?,decided_at=?,decision_note=?,starts_at=?,expires_at=? WHERE id=?",approver.id,iso,note,iso,new Date(now+grant.duration_minutes*60000).toISOString(),id);
      else this.store.run("UPDATE jit_grants SET status='denied',decided_by=?,decided_at=?,decision_note=? WHERE id=?",approver.id,iso,note,id);
      this.store.audit(approver.id,`jit.${status}`,id,{requested_role:grant.requested_role,user_id:grant.user_id},iso);
    });
    return this.jitGrant(id);
  }
  revokeJit(actor,id) {
    this.requireRecentMfa(actor);
    const grant=this.store.require('SELECT * FROM jit_grants WHERE id=?',[id]);fail(grant.status==='approved'||grant.status==='pending',409,'jit_not_revocable');
    fail(grant.user_id===actor.id||(actor.base_role||actor.role)==='admin',403,'insufficient_role');
    const iso=new Date(this.clock()).toISOString();
    this.store.transaction(()=>{this.store.run("UPDATE jit_grants SET status='revoked',revoked_by=?,revoked_at=? WHERE id=?",actor.id,iso,id);this.store.audit(actor.id,'jit.revoked',id,{user_id:grant.user_id},iso);});
    return this.jitGrant(id);
  }
  recordJitUse(user,path) {
    if(!user.jit)return;
    this.store.transaction(()=>{this.store.run('UPDATE jit_grants SET used_actions=used_actions+1 WHERE id=?',user.jit.id);this.store.audit(user.id,'jit.used',user.jit.id,{path},new Date(this.clock()).toISOString());});
  }
  jitGrant(id) {
    const row=this.store.require('SELECT g.*,u.username,d.username decided_by_name FROM jit_grants g JOIN users u ON u.id=g.user_id LEFT JOIN users d ON d.id=g.decided_by WHERE g.id=?',[id]),now=new Date(this.clock()).toISOString();
    const state=row.status!=='approved'?row.status:row.used_actions>=row.max_actions?'exhausted':row.expires_at<=now?'expired':'active';
    return {...row,state};
  }
  listJit(user) {
    const admin=(user.base_role||user.role)==='admin';
    const ids=this.store.all(`SELECT id FROM jit_grants ${admin?'':'WHERE user_id=?'} ORDER BY requested_at DESC LIMIT 200`,...(admin?[]:[user.id])).map(row=>row.id);
    return {items:ids.map(id=>this.jitGrant(id)),claim:'Just-in-time elevation inside CyberGuard: a time-boxed, action-capped role raise with a written reason and scope, approved by a different standing administrator, effective immediately on approval, ending automatically at expiry or after the action cap, revocable at any time, and recorded in the append-only audit log.'};
  }
  activeBreakGlass(userId,now=this.clock()){const iso=new Date(now).toISOString();return this.store.get("SELECT * FROM break_glass_grants WHERE user_id=? AND status='approved' AND expires_at>? AND used_actions<max_actions ORDER BY expires_at DESC LIMIT 1",userId,iso)||null;}
  requestBreakGlass(user,input){this.requireRecentMfa(user);const scope=text(input.scope,'break_glass_scope',300),reason=text(input.reason,'break_glass_reason',1000);fail(reason.length>=20,400,'break_glass_reason_too_short');const duration=Number(input.duration_minutes),maxActions=Number(input.max_actions);fail(Number.isInteger(duration)&&duration>=5&&duration<=60,400,'invalid_break_glass_duration');fail(Number.isInteger(maxActions)&&maxActions>=1&&maxActions<=5,400,'invalid_break_glass_action_cap');const at=new Date(this.clock()).toISOString();return this.store.transaction(()=>{fail(!this.store.get("SELECT id FROM break_glass_grants WHERE user_id=? AND (status='pending' OR (status='approved' AND expires_at>? AND used_actions<max_actions))",user.id,at),409,'break_glass_request_already_open');const id=randomUUID();this.store.run("INSERT INTO break_glass_grants(id,user_id,base_role,scope,reason,duration_minutes,max_actions,status,requested_at) VALUES (?,?,?,?,?,?,?,'pending',?)",id,user.id,user.base_role||user.role,scope,reason,duration,maxActions,at);this.store.audit(user.id,'break-glass.requested',id,{scope,duration_minutes:duration,max_actions:maxActions},at);return this.breakGlassGrant(id);});}
  decideBreakGlass(approver,id,decision){this.requireRecentMfa(approver);fail((approver.base_role||approver.role)==='admin',403,'break_glass_approver_must_be_standing_admin');const grant=this.store.require('SELECT * FROM break_glass_grants WHERE id=?',[id]);fail(grant.status==='pending',409,'break_glass_not_pending');fail(grant.user_id!==approver.id,403,'break_glass_self_approval_forbidden');const at=new Date(this.clock()).toISOString(),status=decision==='approve'?'approved':'denied';this.store.transaction(()=>{if(status==='approved')this.store.run("UPDATE break_glass_grants SET status='approved',approved_by=?,approved_at=?,expires_at=? WHERE id=?",approver.id,at,new Date(this.clock()+grant.duration_minutes*60000).toISOString(),id);else this.store.run("UPDATE break_glass_grants SET status='denied',approved_by=?,approved_at=? WHERE id=?",approver.id,at,id);this.store.audit(approver.id,`break-glass.${status}`,id,{user_id:grant.user_id,scope:grant.scope},at);});return this.breakGlassGrant(id);}
  revokeBreakGlass(actor,id){this.requireRecentMfa(actor);const grant=this.store.require('SELECT * FROM break_glass_grants WHERE id=?',[id]);fail(['pending','approved'].includes(grant.status),409,'break_glass_not_revocable');fail(grant.user_id===actor.id||(actor.base_role||actor.role)==='admin',403,'insufficient_role');const at=new Date(this.clock()).toISOString();this.store.transaction(()=>{this.store.run("UPDATE break_glass_grants SET status='revoked',revoked_by=?,revoked_at=? WHERE id=?",actor.id,at,id);this.store.audit(actor.id,'break-glass.revoked',id,{user_id:grant.user_id,scope:grant.scope},at);});return this.breakGlassGrant(id);}
  breakGlassGrant(id){const row=this.store.require('SELECT g.*,u.username,a.username approved_by_name FROM break_glass_grants g JOIN users u ON u.id=g.user_id LEFT JOIN users a ON a.id=g.approved_by WHERE g.id=?',[id]),now=new Date(this.clock()).toISOString(),state=row.status!=='approved'?row.status:row.used_actions>=row.max_actions?'exhausted':row.expires_at<=now?'expired':'active';return {...row,state};}
  listBreakGlass(user){const standing=(user.base_role||user.role)==='admin',ids=this.store.all(`SELECT id FROM break_glass_grants ${standing?'':'WHERE user_id=?'} ORDER BY requested_at DESC LIMIT 200`,...(standing?[]:[user.id])).map(row=>row.id);return {items:ids.map(id=>this.breakGlassGrant(id)),claim:'Controlled emergency elevation requires recent TOTP, a written narrow scope, a 5–60 minute window, a 1–5 action cap and approval by a different standing administrator. It never bypasses action-specific safety preflights or independent action approval, and every transition is appended to the audit chain.'};}
  recordPrivilegedUse(user,path){if(user.break_glass){this.store.transaction(()=>{const grant=this.store.require('SELECT * FROM break_glass_grants WHERE id=?',[user.break_glass.id]);fail(grant.status==='approved'&&grant.expires_at>new Date(this.clock()).toISOString()&&grant.used_actions<grant.max_actions,403,'break_glass_expired_or_exhausted');this.store.run('UPDATE break_glass_grants SET used_actions=used_actions+1 WHERE id=?',grant.id);this.store.audit(user.id,'break-glass.used',grant.id,{path},new Date(this.clock()).toISOString());});return;}this.recordJitUse(user,path);}
  logout(user) { this.store.run('DELETE FROM sessions WHERE token_hash=?',user.session_hash); this.store.audit(user.id,'logout','session'); }
}
