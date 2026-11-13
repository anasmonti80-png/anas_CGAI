import { randomBytes, randomUUID, scrypt as scryptCallback } from 'node:crypto';
import { promisify } from 'node:util';
import { AppError, fail, token, digest, equal, text, choice } from './common.js';
const scrypt = promisify(scryptCallback);
const cost = { N:32768, r:8, p:3, maxmem:64*1024*1024 };
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
  constructor(store, {clock = () => Date.now()} = {}) { this.store=store; this.clock=clock; this.attempts=new Map(); this.inFlight=0; }
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
    const session=token(), csrf=token(), now=this.clock();
    this.store.run('DELETE FROM sessions WHERE expires_at < ? OR last_seen < ?',now,now-30*60*1000);
    this.store.run('INSERT INTO sessions VALUES (?,?,?,?,?,?)',digest(session),user.id,csrf,now,now,now+8*60*60*1000);
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
    const jit=this.activeJit(row.user_id,now);
    return {id:row.user_id,username:row.username,role:jit?jit.requested_role:row.role,base_role:row.role,jit:jit?{id:jit.id,role:jit.requested_role,scope:jit.scope,expires_at:jit.expires_at,actions_left:jit.max_actions-jit.used_actions}:null,csrf:row.csrf,session_hash:row.token_hash};
  }
  require(user, roles) { fail(roles.includes(user.role),403,'insufficient_role'); }
  activeJit(userId,now=this.clock()) {
    const iso=new Date(now).toISOString();
    return this.store.get("SELECT * FROM jit_grants WHERE user_id=? AND status='approved' AND starts_at<=? AND expires_at>? AND used_actions<max_actions ORDER BY expires_at DESC LIMIT 1",userId,iso,iso)||null;
  }
  requestJit(user,input) {
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
  logout(user) { this.store.run('DELETE FROM sessions WHERE token_hash=?',user.session_hash); this.store.audit(user.id,'logout','session'); }
}
