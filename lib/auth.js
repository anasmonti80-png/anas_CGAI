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
    const role=choice(input.role || 'admin',['admin','analyst','viewer'],'role');
    const password= passwordInput(input.password);
    if (first) fail(!this.store.get('SELECT id FROM users LIMIT 1'),409,'setup_complete');
    const passwordHash=await hashPassword(password);
    return this.store.transaction(() => {
      if (first) fail(!this.store.get('SELECT id FROM users LIMIT 1'),409,'setup_complete');
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
    return {id:row.user_id,username:row.username,role:row.role,csrf:row.csrf,session_hash:row.token_hash};
  }
  require(user, roles) { fail(roles.includes(user.role),403,'insufficient_role'); }
  logout(user) { this.store.run('DELETE FROM sessions WHERE token_hash=?',user.session_hash); this.store.audit(user.id,'logout','session'); }
}
