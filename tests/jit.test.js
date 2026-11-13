import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../lib/store.js';
import { Auth } from '../lib/auth.js';

function fixture(t){const s=new Store(':memory:');t.after(()=>s.close());let now=Date.parse('2026-11-11T10:00:00.000Z');const auth=new Auth(s,{clock:()=>now});
  for(const [id,role] of [['admin-a','admin'],['admin-b','admin'],['analyst-1','analyst'],['viewer-1','viewer']])s.run('INSERT INTO users VALUES (?,?,?,?,?)',id,id,'fixture-not-a-password-hash',role,new Date(now).toISOString());
  const user=id=>{const row=s.get('SELECT id,role FROM users WHERE id=?',id);const jit=auth.activeJit(id,now);return {id,role:jit?jit.requested_role:row.role,base_role:row.role,jit:jit?{id:jit.id}:null};};
  return {s,auth,user,advance:ms=>{now+=ms;}};}

test('just-in-time elevation needs a reason, a higher role, a different standing admin, and ends at expiry or the action cap with audit',t=>{
  const {s,auth,user,advance}=fixture(t);
  assert.throws(()=>auth.requestJit(user('analyst-1'),{role:'analyst',scope:'x',reason:'long enough reason',duration_minutes:30,max_actions:5}),/jit_role_must_exceed_current_role/);
  assert.throws(()=>auth.requestJit(user('analyst-1'),{role:'admin',scope:'x',reason:'short',duration_minutes:30,max_actions:5}),/jit_reason_too_short/);
  assert.throws(()=>auth.requestJit(user('analyst-1'),{role:'admin',scope:'x',reason:'long enough reason',duration_minutes:600,max_actions:5}),/invalid_jit_duration/);
  const g=auth.requestJit(user('analyst-1'),{role:'admin',scope:'Rotate the LAB source token',reason:'Incident 17 needs a source rotation now',duration_minutes:30,max_actions:2});assert.equal(g.state,'pending');assert.equal(user('analyst-1').role,'analyst');
  assert.throws(()=>auth.requestJit(user('analyst-1'),{role:'admin',scope:'x',reason:'second open request',duration_minutes:30,max_actions:2}),/jit_request_already_open/);
  assert.throws(()=>auth.decideJit(user('analyst-1'),g.id,'approve'),/jit_approver_must_be_standing_admin/);
  const v=auth.requestJit(user('viewer-1'),{role:'admin',scope:'self',reason:'trying to approve own request',duration_minutes:10,max_actions:1});
  auth.decideJit(user('admin-a'),v.id,'approve');const ev=user('viewer-1');assert.equal(ev.role,'admin');assert.throws(()=>auth.decideJit(ev,g.id,'approve'),/jit_approver_must_be_standing_admin/);
  const approved=auth.decideJit(user('admin-b'),g.id,'approve','ok');assert.equal(approved.state,'active');assert.equal(user('analyst-1').role,'admin');assert.equal(approved.expires_at,'2026-11-11T10:30:00.000Z');
  auth.recordJitUse(user('analyst-1'),'/api/sources');assert.equal(user('analyst-1').role,'admin');auth.recordJitUse(user('analyst-1'),'/api/sources');assert.equal(user('analyst-1').role,'analyst');assert.equal(auth.jitGrant(g.id).state,'exhausted');
  const g2=auth.requestJit(user('analyst-1'),{role:'admin',scope:'Review audit log',reason:'Weekly audit review window',duration_minutes:15,max_actions:50});auth.decideJit(user('admin-a'),g2.id,'approve');assert.equal(user('analyst-1').role,'admin');advance(15*60000);assert.equal(user('analyst-1').role,'analyst');assert.equal(auth.jitGrant(g2.id).state,'expired');
  const g3=auth.requestJit(user('analyst-1'),{role:'admin',scope:'x',reason:'revocation check request',duration_minutes:60,max_actions:5});auth.decideJit(user('admin-a'),g3.id,'approve');auth.revokeJit(user('admin-b'),g3.id);assert.equal(user('analyst-1').role,'analyst');
  const g4=auth.requestJit(user('analyst-1'),{role:'admin',scope:'x',reason:'denial check request',duration_minutes:60,max_actions:5});assert.throws(()=>auth.decideJit(user('analyst-1'),g4.id,'approve'),/jit_approver_must_be_standing_admin/);auth.decideJit(user('admin-a'),g4.id,'deny','not needed');assert.equal(auth.jitGrant(g4.id).state,'denied');
  const audit=s.all("SELECT action FROM audit WHERE action LIKE 'jit.%'").map(r=>r.action);for(const a of ['jit.requested','jit.approved','jit.used','jit.revoked','jit.denied'])assert.ok(audit.includes(a),a);assert.equal(s.verifyAudit().valid,true);
});
