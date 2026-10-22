import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { hashPassword,verifyPassword,fields,text,email,password,choice,uuid,mayRead,sessionCookie,readCookie,equal } from '../server/security.mjs';

test('passwords have independent salts and verify without accepting a wrong password',async () => {
  const pass = 'this is a long test passphrase';
  const a = await hashPassword(pass), b = await hashPassword(pass);
  assert.notEqual(a,b); assert.equal(await verifyPassword(pass,a),true); assert.equal(await verifyPassword('wrong',a),false);
});
test('input schemas reject privilege escalation fields and invalid data',() => {
  assert.throws(() => fields({ name:'Student',role:'admin' },['name']));
  assert.throws(() => fields([],[])); assert.throws(() => text('x',2,10));
  assert.throws(() => text('a\u0000b',1,10)); assert.throws(() => password('short'));
  assert.throws(() => email('invalid')); assert.throws(() => choice('root',['student','staff']));
  assert.throws(() => uuid("' OR 1=1--")); assert.equal(uuid(randomUUID()).length,36);
  assert.equal(email('Student@Example.com'),'student@example.com');
});
test('ticket permissions separate ownership, assigned staff, and administrators',() => {
  const ticket = { owner_id:'owner',assigned_to:'assigned' };
  assert.equal(mayRead({ id:'other',role:'student' },ticket),false);
  assert.equal(mayRead({ id:'owner',role:'student' },ticket),true);
  assert.equal(mayRead({ id:'other',role:'staff' },ticket),false);
  assert.equal(mayRead({ id:'assigned',role:'staff' },ticket),true);
  assert.equal(mayRead({ id:'admin',role:'admin' },ticket),true);
});
test('production cookies are host-scoped, inaccessible to JS, and expire on logout',() => {
  const value = 'a'.repeat(64), cookie = sessionCookie(value,true);
  assert.match(cookie,/^__Host-campus=/); assert.match(cookie,/; Secure/); assert.match(cookie,/HttpOnly/); assert.match(cookie,/SameSite=Strict/); assert.doesNotMatch(cookie,/Domain=/);
  assert.equal(readCookie(`__Host-campus=${value}`,true),value);
  assert.equal(readCookie(`__Host-campus=${value}; __Host-campus=${value}`,true),null);
  assert.match(sessionCookie('',true,true),/Max-Age=0/);
  assert.equal(equal('abc','different'),false);
  assert.equal(equal('é','a'),false);
});
