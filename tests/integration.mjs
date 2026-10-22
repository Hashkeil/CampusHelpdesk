import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { PGlite } from '@electric-sql/pglite';
import { createTestHandler } from '../server/api.mjs';
process.env.APP_ORIGIN = 'http://localhost:8888';
process.env.RATE_LIMIT_SECRET = 'integration-only-secret-with-at-least-32-characters';
process.env.NODE_ENV = 'test';
delete process.env.NETLIFY;
delete process.env.ALERT_WEBHOOK_URL;

test('API security boundaries against an embedded PostgreSQL engine', async t => {
  const engine = new PGlite();
  await engine.exec(await readFile(new URL('../db/001-initial.sql',import.meta.url),'utf8'));
  const db = { query: async (...args) => { const result = await engine.query(...args); return { ...result,rowCount:result.rows.length || result.affectedRows || 0 }; } };
  db.connect = async () => ({ ...db,release() {} });
  const handler = createTestHandler(db);
  const pass = 'correct horse campus battery';
  async function call(path, method = 'GET', body, auth = {}, extra = {}) {
    const result = await handler({ httpMethod:method,rawUrl:`http://localhost:8888/api${path}`,headers:{ origin:process.env.APP_ORIGIN,'content-type':'application/json','x-campus-request':'1',cookie:auth.cookie || '', 'x-csrf-token':auth.csrf || '',...extra },body:body === undefined ? '' : JSON.stringify(body) });
    return { ...result,json:JSON.parse(result.body) };
  }
  async function register(address) { const result = await call('/auth/register','POST',{ name:'Test Student',email:address,password:pass }); assert.equal(result.statusCode,202); }
  async function login(address) { const result = await call('/auth/login','POST',{ email:address,password:pass }); assert.equal(result.statusCode,200); return { cookie:result.headers['Set-Cookie'].split(';')[0],csrf:result.json.csrfToken,id:result.json.user.id }; }
  try {
    await register('alice@example.com'); await register('bob@example.com');
    let alice = await login('alice@example.com'); const bob = await login('bob@example.com');
    let ticket;
    await t.test('SQL and HTML payloads remain literal data',async () => {
      const payload = "<img src=x onerror=alert(1)> ' OR 1=1 --";
      const result = await call('/tickets','POST',{ title:payload,body:'A legitimate support request with a payload.',category:'IT support',priority:'normal' },alice);
      assert.equal(result.statusCode,201); ticket = result.json.ticket;
      const read = await call(`/tickets/${ticket.id}`,'GET',undefined,alice); assert.equal(read.json.ticket.title,payload);
      const search = await call('/tickets?search='+encodeURIComponent("' OR 1=1 --"),'GET',undefined,bob); assert.equal(search.json.tickets.length,0);
      assert.equal((await db.query('SELECT count(*)::int AS count FROM users')).rows[0].count,2);
    });
    await t.test('other students cannot read or reply to private tickets',async () => {
      assert.equal((await call(`/tickets/${ticket.id}`,'GET',undefined,bob)).statusCode,404);
      assert.equal((await call(`/tickets/${ticket.id}/replies`,'POST',{ body:'unauthorized reply' },bob)).statusCode,404);
      assert.equal((await call('/tickets','GET',undefined,bob)).json.tickets.length,0);
    });
    await t.test('CSRF, cross-origin requests, content types and mass assignment are rejected',async () => {
      assert.equal((await call('/auth/logout','POST',{},alice,{ 'x-csrf-token':'wrong' })).statusCode,403);
      assert.equal((await call('/auth/logout','POST',{},alice,{ origin:'https://attacker.example' })).statusCode,403);
      assert.equal((await call('/auth/logout','POST',{},alice,{ 'content-type':'text/plain' })).statusCode,415);
      assert.equal((await call('/auth/register','POST',{ name:'Attacker',email:'evil@example.com',password:pass,role:'admin' })).statusCode,400);
      assert.equal((await call('/admin/users','GET',undefined,alice)).statusCode,403);
      assert.equal((await call(`/tickets/${ticket.id}`,'PATCH',{ status:'resolved' },alice)).statusCode,403);
    });
    await t.test('session rotation and logout invalidate old cookies',async () => {
      const old = alice; alice = await login('alice@example.com');
      assert.equal((await call('/auth/me','GET',undefined,old)).statusCode,401);
      const loggedOut = await call('/auth/logout','POST',{},alice); assert.equal(loggedOut.statusCode,200);
      assert.match(loggedOut.headers['Set-Cookie'],/Max-Age=0/);
      assert.equal((await call('/auth/me','GET',undefined,alice)).statusCode,401);
      alice = await login('alice@example.com');
    });
    await t.test('unassigned staff are denied; assigned staff may respond',async () => {
      await db.query("UPDATE users SET role='staff' WHERE id=$1",[bob.id]);
      assert.equal((await call(`/tickets/${ticket.id}`,'GET',undefined,bob)).statusCode,404);
      await db.query('UPDATE tickets SET assigned_to=$1 WHERE id=$2',[bob.id,ticket.id]);
      assert.equal((await call(`/tickets/${ticket.id}/replies`,'POST',{ body:'We are looking into this.' },bob)).statusCode,201);
      assert.equal((await call(`/tickets/${ticket.id}`,'PATCH',{ status:'in_progress' },bob)).statusCode,200);
    });
    await t.test('expired and blocked sessions are rejected',async () => {
      await db.query("UPDATE sessions SET expires_at=now()-interval '1 minute' WHERE user_id=$1",[bob.id]);
      assert.equal((await call('/auth/me','GET',undefined,bob)).statusCode,401);
      await db.query('UPDATE users SET blocked=true WHERE id=$1',[alice.id]);
      assert.equal((await call('/auth/me','GET',undefined,alice)).statusCode,401);
      await db.query('UPDATE users SET blocked=false WHERE id=$1',[alice.id]);
    });
    await t.test('failed authentication raises a deduplicated alert without exposing credentials',async () => {
      await db.query('DELETE FROM rate_limits');
      for (let i=0;i<6;i++) assert.equal((await call('/auth/login','POST',{ email:'missing@example.com',password:pass })).statusCode,401);
      const alerts = (await db.query('SELECT * FROM security_alerts')).rows;
      assert.equal(alerts.length,1); assert.equal(alerts[0].status,'not_configured');
      const logs = JSON.stringify((await db.query('SELECT * FROM audit_events')).rows);
      assert.ok(!logs.includes(pass)); assert.ok(!logs.includes('missing@example.com'));
    });
    await t.test('rate limiting persists across requests and oversized bodies are rejected',async () => {
      await db.query('DELETE FROM rate_limits');
      let result;
      for (let i=0;i<121;i++) result = await call('/auth/me','GET',undefined,alice);
      assert.equal(result.statusCode,429); assert.ok(result.headers['Retry-After']);
      assert.equal((await call('/tickets','POST',{ body:'x'.repeat(17000) },alice)).statusCode,413);
    });
    await t.test('administrators can block accounts and revoke their sessions',async () => {
      await db.query('DELETE FROM rate_limits');
      await db.query("UPDATE users SET role='admin' WHERE id=$1",[alice.id]);
      const result = await call(`/admin/users/${bob.id}`,'PATCH',{ role:'student',blocked:true },alice);
      assert.equal(result.statusCode,200);
      assert.equal((await db.query('SELECT blocked FROM users WHERE id=$1',[bob.id])).rows[0].blocked,true);
      assert.equal((await db.query('SELECT * FROM sessions WHERE user_id=$1',[bob.id])).rows.length,0);
      assert.equal((await call(`/admin/users/${alice.id}`,'PATCH',{ role:'student',blocked:false },alice)).statusCode,400);
    });
    await t.test('webhook success and failure are recorded without leaking destination secrets',async () => {
      const originalFetch = globalThis.fetch;
      process.env.ALERT_WEBHOOK_URL = 'https://alerts.example.test/receiver';
      try {
        for (const succeed of [true,false]) {
          await db.query('DELETE FROM rate_limits');
          globalThis.fetch = async (_url,options) => { assert.equal(options.redirect,'error'); assert.ok(!options.body.includes(pass)); if (!succeed) throw new Error('unreachable'); return { ok:true }; };
          for (let i=0;i<5;i++) await call('/auth/login','POST',{ email:'absent@example.com',password:pass });
          const alert = (await db.query('SELECT status FROM security_alerts ORDER BY created_at DESC LIMIT 1')).rows[0];
          assert.equal(alert.status,succeed ? 'delivered' : 'failed');
        }
      } finally { globalThis.fetch = originalFetch; delete process.env.ALERT_WEBHOOK_URL; }
    });
    await t.test('database failures fail closed with a redacted error',async () => {
      const broken = createTestHandler({ query:async () => { throw new Error('secret database connection'); } });
      const response = await broken({ httpMethod:'GET',rawUrl:'http://localhost:8888/api/auth/me',headers:{} });
      assert.equal(response.statusCode,500); assert.ok(!response.body.includes('secret'));
    });
  } finally { await engine.close(); }
});
