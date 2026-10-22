import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { PGlite } from '@electric-sql/pglite';
import { createTestHandler } from '../server/api.mjs';
import { rateKey } from '../server/security.mjs';
process.env.APP_ORIGIN = 'http://localhost:8888';
process.env.RATE_LIMIT_SECRET = 'integration-only-secret-with-at-least-32-characters';
process.env.NODE_ENV = 'test';
delete process.env.NETLIFY;
delete process.env.ALERT_WEBHOOK_URL;
delete process.env.PASSWORD_RESET_WEBHOOK_URL;

test('API security boundaries against an embedded PostgreSQL engine', async t => {
  const engine = new PGlite();
  const migrations = new URL('../db/',import.meta.url);
  for (const file of (await readdir(migrations)).filter(name => name.endsWith('.sql')).sort()) await engine.exec(await readFile(new URL(file,migrations),'utf8'));
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
    await t.test('staff ownership does not grant ticket update permission',async () => {
      const result = await call('/tickets','POST',{ title:'Staff support request',body:'A staff member needs technical assistance.',category:'IT support',priority:'normal' },bob);
      assert.equal(result.statusCode,201);
      const id = result.json.ticket.id;
      assert.equal((await call(`/tickets/${id}`,'GET',undefined,bob)).statusCode,200);
      assert.equal((await call(`/tickets/${id}`,'PATCH',{ status:'resolved' },bob)).statusCode,403);
      assert.equal((await db.query('SELECT status FROM tickets WHERE id=$1',[id])).rows[0].status,'open');
      await db.query('UPDATE tickets SET assigned_to=$1 WHERE id=$2',[bob.id,id]);
      assert.equal((await call(`/tickets/${id}`,'PATCH',{ status:'in_progress' },bob)).statusCode,200);
    });
    await t.test('internal staff notes are hidden from the requester',async () => {
      await db.query('DELETE FROM rate_limits');
      const before = (await call('/tickets','GET',undefined,alice)).json.tickets.find(item => item.id === ticket.id).updated_at;
      assert.equal((await call(`/tickets/${ticket.id}/replies`,'POST',{ body:'Requester tries a hidden note.',internal:true },alice)).statusCode,400);
      assert.equal((await call(`/tickets/${ticket.id}/replies`,'POST',{ body:'Not a boolean.',internal:'yes' },bob)).statusCode,400);
      assert.equal((await call(`/tickets/${ticket.id}/replies`,'POST',{ body:'Staff-only: likely a router fault.',internal:true },bob)).statusCode,201);
      const staffRead = await call(`/tickets/${ticket.id}`,'GET',undefined,bob);
      assert.equal(staffRead.json.canAddInternalNotes,true);
      assert.ok(staffRead.json.replies.some(reply => reply.internal && reply.body === 'Staff-only: likely a router fault.'));
      const ownerRead = await call(`/tickets/${ticket.id}`,'GET',undefined,alice);
      assert.equal(ownerRead.json.canAddInternalNotes,false);
      assert.ok(!ownerRead.body.includes('router fault')); assert.ok(ownerRead.json.replies.every(reply => !reply.internal));
      assert.equal((await call('/tickets','GET',undefined,alice)).json.tickets.find(item => item.id === ticket.id).updated_at,before);
      assert.equal((await db.query("SELECT count(*)::int AS count FROM audit_events WHERE event='ticket_internal_note' AND target_id=$1",[ticket.id])).rows[0].count,1);
      const own = (await call('/tickets','POST',{ title:'Staff member request',body:'A staff member needs help too.',category:'Other',priority:'low' },bob)).json.ticket;
      assert.equal((await call(`/tickets/${own.id}/replies`,'POST',{ body:'Hidden from myself?',internal:true },bob)).statusCode,400);
    });
    await t.test('attachments are validated, ownership-controlled and served as downloads',async () => {
      await db.query('DELETE FROM rate_limits');
      const png = Buffer.from('89504e470d0a1a0a0000000d49484452','hex'), b64 = png.toString('base64');
      await register('zoe@example.com'); const zoe = await login('zoe@example.com');
      const upload = async (name,data,auth = alice) => call(`/tickets/${ticket.id}/attachments`,'POST',{ name,data },auth);
      assert.equal((await upload('screenshot.png',b64)).statusCode,201);
      assert.equal((await upload('capture.PNG',b64)).statusCode,201);
      const list = (await call(`/tickets/${ticket.id}/attachments`,'GET',undefined,alice)).json;
      assert.equal(list.attachments.length,2); assert.equal(list.attachments[0].name,'screenshot.png');
      assert.equal(list.attachments[0].size,png.length); assert.equal(list.attachments[0].content_type,'image/png');
      assert.equal((await upload('broken.png','zzzw' + b64.slice(4))).statusCode,400);
      assert.equal((await upload('notes.png',Buffer.from('ffd8ff00','hex').toString('base64'))).statusCode,400);
      assert.equal((await upload('tool.com',b64)).statusCode,400);
      assert.equal((await upload('guess.exe',b64)).statusCode,400);
      assert.equal((await upload('../etc/passwd.png',b64)).statusCode,400);
      assert.equal((await upload('bad%2f.png',b64)).statusCode,400);
      assert.equal((await upload('empty.png','')).statusCode,400);
      assert.equal((await call(`/tickets/${ticket.id}/attachments`,'POST',{ name:'extra.png',data:b64,role:'admin' },alice)).statusCode,400);
      assert.equal((await upload('hidden.txt',b64)).statusCode,400);
      const csv = await upload('people.csv',Buffer.from('name,room\nAda,CS-01\n').toString('base64'));
      assert.equal(csv.statusCode,201); assert.equal(csv.json.attachment.contentType,'text/csv; charset=utf-8');
      assert.equal((await upload('evil.png','x'.repeat(4190000))).statusCode,400);
      assert.equal((await upload('evil.png','x'.repeat(7000000))).statusCode,413);
      assert.equal((await call(`/tickets/${ticket.id}/attachments`,'GET',undefined,zoe)).statusCode,404);
      assert.equal((await call(`/tickets/${ticket.id}/attachments`,'POST',{ name:'denied.png',data:b64 },zoe)).statusCode,404);
      assert.equal((await db.query("SELECT count(*)::int AS count FROM audit_events WHERE event='ticket_access_denied' AND target_id=$1",[ticket.id])).rows[0].count,5);
      const first = (await call(`/tickets/${ticket.id}/attachments`,'GET',undefined,bob)).json.attachments[0];
      const download = await handler({ httpMethod:'GET',rawUrl:`http://localhost:8888/api/tickets/${ticket.id}/attachments/${first.id}`,headers:{ cookie:alice.cookie },body:'' });
      assert.equal(download.statusCode,200); assert.ok(download.isBase64Encoded);
      assert.equal(download.headers['Content-Type'],'image/png'); assert.ok(download.headers['Content-Disposition'].startsWith('attachment;'));
      assert.ok(Buffer.from(download.body,'base64').equals(png));
      assert.equal((await call(`/tickets/${ticket.id}/attachments/00000000-0000-4000-8000-000000000000`,'GET',undefined,alice)).statusCode,404);
      for (let i=4;i<=5;i++) await upload(`more${i}.png`,b64);
      assert.equal((await db.query('SELECT count(*)::int AS count FROM attachments WHERE ticket_id=$1',[ticket.id])).rows[0].count,5);
      assert.equal((await upload('six.png',b64)).statusCode,400);
      assert.equal((await db.query("SELECT count(*)::int AS count FROM audit_events WHERE event='attachment_uploaded' AND target_id=$1",[ticket.id])).rows[0].count,5);
      await db.query('DELETE FROM rate_limits');
    });
    await t.test('login cooldown blocks correct credentials until the failure window expires',async () => {
      await db.query('DELETE FROM rate_limits');
      const key = rateKey(process.env.RATE_LIMIT_SECRET, 'failures-email:alice@example.com');
      await db.query("INSERT INTO rate_limits(key,hits,expires_at) VALUES($1,9,now()+interval '15 minutes')", [key]);
      assert.equal((await call('/auth/login','POST',{ email:'alice@example.com',password:'this password is incorrect' })).statusCode,401);
      const blocked = await call('/auth/login','POST',{ email:'ALICE@example.com',password:pass });
      assert.equal(blocked.statusCode,429);
      assert.equal(blocked.headers['Set-Cookie'],undefined);
      assert.equal((await call('/auth/me','GET',undefined,alice)).statusCode,200);
      await db.query("UPDATE rate_limits SET expires_at=now()-interval '1 second' WHERE key=$1", [key]);
      alice = await login('alice@example.com');
      await db.query('DELETE FROM rate_limits');
    });
    await t.test('password changes require the current password and revoke old sessions',async () => {
      await db.query('DELETE FROM rate_limits');
      await register('carol@example.com'); const carol = await login('carol@example.com');
      const newPass = 'a brand new campus passphrase';
      assert.ok(Date.parse((await call('/auth/me','GET',undefined,carol)).json.sessionExpiresAt) > Date.now());
      assert.equal((await call('/auth/password','POST',{ currentPassword:pass,newPassword:newPass,role:'admin' },carol)).statusCode,400);
      assert.equal((await call('/auth/password','POST',{ currentPassword:pass,newPassword:'too short' },carol)).statusCode,400);
      assert.equal((await call('/auth/password','POST',{ currentPassword:pass,newPassword:pass },carol)).statusCode,400);
      const wrong = await call('/auth/password','POST',{ currentPassword:'not the right password at all',newPassword:newPass },carol);
      assert.equal(wrong.statusCode,400); assert.equal((await call('/auth/me','GET',undefined,carol)).statusCode,200);
      const changed = await call('/auth/password','POST',{ currentPassword:pass,newPassword:newPass },carol);
      assert.equal(changed.statusCode,200);
      const rotated = { cookie:changed.headers['Set-Cookie'].split(';')[0],csrf:changed.json.csrfToken };
      assert.notEqual(rotated.cookie,carol.cookie);
      assert.equal((await call('/auth/me','GET',undefined,carol)).statusCode,401);
      assert.equal((await call('/auth/me','GET',undefined,rotated)).statusCode,200);
      assert.equal((await call('/auth/logout','POST',{},{ cookie:rotated.cookie,csrf:carol.csrf })).statusCode,403);
      assert.equal((await call('/auth/login','POST',{ email:'carol@example.com',password:pass })).statusCode,401);
      const events = (await db.query("SELECT event FROM audit_events WHERE actor_id=$1 AND event LIKE 'password%' ORDER BY id",[carol.id])).rows.map(row => row.event);
      assert.deepEqual(events,['password_change_failed','password_changed']);
      assert.ok(!JSON.stringify((await db.query('SELECT * FROM audit_events')).rows).includes(newPass));
      const fresh = (await call('/auth/login','POST',{ email:'carol@example.com',password:newPass }));
      assert.equal(fresh.statusCode,200);
      const session = { cookie:fresh.headers['Set-Cookie'].split(';')[0],csrf:fresh.json.csrfToken };
      let limited;
      for (let i=0;i<4;i++) limited = await call('/auth/password','POST',{ currentPassword:'guessing the password again',newPassword:'another long passphrase here' },session);
      assert.equal(limited.statusCode,429);
    });
    await t.test('password reset links are single-use, expire and revoke sessions',async () => {
      await db.query('DELETE FROM rate_limits');
      await register('dave@example.com'); const dave = await login('dave@example.com');
      const originalFetch = globalThis.fetch, sent = [];
      process.env.PASSWORD_RESET_WEBHOOK_URL = 'https://mail.example.test/reset';
      globalThis.fetch = async (_url,options) => { assert.equal(options.redirect,'error'); sent.push(JSON.parse(options.body)); return { ok:true }; };
      const forgot = async address => call('/auth/forgot','POST',{ email:address });
      const linkToken = () => { const match = sent.at(-1).link.match(/^http:\/\/localhost:8888\/#reset=([0-9a-f]{64})$/); assert.ok(match); return match[1]; };
      try {
        const missing = await forgot('nobody@example.com');
        assert.equal(missing.statusCode,202); assert.equal(sent.length,0);
        const requested = await forgot('dave@example.com');
        assert.equal(requested.statusCode,202); assert.equal(requested.json.message,missing.json.message);
        assert.equal(sent.length,1); assert.equal(sent[0].email,'dave@example.com');
        const first = linkToken();
        assert.equal((await db.query('SELECT count(*)::int AS count FROM password_resets WHERE token_hash=$1',[first])).rows[0].count,0);
        await forgot('dave@example.com'); const second = linkToken();
        const newPass = 'dave recovered his campus passphrase';
        assert.equal((await call('/auth/reset','POST',{ token:first,password:newPass })).statusCode,400);
        assert.equal((await call('/auth/reset','POST',{ token:'not-a-token',password:newPass })).statusCode,400);
        assert.equal((await call('/auth/reset','POST',{ token:second,password:'short' })).statusCode,400);
        assert.equal((await call('/auth/reset','POST',{ token:second,password:newPass,email:'dave@example.com' })).statusCode,400);
        assert.equal((await call('/auth/reset','POST',{ token:second,password:newPass })).statusCode,200);
        assert.equal((await call('/auth/me','GET',undefined,dave)).statusCode,401);
        assert.equal((await call('/auth/reset','POST',{ token:second,password:'an attacker replaying the link' })).statusCode,400);
        assert.equal((await call('/auth/login','POST',{ email:'dave@example.com',password:pass })).statusCode,401);
        assert.equal((await call('/auth/login','POST',{ email:'dave@example.com',password:newPass })).statusCode,200);
        await forgot('dave@example.com'); const expired = linkToken();
        await db.query("UPDATE password_resets SET expires_at=now()-interval '1 minute'");
        assert.equal((await call('/auth/reset','POST',{ token:expired,password:'too late for this reset link' })).statusCode,400);
        const limited = await forgot('dave@example.com');
        assert.equal(limited.statusCode,202); assert.equal(sent.length,3);
        const events = (await db.query("SELECT event FROM audit_events WHERE event LIKE 'password_reset%'")).rows.map(row => row.event);
        assert.deepEqual(events.sort(),['password_reset_completed','password_reset_requested','password_reset_requested','password_reset_requested']);
        const logs = JSON.stringify((await db.query('SELECT * FROM audit_events')).rows);
        assert.ok(!logs.includes(second)); assert.ok(!logs.includes('dave@example.com'));
      } finally { globalThis.fetch = originalFetch; delete process.env.PASSWORD_RESET_WEBHOOK_URL; }
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
    await t.test('admin overview, people search, audit log and remote sign-out are admin-only',async () => {
      await db.query('DELETE FROM rate_limits');
      await register('erin@example.com'); const erin = await login('erin@example.com');
      const created = await call('/tickets','POST',{ title:'Projector broken',body:'The projector in room 2 does not turn on.',category:'Facilities',priority:'high' },erin);
      for (const path of ['/admin/overview','/admin/users','/admin/assignees','/admin/security']) assert.equal((await call(path,'GET',undefined,erin)).statusCode,403);
      assert.equal((await call(`/admin/users/${alice.id}/sign-out`,'POST',{},erin)).statusCode,403);
      const overview = (await call('/admin/overview','GET',undefined,alice)).json;
      assert.equal(overview.people.total,(await db.query('SELECT count(*)::int AS count FROM users')).rows[0].count);
      assert.equal(overview.people.blocked,1);
      assert.ok(overview.waiting.some(item => item.id === created.json.ticket.id && item.priority === 'high'));
      assert.ok(overview.tickets.unassigned >= 1 && overview.lastDay.failed_sign_ins >= 1);
      const found = (await call('/admin/users?search=ERIN','GET',undefined,alice)).json.users;
      assert.deepEqual(found.map(u => u.email),['erin@example.com']); assert.equal(found[0].signed_in,true); assert.equal(found[0].tickets,1); assert.ok(found[0].last_sign_in);
      assert.deepEqual((await call('/admin/users?role=blocked','GET',undefined,alice)).json.users.map(u => u.email),['bob@example.com']);
      assert.equal((await call("/admin/users?search="+encodeURIComponent("' OR 1=1 --"),'GET',undefined,alice)).json.users.length,0);
      assert.equal((await call('/admin/users?role=superuser','GET',undefined,alice)).statusCode,400);
      assert.equal((await call('/admin/users?offset=-1','GET',undefined,alice)).statusCode,400);
      assert.ok(!(await call('/admin/assignees','GET',undefined,alice)).json.users.some(u => u.id === bob.id));
      const log = (await call('/admin/security?event=ticket_created','GET',undefined,alice)).json;
      assert.ok(log.events.length >= 1 && log.events.every(item => item.event === 'ticket_created'));
      assert.ok(log.events.some(item => item.actor === 'erin@example.com' && item.target === 'Projector broken'));
      assert.ok(log.eventTypes.includes('login_success'));
      assert.equal((await call("/admin/security?event=x'--",'GET',undefined,alice)).statusCode,400);
      assert.equal((await call(`/admin/users/${alice.id}/sign-out`,'POST',{},alice)).statusCode,400);
      assert.equal((await call(`/admin/users/${erin.id}/sign-out`,'POST',{ force:true },alice)).statusCode,400);
      assert.equal((await call('/admin/users/00000000-0000-4000-8000-000000000000/sign-out','POST',{},alice)).statusCode,404);
      assert.equal((await call(`/admin/users/${erin.id}/sign-out`,'POST',{},alice)).statusCode,200);
      assert.equal((await call('/auth/me','GET',undefined,erin)).statusCode,401);
      assert.equal((await db.query("SELECT count(*)::int AS count FROM audit_events WHERE event='sessions_revoked_by_admin' AND actor_id=$1 AND target_id=$2",[alice.id,erin.id])).rows[0].count,1);
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
