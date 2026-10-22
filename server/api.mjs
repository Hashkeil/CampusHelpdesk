import { randomUUID } from 'node:crypto';
import { database } from './db.mjs';
import { HttpError, requireValue, token, digest, rateKey, equal, hashPassword, verifyPassword, fields, text, email, password, choice, uuid, mayRead, sessionCookie, readCookie, headers } from './security.mjs';

const dummyHash = hashPassword('not-a-real-account-password');
const publicUser = u => ({ id: u.id, name: u.name, email: u.email, role: u.role, blocked: u.blocked });
async function bump(db, key, seconds) {
  const { rows } = await db.query(`INSERT INTO rate_limits(key,hits,expires_at) VALUES($1,1,now()+$2*interval '1 second')
    ON CONFLICT(key) DO UPDATE SET hits=CASE WHEN rate_limits.expires_at<=now() THEN 1 ELSE rate_limits.hits+1 END,
    expires_at=CASE WHEN rate_limits.expires_at<=now() THEN EXCLUDED.expires_at ELSE rate_limits.expires_at END RETURNING hits`, [key, seconds]);
  return rows[0].hits;
}
async function audit(db, event, requestId, actor = null, target = null) {
  await db.query('INSERT INTO audit_events(event,actor_id,target_id,request_id) VALUES($1,$2,$3,$4)', [event, actor, target, requestId]);
}
async function transaction(db, action) {
  const client = await db.connect();
  try { await client.query('BEGIN'); const result = await action(client); await client.query('COMMIT'); return result; }
  catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}
async function alert(db, event, requestId) {
  const id = randomUUID();
  const destination = process.env.ALERT_WEBHOOK_URL;
  await db.query('INSERT INTO security_alerts(id,event,status) VALUES($1,$2,$3)', [id, event, destination ? 'pending' : 'not_configured']);
  if (!destination) return;
  try {
    requireValue(new URL(destination).protocol === 'https:');
    const response = await fetch(destination, { method: 'POST', redirect: 'error', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id, event, requestId }), signal: AbortSignal.timeout(3000) });
    if (!response.ok) throw new Error('delivery failed');
    await db.query("UPDATE security_alerts SET status='delivered' WHERE id=$1", [id]);
  } catch {
    await db.query("UPDATE security_alerts SET status='failed' WHERE id=$1", [id]);
    console.error(JSON.stringify({ event: 'alert_delivery_failed', requestId }));
  }
}
let lastCleanup = 0;
async function cleanup(db) {
  if (Date.now() - lastCleanup < 60000) return;
  lastCleanup = Date.now();
  try {
    await db.query('DELETE FROM rate_limits WHERE expires_at<now()');
    await db.query("DELETE FROM sessions WHERE expires_at<now()-interval '1 day'");
  } catch (error) { console.error(JSON.stringify({ event: 'cleanup_failed', message: error.message })); }
}
export const handler = event => handle(event);
export const createTestHandler = store => event => handle(event, store);
async function handle(event, store) {
  const requestId = randomUUID();
  const production = process.env.NETLIFY === 'true' || process.env.NODE_ENV === 'production';
  const response = (statusCode, body, extra = {}) => ({ statusCode, headers: { ...headers, ...(production ? { 'Strict-Transport-Security': 'max-age=31536000' } : {}), 'X-Request-Id': requestId, ...extra }, body: JSON.stringify(body) });
  let db, user;
  try {
    const origin = process.env.APP_ORIGIN;
    const secret = process.env.RATE_LIMIT_SECRET;
    if (!origin || new URL(origin).origin !== origin || !secret || secret.length < 32 || secret.startsWith('replace-')) throw new Error('Invalid server configuration');
    if (production && new URL(origin).protocol !== 'https:') throw new Error('HTTPS required');
    const method = event.httpMethod;
    requireValue(['GET', 'POST', 'PATCH'].includes(method), 405, 'Method not allowed.');
    const h = Object.fromEntries(Object.entries(event.headers || {}).map(([k,v]) => [k.toLowerCase(),v]));
    const raw = Buffer.from(event.body || '', event.isBase64Encoded ? 'base64' : 'utf8');
    requireValue(raw.length <= 16384, 413, 'Request too large.');
    if (method !== 'GET') {
      requireValue(h.origin === origin && h['x-campus-request'] === '1', 403, 'Request origin rejected.');
      requireValue((h['content-type'] || '').split(';')[0].trim() === 'application/json', 415, 'JSON required.');
    }
    let input = {};
    if (method !== 'GET') { try { input = JSON.parse(raw.toString('utf8')); } catch { throw new HttpError(400, 'Invalid JSON.'); } }
    const url = new URL(event.rawUrl || event.path, origin);
    const path = url.pathname.replace(/^\/(?:\.netlify\/functions\/api|api)(?=\/|$)/, '') || '/';
    db = store || database();
    await cleanup(db);
    // Only Netlify's platform-provided client IP is trusted in production.
    const ip = production ? (h['x-nf-client-connection-ip'] || 'unknown') : 'local';
    const ipKey = rateKey(secret, `ip:${ip}`);
    if (await bump(db, ipKey, 60) > 120) throw new HttpError(429, 'Too many requests. Try again later.');
    if (method === 'POST' && ['/auth/register','/auth/login'].includes(path)) {
      fields(input, path.endsWith('register') ? ['name','email','password'] : ['email','password']);
      const address = email(input.email);
      const pass = password(input.password);
      requireValue(await bump(db, rateKey(secret, `auth-ip:${ip}`), 900) <= 20, 429, 'Too many sign-in attempts. Try again later.');
      if (path.endsWith('register')) {
        const name = text(input.name, 2, 80);
        const encoded = await hashPassword(pass);
        await transaction(db, async client => {
          const result = await client.query('INSERT INTO users(id,email,name,password_hash) VALUES($1,$2,$3,$4) ON CONFLICT(email) DO NOTHING RETURNING id', [randomUUID(), address, name, encoded]);
          await audit(client, 'registration_attempt', requestId, result.rows[0]?.id);
        });
        return response(202, { message: 'If this address is available, your account is ready. You can now sign in.' });
      }
      const account = (await db.query('SELECT * FROM users WHERE email=$1', [address])).rows[0];
      const valid = await verifyPassword(pass, account?.password_hash || await dummyHash);
      if (!account || !valid || account.blocked) {
        await audit(db, 'login_failed', requestId);
        requireValue(await bump(db, rateKey(secret, `failures-email:${address}`), 900) <= 10, 429, 'Too many sign-in attempts. Try again later.');
        if (await bump(db, rateKey(secret, `failures-ip:${ip}`), 900) === 5) await alert(db, 'repeated_login_failures', requestId);
        throw new HttpError(401, 'Email or password is incorrect.');
      }
      const sessionToken = token(), csrfToken = token();
      await transaction(db, async client => {
        // Lock the account so blocking and session creation cannot race.
        const current = (await client.query('SELECT blocked FROM users WHERE id=$1 FOR UPDATE', [account.id])).rows[0];
        requireValue(!current.blocked, 401, 'Email or password is incorrect.');
        await client.query('DELETE FROM sessions WHERE user_id=$1', [account.id]);
        await client.query("INSERT INTO sessions(token_hash,csrf_token,user_id,expires_at) VALUES($1,$2,$3,now()+interval '8 hours')", [digest(sessionToken), csrfToken, account.id]);
        await audit(client, 'login_success', requestId, account.id);
      });
      return response(200, { user: publicUser(account), csrfToken }, { 'Set-Cookie': sessionCookie(sessionToken, production) });
    }
    const cookie = readCookie(h.cookie, production);
    const session = cookie && (await db.query('SELECT u.*,s.csrf_token FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() AND NOT u.blocked', [digest(cookie)])).rows[0];
    requireValue(session, 401, 'Please sign in.');
    user = publicUser(session);
    if (method !== 'GET') requireValue(equal(h['x-csrf-token'], session.csrf_token), 403, 'Invalid security token. Refresh and try again.');
    if (method === 'GET') requireValue(await bump(db, rateKey(secret, `read:${user.id}`), 60) <= 120, 429, 'Too many requests. Try again later.');
    if (path === '/auth/me' && method === 'GET') return response(200, { user, csrfToken: session.csrf_token });
    if (path === '/auth/logout' && method === 'POST') {
      fields(input, []);
      await transaction(db, async client => { await client.query('DELETE FROM sessions WHERE token_hash=$1', [digest(cookie)]); await audit(client, 'logout', requestId, user.id); });
      return response(200, { message: 'Signed out.' }, { 'Set-Cookie': sessionCookie('', production, true) });
    }
    if (path === '/tickets' && method === 'POST') {
      fields(input, ['title','body','category','priority']);
      const values = [randomUUID(), user.id, text(input.title,3,120), text(input.body,10,4000), choice(input.category,['IT support','Facilities','Academic','Other']), choice(input.priority,['low','normal','high'])];
      requireValue(await bump(db, rateKey(secret, `create:${user.id}`), 3600) <= 20, 429, 'Ticket limit reached. Try again later.');
      const ticket = await transaction(db, async client => {
        const result = await client.query('INSERT INTO tickets(id,owner_id,title,body,category,priority) VALUES($1,$2,$3,$4,$5,$6) RETURNING *', values);
        await audit(client, 'ticket_created', requestId, user.id, values[0]); return result.rows[0];
      });
      return response(201, { ticket });
    }
    if (path === '/tickets' && method === 'GET') {
      const offset = Number(url.searchParams.get('offset') || 0);
      requireValue(Number.isInteger(offset) && offset >= 0 && offset <= 10000);
      const search = text(url.searchParams.get('search') || '',0,100);
      const status = url.searchParams.get('status') || '';
      choice(status, ['', 'open','in_progress','resolved']);
      const { rows } = await db.query(`SELECT id,title,category,priority,status,created_at,updated_at FROM tickets
        WHERE ($1='admin' OR owner_id=$2 OR ($1='staff' AND assigned_to=$2))
        AND ($3='' OR status=$3) AND ($4='' OR position(lower($4) in lower(title))>0)
        ORDER BY created_at DESC,id LIMIT 21 OFFSET $5`, [user.role,user.id,status,search,offset]);
      return response(200, { tickets: rows.slice(0,20), hasMore: rows.length > 20 });
    }
    const ticketMatch = path.match(/^\/tickets\/([^/]+)(\/replies)?$/);
    if (ticketMatch) {
      const id = uuid(ticketMatch[1]);
      const ticket = (await db.query('SELECT * FROM tickets WHERE id=$1', [id])).rows[0];
      if (!ticket || !mayRead(user,ticket)) {
        await audit(db, 'ticket_access_denied', requestId, user.id, id);
        throw new HttpError(404, 'Ticket not found.');
      }
      if (method === 'GET' && !ticketMatch[2]) {
        const { rows } = await db.query('SELECT r.id,r.body,r.created_at,u.name AS author FROM replies r JOIN users u ON u.id=r.author_id WHERE ticket_id=$1 ORDER BY r.created_at DESC LIMIT 100', [id]);
        return response(200, { ticket, replies: rows.reverse() });
      }
      if (method === 'POST' && ticketMatch[2]) {
        fields(input,['body']);
        const body = text(input.body,1,2000);
        requireValue(await bump(db, rateKey(secret, `reply:${user.id}`), 3600) <= 60, 429, 'Reply limit reached.');
        await transaction(db, async client => {
          await client.query('INSERT INTO replies(id,ticket_id,author_id,body) VALUES($1,$2,$3,$4)', [randomUUID(),id,user.id,body]);
          await client.query('UPDATE tickets SET updated_at=now() WHERE id=$1', [id]);
          await audit(client, 'ticket_replied',requestId,user.id,id);
        });
        return response(201, { message: 'Reply added.' });
      }
      if (method === 'PATCH' && !ticketMatch[2]) {
        requireValue(['staff','admin'].includes(user.role),403,'Staff access required.');
        requireValue(await bump(db, rateKey(secret, `update:${user.id}`), 60) <= 30, 429, 'Update limit reached.');
        fields(input, user.role === 'admin' ? ['status','assignedTo'] : ['status']);
        const status = choice(input.status,['open','in_progress','resolved']);
        const assignee = input.assignedTo === undefined ? ticket.assigned_to : (input.assignedTo === null ? null : uuid(input.assignedTo));
        if (assignee) requireValue((await db.query("SELECT id FROM users WHERE id=$1 AND role IN ('staff','admin') AND NOT blocked",[assignee])).rowCount === 1);
        await transaction(db, async client => {
          await client.query('UPDATE tickets SET status=$1,assigned_to=$2,updated_at=now() WHERE id=$3',[status,assignee,id]);
          await audit(client,'ticket_updated',requestId,user.id,id);
        });
        return response(200,{ message: 'Ticket updated.' });
      }
    }
    if (path.startsWith('/admin/')) {
      requireValue(user.role === 'admin',403,'Administrator access required.');
      if (path === '/admin/users' && method === 'GET') {
        const { rows } = await db.query('SELECT id,name,email,role,blocked FROM users ORDER BY created_at DESC LIMIT 100');
        return response(200,{ users: rows });
      }
      if (path === '/admin/security' && method === 'GET') {
        const events = (await db.query('SELECT * FROM audit_events ORDER BY id DESC LIMIT 100')).rows;
        const alerts = (await db.query('SELECT * FROM security_alerts ORDER BY created_at DESC LIMIT 50')).rows;
        return response(200,{ events, alerts, alertDeliveryConfigured: Boolean(process.env.ALERT_WEBHOOK_URL) });
      }
      const match = path.match(/^\/admin\/users\/([^/]+)$/);
      if (match && method === 'PATCH') {
        requireValue(await bump(db, rateKey(secret, `update:${user.id}`), 60) <= 30, 429, 'Update limit reached.');
        const id = uuid(match[1]); fields(input,['role','blocked']);
        const role = choice(input.role,['student','staff','admin']);
        requireValue(typeof input.blocked === 'boolean');
        requireValue(id !== user.id,400,'You cannot change your own role or blocked status.');
        await transaction(db, async client => {
          await client.query('SELECT pg_advisory_xact_lock(731249)');
          const actor = (await client.query('SELECT role,blocked FROM users WHERE id=$1 FOR UPDATE',[user.id])).rows[0];
          requireValue(actor?.role === 'admin' && !actor.blocked,403,'Administrator access required.');
          const result = await client.query('UPDATE users SET role=$1,blocked=$2 WHERE id=$3 RETURNING id',[role,input.blocked,id]);
          requireValue(result.rowCount === 1,404,'User not found.');
          await client.query('DELETE FROM sessions WHERE user_id=$1',[id]);
          await audit(client,'account_permissions_changed',requestId,user.id,id);
        });
        return response(200,{ message: 'Account updated. Existing sessions revoked.' });
      }
    }
    throw new HttpError(404,'Endpoint not found.');
  } catch (error) {
    const status = error instanceof HttpError ? error.status : 500;
    if (status === 403 && db) { try { await audit(db,'request_forbidden',requestId,user?.id); } catch {} }
    if (status >= 500) console.error(JSON.stringify({ event: 'request_failed',requestId }));
    return response(status,{ error: status >= 500 ? 'Service temporarily unavailable. Please try again.' : error.message, requestId },status === 429 ? { 'Retry-After': '900' } : {});
  }
}
