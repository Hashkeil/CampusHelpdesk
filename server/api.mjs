import { randomUUID } from 'node:crypto';
import { database } from './db.mjs';
import { HttpError, requireValue, token, digest, rateKey, equal, hashPassword, verifyPassword, fields, text, email, password, choice, uuid, mayRead, sessionCookie, readCookie, headers, attachment } from './security.mjs';

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
async function deliverReset(address, link, production, requestId) {
  const destination = process.env.PASSWORD_RESET_WEBHOOK_URL;
  if (!destination) {
    // Local development has no mail service, so the link is printed for the developer instead.
    if (production) console.error(JSON.stringify({ event: 'password_reset_not_configured', requestId }));
    else console.log(JSON.stringify({ event: 'password_reset_link', email: address, link }));
    return;
  }
  try {
    requireValue(new URL(destination).protocol === 'https:');
    const response = await fetch(destination, { method: 'POST', redirect: 'error', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: address, link, requestId }), signal: AbortSignal.timeout(3000) });
    if (!response.ok) throw new Error('delivery failed');
  } catch { console.error(JSON.stringify({ event: 'password_reset_delivery_failed', requestId })); }
}
let lastCleanup = 0;
async function cleanup(db) {
  if (Date.now() - lastCleanup < 60000) return;
  lastCleanup = Date.now();
  try {
    await db.query('DELETE FROM rate_limits WHERE expires_at<now()');
    await db.query("DELETE FROM sessions WHERE expires_at<now()-interval '1 day'");
    await db.query('DELETE FROM password_resets WHERE expires_at<now()');
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
    const url = new URL(event.rawUrl || event.path, origin);
    const path = url.pathname.replace(/^\/(?:\.netlify\/functions\/api|api)(?=\/|$)/, '') || '/';
    // Attachment uploads carry the encoded file, so only that route gets an expanded body limit.
    const uploadPost = method === 'POST' && /^\/tickets\/[^/]+\/attachments\/?$/.test(path);
    const raw = Buffer.from(event.body || '', event.isBase64Encoded ? 'base64' : 'utf8');
    requireValue(raw.length <= (uploadPost ? 5 * 1024 * 1024 : 16384), 413, 'Request too large.');
    if (method !== 'GET') {
      requireValue(h.origin === origin && h['x-campus-request'] === '1', 403, 'Request origin rejected.');
      requireValue((h['content-type'] || '').split(';')[0].trim() === 'application/json', 415, 'JSON required.');
    }
    let input = {};
    if (method !== 'GET') { try { input = JSON.parse(raw.toString('utf8')); } catch { throw new HttpError(400, 'Invalid JSON.'); } }
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
      // Enforce the per-account limit before checking the password, so the right password cannot get through once the limit is hit.
      const failKey = rateKey(secret, `failures-email:${address}`);
      const priorFailures = (await db.query('SELECT hits FROM rate_limits WHERE key=$1 AND expires_at>now()', [failKey])).rows[0]?.hits || 0;
      requireValue(priorFailures < 10, 429, 'Too many sign-in attempts. Try again later.');
      const account = (await db.query('SELECT * FROM users WHERE email=$1', [address])).rows[0];
      const valid = await verifyPassword(pass, account?.password_hash || await dummyHash);
      if (!account || !valid || account.blocked) {
        await audit(db, 'login_failed', requestId);
        requireValue(await bump(db, failKey, 900) <= 10, 429, 'Too many sign-in attempts. Try again later.');
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
    if (method === 'POST' && path === '/auth/forgot') {
      fields(input, ['email']);
      const address = email(input.email);
      requireValue(await bump(db, rateKey(secret, `auth-ip:${ip}`), 900) <= 20, 429, 'Too many sign-in attempts. Try again later.');
      // The same answer is returned whether or not the account exists, so the form cannot be used to discover accounts.
      const accepted = response(202, { message: 'If an account exists for this address, a reset link is on its way. It expires in 30 minutes.' });
      if (await bump(db, rateKey(secret, `reset-email:${address}`), 3600) > 3) return accepted;
      const account = (await db.query('SELECT id FROM users WHERE email=$1 AND NOT blocked', [address])).rows[0];
      if (!account) return accepted;
      const resetToken = token();
      await transaction(db, async client => {
        // Only the newest link works; older ones are revoked.
        await client.query('DELETE FROM password_resets WHERE user_id=$1', [account.id]);
        await client.query("INSERT INTO password_resets(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '30 minutes')", [digest(resetToken), account.id]);
        await audit(client, 'password_reset_requested', requestId, null, account.id);
      });
      // The token travels in the URL fragment, which browsers never send to the server or in Referer headers.
      await deliverReset(address, `${origin}/#reset=${resetToken}`, production, requestId);
      return accepted;
    }
    if (method === 'POST' && path === '/auth/reset') {
      fields(input, ['token','password']);
      requireValue(typeof input.token === 'string' && /^[0-9a-f]{64}$/.test(input.token), 400, 'This reset link is invalid or has expired.');
      const pass = password(input.password);
      requireValue(await bump(db, rateKey(secret, `auth-ip:${ip}`), 900) <= 20, 429, 'Too many sign-in attempts. Try again later.');
      const encoded = await hashPassword(pass);
      await transaction(db, async client => {
        const reset = (await client.query('SELECT r.user_id FROM password_resets r JOIN users u ON u.id=r.user_id WHERE r.token_hash=$1 AND r.expires_at>now() AND NOT u.blocked FOR UPDATE OF r', [digest(input.token)])).rows[0];
        requireValue(reset, 400, 'This reset link is invalid or has expired.');
        await client.query('UPDATE users SET password_hash=$1 WHERE id=$2', [encoded, reset.user_id]);
        // Single use: the link and every signed-in session stop working once the password is replaced.
        await client.query('DELETE FROM password_resets WHERE user_id=$1', [reset.user_id]);
        await client.query('DELETE FROM sessions WHERE user_id=$1', [reset.user_id]);
        await audit(client, 'password_reset_completed', requestId, reset.user_id);
      });
      return response(200, { message: 'Your password has been reset. You can now sign in.' });
    }
    const cookie = readCookie(h.cookie, production);
    const session = cookie && (await db.query('SELECT u.*,s.csrf_token,s.expires_at AS session_expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() AND NOT u.blocked', [digest(cookie)])).rows[0];
    requireValue(session, 401, 'Please sign in.');
    user = publicUser(session);
    if (method !== 'GET') requireValue(equal(h['x-csrf-token'], session.csrf_token), 403, 'Invalid security token. Refresh and try again.');
    if (method === 'GET') requireValue(await bump(db, rateKey(secret, `read:${user.id}`), 60) <= 120, 429, 'Too many requests. Try again later.');
    if (path === '/auth/me' && method === 'GET') return response(200, { user, csrfToken: session.csrf_token, sessionExpiresAt: session.session_expires_at });
    if (path === '/auth/logout' && method === 'POST') {
      fields(input, []);
      await transaction(db, async client => { await client.query('DELETE FROM sessions WHERE token_hash=$1', [digest(cookie)]); await audit(client, 'logout', requestId, user.id); });
      return response(200, { message: 'Signed out.' }, { 'Set-Cookie': sessionCookie('', production, true) });
    }
    if (path === '/auth/password' && method === 'POST') {
      fields(input, ['currentPassword','newPassword']);
      requireValue(typeof input.currentPassword === 'string' && input.currentPassword.length <= 128);
      const next = password(input.newPassword);
      requireValue(next !== input.currentPassword, 400, 'Choose a password you are not already using.');
      // Counted before scrypt runs, so a stolen session cannot brute-force the current password.
      requireValue(await bump(db, rateKey(secret, `password:${user.id}`), 900) <= 5, 429, 'Too many password change attempts. Try again later.');
      if (!await verifyPassword(input.currentPassword, session.password_hash)) {
        await audit(db, 'password_change_failed', requestId, user.id);
        throw new HttpError(400, 'Current password is incorrect.');
      }
      const encoded = await hashPassword(next), sessionToken = token(), csrfToken = token();
      await transaction(db, async client => {
        await client.query('UPDATE users SET password_hash=$1 WHERE id=$2', [encoded, user.id]);
        // Revoke every session and issue a fresh one, so a hijacked cookie stops working.
        await client.query('DELETE FROM sessions WHERE user_id=$1', [user.id]);
        await client.query('DELETE FROM password_resets WHERE user_id=$1', [user.id]);
        await client.query("INSERT INTO sessions(token_hash,csrf_token,user_id,expires_at) VALUES($1,$2,$3,now()+interval '8 hours')", [digest(sessionToken), csrfToken, user.id]);
        await audit(client, 'password_changed', requestId, user.id);
      });
      return response(200, { message: 'Password changed. Other sessions were signed out.', csrfToken }, { 'Set-Cookie': sessionCookie(sessionToken, production) });
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
      // Internal notes are for support staff only, never for the requester, even when the requester is staff.
      const staffView = ['staff','admin'].includes(user.role) && ticket.owner_id !== user.id;
      if (method === 'GET' && !ticketMatch[2]) {
        const { rows } = await db.query('SELECT r.id,r.body,r.internal,r.created_at,u.name AS author FROM replies r JOIN users u ON u.id=r.author_id WHERE ticket_id=$1 AND ($2 OR NOT r.internal) ORDER BY r.created_at DESC LIMIT 100', [id,staffView]);
        return response(200, { ticket, replies: rows.reverse(), canAddInternalNotes: staffView });
      }
      if (method === 'POST' && ticketMatch[2]) {
        fields(input, staffView ? ['body','internal'] : ['body']);
        const body = text(input.body,1,2000);
        requireValue(input.internal === undefined || typeof input.internal === 'boolean');
        const internal = input.internal === true;
        requireValue(await bump(db, rateKey(secret, `reply:${user.id}`), 3600) <= 60, 429, 'Reply limit reached.');
        await transaction(db, async client => {
          await client.query('INSERT INTO replies(id,ticket_id,author_id,body,internal) VALUES($1,$2,$3,$4,$5)', [randomUUID(),id,user.id,body,internal]);
          // Leave updated_at alone for internal notes so the requester's list does not reveal hidden activity.
          if (!internal) await client.query('UPDATE tickets SET updated_at=now() WHERE id=$1', [id]);
          await audit(client, internal ? 'ticket_internal_note' : 'ticket_replied',requestId,user.id,id);
        });
        return response(201, { message: internal ? 'Internal note added.' : 'Reply added.' });
      }
      if (method === 'PATCH' && !ticketMatch[2]) {
        // Only admins or the assigned staff member may change a ticket; staff cannot edit tickets they merely own.
        requireValue(user.role === 'admin' || (user.role === 'staff' && ticket.assigned_to === user.id),403,'Staff access required.');
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
    const attachmentMatch = path.match(/^\/tickets\/([^/]+)\/attachments(?:\/([^/]+))?\/?$/);
    if (attachmentMatch) {
      const id = uuid(attachmentMatch[1]);
      const ticket = (await db.query('SELECT * FROM tickets WHERE id=$1', [id])).rows[0];
      if (!ticket || !mayRead(user,ticket)) {
        await audit(db, 'ticket_access_denied', requestId, user.id, id);
        throw new HttpError(404, 'Ticket not found.');
      }
      if (method === 'GET' && !attachmentMatch[2]) {
        const { rows } = await db.query('SELECT a.id,a.name,a.content_type,a.uploader_id,octet_length(a.content) AS size,a.created_at FROM attachments a WHERE a.ticket_id=$1 ORDER BY a.created_at', [id]);
        return response(200, { attachments: rows });
      }
      if (method === 'POST' && !attachmentMatch[2]) {
        fields(input, ['name','data']);
        const file = attachment(input, 3 * 1024 * 1024);
        requireValue(await bump(db, rateKey(secret, `upload:${user.id}`), 3600) <= 10, 429, 'Attachment limit reached. Try again later.');
        const count = (await db.query('SELECT count(*)::int AS count FROM attachments WHERE ticket_id=$1', [id])).rows[0].count;
        requireValue(count < 5, 400, 'This conversation already has the maximum of 5 attachments.');
        const attachmentId = randomUUID();
        await transaction(db, async client => {
          await client.query('INSERT INTO attachments(id,ticket_id,uploader_id,name,content_type,content) VALUES($1,$2,$3,$4,$5,$6)', [attachmentId,id,user.id,file.name,file.type,file.bytes]);
          await client.query('UPDATE tickets SET updated_at=now() WHERE id=$1', [id]);
          await audit(client, 'attachment_uploaded', requestId, user.id, id);
        });
        return response(201, { message: 'Attachment stored.', attachment: { id: attachmentId, name: file.name, contentType: file.type, size: file.bytes.length } });
      }
      if (method === 'GET' && attachmentMatch[2]) {
        const attachmentId = uuid(attachmentMatch[2]);
        const file = (await db.query('SELECT * FROM attachments WHERE id=$1 AND ticket_id=$2', [attachmentId,id])).rows[0];
        if (!file) { await audit(db, 'attachment_access_denied', requestId, user.id, id); throw new HttpError(404, 'Attachment not found.'); }
        return { statusCode: 200, headers: { ...headers, 'Content-Type': file.content_type, 'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(file.name)}`, 'Cache-Control': 'private, no-store', 'X-Request-Id': requestId }, isBase64Encoded: true, body: Buffer.from(file.content).toString('base64') };
      }
    }
    if (path.startsWith('/admin/')) {
      requireValue(user.role === 'admin',403,'Administrator access required.');
      if (path === '/admin/overview' && method === 'GET') {
        const [people, tickets, activity, waiting, workload] = await Promise.all([
          db.query(`SELECT count(*)::int AS total, count(*) FILTER (WHERE role='student')::int AS students, count(*) FILTER (WHERE role='staff')::int AS staff,
            count(*) FILTER (WHERE role='admin')::int AS admins, count(*) FILTER (WHERE blocked)::int AS blocked,
            count(*) FILTER (WHERE created_at>now()-interval '7 days')::int AS new_this_week,
            (SELECT count(*)::int FROM sessions WHERE expires_at>now()) AS signed_in FROM users`),
          db.query(`SELECT count(*) FILTER (WHERE status='open')::int AS open, count(*) FILTER (WHERE status='in_progress')::int AS in_progress,
            count(*) FILTER (WHERE status='resolved')::int AS resolved, count(*) FILTER (WHERE status<>'resolved' AND assigned_to IS NULL)::int AS unassigned,
            count(*) FILTER (WHERE status<>'resolved' AND priority='high')::int AS high_priority FROM tickets`),
          db.query(`SELECT count(*) FILTER (WHERE event='login_failed')::int AS failed_sign_ins,
            count(*) FILTER (WHERE event IN ('request_forbidden','ticket_access_denied'))::int AS denied_requests,
            (SELECT count(*)::int FROM security_alerts WHERE created_at>now()-interval '1 day') AS alerts
            FROM audit_events WHERE created_at>now()-interval '1 day'`),
          db.query(`SELECT id,title,priority,status,created_at FROM tickets WHERE status<>'resolved' AND assigned_to IS NULL
            ORDER BY CASE priority WHEN 'high' THEN 0 WHEN 'normal' THEN 1 ELSE 2 END,created_at LIMIT 8`),
          db.query(`SELECT u.id,u.name,u.role,count(t.id)::int AS active_tickets FROM users u
            LEFT JOIN tickets t ON t.assigned_to=u.id AND t.status<>'resolved'
            WHERE u.role IN ('staff','admin') AND NOT u.blocked GROUP BY u.id ORDER BY active_tickets DESC,u.name LIMIT 20`)
        ]);
        return response(200,{ people: people.rows[0], tickets: tickets.rows[0], lastDay: activity.rows[0], waiting: waiting.rows, workload: workload.rows });
      }
      if (path === '/admin/users' && method === 'GET') {
        const offset = Number(url.searchParams.get('offset') || 0);
        requireValue(Number.isInteger(offset) && offset >= 0 && offset <= 10000);
        const search = text(url.searchParams.get('search') || '',0,100);
        const role = url.searchParams.get('role') || '';
        choice(role,['','student','staff','admin','blocked']);
        const { rows } = await db.query(`SELECT u.id,u.name,u.email,u.role,u.blocked,u.created_at,
            EXISTS(SELECT 1 FROM sessions s WHERE s.user_id=u.id AND s.expires_at>now()) AS signed_in,
            (SELECT max(e.created_at) FROM audit_events e WHERE e.actor_id=u.id AND e.event='login_success') AS last_sign_in,
            (SELECT count(*)::int FROM tickets t WHERE t.owner_id=u.id) AS tickets
          FROM users u WHERE ($1='' OR ($1='blocked' AND u.blocked) OR u.role=$1)
          AND ($2='' OR position(lower($2) in lower(u.name))>0 OR position(lower($2) in u.email)>0)
          ORDER BY u.created_at DESC,u.id LIMIT 26 OFFSET $3`,[role,search,offset]);
        return response(200,{ users: rows.slice(0,25), hasMore: rows.length > 25 });
      }
      if (path === '/admin/assignees' && method === 'GET') {
        const { rows } = await db.query("SELECT id,name FROM users WHERE role IN ('staff','admin') AND NOT blocked ORDER BY name LIMIT 200");
        return response(200,{ users: rows });
      }
      if (path === '/admin/security' && method === 'GET') {
        const offset = Number(url.searchParams.get('offset') || 0);
        requireValue(Number.isInteger(offset) && offset >= 0 && offset <= 10000);
        const event = url.searchParams.get('event') || '';
        requireValue(/^[a-z_]{0,40}$/.test(event));
        // Targets can be accounts or tickets, so both are looked up and whichever exists is shown.
        const events = (await db.query(`SELECT e.id,e.event,e.request_id,e.created_at,coalesce(a.email,CASE WHEN e.actor_id IS NOT NULL THEN 'a deleted account' END) AS actor,coalesce(t.email,k.title) AS target
          FROM audit_events e LEFT JOIN users a ON a.id=e.actor_id LEFT JOIN users t ON t.id=e.target_id LEFT JOIN tickets k ON k.id=e.target_id
          WHERE ($1='' OR e.event=$1) ORDER BY e.id DESC LIMIT 51 OFFSET $2`,[event,offset])).rows;
        const eventTypes = (await db.query('SELECT DISTINCT event FROM audit_events ORDER BY event')).rows.map(row => row.event);
        const alerts = (await db.query('SELECT id,event,status,created_at FROM security_alerts ORDER BY created_at DESC LIMIT 20')).rows;
        return response(200,{ events: events.slice(0,50), hasMore: events.length > 50, eventTypes, alerts, alertDeliveryConfigured: Boolean(process.env.ALERT_WEBHOOK_URL) });
      }
      const signOut = path.match(/^\/admin\/users\/([^/]+)\/sign-out$/);
      if (signOut && method === 'POST') {
        fields(input,[]);
        const id = uuid(signOut[1]);
        requireValue(id !== user.id,400,'Use Sign out to end your own session.');
        requireValue(await bump(db, rateKey(secret, `update:${user.id}`), 60) <= 30, 429, 'Update limit reached.');
        await transaction(db, async client => {
          requireValue((await client.query('SELECT id FROM users WHERE id=$1',[id])).rowCount === 1,404,'User not found.');
          await client.query('DELETE FROM sessions WHERE user_id=$1',[id]);
          await audit(client,'sessions_revoked_by_admin',requestId,user.id,id);
        });
        return response(200,{ message: 'The account was signed out everywhere.' });
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
