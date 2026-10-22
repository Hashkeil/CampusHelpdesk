const $ = selector => document.querySelector(selector);
let currentUser = null, csrfToken = '', registering = false, offset = 0, resetToken = '';
const statusLabel = value => ({ open:'Open', in_progress:'In progress', resolved:'Resolved' })[value] || value;
function node(tag, className, content) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (content !== undefined) element.textContent = content;
  return element;
}
function notice(message, error = false) { $('#notice').textContent = message; $('#notice').className = error ? 'error' : ''; $('#notice').hidden = false; }
function view(name) {
  for (const section of ['auth','tickets','detail','users','security','account']) $(`#${section}-view`).hidden = section !== name;
  $('#breadcrumb').textContent = ({ auth:'Welcome',tickets:'Support tickets',detail:'Request details',users:'People',security:'Security activity',account:'Your account' })[name];
  for (const item of ['tickets','users','security','account']) $(`#nav-${item}`).classList.toggle('active', item === name || (item === 'tickets' && name === 'detail'));
}
async function api(path, method = 'GET', data) {
  const result = await fetch(`/api${path}`,{ method, credentials:'same-origin', headers:method === 'GET' ? {} : { 'Content-Type':'application/json','X-Campus-Request':'1','X-CSRF-Token':csrfToken }, ...(data === undefined ? {} : { body:JSON.stringify(data) }) });
  const body = await result.json();
  if (!result.ok) {
    if (result.status === 401 && currentUser) { currentUser = null; csrfToken = ''; updateAccount(); view('auth'); }
    throw new Error(body.error || 'The request could not be completed.');
  }
  return body;
}
function updateAccount() {
  $('#logout').hidden = $('#nav-account').hidden = !currentUser;
  $('#account-label').textContent = currentUser ? `${currentUser.name} · ${currentUser.role}` : 'Campus community';
  $('#nav-users').hidden = $('#nav-security').hidden = currentUser?.role !== 'admin';
  if (currentUser) $('#welcome-name').textContent = `Hi, ${currentUser.name.split(' ')[0]}.`;
}
function action(fn) { return async event => { try { await fn(event); } catch (error) { notice(error.message,true); } }; }
async function busy(form, fn) {
  const button = form.querySelector('button[type="submit"]') || form.querySelector('button');
  button.disabled = true;
  try { await fn(); } finally { button.disabled = false; }
}
$('#auth-toggle').addEventListener('click',() => {
  registering = !registering;
  $('#name-field').hidden = !registering;
  $('#auth-form').elements.name.required = registering;
  $('#auth-form').elements.password.autocomplete = registering ? 'new-password' : 'current-password';
  $('#auth-title').textContent = registering ? 'Make yourself at home.' : 'Welcome back.';
  $('#auth-description').textContent = registering ? 'Create your student support account.' : 'Sign in to check in on your requests.';
  $('#auth-submit').textContent = registering ? 'Create account →' : 'Sign in →';
  $('#auth-toggle').textContent = registering ? 'Sign in' : 'Create an account';
  $('#auth-switch-label').textContent = registering ? 'Already have an account?' : 'New to Campus Helpdesk?';
  $('#forgot-link').hidden = registering;
});
function authPanel(name) {
  for (const panel of ['auth','forgot','reset']) $(`#${panel}-form`).hidden = panel !== name;
  $('#auth-switch-label').parentElement.hidden = $('#forgot-link').hidden = name !== 'auth'; $('#auth-back').hidden = name === 'auth';
  const [title,description] = ({ auth:['Welcome back.','Sign in to check in on your requests.'],forgot:['Forgot your password?','Enter your account email and we’ll send you a reset link.'],reset:['Choose a new password.','This link works once and expires 30 minutes after it was sent.'] })[name];
  $('#auth-title').textContent = title; $('#auth-description').textContent = description; $('#reset-error').textContent = '';
}
$('#forgot-toggle').addEventListener('click',() => authPanel('forgot'));
$('#back-to-signin').addEventListener('click',() => { resetToken = ''; authPanel('auth'); });
$('#forgot-form').addEventListener('submit',action(async event => {
  event.preventDefault();
  await busy(event.target,async () => { const result = await api('/auth/forgot','POST',{ email:event.target.elements.email.value }); event.target.reset(); authPanel('auth'); notice(result.message); });
}));
$('#reset-form').addEventListener('submit',async event => {
  event.preventDefault(); const form = event.target; $('#reset-error').textContent = '';
  try {
    if (form.elements.password.value !== form.elements.confirmPassword.value) throw new Error('The new passwords do not match.');
    await busy(form,async () => { const result = await api('/auth/reset','POST',{ token:resetToken,password:form.elements.password.value }); resetToken = ''; form.reset(); authPanel('auth'); notice(result.message); });
  } catch (error) { $('#reset-error').textContent = error.message; }
});
$('#auth-form').addEventListener('submit',action(async event => {
  event.preventDefault();
  await busy(event.target,async () => {
    const data = Object.fromEntries(new FormData(event.target));
    if (!registering) delete data.name;
    const result = await api(registering ? '/auth/register' : '/auth/login','POST',data);
    event.target.elements.password.value = '';
    if (registering) { $('#auth-toggle').click(); notice(result.message); return; }
    currentUser = result.user; csrfToken = result.csrfToken; updateAccount(); $('#notice').hidden = true; await loadTickets();
  });
}));
$('#logout').addEventListener('click',action(async () => {
  await api('/auth/logout','POST',{}); currentUser = null; csrfToken = ''; updateAccount(); view('auth'); notice('You have signed out.');
}));
async function loadTickets() {
  if (!currentUser) { view('auth'); return; }
  const params = new URLSearchParams(new FormData($('#filters'))); params.set('offset',offset);
  const result = await api(`/tickets?${params}`);
  const list = $('#ticket-list'); list.replaceChildren();
  $('#ticket-count').textContent = `${result.tickets.length} requests`;
  if (!result.tickets.length) { const empty = node('div','empty'); empty.append(node('strong','','A fresh start.'),node('span','','No requests match this view. Create a request whenever you need a hand.')); list.append(empty); }
  for (const ticket of result.tickets) {
    const row = node('button','ticket-row'); row.type = 'button';
    const description = node('span','ticket-description');
    description.append(node('strong','',ticket.title),node('small','',`${ticket.category} · ${ticket.priority} priority · ${new Date(ticket.created_at).toLocaleDateString()}`));
    row.append(node('span','ticket-icon','↗'),description,node('span',`badge ${ticket.status}`,statusLabel(ticket.status)),node('span','','→'));
    row.addEventListener('click',action(() => loadTicket(ticket.id))); list.append(row);
  }
  $('#previous').disabled = offset === 0; $('#next').disabled = !result.hasMore; $('#page-label').textContent = `Page ${offset / 20 + 1}`; view('tickets');
}
$('#nav-tickets').addEventListener('click',action(loadTickets));
$('#back').addEventListener('click',action(loadTickets));
$('#filters').addEventListener('submit',action(async event => { event.preventDefault(); offset = 0; await loadTickets(); }));
$('#previous').addEventListener('click',action(async () => { offset = Math.max(0,offset-20); await loadTickets(); }));
$('#next').addEventListener('click',action(async () => { offset += 20; await loadTickets(); }));
$('#new-ticket').addEventListener('click',() => { $('#ticket-error').textContent = ''; $('#ticket-dialog').showModal(); });
$('#close-dialog').addEventListener('click',() => $('#ticket-dialog').close());
$('#ticket-form').addEventListener('submit',async event => {
  event.preventDefault();
  try { await busy(event.target,async () => { const result = await api('/tickets','POST',Object.fromEntries(new FormData(event.target))); $('#ticket-dialog').close(); event.target.reset(); await loadTicket(result.ticket.id); notice('Your request has been sent.'); }); }
  catch (error) { $('#ticket-error').textContent = error.message; }
});
function selectField(label, values, selected) {
  const wrapper = node('label','',label), select = node('select');
  for (const [value,name] of values) { const option = node('option','',name); option.value = value; option.selected = value === selected; select.append(option); }
  wrapper.append(select); return { wrapper,select };
}
async function loadTicket(id) {
  const { ticket,replies,canAddInternalNotes } = await api(`/tickets/${id}`);
  const detail = $('#detail'); detail.replaceChildren();
  const card = node('article','panel detail-card');
  card.append(node('span',`badge ${ticket.status}`,statusLabel(ticket.status)),node('p','detail-meta',`${ticket.category} · ${ticket.priority} priority · ${new Date(ticket.created_at).toLocaleString()}`),node('h1','',ticket.title),node('p','detail-body',ticket.body));
  if (['staff','admin'].includes(currentUser.role)) {
    const form = node('form','reply-form'); const status = selectField('Status',[['open','Open'],['in_progress','In progress'],['resolved','Resolved']],ticket.status); form.append(status.wrapper);
    let assignee;
    if (currentUser.role === 'admin') {
      const result = await api('/admin/users');
      assignee = selectField('Assigned support member',[['','Unassigned'],...result.users.filter(u => ['staff','admin'].includes(u.role) && !u.blocked).map(u => [u.id,u.name])],ticket.assigned_to || ''); form.append(assignee.wrapper);
    }
    const save = node('button','button secondary','Update request'); save.type = 'submit'; form.append(save);
    form.addEventListener('submit',action(async event => { event.preventDefault(); await busy(form,async () => { await api(`/tickets/${id}`,'PATCH',{ status:status.select.value,...(assignee ? { assignedTo:assignee.select.value || null } : {}) }); await loadTicket(id); notice('Request updated.'); }); })); card.append(form);
  }
  card.append(node('h2','section-title','Conversation'));
  if (!replies.length) card.append(node('p','muted','No replies yet. Updates will appear here.'));
  for (const reply of replies) { const item = node('article',reply.internal ? 'reply internal' : 'reply'); item.append(node('strong','',reply.author),node('small','',new Date(reply.created_at).toLocaleString())); if (reply.internal) item.append(node('span','badge internal','Internal note')); item.append(node('p','reply-text',reply.body)); card.append(item); }
  const form = node('form','reply-form'), label = node('label','','Add a reply'), textarea = node('textarea'); textarea.required = true; textarea.maxLength = 2000; textarea.rows = 4; label.append(textarea);
  const send = node('button','button primary','Send reply →'); send.type = 'submit'; form.append(label);
  let internal;
  if (canAddInternalNotes) {
    const internalLabel = node('label','internal-toggle','Internal note — hidden from the requester'); internal = node('input'); internal.type = 'checkbox'; internalLabel.prepend(internal); form.append(internalLabel);
    internal.addEventListener('change',() => { send.textContent = internal.checked ? 'Add internal note →' : 'Send reply →'; });
  }
  form.append(send);
  form.addEventListener('submit',action(async event => { event.preventDefault(); await busy(form,async () => { await api(`/tickets/${id}/replies`,'POST',{ body:textarea.value,...(internal?.checked ? { internal:true } : {}) }); await loadTicket(id); }); }));
  card.append(form); detail.append(card); view('detail');
}
async function loadUsers() {
  const { users } = await api('/admin/users'); const container = $('#users-list'); container.replaceChildren();
  for (const user of users) {
    const row = node('form','admin-row'), info = node('div'); info.append(node('strong','',user.name),node('p','',user.email));
    const role = selectField('Role',[['student','Student'],['staff','Staff'],['admin','Admin']],user.role);
    const blockedLabel = node('label','','Blocked'), blocked = node('input'); blocked.type = 'checkbox'; blocked.checked = user.blocked; blockedLabel.append(blocked);
    const save = node('button','button secondary small','Save'); save.type = 'submit'; save.disabled = user.id === currentUser.id; role.select.disabled = blocked.disabled = save.disabled;
    row.append(info,role.wrapper,blockedLabel,save);
    row.addEventListener('submit',action(async event => { event.preventDefault(); await busy(row,async () => { await api(`/admin/users/${user.id}`,'PATCH',{ role:role.select.value,blocked:blocked.checked }); notice('Account updated and sessions revoked.'); }); })); container.append(row);
  }
  view('users');
}
$('#nav-users').addEventListener('click',action(loadUsers));
$('#nav-security').addEventListener('click',action(async () => {
  const result = await api('/admin/security'), container = $('#security-content'); container.replaceChildren();
  container.append(node('p','muted',result.alertDeliveryConfigured ? 'An alert delivery destination is configured. Check the states below to verify delivery.' : 'External alert delivery is not configured. Alerts remain visible here.'));
  for (const [title,items] of [['Alerts',result.alerts],['Recent audit events',result.events]]) {
    container.append(node('h2','section-title',title)); const panel = node('div','panel');
    if (!items.length) panel.append(node('p','empty','No recorded events yet.'));
    for (const item of items) { const row = node('div','log-row'); row.append(node('span','',`${item.event}${item.status ? ` · ${item.status}` : ''}`),node('time','',new Date(item.created_at).toLocaleString())); panel.append(row); }
    container.append(panel);
  }
  view('security');
}));
$('#nav-account').addEventListener('click',action(async () => {
  const { user,sessionExpiresAt } = await api('/auth/me'), details = $('#account-details'); details.replaceChildren();
  for (const [term,value] of [['Name',user.name],['Email',user.email],['Role',user.role],['Session expires',new Date(sessionExpiresAt).toLocaleString()]]) details.append(node('dt','',term),node('dd','',value));
  $('#password-form').elements.username.value = user.email; $('#password-error').textContent = ''; view('account');
}));
$('#password-form').addEventListener('submit',async event => {
  event.preventDefault(); const form = event.target; $('#password-error').textContent = '';
  try {
    if (form.elements.newPassword.value !== form.elements.confirmPassword.value) throw new Error('The new passwords do not match.');
    await busy(form,async () => { const result = await api('/auth/password','POST',{ currentPassword:form.elements.currentPassword.value,newPassword:form.elements.newPassword.value }); csrfToken = result.csrfToken; form.reset(); notice(result.message); });
  } catch (error) { $('#password-error').textContent = error.message; }
});
// Take the reset token out of the address bar straight away so it does not linger in history or get shared by copy-paste.
function openResetLink() {
  const link = location.hash.match(/^#reset=([0-9a-f]{64})$/);
  if (!link) return false;
  resetToken = link[1]; history.replaceState(null,'',location.pathname + location.search); $('#notice').hidden = true; view('auth'); authPanel('reset'); return true;
}
addEventListener('hashchange',openResetLink);
if (!openResetLink()) try { const result = await api('/auth/me'); currentUser = result.user; csrfToken = result.csrfToken; updateAccount(); await loadTickets(); }
catch (error) { view('auth'); if (error.message !== 'Please sign in.') notice(error.message,true); }
