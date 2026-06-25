'use strict';

let me = null;
let allCreds = [];

// ---- API helper ----
async function api(path, opts = {}) {
  const res = await fetch('/api' + path, {
    method: opts.method || 'GET',
    headers: { 'Content-Type': 'application/json' },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

const $ = (sel) => document.querySelector(sel);
const el = (tag, props = {}, ...kids) => {
  const n = Object.assign(document.createElement(tag), props);
  for (const k of kids) n.append(k);
  return n;
};
const esc = (s) => (s ?? '').toString();

// ---- Auth flow ----
async function boot() {
  try {
    const { user } = await api('/auth/me');
    me = user;
    showApp();
  } catch {
    show('login-view');
  }
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#login-error').textContent = '';
  try {
    const { user } = await api('/auth/login', {
      method: 'POST',
      body: { username: $('#login-username').value, password: $('#login-password').value },
    });
    me = user;
    showApp();
  } catch (err) {
    $('#login-error').textContent = err.message;
  }
});

$('#logout-btn').addEventListener('click', async () => {
  await api('/auth/logout', { method: 'POST' }).catch(() => {});
  me = null;
  location.reload();
});

$('#change-pw-btn').addEventListener('click', openChangePassword);

function show(viewId) {
  document.querySelectorAll('.view').forEach((v) => v.classList.add('hidden'));
  $('#' + viewId).classList.remove('hidden');
}

function showApp() {
  show('app-view');
  $('#whoami').textContent = `${me.username} (${me.role})`;
  const isAdmin = me.role === 'admin';
  document.querySelectorAll('.admin-only').forEach((n) => n.classList.toggle('hidden', !isAdmin));
  $('#add-cred-btn').classList.toggle('hidden', !(isAdmin || me.can_create));
  switchTab('vault');
  loadVault();
}

// ---- Tabs ----
document.querySelectorAll('.tab').forEach((t) =>
  t.addEventListener('click', () => switchTab(t.dataset.tab)));

function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.tab-panel').forEach((p) => p.classList.add('hidden'));
  $('#tab-' + name).classList.remove('hidden');
  if (name === 'users') loadUsers();
  if (name === 'audit') loadAudit();
}

// ---- Vault ----
async function loadVault() {
  try {
    const { credentials } = await api('/credentials');
    allCreds = credentials;
    renderVault();
  } catch (err) {
    $('#cred-list').innerHTML = `<p class="muted">${esc(err.message)}</p>`;
  }
}

$('#search').addEventListener('input', renderVault);
$('#add-cred-btn').addEventListener('click', () => openCredModal(null));

function renderVault() {
  const q = $('#search').value.toLowerCase();
  const list = $('#cred-list');
  list.innerHTML = '';
  const filtered = allCreds.filter((c) =>
    [c.title, c.username, c.url, c.folder].some((f) => (f || '').toLowerCase().includes(q)));

  if (!filtered.length) {
    list.append(el('p', { className: 'muted', textContent: 'No entries.' }));
    return;
  }
  const byFolder = {};
  for (const c of filtered) (byFolder[c.folder] ||= []).push(c);

  const canEdit = me.role === 'admin' || me.can_edit;
  const canDelete = me.role === 'admin' || me.can_delete;

  for (const folder of Object.keys(byFolder).sort()) {
    list.append(el('div', { className: 'folder-head', textContent: folder }));
    for (const c of byFolder[folder]) {
      const actions = el('div', { className: 'actions' });
      actions.append(el('button', { textContent: '👁 Reveal', onclick: () => revealPassword(c) }));
      if (canEdit) actions.append(el('button', { textContent: 'Edit', onclick: () => openCredModal(c) }));
      if (canDelete) actions.append(el('button', { className: 'danger', textContent: 'Delete', onclick: () => deleteCred(c) }));

      const sub = [c.username, c.url].filter(Boolean).join('  ·  ');
      list.append(el('div', { className: 'row' },
        el('div', { className: 'grow' },
          el('div', { className: 'title', textContent: c.title }),
          el('div', { className: 'sub', textContent: sub || '—' })),
        actions));
    }
  }
}

async function revealPassword(c) {
  try {
    const { password } = await api(`/credentials/${c.id}/reveal`);
    await navigator.clipboard?.writeText(password).catch(() => {});
    alert(`Password for "${c.title}":\n\n${password}\n\n(Copied to clipboard if your browser allowed it.)`);
  } catch (err) {
    alert(err.message);
  }
}

async function deleteCred(c) {
  if (!confirm(`Delete "${c.title}"? This cannot be undone.`)) return;
  try {
    await api(`/credentials/${c.id}`, { method: 'DELETE' });
    loadVault();
  } catch (err) { alert(err.message); }
}

function openCredModal(cred) {
  const editing = !!cred;
  const body = el('div', {},
    field('Title', `<input id="f-title" value="${esc(cred?.title)}" />`),
    field('Folder', `<input id="f-folder" value="${esc(cred?.folder || 'General')}" />`),
    field('Username', `<input id="f-username" value="${esc(cred?.username)}" autocomplete="off" />`),
    field('URL', `<input id="f-url" value="${esc(cred?.url)}" />`),
    field(editing ? 'Password (leave blank to keep)' : 'Password',
      `<input id="f-password" type="text" autocomplete="off" />`),
    field('Notes', `<textarea id="f-notes">${esc(cred?.notes)}</textarea>`),
  );
  openModal(editing ? 'Edit entry' : 'New entry', body, async () => {
    const payload = {
      title: $('#f-title').value.trim(),
      folder: $('#f-folder').value.trim() || 'General',
      username: $('#f-username').value,
      url: $('#f-url').value,
      notes: $('#f-notes').value,
      password: $('#f-password').value,
    };
    if (!payload.title) throw new Error('Title is required');
    if (!editing && !payload.password) throw new Error('Password is required');
    if (editing) await api(`/credentials/${cred.id}`, { method: 'PUT', body: payload });
    else await api('/credentials', { method: 'POST', body: payload });
    loadVault();
  });
}

// ---- Users (admin) ----
async function loadUsers() {
  const wrap = $('#user-list');
  try {
    const { users } = await api('/users');
    wrap.innerHTML = '';
    for (const u of users) wrap.append(renderUserRow(u));
  } catch (err) {
    wrap.innerHTML = `<p class="muted">${esc(err.message)}</p>`;
  }
}

function renderUserRow(u) {
  const isAdmin = u.role === 'admin';
  const perms = el('div', { className: 'actions' });
  for (const [flag, label] of [['can_view','view'],['can_create','create'],['can_edit','edit'],['can_delete','delete']]) {
    perms.append(el('span', {
      className: 'pill ' + (isAdmin || u[flag] ? 'on' : 'off'),
      textContent: label,
    }));
  }
  const actions = el('div', { className: 'actions' });
  if (!isAdmin) {
    actions.append(el('button', { textContent: 'Edit access', onclick: () => openUserModal(u) }));
    actions.append(el('button', {
      textContent: u.is_active ? 'Disable' : 'Enable',
      onclick: () => toggleActive(u),
    }));
  }
  actions.append(el('button', { textContent: 'Reset pw', onclick: () => resetPassword(u) }));
  if (!isAdmin) actions.append(el('button', { className: 'danger', textContent: 'Delete', onclick: () => deleteUser(u) }));

  return el('div', { className: 'row' },
    el('div', { className: 'grow' },
      el('div', { className: 'title' },
        u.username + '  ',
        el('span', { className: 'pill ' + (isAdmin ? 'admin' : ''), textContent: u.role }),
        ...(u.is_active ? [] : [el('span', { className: 'pill off', textContent: 'disabled' })])),
      el('div', { className: 'sub', textContent: u.email || '—' })),
    perms, actions);
}

function openUserModal(u) {
  const checks = el('div', { className: 'perm-grid' });
  const inputs = {};
  for (const [flag, label] of [['can_view','Can view'],['can_create','Can create'],['can_edit','Can edit'],['can_delete','Can delete']]) {
    const cb = el('input', { type: 'checkbox', checked: !!u[flag] });
    inputs[flag] = cb;
    checks.append(el('label', {}, cb, label));
  }
  openModal(`Access for ${u.username}`, checks, async () => {
    const body = {};
    for (const f in inputs) body[f] = inputs[f].checked;
    await api(`/users/${u.id}`, { method: 'PATCH', body });
    loadUsers();
  });
}

$('#add-user-btn').addEventListener('click', () => {
  const adminCb = el('input', { type: 'checkbox' });
  const permInputs = {};
  const permGrid = el('div', { className: 'perm-grid' });
  for (const [flag, label] of [['can_view','Can view'],['can_create','Can create'],['can_edit','Can edit'],['can_delete','Can delete']]) {
    const cb = el('input', { type: 'checkbox', checked: flag === 'can_view' });
    permInputs[flag] = cb;
    permGrid.append(el('label', {}, cb, label));
  }
  const body = el('div', {},
    field('Username', `<input id="u-username" autocomplete="off" />`),
    field('Email', `<input id="u-email" autocomplete="off" />`),
    field('Temp password (min 8 chars)', `<input id="u-password" type="text" autocomplete="off" />`),
  );
  const adminRow = el('label', { className: 'checkbox-row' }, adminCb, 'Make this user an admin (full access)');
  body.append(adminRow, el('div', { className: 'field' }, permGrid));

  openModal('Add user', body, async () => {
    const payload = {
      username: $('#u-username').value.trim(),
      email: $('#u-email').value.trim(),
      password: $('#u-password').value,
      role: adminCb.checked ? 'admin' : 'member',
    };
    for (const f in permInputs) payload[f] = permInputs[f].checked;
    if (!payload.username) throw new Error('Username is required');
    if ((payload.password || '').length < 8) throw new Error('Password must be at least 8 characters');
    await api('/users', { method: 'POST', body: payload });
    loadUsers();
  });
});

async function toggleActive(u) {
  await api(`/users/${u.id}`, { method: 'PATCH', body: { ...u, is_active: !u.is_active } }).catch((e) => alert(e.message));
  loadUsers();
}

async function deleteUser(u) {
  if (!confirm(`Delete user "${u.username}"?`)) return;
  await api(`/users/${u.id}`, { method: 'DELETE' }).catch((e) => alert(e.message));
  loadUsers();
}

async function resetPassword(u) {
  const np = prompt(`New password for "${u.username}" (min 8 chars):`);
  if (!np) return;
  try {
    await api(`/users/${u.id}/reset-password`, { method: 'POST', body: { newPassword: np } });
    alert('Password reset.');
  } catch (e) { alert(e.message); }
}

function openChangePassword() {
  const body = el('div', {},
    field('Current password', `<input id="cp-cur" type="password" autocomplete="off" />`),
    field('New password (min 8 chars)', `<input id="cp-new" type="password" autocomplete="off" />`),
  );
  openModal('Change your password', body, async () => {
    await api('/auth/change-password', {
      method: 'POST',
      body: { currentPassword: $('#cp-cur').value, newPassword: $('#cp-new').value },
    });
    alert('Password changed.');
  });
}

// ---- Audit ----
async function loadAudit() {
  const wrap = $('#audit-list');
  try {
    const { events } = await api('/audit');
    wrap.innerHTML = '';
    for (const e of events) {
      wrap.append(el('div', { className: 'row' },
        el('div', { className: 'grow' },
          el('div', { className: 'title', textContent: `${e.action}${e.target ? ' · ' + e.target : ''}` }),
          el('div', { className: 'sub', textContent: `${e.username || 'unknown'} — ${e.created_at} UTC` }))));
    }
    if (!events.length) wrap.append(el('p', { className: 'muted', textContent: 'No events yet.' }));
  } catch (err) {
    wrap.innerHTML = `<p class="muted">${esc(err.message)}</p>`;
  }
}

// ---- Modal plumbing ----
function field(label, innerHTML) {
  const f = el('div', { className: 'field' });
  f.append(el('label', { textContent: label }));
  const holder = el('div');
  holder.innerHTML = innerHTML;
  f.append(holder.firstElementChild);
  return f;
}

function openModal(title, bodyNode, onSave) {
  const host = $('#modal-host');
  const err = el('div', { className: 'error' });
  const saveBtn = el('button', { className: 'primary', textContent: 'Save' });
  const modal = el('div', { className: 'modal' },
    el('h2', { textContent: title }),
    bodyNode, err,
    el('div', { className: 'modal-actions' },
      el('button', { textContent: 'Cancel', onclick: closeModal }),
      saveBtn));
  saveBtn.addEventListener('click', async () => {
    err.textContent = '';
    saveBtn.disabled = true;
    try { await onSave(); closeModal(); }
    catch (e) { err.textContent = e.message; }
    finally { saveBtn.disabled = false; }
  });
  host.innerHTML = '';
  host.append(modal);
  host.classList.remove('hidden');
  host.onclick = (e) => { if (e.target === host) closeModal(); };
}
function closeModal() {
  $('#modal-host').classList.add('hidden');
  $('#modal-host').innerHTML = '';
}

boot();
