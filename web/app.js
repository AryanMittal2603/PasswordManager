'use strict';
import * as C from './crypto.js';

const STORAGE_KEY = 'team_vault_v1';

// ---------- In-memory session state (cleared on lock) ----------
const state = {
  vk: null,        // raw Vault Key bytes (Uint8Array) while unlocked
  vkKey: null,     // imported AES-GCM CryptoKey
  data: null,      // decrypted vault: { users: {username:{role,perms}}, entries: [], nextId }
  me: null,        // { username, role, perms }
};

// ---------- Persistent vault file (in localStorage; also exportable) ----------
function loadFile() {
  const raw = localStorage.getItem(STORAGE_KEY);
  return raw ? JSON.parse(raw) : null;
}
function saveFile(file) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(file));
}

// Re-encrypt the in-memory vault data and write the whole file back.
async function persist() {
  const file = loadFile();
  file.vault = await C.encryptJSON(state.vkKey, state.data);
  saveFile(file);
}

// ---------- Tiny DOM helpers ----------
const $ = (s) => document.querySelector(s);
const el = (tag, props = {}, ...kids) => {
  const n = Object.assign(document.createElement(tag), props);
  for (const k of kids) if (k != null) n.append(k);
  return n;
};
const esc = (s) => (s ?? '').toString();
const ALL_PERMS = { view: true, create: true, edit: true, delete: true };

// ---------- Boot ----------
function boot() {
  if (loadFile()) show('login-view');
  else show('setup-view');
}
function show(viewId) {
  document.querySelectorAll('.view').forEach((v) => v.classList.add('hidden'));
  $('#' + viewId).classList.remove('hidden');
}

// ---------- First-run setup ----------
$('#setup-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#setup-error').textContent = '';
  const username = $('#setup-username').value.trim();
  const pw = $('#setup-password').value;
  const pw2 = $('#setup-password2').value;
  try {
    if (!username) throw new Error('Username is required');
    if (pw.length < 10) throw new Error('Admin password must be at least 10 characters');
    if (pw !== pw2) throw new Error('Passwords do not match');

    const vk = C.randomBytes(32);
    const { salt, wrapped } = await C.wrapVKForPassword(vk, pw);
    const vkKey = await C.importVK(vk);
    const data = {
      users: { [username]: { role: 'admin', perms: { ...ALL_PERMS } } },
      entries: [],
      nextId: 1,
    };
    const file = {
      v: 1,
      auth: { [username]: { salt, wrapped } },
      vault: await C.encryptJSON(vkKey, data),
    };
    saveFile(file);
    // Open the session directly.
    state.vk = vk; state.vkKey = vkKey; state.data = data;
    state.me = { username, ...data.users[username] };
    enterApp();
  } catch (err) {
    $('#setup-error').textContent = err.message;
  }
});

// ---------- Login / lock ----------
$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#login-error').textContent = '';
  const username = $('#login-username').value.trim();
  const pw = $('#login-password').value;
  try {
    const file = loadFile();
    const authEntry = file && file.auth[username];
    if (!authEntry) throw new Error('Invalid username or password');
    let vk;
    try {
      vk = await C.unwrapVKWithPassword(authEntry, pw);
    } catch {
      throw new Error('Invalid username or password');
    }
    const vkKey = await C.importVK(vk);
    const data = await C.decryptJSON(vkKey, file.vault);
    const u = data.users[username];
    if (!u) throw new Error('Account not present in vault');
    state.vk = vk; state.vkKey = vkKey; state.data = data;
    state.me = { username, ...u };
    enterApp();
  } catch (err) {
    $('#login-error').textContent = err.message;
  }
});

$('#lock-btn').addEventListener('click', lock);
function lock() {
  state.vk = null; state.vkKey = null; state.data = null; state.me = null;
  $('#login-password').value = '';
  show('login-view');
}

function enterApp() {
  show('app-view');
  $('#whoami').textContent = `${state.me.username} (${state.me.role})`;
  const isAdmin = state.me.role === 'admin';
  document.querySelectorAll('.admin-only').forEach((n) => n.classList.toggle('hidden', !isAdmin));
  $('#add-cred-btn').classList.toggle('hidden', !(isAdmin || state.me.perms.create));
  switchTab('vault');
  renderVault();
}

// ---------- Permission helpers ----------
const can = (action) => state.me.role === 'admin' || !!state.me.perms[action];

// ---------- Tabs ----------
document.querySelectorAll('.tab').forEach((t) =>
  t.addEventListener('click', () => switchTab(t.dataset.tab)));
function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.tab-panel').forEach((p) => p.classList.add('hidden'));
  $('#tab-' + name).classList.remove('hidden');
  if (name === 'users') renderUsers();
  if (name === 'vault') renderVault();
}

// ---------- Vault ----------
$('#search').addEventListener('input', renderVault);
$('#add-cred-btn').addEventListener('click', () => openCredModal(null));

function renderVault() {
  const list = $('#cred-list');
  list.innerHTML = '';
  if (!can('view')) {
    list.append(el('p', { className: 'muted', textContent: 'You do not have permission to view entries.' }));
    return;
  }
  const q = $('#search').value.toLowerCase();
  const entries = state.data.entries.filter((c) =>
    [c.title, c.username, c.url, c.folder].some((f) => (f || '').toLowerCase().includes(q)));
  if (!entries.length) {
    list.append(el('p', { className: 'muted', textContent: 'No entries yet.' }));
    return;
  }
  const byFolder = {};
  for (const c of entries) (byFolder[c.folder || 'General'] ||= []).push(c);

  for (const folder of Object.keys(byFolder).sort()) {
    list.append(el('div', { className: 'folder-head', textContent: folder }));
    for (const c of byFolder[folder]) {
      const actions = el('div', { className: 'actions' });
      actions.append(el('button', { textContent: '👁 Reveal', onclick: () => revealPassword(c) }));
      if (can('edit')) actions.append(el('button', { textContent: 'Edit', onclick: () => openCredModal(c) }));
      if (can('delete')) actions.append(el('button', { className: 'danger', textContent: 'Delete', onclick: () => deleteCred(c) }));
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
  try { await navigator.clipboard?.writeText(c.password); } catch { /* clipboard may be blocked */ }
  alert(`Password for "${c.title}":\n\n${c.password}\n\n(Copied to clipboard if your browser allowed it.)`);
}

async function deleteCred(c) {
  if (!confirm(`Delete "${c.title}"? This cannot be undone.`)) return;
  state.data.entries = state.data.entries.filter((e) => e.id !== c.id);
  await persist();
  renderVault();
}

function openCredModal(cred) {
  const editing = !!cred;
  const pwInput = el('input', { id: 'f-password', type: 'text', autocomplete: 'off', value: editing ? cred.password : '' });
  const genBtn = el('button', { type: 'button', textContent: 'Generate', onclick: () => { pwInput.value = C.generatePassword(20); } });
  const body = el('div', {},
    field('Title', `<input id="f-title" value="${esc(cred?.title)}" />`),
    field('Folder', `<input id="f-folder" value="${esc(cred?.folder || 'General')}" />`),
    field('Username', `<input id="f-username" value="${esc(cred?.username)}" autocomplete="off" />`),
    field('URL', `<input id="f-url" value="${esc(cred?.url)}" />`),
    labeled('Password', el('div', { className: 'gen-row' }, pwInput, genBtn)),
    field('Notes', `<textarea id="f-notes">${esc(cred?.notes)}</textarea>`),
  );
  openModal(editing ? 'Edit entry' : 'New entry', body, async () => {
    const title = $('#f-title').value.trim();
    const password = pwInput.value;
    if (!title) throw new Error('Title is required');
    if (!password) throw new Error('Password is required');
    const fields = {
      title,
      folder: $('#f-folder').value.trim() || 'General',
      username: $('#f-username').value,
      url: $('#f-url').value,
      notes: $('#f-notes').value,
      password,
    };
    if (editing) Object.assign(cred, fields);
    else state.data.entries.push({ id: state.data.nextId++, ...fields });
    await persist();
    renderVault();
  });
}

// ---------- Users (admin) ----------
function renderUsers() {
  const wrap = $('#user-list');
  wrap.innerHTML = '';
  const users = state.data.users;
  for (const username of Object.keys(users)) {
    const u = users[username];
    const isAdmin = u.role === 'admin';
    const perms = el('div', { className: 'actions' });
    for (const p of ['view', 'create', 'edit', 'delete']) {
      perms.append(el('span', {
        className: 'pill ' + (isAdmin || u.perms?.[p] ? 'on' : 'off'),
        textContent: p,
      }));
    }
    const actions = el('div', { className: 'actions' });
    if (!isAdmin) actions.append(el('button', { textContent: 'Edit access', onclick: () => openUserPermModal(username) }));
    actions.append(el('button', { textContent: 'Reset pw', onclick: () => resetUserPassword(username) }));
    if (!isAdmin) actions.append(el('button', { className: 'danger', textContent: 'Delete', onclick: () => deleteUser(username) }));

    wrap.append(el('div', { className: 'row' },
      el('div', { className: 'grow' },
        el('div', { className: 'title' },
          username + '  ',
          el('span', { className: 'pill ' + (isAdmin ? 'admin' : ''), textContent: u.role })),
        el('div', { className: 'sub', textContent: isAdmin ? 'Full access' : 'Member' })),
      perms, actions));
  }
}

$('#add-user-btn').addEventListener('click', () => {
  const permInputs = {};
  const permGrid = el('div', { className: 'perm-grid' });
  for (const [p, label] of [['view', 'Can view'], ['create', 'Can create'], ['edit', 'Can edit'], ['delete', 'Can delete']]) {
    const cb = el('input', { type: 'checkbox', checked: p === 'view' });
    permInputs[p] = cb;
    permGrid.append(el('label', {}, cb, label));
  }
  const adminCb = el('input', { type: 'checkbox' });
  const body = el('div', {},
    field('Username', `<input id="u-username" autocomplete="off" />`),
    field('Password (min 8 chars)', `<input id="u-password" type="text" autocomplete="off" />`),
  );
  body.append(
    el('label', { className: 'checkbox-row' }, adminCb, 'Make admin (full access)'),
    el('div', { className: 'field' }, permGrid),
  );
  openModal('Add user', body, async () => {
    const username = $('#u-username').value.trim();
    const pw = $('#u-password').value;
    if (!username) throw new Error('Username is required');
    if (state.data.users[username]) throw new Error('Username already exists');
    if (pw.length < 8) throw new Error('Password must be at least 8 characters');

    const isAdmin = adminCb.checked;
    const perms = isAdmin ? { ...ALL_PERMS } : Object.fromEntries(Object.keys(permInputs).map((p) => [p, permInputs[p].checked]));
    // Wrap the shared VK with the new user's password and add their record.
    const { salt, wrapped } = await C.wrapVKForPassword(state.vk, pw);
    const file = loadFile();
    file.auth[username] = { salt, wrapped };
    saveFile(file);
    state.data.users[username] = { role: isAdmin ? 'admin' : 'member', perms };
    await persist();
    renderUsers();
  });
});

function openUserPermModal(username) {
  const u = state.data.users[username];
  const inputs = {};
  const grid = el('div', { className: 'perm-grid' });
  for (const [p, label] of [['view', 'Can view'], ['create', 'Can create'], ['edit', 'Can edit'], ['delete', 'Can delete']]) {
    const cb = el('input', { type: 'checkbox', checked: !!u.perms?.[p] });
    inputs[p] = cb;
    grid.append(el('label', {}, cb, label));
  }
  openModal(`Access for ${username}`, grid, async () => {
    u.perms = Object.fromEntries(Object.keys(inputs).map((p) => [p, inputs[p].checked]));
    await persist();
    renderUsers();
  });
}

async function deleteUser(username) {
  if (!confirm(`Delete user "${username}"?`)) return;
  delete state.data.users[username];
  const file = loadFile();
  delete file.auth[username];
  saveFile(file);
  await persist();
  renderUsers();
}

async function resetUserPassword(username) {
  const np = prompt(`New password for "${username}" (min 8 chars):`);
  if (np == null) return;
  if (np.length < 8) { alert('Password must be at least 8 characters'); return; }
  const { salt, wrapped } = await C.wrapVKForPassword(state.vk, np);
  const file = loadFile();
  file.auth[username] = { salt, wrapped };
  saveFile(file);
  alert(`Password for "${username}" was reset. Export the vault and share it so they can use the new password.`);
}

// ---------- Change my own password ----------
$('#change-pw-btn').addEventListener('click', () => {
  const body = el('div', {},
    field('Current password', `<input id="cp-cur" type="password" autocomplete="off" />`),
    field('New password (min 8 chars)', `<input id="cp-new" type="password" autocomplete="off" />`),
  );
  openModal('Change your password', body, async () => {
    const cur = $('#cp-cur').value;
    const np = $('#cp-new').value;
    if (np.length < 8) throw new Error('New password must be at least 8 characters');
    // Verify current password by unwrapping VK with it.
    const file = loadFile();
    try {
      await C.unwrapVKWithPassword(file.auth[state.me.username], cur);
    } catch {
      throw new Error('Current password is incorrect');
    }
    const { salt, wrapped } = await C.wrapVKForPassword(state.vk, np);
    file.auth[state.me.username] = { salt, wrapped };
    saveFile(file);
    alert('Password changed.');
  });
});

// ---------- Export / Import (the "file-based DB") ----------
$('#export-btn').addEventListener('click', () => {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return;
  const blob = new Blob([raw], { type: 'application/json' });
  const a = el('a', { href: URL.createObjectURL(blob), download: 'team-vault.json' });
  document.body.append(a); a.click(); a.remove();
});

const fileInput = $('#file-input');
$('#login-import').addEventListener('click', () => fileInput.click());
$('#setup-import').addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', async () => {
  const file = fileInput.files[0];
  if (!file) return;
  try {
    const text = await file.text();
    const parsed = JSON.parse(text);
    if (!parsed.auth || !parsed.vault) throw new Error('Not a valid vault file');
    if (loadFile() && !confirm('This will replace the vault stored in this browser. Continue?')) return;
    saveFile(parsed);
    fileInput.value = '';
    show('login-view');
    alert('Vault imported. Log in with your account.');
  } catch (err) {
    alert('Import failed: ' + err.message);
  }
});

// ---------- Modal plumbing ----------
function labeled(label, node) {
  return el('div', { className: 'field' }, el('label', { textContent: label }), node);
}
function field(label, innerHTML) {
  const holder = el('div');
  holder.innerHTML = innerHTML;
  return labeled(label, holder.firstElementChild);
}
function openModal(title, bodyNode, onSave) {
  const host = $('#modal-host');
  const err = el('div', { className: 'error' });
  const saveBtn = el('button', { className: 'primary', textContent: 'Save' });
  const modal = el('div', { className: 'modal' },
    el('h2', { textContent: title }), bodyNode, err,
    el('div', { className: 'modal-actions' },
      el('button', { textContent: 'Cancel', onclick: closeModal }), saveBtn));
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
