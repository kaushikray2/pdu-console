'use strict';
const $ = id => document.getElementById(id);
const VIEWS = ['authView', 'overviewView', 'detailView', 'settingsView', 'consoleView'];
let CUR = null;             // pdu id shown in detail/settings
let S = null, OUT = {}, GROUP_OF = {}, GROUPS = [], LOCKED = new Set(), PROTECTED = new Set();
let pollMs = 15000, detTimer = null, ovTimer = null;
function show(view) {
  for (const v of VIEWS) $(v).hidden = v !== view;
  clearInterval(detTimer); clearInterval(ovTimer); detTimer = ovTimer = null;
}
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
async function api(path, opts) {
  const r = await fetch(path, opts);
  let body = null;
  try { body = await r.json(); } catch (e) { /* non-json */ }
  if (r.status === 401 && !path.startsWith('/api/auth/')) { showAuth(); throw new Error('signed out'); }
  return { status: r.status, body };
}
const get = p => api(p);
const post = (p, data) => api(p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data || {}) });
let toastTimer = null;
function toast(msg) {
  const t = $('toast'); t.textContent = msg; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, 4500);
}
let cfResolve = null;
function confirmDlg(text, sub, okLabel) {
  $('cfText').textContent = text; $('cfSub').textContent = sub || ''; $('cfOk').textContent = okLabel || 'Confirm';
  $('confirmModal').hidden = false;
  return new Promise(res => { cfResolve = res; });
}
$('cfOk').addEventListener('click', () => { $('confirmModal').hidden = true; cfResolve && cfResolve(true); });
$('cfCancel').addEventListener('click', () => { $('confirmModal').hidden = true; cfResolve && cfResolve(false); });
let pwResolve = null;
function passwordDlg(text) {
  $('pwText').textContent = text; $('pwInput').value = ''; $('pwErr').textContent = '';
  $('pwModal').hidden = false; $('pwInput').focus();
  return new Promise(res => { pwResolve = res; });
}
$('pwOk').addEventListener('click', () => { const v = $('pwInput').value; $('pwModal').hidden = true; pwResolve && pwResolve(v); });
$('pwCancel').addEventListener('click', () => { $('pwModal').hidden = true; pwResolve && pwResolve(null); });
// ---- auth ----
async function showAuth() {
  show('authView');
  const { body } = await get('/api/auth/state');
  document.title = 'PDU Console';
  $('setupForm').hidden = body.configured;
  $('loginForm').hidden = !body.configured;
  $('authErr').textContent = '';
}
$('setupBtn').addEventListener('click', async () => {
  const a = $('setupPw').value, b = $('setupPw2').value;
  if (a.length < 8) { $('authErr').textContent = 'Use at least 8 characters.'; return; }
  if (a !== b) { $('authErr').textContent = 'The two passwords do not match.'; return; }
  const { status, body } = await post('/api/auth/setup', { password: a });
  if (status !== 200) { $('authErr').textContent = (body && body.error) || 'Setup failed'; return; }
  route();
});
$('loginBtn').addEventListener('click', async () => {
  const { status, body } = await post('/api/auth/login', { password: $('loginPw').value });
  if (status !== 200) { $('authErr').textContent = (body && body.error) || 'Sign-in failed'; return; }
  $('loginPw').value = ''; route();
});
$('loginPw').addEventListener('keydown', e => { if (e.key === 'Enter') $('loginBtn').click(); });
async function signOut() { await post('/api/auth/logout'); location.hash = ''; showAuth(); }
for (const id of ['ovOut', 'logoutBtn', 'setOut', 'conOut']) $(id).addEventListener('click', signOut);
// ---- router ----
function route() {
  const h = location.hash || '#/';
  let m;
  if ((m = h.match(/^#\/pdu\/([^/]+)\/settings$/))) { CUR = m[1]; loadPduSettings(); }
  else if ((m = h.match(/^#\/pdu\/([^/]+)$/))) { CUR = m[1]; loadDetail(); }
  else if (h === '#/console') { loadConsole(); }
  else { loadOverview(); }
}
window.addEventListener('hashchange', route);
// ---- overview (landing) ----
async function loadOverview() {
  show('overviewView');
  document.title = 'PDU Console';
  await refreshOverview();
  ovTimer = setInterval(refreshOverview, 10000);
}
async function refreshOverview() {
  const { status, body } = await get('/api/pdus');
  if (status !== 200 || !body) return;
  const list = body.pdus || [];
  $('ovErr').textContent = '';
  $('ovEmpty').hidden = list.length > 0;
  $('ovMeta').textContent = list.length === 1 ? '1 PDU managed' : list.length + ' PDUs managed';
  const grid = $('ovGrid'); grid.innerHTML = '';
  for (const p of list) grid.append(ovCard(p));
}
function ovCard(p) {
  const card = document.createElement('div');
  card.className = 'card ov-card';
  const head = document.createElement('div'); head.className = 'card-head';
  const nm = document.createElement('span'); nm.className = 'card-name'; nm.textContent = '⚡ ' + p.name;
  const pill = document.createElement('span');
  if (!p.ok) { pill.className = 'pill bad'; pill.textContent = 'Unreachable'; }
  else if (p.alarms) { pill.className = 'pill bad'; pill.textContent = 'Alarm'; }
  else { pill.className = 'pill ok'; pill.textContent = 'No alarms'; }
  head.append(nm, pill);
  const ip = document.createElement('p'); ip.className = 'muted small'; ip.textContent = p.ip;
  card.append(head, ip);
  if (p.ok) {
    const load = document.createElement('div'); load.className = 'ov-load';
    load.textContent = p.total_load === null || p.total_load === undefined ? '–' : p.total_load.toFixed(1) + ' A total';
    const banks = document.createElement('p'); banks.className = 'muted small';
    banks.textContent = Object.keys(p.bank_loads || {}).sort().map(b => 'B' + b + ' ' + Number(p.bank_loads[b]).toFixed(1) + ' A').join(' · ');
    const meta = document.createElement('p'); meta.className = 'muted small';
    meta.textContent = 'Outlets on ' + p.outlets_on + ' / ' + p.outlets_total +
      (p.groups ? ' · ' + p.groups + ' group' + (p.groups === 1 ? '' : 's') : '') +
      (p.locked ? ' · 🔒 ' + p.locked + ' locked' : '');
    const upd = document.createElement('p'); upd.className = 'muted small';
    upd.textContent = 'Updated ' + new Date(p.updated * 1000).toLocaleTimeString();
    card.append(load, banks, meta, upd);
  } else {
    const err = document.createElement('p'); err.className = 'err small';
    err.textContent = p.error || 'Waiting for first poll…';
    card.append(err);
  }
  const open = document.createElement('button'); open.className = 'primary wide'; open.textContent = 'Open →';
  open.addEventListener('click', () => { location.hash = '#/pdu/' + p.id; });
  card.append(open);
  return card;
}
$('ovRefresh').addEventListener('click', refreshOverview);
$('ovAdd').addEventListener('click', () => {
  $('addErr').textContent = '';
  for (const id of ['addIp', 'addName', 'addUser', 'addPass']) $(id).value = '';
  $('addModal').hidden = false; $('addIp').focus();
});
$('addCancel').addEventListener('click', () => { $('addModal').hidden = true; });
$('addSave').addEventListener('click', async () => {
  $('addErr').textContent = '';
  const payload = { ip: $('addIp').value.trim(), name: $('addName').value.trim(), username: $('addUser').value.trim(), password: $('addPass').value };
  if (!payload.ip || !payload.name || !payload.username || !payload.password) { $('addErr').textContent = 'Fill in every field.'; return; }
  $('addSave').disabled = true;
  const { status, body } = await post('/api/pdus', payload);
  $('addSave').disabled = false;
  if (status !== 200) { $('addErr').textContent = (body && body.error) || 'Add failed'; return; }
  $('addModal').hidden = true;
  toast('"' + payload.name + '" added');
  refreshOverview();
});
$('ovConsole').addEventListener('click', () => { location.hash = '#/console'; });
// ---- PDU detail ----
const pduUrl = (sub) => '/api/pdus/' + CUR + (sub || '');
async function loadDetail() {
  show('detailView');
  await refreshDetail();
  detTimer = setInterval(refreshDetail, 5000);
}
$('backBtn').addEventListener('click', () => { location.hash = '#/'; });
$('settingsBtn').addEventListener('click', () => { location.hash = '#/pdu/' + CUR + '/settings'; });
$('refreshBtn').addEventListener('click', async () => {
  const { body } = await post(pduUrl('/refresh'));
  if (body) renderDetail(body);
});
async function refreshDetail() {
  const { status, body } = await get(pduUrl('/status'));
  if (status !== 200 || !body) return;
  renderDetail(body);
}
function renderDetail(body) {
  S = body;
  if (body.device) {
    $('devTitle').textContent = body.device.name;
    document.title = body.device.name + ' — PDU Console';
    $('devMeta').textContent = body.device.ip + ' · ' + body.device.name;
    $('nativeLink').href = 'http://' + body.device.ip + '/';
    $('nativeLink').textContent = body.device.ip;
  }
  GROUPS = body.groups || []; LOCKED = new Set(body.locked || []); PROTECTED = new Set(body.protected || []);
  $('mainErr').textContent = body.error ? 'PDU poll error: ' + body.error : '';
  renderGroups();
  const s = body.status;
  if (!s) { $('updated').textContent = 'waiting for first poll…'; return; }
  $('updated').textContent = 'Updated ' + new Date(s.fetched_at * 1000).toLocaleTimeString();
  const pill = $('alarmPill');
  pill.textContent = s.alarms ? 'Alarm present' : 'No alarms';
  pill.className = 'pill ' + (s.alarms ? 'bad' : 'ok');
  OUT = {}; GROUP_OF = {};
  for (const o of s.outlets) OUT[o.n] = o;
  for (const g of GROUPS) for (const n of g.outlets) GROUP_OF[n] = g;
  $('loadTotal').textContent = s.loads.total === null ? '–' : s.loads.total.toFixed(1) + ' A';
  const bc = $('bankCards'); bc.innerHTML = '';
  for (const b of Object.keys(s.loads.banks).sort()) {
    const c = document.createElement('div'); c.className = 'load-card';
    const k = document.createElement('span'); k.className = 'k'; k.textContent = 'Bank B' + b;
    const v = document.createElement('span'); v.className = 'v'; v.textContent = Number(s.loads.banks[b]).toFixed(1) + ' A';
    c.append(k, v); bc.append(c);
  }
  $('onCount').textContent = s.outlets.filter(o => o.state === 'On').length + ' / ' + s.outlets.length;
  renderGroups();
  renderBanks(s.outlets);
}
function pillFor(state) {
  const p = document.createElement('span');
  p.className = 'pill ' + (state === 'On' ? 'on' : state === 'Off' ? 'off' : 'mixed');
  p.textContent = state;
  return p;
}
function lockButton(locked, onclick) {
  const b = document.createElement('button'); b.className = 'lockbtn';
  b.textContent = locked ? '🔒' : '🔓';
  b.title = locked ? 'Locked — click to unlock' : 'Unlocked — click to lock';
  b.addEventListener('click', onclick);
  return b;
}
function ctrlButtons(onAct, state, locked, ctrlGreyTitle) {
  const ctrl = document.createElement('div'); ctrl.className = 'ctrl' + (locked ? ' greyed' : '');
  if (locked) ctrl.title = ctrlGreyTitle || 'Locked — you will be asked for the console password';
  const mk = (label, action, cls) => {
    const b = document.createElement('button'); b.textContent = label; if (cls) b.className = cls;
    b.disabled = (action === 'on' && state === 'On') || (action === 'off' && state === 'Off');
    b.addEventListener('click', () => onAct(action));
    return b;
  };
  ctrl.append(mk('On', 'on'), mk('Reboot', 'reboot', 'warn'), mk('Off', 'off', 'danger'));
  return ctrl;
}
function renderGroups() {
  const el = $('groupGrid'); el.innerHTML = '';
  $('noGroups').hidden = GROUPS.length > 0;
  for (const g of GROUPS) {
    const members = g.outlets.map(n => OUT[n]).filter(Boolean);
    const on = members.filter(o => o.state === 'On').length;
    const agg = !members.length ? 'No data' : on === members.length ? 'On' : on === 0 ? 'Off' : 'Mixed';
    const card = document.createElement('div'); card.className = 'outlet';
    const top = document.createElement('div'); top.className = 'top';
    const nm = document.createElement('span'); nm.className = 'name'; nm.textContent = '⛓ ' + g.name;
    const gright = document.createElement('span'); gright.className = 'topright';
    gright.append(pillFor(agg));
    gright.append(lockButton(g.locked, () => toggleGroupLock(g)));
    top.append(nm, gright);
    const mem = document.createElement('div'); mem.className = 'members';
    mem.textContent = g.outlets.map(n => OUT[n] ? '#' + n + ' ' + OUT[n].name + ' · ' + OUT[n].state : '#' + n).join('  |  ') + (agg === 'Mixed' ? '  (' + on + '/' + members.length + ' on)' : '');
    card.append(top, mem);
    const lockedMembers = g.outlets.filter(n => LOCKED.has(n));
    if (g.locked) {
      const l = document.createElement('div'); l.className = 'locked-note';
      l.textContent = '🔒 Group locked — password needed to switch';
      card.append(l);
    }
    if (lockedMembers.length) {
      const l = document.createElement('div'); l.className = 'locked-note';
      l.textContent = '🔒 Includes locked outlet(s): ' + lockedMembers.join(', ');
      card.append(l);
    }
    card.append(ctrlButtons(a => controlFlow('group', g.name, g.outlets, a), agg, g.locked || lockedMembers.length > 0,
      g.locked ? 'Group locked — you will be asked for the console password' : undefined));
    const row = document.createElement('div'); row.className = 'grp-actions'; row.style.marginTop = '8px';
    const ed = document.createElement('button'); ed.className = 'ghost'; ed.textContent = 'Edit group';
    ed.addEventListener('click', () => openGroupEditor(g));
    row.append(ed);
    card.append(row);
    el.append(card);
  }
}
function renderBanks(outlets) {
  const wrap = $('banks'); wrap.innerHTML = '';
  const banks = [...new Set(outlets.map(o => o.bank))].sort((a, b) => a - b);
  for (const b of banks) {
    const list = outlets.filter(o => o.bank === b);
    const sec = document.createElement('section');
    const hd = document.createElement('h2');
    hd.textContent = 'Bank B' + b + ' ';
    const rng = document.createElement('span'); rng.className = 'muted thin';
    rng.textContent = 'outlets ' + list[0].n + '–' + list[list.length - 1].n;
    hd.append(rng);
    const grid = document.createElement('div'); grid.className = 'grid';
    sec.append(hd, grid); wrap.append(sec);
    renderBankInto(grid, list);
  }
}
function renderBankInto(el, outlets) {
  for (const o of outlets) {
    const grp = GROUP_OF[o.n];
    const card = document.createElement('div'); card.className = 'outlet' + (grp ? ' grouped' : '');
    const top = document.createElement('div'); top.className = 'top';
    const num = document.createElement('span'); num.className = 'num'; num.textContent = '#' + o.n;
    const right = document.createElement('span'); right.className = 'topright';
    right.append(pillFor(o.state));
    if (!PROTECTED.has(o.n) && !grp) right.append(lockButton(LOCKED.has(o.n), () => toggleLock(o)));
    top.append(num, right);
    const name = document.createElement('div'); name.className = 'name'; name.textContent = o.name;
    card.append(top, name);
    if (grp) {
      const l = document.createElement('div'); l.className = 'members';
      l.textContent = '⛓ In group "' + grp.name + '" — controlled from the group card';
      card.append(l);
      const ctrl = ctrlButtons(() => {}, o.state, true, 'Controlled by group "' + grp.name + '"');
      ctrl.querySelectorAll('button').forEach(b => { b.disabled = true; });
      card.append(ctrl);
    } else if (PROTECTED.has(o.n)) {
      const l = document.createElement('div'); l.className = 'lock';
      l.textContent = '🔒 Permanently protected — never switched';
      card.append(l);
    } else {
      if (LOCKED.has(o.n)) {
        const l = document.createElement('div'); l.className = 'locked-note';
        l.textContent = '🔒 Locked — password needed to switch';
        card.append(l);
      }
      card.append(ctrlButtons(a => controlFlow('outlet', o.name, [o.n], a), o.state, LOCKED.has(o.n)));
    }
    el.append(card);
  }
}
async function controlFlow(via, label, targets, action) {
  const verb = action === 'reboot' ? 'Reboot' : action === 'on' ? 'Turn ON' : 'Turn OFF';
  const ok = await confirmDlg(verb + ' ' + label + '?',
    via === 'group' ? 'This switches all ' + targets.length + ' outlets in the group together.' : 'This sends the command to the PDU immediately.', verb);
  if (!ok) return;
  let password = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    const payload = via === 'group'
      ? { group: label, action, confirm: true, password }
      : { outlet: targets[0], action, confirm: true, password };
    const { status, body } = await post(pduUrl(via === 'group' ? '/group-control' : '/control'), payload);
    if (status === 200) { toast(body.message || 'Done'); refreshDetail(); return; }
    if (status === 428) {
      password = await passwordDlg('"' + label + '" is locked');
      if (password === null) return;
      continue;
    }
    toast((body && body.error) || 'Command failed'); return;
  }
}
async function toggleLock(o) {
  if (!LOCKED.has(o.n)) {
    const { status, body } = await post(pduUrl('/lock'), { outlet: o.n, locked: true });
    if (status === 200) { LOCKED = new Set(body.locked); toast('Outlet #' + o.n + ' ' + o.name + ' locked'); renderDetail(S); }
    else toast((body && body.error) || 'Lock failed');
    return;
  }
  const pw = await passwordDlg('Unlock outlet #' + o.n + ' ' + o.name + '?');
  if (pw === null) return;
  const { status, body } = await post(pduUrl('/lock'), { outlet: o.n, locked: false, password: pw });
  if (status === 200) { LOCKED = new Set(body.locked); toast('Outlet #' + o.n + ' unlocked'); renderDetail(S); }
  else toast((body && body.error) || 'Unlock failed');
}
async function toggleGroupLock(g) {
  if (!g.locked) {
    const { status, body } = await post(pduUrl('/grouplock'), { group: g.name, locked: true });
    if (status === 200) { GROUPS = body.groups; toast('Group "' + g.name + '" locked'); renderDetail(S); }
    else toast((body && body.error) || 'Lock failed');
    return;
  }
  const pw = await passwordDlg('Unlock group "' + g.name + '"?');
  if (pw === null) return;
  const { status, body } = await post(pduUrl('/grouplock'), { group: g.name, locked: false, password: pw });
  if (status === 200) { GROUPS = body.groups; toast('Group "' + g.name + '" unlocked'); renderDetail(S); }
  else toast((body && body.error) || 'Unlock failed');
}
// ---- group editor ----
let grpOriginal = null;
function openGroupEditor(g) {
  grpOriginal = g ? g.name : null;
  $('grpTitle').textContent = g ? 'Edit group' : 'New group';
  $('grpName').value = g ? g.name : '';
  $('grpErr').textContent = '';
  $('grpDelete').hidden = !g;
  const box = $('grpOutlets'); box.innerHTML = '';
  const outlets = S && S.status ? S.status.outlets : [];
  for (const o of outlets) {
    const owner = GROUP_OF[o.n];
    const taken = owner && (!g || owner.name !== g.name);
    const lab = document.createElement('label');
    lab.className = 'pick' + (taken ? ' taken' : '');
    const cb = document.createElement('input'); cb.type = 'checkbox'; cb.value = o.n;
    cb.checked = !!(g && g.outlets.includes(o.n)); cb.disabled = taken;
    const txt = document.createElement('span');
    txt.textContent = '#' + o.n + ' ' + o.name + (taken ? ' (' + owner.name + ')' : '');
    lab.append(cb, txt); box.append(lab);
  }
  $('groupModal').hidden = false;
}
$('newGroupBtn').addEventListener('click', () => openGroupEditor(null));
$('grpCancel').addEventListener('click', () => { $('groupModal').hidden = true; });
$('grpSave').addEventListener('click', async () => {
  const outlets = [...$('grpOutlets').querySelectorAll('input:checked')].map(cb => Number(cb.value));
  const { status, body } = await post(pduUrl('/groups'), { name: $('grpName').value, outlets, original: grpOriginal });
  if (status !== 200) { $('grpErr').textContent = (body && body.error) || 'Save failed'; return; }
  $('groupModal').hidden = true; GROUPS = body.groups; toast('Group saved'); renderDetail(S);
});
$('grpDelete').addEventListener('click', async () => {
  const ok = await confirmDlg('Delete group "' + grpOriginal + '"?', 'The outlets stay as they are; they just stop switching together.', 'Delete');
  if (!ok) return;
  const { status, body } = await post(pduUrl('/groups/delete'), { name: grpOriginal });
  if (status !== 200) { $('grpErr').textContent = (body && body.error) || 'Delete failed'; return; }
  $('groupModal').hidden = true; GROUPS = body.groups; toast('Group deleted'); renderDetail(S);
});
// ---- per-PDU settings ----
function fmtEvent(ev) {
  const when = new Date(ev.ts * 1000).toLocaleString();
  const bits = [ev.event];
  if (ev.pdu) bits.push('pdu ' + ev.pdu);
  if (ev.action) bits.push(ev.action);
  if (ev.outlets) bits.push('outlets ' + ev.outlets.join(','));
  if (ev.outlet !== undefined) bits.push('outlet ' + ev.outlet);
  if (ev.group) bits.push('group ' + ev.group);
  if (ev.name) bits.push('"' + ev.name + '"');
  if (ev.ip) bits.push(ev.ip);
  if (ev.seconds) bits.push(ev.seconds + 's');
  return { when, text: bits.join(' · ') };
}
function renderActivity(el, events) {
  el.innerHTML = '';
  if (!events || !events.length) { el.innerHTML = '<p class="muted small">Nothing recorded yet.</p>'; return; }
  for (const ev of events) {
    const row = document.createElement('div'); row.className = 'act-row';
    const a = document.createElement('span'); a.textContent = fmtEvent(ev).text;
    const b = document.createElement('span'); b.className = 'muted'; b.textContent = fmtEvent(ev).when;
    row.append(a, b); el.append(row);
  }
}
async function loadPduSettings() {
  show('settingsView');
  const { status, body } = await get(pduUrl('/settings'));
  if (status !== 200 || !body) { location.hash = '#/'; return; }
  document.title = 'Settings — ' + body.device.name;
  $('setDevName').textContent = body.device.name;
  $('setIp').value = body.device.ip; $('setName').value = body.device.name;
  $('setUser').value = body.device.username; $('setPass').value = '';
  $('setConnMsg').textContent = ''; $('renameMsg').textContent = ''; $('setPollMsg').textContent = ''; $('removeMsg').textContent = '';
  const sel = $('setPoll'); sel.innerHTML = '';
  for (const v of (body.poll_choices || [30])) {
    const opt = document.createElement('option'); opt.value = v;
    opt.textContent = v < 60 ? v + ' seconds' : (v / 60) + (v === 60 ? ' minute' : ' minutes');
    sel.append(opt);
  }
  sel.value = String(body.poll_seconds);
  renderActivity($('activityList'), body.recent);
  const { body: st } = await get(pduUrl('/status'));
  renderRenameList(st && st.status ? st.status.outlets : []);
}
function renderRenameList(outlets) {
  const box = $('renameList'); box.innerHTML = '';
  if (!outlets.length) { box.innerHTML = '<p class="muted small">Outlet names load after the next successful poll.</p>'; return; }
  for (const o of outlets) {
    const row = document.createElement('div'); row.className = 'rename-row';
    const lab = document.createElement('span'); lab.className = 'muted'; lab.textContent = '#' + o.n;
    const inp = document.createElement('input'); inp.type = 'text'; inp.value = o.name; inp.maxLength = 23;
    inp.setAttribute('aria-label', 'Name for outlet ' + o.n);
    const btn = document.createElement('button'); btn.textContent = 'Save';
    btn.addEventListener('click', async () => {
      $('renameMsg').textContent = '';
      const { status, body } = await post(pduUrl('/rename'), { outlet: o.n, name: inp.value });
      if (status !== 200) { $('renameMsg').textContent = (body && body.error) || 'Rename failed'; return; }
      toast(body.message || 'Renamed');
      const { body: st } = await get(pduUrl('/status'));
      renderRenameList(st && st.status ? st.status.outlets : []);
    });
    row.append(lab, inp, btn); box.append(row);
  }
}
$('setBack').addEventListener('click', () => { location.hash = '#/pdu/' + CUR; });
$('setConnSave').addEventListener('click', async () => {
  $('setConnMsg').textContent = '';
  const payload = { ip: $('setIp').value.trim(), name: $('setName').value.trim(), username: $('setUser').value.trim(), password: $('setPass').value };
  $('setConnSave').disabled = true;
  const { status, body } = await post(pduUrl('/settings/connection'), payload);
  $('setConnSave').disabled = false;
  if (status !== 200) { $('setConnMsg').textContent = (body && body.error) || 'Save failed'; return; }
  $('setPass').value = '';
  $('setDevName').textContent = payload.name;
  toast(body.message || 'Saved');
});
$('setPollSave').addEventListener('click', async () => {
  $('setPollMsg').textContent = '';
  const { status, body } = await post(pduUrl('/settings/poll'), { poll_seconds: Number($('setPoll').value) });
  if (status !== 200) { $('setPollMsg').textContent = (body && body.error) || 'Save failed'; return; }
  toast('This PDU will be polled every ' + body.poll_seconds + ' s');
});
$('removePduBtn').addEventListener('click', async () => {
  $('removeMsg').textContent = '';
  const ok = await confirmDlg('Remove "' + $('setDevName').textContent + '" from the console?',
    'Its settings are archived in the data folder. The PDU itself is not changed.', 'Remove');
  if (!ok) return;
  const { status, body } = await post(pduUrl('/remove'), {});
  if (status !== 200) { $('removeMsg').textContent = (body && body.error) || 'Remove failed'; return; }
  toast('PDU removed');
  location.hash = '#/';
});
// ---- console settings ----
async function loadConsole() {
  show('consoleView');
  document.title = 'Console settings — PDU Console';
  const { status, body } = await get('/api/console/settings');
  if (status !== 200 || !body) { location.hash = '#/'; return; }
  $('setBlocked').value = (body.blocked_ips || []).join(', ');
  $('setBlockedMsg').textContent = ''; $('pwMsg').textContent = '';
  renderActivity($('conActivity'), body.recent);
}
$('conBack').addEventListener('click', () => { location.hash = '#/'; });
$('setBlockedSave').addEventListener('click', async () => {
  $('setBlockedMsg').textContent = '';
  const { status, body } = await post('/api/console/blocked', { blocked_ips: $('setBlocked').value });
  if (status !== 200) { $('setBlockedMsg').textContent = (body && body.error) || 'Save failed'; return; }
  $('setBlocked').value = (body.blocked_ips || []).join(', ');
  toast('Blocked list saved');
});
$('pwChangeBtn').addEventListener('click', async () => {
  $('pwMsg').textContent = '';
  if ($('pwNew').value !== $('pwNew2').value) { $('pwMsg').textContent = 'The new passwords do not match.'; return; }
  const { status, body } = await post('/api/console/password', { current: $('pwCur').value, new: $('pwNew').value });
  if (status !== 200) { $('pwMsg').textContent = (body && body.error) || 'Change failed'; return; }
  $('pwCur').value = $('pwNew').value = $('pwNew2').value = '';
  toast('Console password changed');
});
// ---- boot ----
(async function boot() {
  const { body } = await get('/api/auth/state');
  if (!body.authed) { showAuth(); return; }
  route();
})();
