/* Travel Checklist — same login pattern as the football site:
   username+password -> bcrypt check server-side -> uuid session token,
   session JSON kept in localStorage. */
'use strict';

const SESSION_KEY = 'travel_session';
const CATEGORIES = ['Documents', 'Clothing', 'Toiletries', 'Electronics',
  'Food & Drink', 'Comfort', 'Personal', 'Health', 'Travel Day', 'Misc'];

const $ = id => document.getElementById(id);
const esc = s => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

let session = null;   // {token, user_id, username, nickname, email}
let trips = [];
let currentTrip = null;
let items = [];

/* ---------------- API ---------------- */
async function api(fn, args) {
  const res = await fetch(`/api/rpc/${fn}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(args || {}),
  });
  const text = await res.text();
  let data = null, isJson = false;
  try { data = text ? JSON.parse(text) : null; isJson = true; } catch (e) { /* not json */ }
  if (!res.ok) {
    let msg = 'Request failed.';
    if (data && data.message) msg = data.message;
    else if (text) msg = text.slice(0, 300);
    const err = new Error(msg);
    err.status = res.status;
    err.isJson = isJson;
    throw err;
  }
  return data;
}
const authed = extra => Object.assign({ p_token: session.token }, extra || {});

/* ---------------- toast ---------------- */
let toastTimer = null;
function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 2600);
}
function showError(el, err) {
  el.textContent = err && err.message ? err.message : 'Something went wrong.';
  el.hidden = false;
}

/* ---------------- in-app confirm / prompt ----------------
   Promise-based modal replacing native confirm()/prompt(), which block
   badly in some embedded browsers and look out of place on mobile.
   Resolves true/false for confirms, or the entered string / null for prompts. */
function uiDialog(opts) {
  return new Promise(resolve => {
    const modal = $('confirm-modal');
    $('confirm-title').textContent = opts.title || 'Are you sure?';
    $('confirm-message').textContent = opts.message || '';
    $('confirm-message').hidden = !opts.message;
    const okBtn = $('confirm-ok');
    okBtn.textContent = opts.okText || 'OK';
    okBtn.classList.toggle('danger-btn', !!opts.danger);
    const wrap = $('confirm-input-wrap');
    const input = $('confirm-input');
    if (opts.input) {
      wrap.hidden = false;
      input.value = opts.inputValue || '';
      input.placeholder = opts.inputPlaceholder || '';
    } else {
      wrap.hidden = true;
    }
    const done = val => {
      modal.hidden = true;
      okBtn.onclick = cancelBtn.onclick = null;
      modal.onclick = null;
      input.onkeydown = null;
      resolve(val);
    };
    const cancelBtn = $('confirm-cancel');
    okBtn.onclick = () => done(opts.input ? input.value : true);
    cancelBtn.onclick = () => done(opts.input ? null : false);
    modal.onclick = e => { if (e.target === modal) done(opts.input ? null : false); };
    input.onkeydown = e => { if (e.key === 'Enter') done(input.value); };
    modal.hidden = false;
    if (opts.input) setTimeout(() => { input.focus(); input.select(); }, 50);
    else setTimeout(() => okBtn.focus(), 50);
  });
}

/* ---------------- session ---------------- */
function saveSession(s) {
  session = s;
  try { localStorage.setItem(SESSION_KEY, JSON.stringify(s)); } catch (e) {}
}
function loadSavedSession() {
  try { return JSON.parse(localStorage.getItem(SESSION_KEY) || 'null'); } catch (e) { return null; }
}
function clearSession() {
  session = null;
  try { localStorage.removeItem(SESSION_KEY); } catch (e) {}
}
function displayName() {
  return (session && (session.nickname || session.username)) || '';
}

async function boot() {
  const saved = loadSavedSession();
  if (saved && saved.token) {
    try {
      // Validate the saved login. Only sign out when the server positively
      // says the session is invalid — never on a network hiccup.
      const me = await api('travel_me', { p_token: saved.token });
      saveSession(me);
    } catch (e) {
      const invalid = e && e.message && e.message.indexOf('invalid_session') === 0;
      if (invalid) clearSession();
      else session = saved; // offline or server error: keep the saved login
    }
  }
  if (session) { showTrips(); } else { showView('auth-view'); }
  wireAuth();
}

function showView(id) {
  ['auth-view', 'trips-view', 'trip-view'].forEach(v => { $(v).hidden = v !== id; });
  window.scrollTo(0, 0);
}

/* ---------------- auth ---------------- */
let authMode = 'signin';
function wireAuth() {
  const tabS = $('tab-signin'), tabR = $('tab-register');
  tabS.onclick = () => setAuthMode('signin');
  tabR.onclick = () => setAuthMode('register');
  $('auth-form').onsubmit = onAuthSubmit;
  $('signout-btn').onclick = onSignOut;
}
function setAuthMode(mode) {
  authMode = mode;
  $('tab-signin').classList.toggle('active', mode === 'signin');
  $('tab-register').classList.toggle('active', mode === 'register');
  $('register-extra').hidden = mode !== 'register';
  $('auth-submit').textContent = mode === 'signin' ? 'Sign in' : 'Create account';
  $('auth-error').hidden = true;
  $('auth-password').setAttribute('autocomplete', mode === 'signin' ? 'current-password' : 'new-password');
}
async function onAuthSubmit(e) {
  e.preventDefault();
  const errEl = $('auth-error');
  errEl.hidden = true;
  const btn = $('auth-submit');
  btn.disabled = true;
  try {
    const username = $('auth-username').value;
    const password = $('auth-password').value;
    let s;
    if (authMode === 'signin') {
      s = await api('travel_login', { p_username: username, p_password: password });
    } else {
      s = await api('travel_register', {
        p_username: username, p_password: password,
        p_email: $('auth-email').value || null,
        p_nickname: $('auth-nickname').value || null,
      });
    }
    saveSession(s);
    $('auth-password').value = '';
    toast(authMode === 'signin' ? `Welcome back, ${esc(displayName())}!` : 'Account created — welcome!');
    showTrips();
  } catch (err) { showError(errEl, err); }
  btn.disabled = false;
}
async function onSignOut() {
  try { if (session) await api('travel_logout', { p_token: session.token }); } catch (e) {}
  clearSession();
  showView('auth-view');
}

/* ---------------- trips list ---------------- */
function fmtDate(iso) {
  if (!iso) return '';
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso);
  if (!m) return iso;
  return new Date(+m[1], +m[2] - 1, +m[3])
    .toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
}
function dateRange(t) {
  const a = fmtDate(t.start_date), b = fmtDate(t.end_date);
  if (a && b) return a === b ? a : `${a} – ${b}`;
  return a || b || '';
}

async function showTrips() {
  showView('trips-view');
  $('user-label').textContent = displayName();
  $('new-trip-btn').onclick = () => openTripModal(null);
  const list = $('trips-list');
  list.innerHTML = '<div class="empty"><p>Loading trips…</p></div>';
  $('trips-empty').hidden = true;
  try {
    trips = await api('travel_trips', authed());
  } catch (e) {
    list.innerHTML = '';
    toast(e.message || 'Could not load trips.');
    return;
  }
  renderTrips();
}
function renderTrips() {
  const list = $('trips-list');
  list.innerHTML = '';
  $('trips-empty').hidden = trips.length > 0;
  trips.forEach(t => {
    const total = +t.total_items || 0, checked = +t.checked_items || 0;
    const pct = total ? Math.round(checked / total * 100) : 0;
    const card = document.createElement('div');
    card.className = 'trip-card';
    card.innerHTML =
      `<h3>${esc(t.name)}</h3>` +
      (t.destination ? `<p class="dest">📍 ${esc(t.destination)}</p>` : '') +
      (dateRange(t) ? `<div class="dates">${esc(dateRange(t))}</div>` : '') +
      (total
        ? `<div class="mini-progress"><div style="width:${pct}%"></div></div>
           <div class="mini-count">${checked} of ${total} packed (${pct}%)</div>`
        : `<div class="mini-count">No items yet — tap to start packing</div>`);
    card.onclick = () => openTrip(t.id);
    list.appendChild(card);
  });
}

/* ---------------- trip modal (new / edit) ---------------- */
let editingTripId = null;
function openTripModal(trip) {
  editingTripId = trip ? trip.id : null;
  $('trip-modal-title').textContent = trip ? 'Edit trip' : 'New trip';
  $('trip-name').value = trip ? trip.name : '';
  $('trip-destination').value = trip ? (trip.destination || '') : '';
  $('trip-start').value = trip ? (trip.start_date || '') : '';
  $('trip-end').value = trip ? (trip.end_date || '') : '';
  $('trip-notes').value = trip ? (trip.notes || '') : '';
  $('trip-form-error').hidden = true;
  $('trip-modal').hidden = false;
  setTimeout(() => $('trip-name').focus(), 50);
}
function closeTripModal() { $('trip-modal').hidden = true; }
function wireTripModal() {
  $('trip-cancel').onclick = closeTripModal;
  $('trip-modal').addEventListener('click', e => { if (e.target === $('trip-modal')) closeTripModal(); });
  $('trip-form').onsubmit = async e => {
    e.preventDefault();
    const errEl = $('trip-form-error');
    errEl.hidden = true;
    const args = authed({
      p_name: $('trip-name').value,
      p_destination: $('trip-destination').value || null,
      p_start_date: $('trip-start').value || null,
      p_end_date: $('trip-end').value || null,
      p_notes: $('trip-notes').value || null,
    });
    try {
      if (editingTripId) {
        await api('travel_trip_update', Object.assign(args, { p_trip_id: editingTripId }));
        toast('Trip updated.');
      } else {
        const created = await api('travel_trip_create', args);
        toast('Trip created.');
        closeTripModal();
        openTrip(created.id);
        return;
      }
    } catch (err) { showError(errEl, err); return; }
    closeTripModal();
    if (currentTrip && editingTripId === currentTrip.id) {
      currentTrip = trips.find(t => t.id === currentTrip.id) || currentTrip;
      // refresh the header from the saved form values
      currentTrip.name = $('trip-name').value;
      currentTrip.destination = $('trip-destination').value || null;
      currentTrip.start_date = $('trip-start').value || null;
      currentTrip.end_date = $('trip-end').value || null;
      currentTrip.notes = $('trip-notes').value || null;
      renderTripHeader();
    }
    showTrips();
  };
}

/* ---------------- trip detail ---------------- */
async function openTrip(tripId) {
  try {
    trips = await api('travel_trips', authed());
  } catch (e) { toast(e.message || 'Could not load trips.'); return; }
  currentTrip = trips.find(t => t.id === tripId);
  if (!currentTrip) { showTrips(); return; }
  showView('trip-view');
  renderTripHeader();
  await loadItems();
  wireTripDetail();
}
function renderTripHeader() {
  const t = currentTrip;
  $('trip-header').innerHTML =
    `<h2>${esc(t.name)}</h2>` +
    (t.destination ? `<p class="dest">📍 ${esc(t.destination)}</p>` : '') +
    (dateRange(t) ? `<div class="dates">${esc(dateRange(t))}</div>` : '') +
    (t.notes ? `<p class="notes">${esc(t.notes)}</p>` : '');
}
function wireTripDetail() {
  $('back-btn').onclick = () => { currentTrip = null; showTrips(); };
  $('edit-trip-btn').onclick = () => openTripModal(currentTrip);
  $('delete-trip-btn').onclick = async () => {
    const ok = await uiDialog({
      title: 'Delete trip?',
      message: `Delete "${currentTrip.name}" and its whole packing list? This can't be undone.`,
      okText: 'Delete', danger: true,
    });
    if (!ok) return;
    try {
      await api('travel_trip_delete', authed({ p_trip_id: currentTrip.id }));
      toast('Trip deleted.');
      currentTrip = null;
      showTrips();
    } catch (e) { toast(e.message || 'Could not delete trip.'); }
  };
  // category picker
  const sel = $('new-item-category');
  if (!sel.options.length) {
    CATEGORIES.forEach(c => {
      const o = document.createElement('option');
      o.value = c; o.textContent = c;
      sel.appendChild(o);
    });
  }
  $('add-item-form').onsubmit = async e => {
    e.preventDefault();
    const input = $('new-item-label');
    const label = input.value.trim();
    if (!label) return;
    try {
      const added = await api('travel_item_add', authed({
        p_trip_id: currentTrip.id, p_label: label, p_category: sel.value,
      }));
      items.push(added);
      input.value = '';
      input.focus();
      renderItems();
    } catch (err) { toast(err.message || 'Could not add item.'); }
  };
  $('starter-btn').onclick = async () => {
    try {
      const r = await api('travel_seed_starter', authed({ p_trip_id: currentTrip.id }));
      toast(`Added ${r.added} starter items.`);
      await loadItems();
    } catch (e) { toast(e.message || 'Could not add starter list.'); }
  };
}
async function loadItems() {
  try {
    items = await api('travel_items', authed({ p_trip_id: currentTrip.id }));
  } catch (e) { toast(e.message || 'Could not load items.'); items = []; }
  renderItems();
}
function groupOrder(cat) {
  const i = CATEGORIES.indexOf(cat);
  return i === -1 ? CATEGORIES.length : i;
}
function renderItems() {
  const wrap = $('items-list');
  wrap.innerHTML = '';
  $('starter-wrap').hidden = items.length > 0;
  const total = items.length;
  const checked = items.filter(i => i.is_checked).length;
  const pct = total ? Math.round(checked / total * 100) : 0;
  $('progress-fill').style.width = pct + '%';
  $('progress-text').textContent = total
    ? `${checked} of ${total} packed — ${pct}%`
    : 'Nothing on the list yet';
  // group by category, in the canonical order
  const groups = {};
  items.forEach(i => { (groups[i.category] = groups[i.category] || []).push(i); });
  Object.keys(groups)
    .sort((a, b) => groupOrder(a) - groupOrder(b) || a.localeCompare(b))
    .forEach(cat => {
      const g = document.createElement('div');
      g.className = 'cat-group';
      const h = document.createElement('p');
      h.className = 'cat-title';
      h.textContent = cat;
      g.appendChild(h);
      groups[cat].forEach(item => g.appendChild(itemEl(item)));
      wrap.appendChild(g);
    });
  // refresh the trip's counts on the list behind this view
  const t = trips.find(x => x.id === currentTrip.id);
  if (t) { t.total_items = total; t.checked_items = checked; }
}
function itemEl(item) {
  const el = document.createElement('div');
  el.className = 'item' + (item.is_checked ? ' done' : '');
  el.innerHTML =
    `<button class="check" type="button" aria-label="toggle packed">✓</button>
     <div class="item-label">${esc(item.label)}</div>
     <button class="item-del" type="button" aria-label="delete">×</button>`;
  el.querySelector('.check').onclick = async () => {
    try {
      const r = await api('travel_item_toggle', authed({ p_item_id: item.id }));
      item.is_checked = r.is_checked;
      renderItems();
    } catch (e) { toast(e.message || 'Could not update item.'); }
  };
  el.querySelector('.item-label').onclick = async () => {
    const next = await uiDialog({
      title: 'Edit item',
      okText: 'Save', danger: false,
      input: true, inputValue: item.label, inputPlaceholder: 'Item name',
    });
    if (next === null) return;
    const label = next.trim();
    if (!label || label === item.label) return;
    try {
      const r = await api('travel_item_update', authed({ p_item_id: item.id, p_label: label }));
      item.label = r.label;
      renderItems();
    } catch (e) { toast(e.message || 'Could not update item.'); }
  };
  el.querySelector('.item-del').onclick = async () => {
    const ok = await uiDialog({
      title: 'Remove item?',
      message: `Remove "${item.label}" from the packing list?`,
      okText: 'Remove', danger: true,
    });
    if (!ok) return;
    try {
      await api('travel_item_delete', authed({ p_item_id: item.id }));
      items = items.filter(i => i.id !== item.id);
      renderItems();
    } catch (e) { toast(e.message || 'Could not delete item.'); }
  };
  return el;
}

document.addEventListener('DOMContentLoaded', () => {
  wireTripModal();
  boot();
});
