/* Cofre — gerenciador de senhas 100% offline.
 * Criptografia: PBKDF2-SHA256 (600 mil iterações) -> chave AES-256-GCM.
 * O cofre inteiro fica cifrado no IndexedDB deste aparelho. Nenhum dado é enviado.
 */
'use strict';

const APP_VERSION = '1.1.1';
const PBKDF2_ITER = 600000;
const AAD = new TextEncoder().encode('cofre-offline-v1');
const enc = new TextEncoder();
const dec = new TextDecoder();
const DEFAULT_SETTINGS = { lockSec: 60, idleMin: 5, clipSec: 45, lastBackup: 0, sort: 'name' };
const CATEGORIES = ['Pessoal', 'Trabalho', 'Banco e finanças', 'E-mail', 'Redes sociais', 'Compras', 'Streaming', 'Governo', 'Saúde', 'Outros'];
const HISTORY_MAX = 10;
const OLD_DAYS = 365;

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

/* ================= utilidades ================= */
const b64 = {
  enc(buf) {
    const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
    return btoa(s);
  },
  dec(str) { return Uint8Array.from(atob(str), c => c.charCodeAt(0)); }
};
const norm = s => (s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
const uid = () => (crypto.randomUUID ? crypto.randomUUID() : b64.enc(crypto.getRandomValues(new Uint8Array(16))).replace(/[+/=]/g, ''));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const fmtDate = t => t ? new Date(t).toLocaleDateString('pt-BR', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';
const fmtDateTime = t => t ? new Date(t).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' }) : '—';
function ago(t) {
  if (!t) return 'nunca';
  const d = Math.floor((Date.now() - t) / 86400000);
  if (d <= 0) return 'hoje';
  if (d === 1) return 'ontem';
  if (d < 30) return `há ${d} dias`;
  if (d < 365) return `há ${Math.floor(d / 30)} ${Math.floor(d / 30) === 1 ? 'mês' : 'meses'}`;
  const y = Math.floor(d / 365); return `há ${y} ${y === 1 ? 'ano' : 'anos'}`;
}
const plural = (n, a, b) => `${n} ${n === 1 ? a : b}`;

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids) if (k != null && k !== false) e.append(k);
  return e;
}
function icon(name, cls) {
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  if (cls) s.setAttribute('class', cls);
  const u = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  u.setAttribute('href', '#i-' + name);
  s.append(u);
  return s;
}
function iconBtn(name, label, onclick, cls = '') {
  return el('button', { class: 'icon-btn ' + cls, 'aria-label': label, title: label, type: 'button', onclick }, icon(name));
}
const store = {
  get(k) { try { return localStorage.getItem(k); } catch (_) { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch (_) {} }
};

/* ================= IndexedDB ================= */
const DB = {
  _db: null,
  open() {
    if (this._db) return Promise.resolve(this._db);
    return new Promise((res, rej) => {
      const r = indexedDB.open('cofre-offline', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('kv');
      r.onsuccess = () => { this._db = r.result; res(r.result); };
      r.onerror = () => rej(r.error);
    });
  },
  async run(mode, fn) {
    const db = await this.open();
    return new Promise((res, rej) => {
      const tx = db.transaction('kv', mode);
      const req = fn(tx.objectStore('kv'));
      tx.oncomplete = () => res(req && req.result);
      tx.onerror = () => rej(tx.error);
      tx.onabort = () => rej(tx.error);
    });
  },
  get(k) { return this.run('readonly', s => s.get(k)); },
  set(k, v) { return this.run('readwrite', s => s.put(v, k)); },
  del(k) { return this.run('readwrite', s => s.delete(k)); }
};

/* ================= criptografia ================= */
async function deriveKey(password, salt, iter) {
  const base = await crypto.subtle.importKey('raw', enc.encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encryptObj(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD }, key, enc.encode(JSON.stringify(obj)));
  return { iv: b64.enc(iv), ct: b64.enc(ct) };
}
async function decryptObj(key, iv, ct) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(iv), additionalData: AAD }, key, b64.dec(ct));
  return JSON.parse(dec.decode(pt));
}
function isVaultRecord(o) {
  return o && typeof o === 'object' && (o.format === 'cofre-offline' || o.format === 'cofre-offline-backup')
    && o.salt && o.iv && o.ct && Number(o.iter) > 0;
}
async function openRecord(rec, password) {
  const salt = b64.dec(rec.salt);
  const key = await deriveKey(password, salt, Number(rec.iter));
  const data = await decryptObj(key, rec.iv, rec.ct);
  return { key, salt, iter: Number(rec.iter), data };
}

/* ================= força da senha ================= */
const COMMON = new Set(['123456', '1234567', '12345678', '123456789', '1234567890', '12345', '1234', '111111', '000000', '123123', '654321',
  '102030', '112233', 'password', 'senha', 'senha123', 'senha1234', 'mudar123', 'qwerty', 'abc123', 'admin', 'iloveyou', 'brasil',
  'flamengo', 'corinthians', 'palmeiras', 'gremio', 'vasco', 'sapo', 'teste', 'teste123', 'master', 'dragon', 'welcome', '123mudar']);
const STRENGTH_LABEL = ['Muito fraca', 'Fraca', 'Razoável', 'Forte', 'Muito forte'];
function strength(pw) {
  if (!pw) return -1;
  const low = pw.toLowerCase();
  if (COMMON.has(low) || COMMON.has(low.replace(/\d+$/, ''))) return 0;
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  let eff = pw.length;
  for (const m of pw.match(/(.)\1{2,}/g) || []) eff -= m.length - 1;
  const seqs = ['0123456789', 'abcdefghijklmnopqrstuvwxyz', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];
  for (const sq of seqs) for (let i = 0; i + 4 <= sq.length; i++) if (low.includes(sq.slice(i, i + 4))) { eff -= 2; break; }
  if (/^(19|20)\d{2}$|\d{2}\/?\d{2}\/?(19|20)?\d{2}/.test(pw)) eff -= 2;
  const bits = Math.max(0, eff) * Math.log2(Math.max(pool, 2));
  return bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
}
const isPin = pw => /^\d{4,8}$/.test(pw || '');
function paintMeter(meterEl, textEl, pw, emptyText = '') {
  const s = strength(pw);
  meterEl.dataset.s = s < 0 ? '' : String(s);
  if (textEl) textEl.textContent = s < 0 ? emptyText : (isPin(pw) ? 'PIN numérico' : STRENGTH_LABEL[s]);
}

/* ================= 2FA (TOTP) ================= */
function base32Decode(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  s = s.toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0, val = 0; const out = [];
  for (const c of s) {
    const i = A.indexOf(c);
    if (i < 0) throw new Error('chave inválida');
    val = (val << 5) | i; bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
function parseTotp(str) {
  str = (str || '').trim();
  if (!str) return null;
  let secret = str, digits = 6, period = 30, algo = 'SHA-1';
  if (/^otpauth:/i.test(str)) {
    const u = new URL(str);
    secret = u.searchParams.get('secret') || '';
    digits = parseInt(u.searchParams.get('digits'), 10) || 6;
    period = parseInt(u.searchParams.get('period'), 10) || 30;
    const a = (u.searchParams.get('algorithm') || 'SHA1').toUpperCase().replace('-', '');
    algo = a === 'SHA256' ? 'SHA-256' : a === 'SHA512' ? 'SHA-512' : 'SHA-1';
  }
  const key = base32Decode(secret);
  if (key.length < 10) throw new Error('chave curta demais');
  if (digits < 6 || digits > 8) digits = 6;
  return { key, digits, period, algo };
}
const totpKeyCache = new Map();
async function totpCode(cfg, t = Date.now()) {
  const counter = Math.floor(t / 1000 / cfg.period);
  const buf = new ArrayBuffer(8), dv = new DataView(buf);
  dv.setUint32(0, Math.floor(counter / 0x100000000));
  dv.setUint32(4, counter >>> 0);
  const ck = b64.enc(cfg.key) + cfg.algo;
  let k = totpKeyCache.get(ck);
  if (!k) { k = await crypto.subtle.importKey('raw', cfg.key, { name: 'HMAC', hash: cfg.algo }, false, ['sign']); totpKeyCache.set(ck, k); }
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', k, buf));
  const o = h[h.length - 1] & 15;
  const bin = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(bin % 10 ** cfg.digits).padStart(cfg.digits, '0');
}

/* ================= estado ================= */
const S = { key: null, salt: null, iter: PBKDF2_ITER, data: null, record: null, currentId: null, editingId: null, tab: 'vault', filter: 'all' };

function normalizeEntry(e) {
  e.name = String(e.name || '').trim() || 'Sem nome';
  for (const f of ['username', 'password', 'url', 'notes', 'category', 'totp']) e[f] = e[f] == null ? '' : String(e[f]);
  e.fav = !!e.fav;
  e.history = Array.isArray(e.history) ? e.history.filter(h => h && h.password) : [];
  e.createdAt = e.createdAt || Date.now();
  e.updatedAt = e.updatedAt || e.createdAt;
  e.pwChangedAt = e.pwChangedAt || e.createdAt;
  return e;
}
function normalizeData(d) {
  d = d && typeof d === 'object' ? d : {};
  d.entries = (Array.isArray(d.entries) ? d.entries : []).filter(e => e && e.id).map(normalizeEntry);
  d.deleted = Array.isArray(d.deleted) ? d.deleted.filter(t => t && t.id) : [];
  d.settings = Object.assign({}, DEFAULT_SETTINGS, d.settings || {});
  return d;
}
async function persist() {
  const { iv, ct } = await encryptObj(S.key, S.data);
  const rec = { format: 'cofre-offline', v: 2, kdf: 'PBKDF2-SHA256', iter: S.iter, salt: b64.enc(S.salt), iv, ct };
  await DB.set('vault', rec);
  S.record = rec;
}
const findEntry = id => S.data && S.data.entries.find(x => x.id === id);

/* ================= tema ================= */
function applyTheme() {
  const pref = store.get('cofre-theme') || 'auto';
  const dark = pref === 'dark' || (pref === 'auto' && matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  const meta = document.querySelector('meta[name=theme-color]');
  if (meta) meta.content = dark ? '#0b1120' : '#f4f6fa';
}
matchMedia('(prefers-color-scheme: dark)').addEventListener?.('change', applyTheme);

/* ================= UI básica ================= */
function showView(name) {
  for (const v of ['setup', 'unlock', 'main']) $('#view-' + v).hidden = v !== name;
}
let toastTimer;
function toast(msg, { ms = 2600, action = null, onAction = null } = {}) {
  const t = $('#toast');
  $('#toast-text').textContent = msg;
  const a = $('#toast-action');
  a.hidden = !action;
  a.textContent = action || '';
  a.onclick = () => { t.hidden = true; clearTimeout(toastTimer); onAction && onAction(); };
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, ms);
}
function busy(on, text = 'Processando…') {
  $('#busy-text').textContent = text;
  $('#busy').hidden = !on;
}

/* Folhas com suporte ao botão Voltar do Android */
const sheetStack = [];
let ignorePop = 0;
function openSheet(id) {
  const s = $('#' + id);
  s.hidden = false; s.scrollTop = 0;
  sheetStack.push(id);
  history.pushState({ sheet: id }, '');
}
function closeTopSheet(fromPop = false) {
  const id = sheetStack.pop();
  if (!id) return;
  $('#' + id).hidden = true;
  if (id === 'sheet-detail') stopTotp();
  if (!fromPop) { ignorePop++; history.back(); }
}
function closeAllSheets() {
  while (sheetStack.length) $('#' + sheetStack.pop()).hidden = true;
  stopTotp();
}
window.addEventListener('popstate', () => {
  if (ignorePop > 0) { ignorePop--; return; }
  if (!$('#big').hidden) { $('#big').hidden = true; history.pushState({}, ''); return; }
  if (!$('#modal').hidden) {
    modalResolve && modalResolve(null);
    if (sheetStack.length) history.pushState({ sheet: sheetStack[sheetStack.length - 1] }, '');
    return;
  }
  if (sheetStack.length) closeTopSheet(true);
});
document.addEventListener('click', e => {
  if (e.target.closest('[data-close]')) closeTopSheet();
  const tg = e.target.closest('[data-toggle-pw]');
  if (tg) {
    const inp = $('#' + tg.dataset.togglePw);
    const show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    tg.querySelector('use').setAttribute('href', show ? '#i-eye-off' : '#i-eye');
  }
});

/* Modal genérico */
let modalResolve = null;
function askFields({ title, text = '', fields = [], okText = 'OK', cancelText = 'Cancelar', validate, danger = false, html = null }) {
  return new Promise(resolve => {
    $('#m-title').textContent = title;
    $('#m-text').textContent = text;
    $('#m-text').hidden = !text;
    $('#m-msg').textContent = '';
    const ok = $('#m-ok'), cancel = $('#m-cancel');
    ok.textContent = okText;
    ok.className = 'btn ' + (danger ? 'primary danger-solid' : 'primary');
    cancel.hidden = cancelText === null;
    cancel.textContent = cancelText || '';
    const box = $('#m-inputs'); box.replaceChildren();
    if (html) box.append(html);
    const inputs = fields.map((f, i) => {
      const inp = el('input', { type: f.type || 'password', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', id: 'm-in-' + i, placeholder: f.placeholder || '' });
      box.append(el('div', { class: 'field-group' }, el('label', { for: 'm-in-' + i, text: f.label }), inp));
      return inp;
    });
    $('#modal').hidden = false;
    setTimeout(() => inputs[0] && inputs[0].focus(), 60);
    const finish = val => {
      $('#modal').hidden = true;
      ok.onclick = cancel.onclick = null;
      box.onkeydown = null; modalResolve = null;
      resolve(val);
    };
    modalResolve = finish;
    cancel.onclick = () => finish(null);
    ok.onclick = async () => {
      const vals = inputs.map(i => i.value);
      if (validate) {
        const err = await validate(vals);
        if (err) { $('#m-msg').textContent = err; return; }
      }
      finish(vals);
    };
    box.onkeydown = e => { if (e.key === 'Enter') ok.click(); };
  });
}
const confirmBox = (title, text, okText = 'Confirmar', danger = false) =>
  askFields({ title, text, okText, danger }).then(v => v !== null);
const infoBox = (title, text, html = null) => askFields({ title, text, okText: 'Entendi', cancelText: null, html });

/* ================= criar / desbloquear / bloquear ================= */
async function createVault() {
  const pw = $('#setup-pw').value, pw2 = $('#setup-pw2').value;
  const msg = $('#setup-msg');
  if (pw.length < 8) { msg.textContent = 'A senha mestra precisa ter pelo menos 8 caracteres.'; return; }
  if (strength(pw) < 2) { msg.textContent = 'Senha mestra muito fraca. Use mais caracteres ou uma frase com várias palavras.'; return; }
  if (pw !== pw2) { msg.textContent = 'As senhas não conferem.'; return; }
  if (!$('#setup-ack').checked) { msg.textContent = 'Confirme que entendeu o aviso sobre a senha mestra.'; return; }
  msg.textContent = '';
  busy(true, 'Criando cofre…');
  try {
    S.salt = crypto.getRandomValues(new Uint8Array(16));
    S.iter = PBKDF2_ITER;
    S.key = await deriveKey(pw, S.salt, S.iter);
    S.data = normalizeData({});
    await persist();
    requestPersistentStorage();
    $('#setup-pw').value = $('#setup-pw2').value = '';
    enterMain();
  } catch (e) {
    msg.textContent = 'Erro ao criar o cofre: ' + e.message;
  } finally { busy(false); }
}

let failCount = 0;
async function unlock() {
  const pw = $('#unlock-pw').value;
  const msg = $('#unlock-msg');
  if (!pw) return;
  busy(true, 'Desbloqueando…');
  try {
    const rec = await DB.get('vault');
    if (!rec) { location.reload(); return; }
    const r = await openRecord(rec, pw);
    Object.assign(S, { key: r.key, salt: r.salt, iter: r.iter, data: normalizeData(r.data), record: rec });
    failCount = 0;
    $('#unlock-pw').value = ''; msg.textContent = '';
    enterMain();
  } catch (e) {
    failCount++;
    msg.textContent = failCount >= 3 ? `Senha incorreta (${failCount} tentativas).` : 'Senha incorreta.';
    $('#unlock-pw').select();
    await sleep(Math.min(600 * failCount, 6000));
  } finally { busy(false); }
}

function lock() {
  S.key = null; S.data = null; S.currentId = null; S.editingId = null;
  closeAllSheets();
  $('#modal').hidden = true; $('#big').hidden = true;
  $('#list').replaceChildren(); $('#d-fields').replaceChildren(); $('#health-groups').replaceChildren();
  for (const id of ['#search', '#e-name', '#e-user', '#e-pass', '#e-url', '#e-notes', '#e-totp']) $(id).value = '';
  $('#gen-out').textContent = '';
  clearTimeout(idleTimer);
  showView('unlock');
  setTimeout(() => $('#unlock-pw').focus(), 100);
}

function enterMain() {
  showView('main');
  switchTab('vault');
  resetIdle();
}

/* Bloqueio automático */
let hiddenAt = null, idleTimer = null, hiddenTimer = null;
function resetIdle() {
  clearTimeout(idleTimer);
  if (!S.key) return;
  idleTimer = setTimeout(lock, S.data.settings.idleMin * 60000);
}
for (const ev of ['pointerdown', 'keydown', 'scroll']) document.addEventListener(ev, resetIdle, { passive: true, capture: true });
document.addEventListener('visibilitychange', () => {
  if (!S.key) return;
  const lockSec = S.data.settings.lockSec;
  if (document.hidden) {
    hiddenAt = Date.now();
    if (lockSec === 0) { lock(); return; }
    clearTimeout(hiddenTimer);
    hiddenTimer = setTimeout(() => { if (document.hidden) lock(); }, lockSec * 1000);
  } else {
    clearTimeout(hiddenTimer);
    if (hiddenAt && Date.now() - hiddenAt >= lockSec * 1000) lock();
    hiddenAt = null;
  }
});
window.addEventListener('pagehide', () => { if (S.key && S.data.settings.lockSec === 0) lock(); });

/* ================= navegação por abas ================= */
function switchTab(tab) {
  S.tab = tab;
  for (const t of ['vault', 'health', 'settings']) $('#tab-' + t).hidden = t !== tab;
  for (const b of $$('.nav-item[data-tab]')) b.classList.toggle('active', b.dataset.tab === tab);
  $('#btn-add').hidden = tab !== 'vault';
  if (tab === 'vault') renderList();
  if (tab === 'health') renderHealth();
  if (tab === 'settings') renderSettings();
  updateHealthBadge();
  window.scrollTo(0, 0);
}

/* ================= lista ================= */
const COLORS = ['#0e9f8e', '#2563eb', '#7c3aed', '#db2777', '#ea580c', '#16a34a', '#0891b2', '#9333ea', '#c2410c', '#4f46e5', '#be123c', '#0369a1'];
function colorFor(s) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) >>> 0; return COLORS[h % COLORS.length]; }
function avatar(name, cls = '') {
  const clean = name.trim().replace(/^(www\.|https?:\/\/)/i, '');
  const a = el('span', { class: 'avatar ' + cls, text: (clean[0] || '?').toUpperCase() });
  a.style.background = `linear-gradient(145deg, ${colorFor(norm(name))}, ${colorFor(norm(name) + 'x')})`;
  return a;
}
function sortEntries(arr) {
  const by = S.data.settings.sort;
  return arr.slice().sort(by === 'recent'
    ? (a, b) => (b.lastUsed || b.updatedAt || 0) - (a.lastUsed || a.updatedAt || 0)
    : (a, b) => a.name.localeCompare(b.name, 'pt-BR', { sensitivity: 'base' }));
}
function itemRow(e, sub) {
  return el('div', { class: 'item' },
    el('button', { class: 'item-main', type: 'button', onclick: () => openDetail(e.id) },
      avatar(e.name),
      el('span', { class: 'item-text' },
        el('span', { class: 'item-name' }, el('span', { text: e.name }), e.fav ? icon('star') : null, e.totp ? el('span', { class: 'tag-2fa', text: '2FA' }) : null),
        el('span', { class: 'item-user', text: sub || e.username || hostOf(e.url) || e.category || '—' }))),
    e.password ? iconBtn('copy', 'Copiar senha de ' + e.name, () => copyText(e.password, 'Senha', e.id)) : null);
}
function hostOf(url) {
  if (!url) return '';
  try { return new URL(/^[a-z][\w+.-]*:/i.test(url) ? url : 'https://' + url).hostname.replace(/^www\./, ''); } catch (_) { return url; }
}

function renderChips() {
  const counts = {};
  for (const e of S.data.entries) if (e.category) counts[e.category] = (counts[e.category] || 0) + 1;
  const favs = S.data.entries.filter(e => e.fav).length;
  const defs = [['all', 'Todas', S.data.entries.length]];
  if (favs) defs.push(['fav', 'Favoritas', favs]);
  for (const c of CATEGORIES) if (counts[c]) defs.push(['cat:' + c, c, counts[c]]);
  if (!defs.some(d => d[0] === S.filter)) S.filter = 'all';
  const box = $('#chips');
  box.hidden = S.data.entries.length === 0;
  box.replaceChildren(...defs.map(([k, label, n]) => el('button', {
    class: 'chip' + (S.filter === k ? ' on' : ''), type: 'button',
    onclick: () => { S.filter = k; renderList(); }
  }, k === 'fav' ? icon('star') : null, label, el('small', { text: String(n) }))));
}

function renderList() {
  if (!S.data) return;
  renderChips();
  const q = norm($('#search').value.trim());
  const all = S.data.entries;
  let items = all.filter(e => {
    if (S.filter === 'fav' && !e.fav) return false;
    if (S.filter.startsWith('cat:') && e.category !== S.filter.slice(4)) return false;
    return !q || norm([e.name, e.username, e.url, e.category, e.notes].join(' ')).includes(q);
  });
  items = sortEntries(items);
  const list = $('#list');
  list.replaceChildren();
  if (items.length) {
    const showFavSection = S.filter === 'all' && !q && S.data.settings.sort === 'name' && items.some(e => e.fav) && items.length > 4;
    if (showFavSection) {
      list.append(el('div', { class: 'list-section', text: 'Favoritas' }), el('div', { class: 'list-card' }, ...items.filter(e => e.fav).map(e => itemRow(e))));
      list.append(el('div', { class: 'list-section', text: 'Todas' }));
    } else if (S.data.settings.sort === 'recent' && !q) {
      list.append(el('div', { class: 'list-section', text: 'Usadas recentemente' }));
    }
    list.append(el('div', { class: 'list-card' }, ...items.map(e => itemRow(e))));
  }
  $('#vault-sub').textContent = all.length ? plural(all.length, 'senha guardada', 'senhas guardadas') + ' neste aparelho' : 'Guardadas só neste aparelho';
  const empty = $('#empty');
  empty.hidden = items.length > 0;
  if (!items.length) {
    const none = all.length === 0;
    $('#empty-title').textContent = none ? 'Seu cofre está vazio' : 'Nada encontrado';
    $('#empty-text').textContent = none
      ? 'Adicione sua primeira senha ou traga as que estão salvas no Google.'
      : 'Tente buscar por outro nome, usuário ou site.';
    $('#empty-btn').hidden = !none;
    $('#empty-import').hidden = !none;
  }
  renderNotice();
  updateHealthBadge();
}

/* Aviso no topo da lista: backup pendente ou instalação */
function renderNotice() {
  const n = $('#notice'), st = S.data.settings, count = S.data.entries.length;
  const changed = S.data.entries.some(e => (e.updatedAt || 0) > (st.lastBackup || 0)) || (S.data.deleted || []).some(t => t.at > (st.lastBackup || 0));
  const old = !st.lastBackup || Date.now() - st.lastBackup > 14 * 86400000;
  if (count > 0 && changed && old) {
    n.hidden = false;
    $('#notice-text').textContent = st.lastBackup ? `Último backup ${ago(st.lastBackup)}. Há alterações sem backup.` : 'Você ainda não fez backup. Se perder o celular, perde as senhas.';
    $('#notice-btn').textContent = 'Fazer backup';
    $('#notice-btn').onclick = exportBackup;
    return;
  }
  if (!isStandalone() && store.get('cofre-install-dismissed') !== '1') {
    n.hidden = false;
    $('#notice-text').textContent = 'Instale o Cofre na tela inicial para usar em tela cheia e sem internet.';
    $('#notice-btn').textContent = 'Instalar';
    $('#notice-btn').onclick = () => { store.set('cofre-install-dismissed', '1'); installApp(); renderNotice(); };
    return;
  }
  n.hidden = true;
}

/* ================= copiar ================= */
let clipTimer;
async function copyText(text, label, entryId) {
  let ok = false;
  try { await navigator.clipboard.writeText(text); ok = true; } catch (_) {
    const ta = el('textarea', { readonly: true });
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.append(ta); ta.select(); ta.setSelectionRange(0, text.length);
    try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
    ta.remove();
  }
  if (!ok) { toast('Não foi possível copiar. Toque e segure no texto para copiar.'); return; }
  const sec = S.data ? S.data.settings.clipSec : 0;
  toast(sec ? `${label} copiado · será apagado em ${sec}s` : `${label} copiado`);
  clearTimeout(clipTimer);
  if (sec) clipTimer = setTimeout(() => { navigator.clipboard && navigator.clipboard.writeText('').catch(() => {}); }, sec * 1000);
  const e = entryId && findEntry(entryId);
  if (e) { e.lastUsed = Date.now(); persist().catch(() => {}); }
}

/* ================= senha em tela grande ================= */
function showBig(pw) {
  const box = $('#big-chars');
  box.replaceChildren(...[...pw].map((c, i) => el('span', { class: /\d/.test(c) ? 'd' : /[a-zA-Z]/.test(c) ? '' : 's' }, c === ' ' ? '␣' : c, el('small', { text: String(i + 1) }))));
  $('#big').hidden = false;
  history.pushState({ big: 1 }, '');
}
function closeBig() { if ($('#big').hidden) return; $('#big').hidden = true; ignorePop++; history.back(); }

/* ================= detalhe ================= */
let totpTimer = null;
function stopTotp() { clearInterval(totpTimer); totpTimer = null; }

function secretValue(value, startShown = false) {
  const v = el('div', { class: 'f-value mono' });
  let shown = startShown;
  const paint = () => { v.textContent = shown ? value : '•'.repeat(Math.min(Math.max(value.length, 8), 16)); };
  paint();
  return { node: v, toggle: (btn) => { shown = !shown; paint(); btn.querySelector('use').setAttribute('href', shown ? '#i-eye-off' : '#i-eye'); } };
}
function row(labelNode, valueNode, ...actions) {
  return el('div', { class: 'f-row' }, el('div', { class: 'f-body' }, labelNode, valueNode), ...actions);
}
function lbl(text, extra) { return el('div', { class: 'f-label' }, text, extra || null); }

function safeLink(url) {
  if (!url) return null;
  let u = url.trim();
  if (!/^[a-z][a-z0-9+.-]*:/i.test(u)) u = 'https://' + u;
  try { const p = new URL(u); return (p.protocol === 'https:' || p.protocol === 'http:') ? p.href : null; } catch (_) { return null; }
}

function openDetail(id, push = true) {
  const e = findEntry(id);
  if (!e) return;
  S.currentId = id;
  stopTotp();
  $('#d-avatar').replaceWith(Object.assign(avatar(e.name, 'xl'), { id: 'd-avatar' }));
  $('#d-name').textContent = e.name;
  $('#d-cat').textContent = [e.category, hostOf(e.url)].filter(Boolean).join(' · ');
  const fav = $('#btn-fav');
  fav.classList.toggle('on', e.fav);
  fav.setAttribute('aria-label', e.fav ? 'Remover dos favoritos' : 'Favoritar');

  const f = $('#d-fields'); f.replaceChildren();
  if (e.username) f.append(row(lbl('Usuário'), el('div', { class: 'f-value', text: e.username }),
    iconBtn('copy', 'Copiar usuário', () => copyText(e.username, 'Usuário', id))));
  if (e.password) {
    const s = strength(e.password);
    const sv = secretValue(e.password);
    const eye = iconBtn('eye', 'Mostrar senha', () => sv.toggle(eye));
    f.append(row(lbl('Senha', isPin(e.password) ? el('span', { class: 'strength-pill', 'data-s': '3', text: 'PIN' }) : el('span', { class: 'strength-pill', 'data-s': String(s), text: STRENGTH_LABEL[s] })),
      sv.node, eye, iconBtn('expand', 'Mostrar em tela grande', () => showBig(e.password)), iconBtn('copy', 'Copiar senha', () => copyText(e.password, 'Senha', id))));
  }
  if (e.totp) {
    let cfg = null;
    try { cfg = parseTotp(e.totp); } catch (_) {}
    if (cfg) {
      const val = el('div', { class: 'f-value totp mono', text: '······' });
      const ring = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      ring.setAttribute('viewBox', '0 0 26 26'); ring.setAttribute('class', 'totp-ring');
      ring.innerHTML = '<circle class="bg" cx="13" cy="13" r="10"/><circle class="fg" cx="13" cy="13" r="10" stroke-dasharray="62.83"/>';
      const fg = ring.querySelector('.fg');
      let code = '';
      const tick = async () => {
        const now = Date.now();
        code = await totpCode(cfg, now);
        val.textContent = code.length === 6 ? code.slice(0, 3) + ' ' + code.slice(3) : code;
        const left = cfg.period - Math.floor(now / 1000) % cfg.period;
        fg.setAttribute('stroke-dashoffset', String(62.83 * (1 - left / cfg.period)));
        ring.classList.toggle('low', left <= 5);
      };
      tick(); totpTimer = setInterval(tick, 1000);
      f.append(row(lbl('Código de verificação (2FA)'), val, ring, iconBtn('copy', 'Copiar código', () => copyText(code, 'Código', id))));
    }
  }
  if (e.url) {
    const link = safeLink(e.url);
    f.append(row(lbl('Site ou app'), el('div', { class: 'f-value', text: e.url }),
      link ? el('a', { class: 'icon-btn', href: link, target: '_blank', rel: 'noopener noreferrer', 'aria-label': 'Abrir site', title: 'Abrir site' }, icon('external')) : null,
      iconBtn('copy', 'Copiar endereço', () => copyText(e.url, 'Endereço', id))));
  }
  if (e.notes) f.append(row(lbl('Observações'), el('div', { class: 'f-value notes', text: e.notes }),
    iconBtn('copy', 'Copiar observações', () => copyText(e.notes, 'Observações', id))));
  if (!f.children.length) f.append(el('div', { class: 'f-row' }, el('span', { class: 'muted', text: 'Nenhum dado. Toque em editar para preencher.' })));

  const h = $('#d-history');
  h.replaceChildren();
  h.hidden = !e.history.length;
  if (e.history.length) {
    const det = el('details', {}, el('summary', {}, icon('history'), `Senhas anteriores (${e.history.length})`));
    det.append(el('div', { class: 'card-list' }, ...e.history.map(item => {
      const sv = secretValue(item.password);
      const eye = iconBtn('eye', 'Mostrar', () => sv.toggle(eye));
      return row(lbl('Usada até ' + fmtDate(item.until)), sv.node, eye, iconBtn('copy', 'Copiar', () => copyText(item.password, 'Senha antiga')));
    })));
    h.append(det);
  }
  $('#d-meta').textContent = `Criada em ${fmtDate(e.createdAt)} · Senha alterada ${ago(e.pwChangedAt)}` + (e.lastUsed ? ` · Usada ${ago(e.lastUsed)}` : '');
  if (push) openSheet('sheet-detail');
}

async function toggleFav() {
  const e = findEntry(S.currentId);
  if (!e) return;
  e.fav = !e.fav; e.updatedAt = Date.now();
  await persist();
  openDetail(e.id, false);
  renderList();
  toast(e.fav ? 'Adicionada aos favoritos' : 'Removida dos favoritos');
}

/* ================= editar ================= */
function fillCategorySelect(value) {
  const sel = $('#e-cat');
  sel.replaceChildren(el('option', { value: '', text: 'Sem categoria' }), ...CATEGORIES.map(c => el('option', { value: c, text: c })));
  sel.value = value || '';
}
function openEdit(id = null) {
  S.editingId = id;
  const e = id ? findEntry(id) : null;
  $('#e-title').textContent = e ? 'Editar' : 'Nova senha';
  $('#e-name').value = e ? e.name : '';
  $('#e-user').value = e ? e.username : '';
  $('#e-pass').value = e ? e.password : '';
  $('#e-url').value = e ? e.url : '';
  $('#e-notes').value = e ? e.notes : '';
  $('#e-totp').value = e ? e.totp : '';
  $('#e-fav').checked = e ? e.fav : false;
  fillCategorySelect(e ? e.category : (S.filter.startsWith('cat:') ? S.filter.slice(4) : ''));
  $('#e-pass').type = 'password';
  $('[data-toggle-pw="e-pass"] use').setAttribute('href', '#i-eye');
  $('#e-msg').textContent = '';
  $('#gen').hidden = true;
  paintMeter($('#e-meter'), $('#e-meter-text'), $('#e-pass').value);
  openSheet('sheet-edit');
  if (!e) setTimeout(() => $('#e-name').focus(), 80);
}
async function saveEdit() {
  const name = $('#e-name').value.trim();
  const msg = $('#e-msg');
  if (!name) { msg.textContent = 'Informe o nome do app ou site.'; $('#e-name').focus(); return; }
  let totp = $('#e-totp').value.trim();
  if (!/^otpauth:/i.test(totp)) totp = totp.replace(/[\s-]+/g, '').toUpperCase();
  if (totp) { try { parseTotp(totp); } catch (_) { msg.textContent = 'A chave de 2 etapas não é válida. Cole a chave em texto (letras e números) ou o link otpauth://.'; return; } }
  const now = Date.now();
  const vals = {
    name, username: $('#e-user').value.trim(), password: $('#e-pass').value, url: $('#e-url').value.trim(),
    notes: $('#e-notes').value, category: $('#e-cat').value, totp, fav: $('#e-fav').checked
  };
  // Aviso de senha repetida
  if (vals.password && !isPin(vals.password)) {
    const dup = S.data.entries.filter(x => x.id !== S.editingId && x.password === vals.password);
    if (dup.length) {
      const go = await confirmBox('Senha repetida', `Esta senha já é usada em: ${dup.slice(0, 3).map(d => d.name).join(', ')}${dup.length > 3 ? '…' : ''}. Usar a mesma senha em vários lugares é arriscado. Salvar mesmo assim?`, 'Salvar mesmo assim');
      if (!go) return;
    }
  }
  let id = S.editingId;
  if (id) {
    const e = findEntry(id);
    if (e.password && e.password !== vals.password) {
      e.history.unshift({ password: e.password, until: now });
      e.history = e.history.slice(0, HISTORY_MAX);
      e.pwChangedAt = now;
    }
    Object.assign(e, vals, { updatedAt: now });
  } else {
    id = uid();
    S.data.entries.push(normalizeEntry(Object.assign({ id, createdAt: now, updatedAt: now, pwChangedAt: now }, vals)));
  }
  try { await persist(); } catch (err) { msg.textContent = 'Erro ao salvar: ' + err.message; return; }
  const wasEditing = !!S.editingId;
  S.editingId = null;
  closeTopSheet();
  renderList();
  if (wasEditing) openDetail(id, false);
  else toast('Senha salva');
}

async function deleteCurrent() {
  const e = findEntry(S.currentId);
  if (!e) return;
  if (!await confirmBox('Excluir senha', `"${e.name}" será removida deste aparelho.`, 'Excluir', true)) return;
  const idx = S.data.entries.indexOf(e);
  S.data.entries.splice(idx, 1);
  const tomb = { id: e.id, at: Date.now() };
  S.data.deleted.push(tomb);
  await persist();
  closeTopSheet();
  renderList();
  toast(`"${e.name}" excluída`, {
    ms: 7000, action: 'Desfazer', onAction: async () => {
      if (!S.data) return;
      S.data.entries.push(e);
      S.data.deleted = S.data.deleted.filter(t => t !== tomb);
      e.updatedAt = Date.now();
      await persist();
      renderList();
      toast('Senha restaurada');
    }
  });
}

/* ================= gerador ================= */
const POOLS = { upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', lower: 'abcdefghijklmnopqrstuvwxyz', digits: '0123456789', symbols: '!@#$%&*()-_=+[]{};:,.?/' };
const AMBIG = /[Il1O0o|]/g;
function randInt(n) {
  const max = Math.floor(0x100000000 / n) * n, a = new Uint32Array(1);
  do crypto.getRandomValues(a); while (a[0] >= max);
  return a[0] % n;
}
function genPassword(len, opts) {
  let pools = Object.keys(POOLS).filter(k => opts[k]).map(k => POOLS[k]);
  if (!pools.length) pools = [POOLS.lower];
  if (opts.noAmbig) pools = pools.map(p => p.replace(AMBIG, ''));
  const all = pools.join('');
  const out = pools.map(p => p[randInt(p.length)]);
  while (out.length < len) out.push(all[randInt(all.length)]);
  for (let i = out.length - 1; i > 0; i--) { const j = randInt(i + 1); [out[i], out[j]] = [out[j], out[i]]; }
  return out.join('').slice(0, len);
}
let genMode = 'chars';
function setGenMode(mode) {
  genMode = mode;
  for (const b of $$('#gen-mode button')) b.classList.toggle('on', b.dataset.mode === mode);
  $('#gen-opts').hidden = mode === 'pin';
  const r = $('#gen-len');
  if (mode === 'pin') { r.min = 4; r.max = 12; r.value = 6; } else { r.min = 8; r.max = 40; r.value = 16; }
  refreshGen();
}
function refreshGen() {
  const len = +$('#gen-len').value;
  $('#gen-len-v').textContent = len;
  $('#gen-out').textContent = genMode === 'pin'
    ? Array.from({ length: len }, () => randInt(10)).join('')
    : genPassword(len, { upper: $('#gen-upper').checked, lower: $('#gen-lower').checked, digits: $('#gen-digits').checked, symbols: $('#gen-symbols').checked, noAmbig: $('#gen-amb').checked });
}

/* ================= segurança (saúde das senhas) ================= */
function analyze() {
  const es = S.data.entries.filter(e => e.password);
  const weak = es.filter(e => !isPin(e.password) && strength(e.password) <= 1);
  const groups = new Map();
  for (const e of es) { if (isPin(e.password)) continue; const g = groups.get(e.password) || []; g.push(e); groups.set(e.password, g); }
  const reusedGroups = [...groups.values()].filter(g => g.length > 1);
  const reused = reusedGroups.flat();
  const old = es.filter(e => Date.now() - (e.pwChangedAt || e.createdAt) > OLD_DAYS * 86400000);
  const n = es.length;
  const bad = new Set([...weak, ...reused].map(e => e.id));
  const score = n ? Math.max(0, Math.round(100 - (bad.size / n) * 85 - (old.length / n) * 15)) : null;
  return { n, weak, reused, reusedGroups, old, score, issues: bad.size };
}
function updateHealthBadge() {
  if (!S.data) return;
  const { issues } = analyze();
  for (const id of ['#health-badge', '#health-badge-m']) { const b = $(id); b.hidden = !issues; b.textContent = issues > 99 ? '99+' : String(issues); }
}
function renderHealth() {
  const a = analyze();
  const fg = $('#ring-fg');
  const C = 326.7;
  $('#score-val').textContent = a.score == null ? '—' : a.score;
  fg.style.strokeDashoffset = a.score == null ? C : C * (1 - a.score / 100);
  fg.style.stroke = a.score == null ? '' : a.score >= 80 ? 'var(--ok)' : a.score >= 50 ? 'var(--warn)' : 'var(--danger)';
  $('#score-title').textContent = a.score == null ? 'Sem senhas para analisar' : a.score >= 80 ? 'Ótima proteção' : a.score >= 50 ? 'Dá para melhorar' : 'Atenção necessária';
  $('#score-text').textContent = a.score == null ? 'Adicione senhas para ver a análise.'
    : a.issues ? `${plural(a.issues, 'senha precisa', 'senhas precisam')} de atenção. ${a.issues === 1 ? 'Troque-a' : 'Troque-as'} no site e atualize aqui.`
      : 'Nenhuma senha fraca ou repetida encontrada.';

  const box = $('#health-groups');
  box.replaceChildren();
  const group = (cls, iconName, title, desc, list, subFn) => {
    const g = el('div', { class: 'h-group' },
      el('div', { class: 'h-head' }, el('span', { class: 'h-icon ' + (list.length ? cls : 'good') }, icon(list.length ? iconName : 'check')),
        el('div', {}, el('b', { text: title }), el('small', { text: desc })), el('span', { class: 'h-count', text: String(list.length) })));
    for (const e of list.slice(0, 50)) g.append(itemRow(e, subFn ? subFn(e) : null));
    box.append(g);
  };
  if (a.n === 0) return;
  const reuseCount = new Map(); for (const g of a.reusedGroups) for (const e of g) reuseCount.set(e.id, g.length);
  group('bad', 'repeat', 'Senhas repetidas', 'Usadas em mais de um lugar', a.reused, e => `Mesma senha em ${reuseCount.get(e.id)} lugares`);
  group('bad', 'alert', 'Senhas fracas', 'Fáceis de adivinhar', a.weak, e => STRENGTH_LABEL[strength(e.password)]);
  group('mid', 'clock', 'Senhas antigas', 'Sem troca há mais de 1 ano', a.old, e => 'Alterada ' + ago(e.pwChangedAt));
}

/* ================= ajustes ================= */
function isStandalone() { return matchMedia('(display-mode: standalone)').matches || navigator.standalone === true; }
const isIOS = () => /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
let deferredInstall = null;
window.addEventListener('beforeinstallprompt', e => { e.preventDefault(); deferredInstall = e; if (S.data && S.tab === 'settings') renderSettings(); });
window.addEventListener('appinstalled', () => { deferredInstall = null; toast('Cofre instalado na tela inicial'); });
async function installApp() {
  if (deferredInstall) {
    deferredInstall.prompt();
    try { await deferredInstall.userChoice; } catch (_) {}
    deferredInstall = null;
    return;
  }
  const steps = isIOS()
    ? ['No Safari, toque no botão Compartilhar (quadrado com seta para cima).', 'Role e toque em "Adicionar à Tela de Início".', 'Toque em "Adicionar". Depois abra o Cofre pelo ícone novo.']
    : ['No Chrome, toque no menu ⋮ (canto superior direito).', 'Toque em "Instalar app" ou "Adicionar à tela inicial".', 'Confirme. Depois abra o Cofre pelo ícone novo.'];
  const ol = el('ol', { class: 'steps' }, ...steps.map(s => el('li', { text: s })));
  await infoBox('Instalar na tela inicial', isIOS() ? 'No iPhone, crie o cofre dentro do app instalado: ele não compartilha dados com o Safari.' : '', ol);
}
function renderSettings() {
  const st = S.data.settings;
  $('#s-lock').value = String(st.lockSec);
  $('#s-idle').value = String(st.idleMin);
  $('#s-clip').value = String(st.clipSec);
  $('#s-theme').value = store.get('cofre-theme') || 'auto';
  $('#backup-info').textContent = st.lastBackup ? 'Último: ' + fmtDateTime(st.lastBackup) : 'Nenhum backup feito ainda';
  $('#settings-sub').textContent = plural(S.data.entries.length, 'senha', 'senhas') + ' · versão ' + APP_VERSION;
  $('#install-group').hidden = isStandalone();
  $('#btn-install').textContent = deferredInstall ? 'Instalar' : 'Como instalar';
  $('#s-version').textContent = `Cofre ${APP_VERSION} · Criptografia AES-256-GCM · PBKDF2-SHA256 ${S.iter.toLocaleString('pt-BR')} iterações · Funciona 100% offline`;
  storageStatus();
}
async function saveSettings() {
  const st = S.data.settings;
  st.lockSec = +$('#s-lock').value;
  st.idleMin = +$('#s-idle').value;
  st.clipSec = +$('#s-clip').value;
  await persist();
  resetIdle();
  toast('Ajuste salvo');
}
async function requestPersistentStorage() {
  try { if (navigator.storage && navigator.storage.persist) return await navigator.storage.persist(); } catch (_) {}
  return false;
}
async function storageStatus() {
  let persisted = null;
  try { persisted = navigator.storage && navigator.storage.persisted ? await navigator.storage.persisted() : null; } catch (_) {}
  if (persisted === false) persisted = await requestPersistentStorage();
  $('#storage-title').textContent = persisted ? 'Armazenamento protegido' : 'Armazenamento comum';
  $('#storage-text').textContent = (persisted ? 'O sistema não apaga os dados do Cofre sozinho.' : 'Mantenha backups em dia; o sistema pode limpar dados de sites pouco usados.')
    + (isStandalone() ? '' : ' Instale o app para mais proteção.');
}

/* ================= arquivos (backup / CSV) ================= */
function stamp() { const d = new Date(), z = n => String(n).padStart(2, '0'); return `${d.getFullYear()}-${z(d.getMonth() + 1)}-${z(d.getDate())}`; }
async function deliverFile(content, name, mime) {
  try {
    const file = new File([content], name, { type: mime });
    if (navigator.canShare && navigator.canShare({ files: [file] })) {
      await navigator.share({ files: [file], title: name });
      return true;
    }
  } catch (e) {
    if (e && e.name === 'AbortError') return false;
  }
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const a = el('a', { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
  return true;
}
async function exportBackup() {
  // Usa o registro já cifrado em memória (mantém o "gesto do usuário" no iOS).
  const rec = Object.assign({}, S.record, { format: 'cofre-offline-backup', exportedAt: new Date().toISOString(), count: S.data.entries.length });
  const ok = await deliverFile(JSON.stringify(rec, null, 1), `cofre-backup-${stamp()}.json`, 'application/json');
  if (!ok) return;
  S.data.settings.lastBackup = Date.now();
  await persist();
  if (S.tab === 'settings') renderSettings();
  renderNotice();
  toast('Backup gerado. Guarde uma cópia fora do celular.', { ms: 3500 });
}

let fileMode = null;
function pickFile(mode) {
  fileMode = mode;
  const fi = $('#file-input');
  fi.value = '';
  fi.click();
}
async function onFilePicked(ev) {
  const file = ev.target.files && ev.target.files[0];
  if (!file) return;
  const text = await file.text();
  if (fileMode === 'csv') return importCSV(text);
  let rec;
  try { rec = JSON.parse(text); } catch (_) {
    if (/,|;/.test(text.split('\n')[0] || '') && fileMode === 'import') return importCSV(text);
    toast('Arquivo inválido.'); return;
  }
  if (!isVaultRecord(rec)) { toast('Este arquivo não é um backup do Cofre.'); return; }
  if (fileMode === 'restore') return restoreFromBackup(rec);
  if (fileMode === 'import') return importBackup(rec);
}
async function askBackupPassword(rec) {
  let opened = null;
  const when = rec.exportedAt ? ' de ' + fmtDateTime(Date.parse(rec.exportedAt)) : '';
  const vals = await askFields({
    title: 'Senha do backup',
    text: `Digite a senha mestra usada quando este backup${when} foi feito.`,
    fields: [{ label: 'Senha mestra do backup' }],
    okText: 'Abrir',
    validate: async ([pw]) => {
      if (!pw) return 'Digite a senha.';
      busy(true, 'Abrindo backup…');
      try { opened = await openRecord(rec, pw); return null; } catch (_) { return 'Senha incorreta para este backup.'; } finally { busy(false); }
    }
  });
  return vals ? opened : null;
}
async function restoreFromBackup(rec) {
  const r = await askBackupPassword(rec);
  if (!r) return;
  Object.assign(S, { key: r.key, salt: r.salt, iter: r.iter, data: normalizeData(r.data) });
  await persist();
  requestPersistentStorage();
  enterMain();
  toast(`Cofre restaurado · ${plural(S.data.entries.length, 'senha', 'senhas')}`);
}
function mergeData(incoming) {
  incoming = normalizeData(incoming);
  let added = 0, updated = 0, removed = 0;
  const tombs = new Map();
  for (const t of [...S.data.deleted, ...incoming.deleted]) if (!tombs.has(t.id) || tombs.get(t.id).at < t.at) tombs.set(t.id, t);
  const byId = new Map(S.data.entries.map(e => [e.id, e]));
  for (const e of incoming.entries) {
    const t = tombs.get(e.id);
    if (t && t.at >= e.updatedAt) continue;
    const cur = byId.get(e.id);
    if (!cur) { S.data.entries.push(e); byId.set(e.id, e); added++; }
    else if (e.updatedAt > cur.updatedAt) { Object.assign(cur, e); updated++; }
  }
  S.data.entries = S.data.entries.filter(e => {
    const t = tombs.get(e.id);
    if (t && t.at >= e.updatedAt) { removed++; return false; }
    return true;
  });
  S.data.deleted = [...tombs.values()];
  return { added, updated, removed };
}
async function importBackup(rec) {
  let incoming = null;
  if (rec.salt === b64.enc(S.salt)) { try { incoming = await decryptObj(S.key, rec.iv, rec.ct); } catch (_) { incoming = null; } }
  if (!incoming) {
    const r = await askBackupPassword(rec);
    if (!r) return;
    incoming = r.data;
  }
  const { added, updated, removed } = mergeData(incoming);
  await persist();
  renderList(); updateHealthBadge();
  toast(`Importado: ${added} nova(s), ${updated} atualizada(s)` + (removed ? `, ${removed} removida(s)` : ''), { ms: 4000 });
}

/* CSV (Google/Chrome, Bitwarden, Samsung Pass, 1Password, LastPass…) */
function detectDelim(line) {
  let c = 0, s = 0, q = false;
  for (const ch of line) { if (ch === '"') q = !q; else if (!q && ch === ',') c++; else if (!q && ch === ';') s++; }
  return s > c ? ';' : ',';
}
function parseCSV(text) {
  text = text.replace(/^﻿/, '');
  const delim = detectDelim(text.split(/\r?\n/)[0] || '');
  const rows = []; let row = [], f = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { f += '"'; i++; } else q = false; }
      else f += c;
    } else if (c === '"') q = true;
    else if (c === delim) { row.push(f); f = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(f); f = '';
      if (row.some(x => x !== '')) rows.push(row);
      row = [];
    } else f += c;
  }
  row.push(f);
  if (row.some(x => x !== '')) rows.push(row);
  return rows;
}
const COLS = {
  name: ['name', 'title', 'nome', 'titulo', 'título', 'account', 'site name'],
  url: ['url', 'login_uri', 'website', 'site', 'web site', 'uri', 'login url', 'origin_url'],
  username: ['username', 'login_username', 'user', 'usuario', 'usuário', 'login', 'email', 'e-mail', 'user name', 'username_value'],
  password: ['password', 'login_password', 'senha', 'pass', 'password_value'],
  notes: ['note', 'notes', 'extra', 'observacoes', 'observações', 'comments', 'comment', 'memo'],
  totp: ['login_totp', 'totp', 'otpauth', 'otp', 'one-time password'],
  category: ['folder', 'grouping', 'category', 'categoria', 'group'],
  fav: ['favorite', 'fav', 'favorito']
};
async function importCSV(text) {
  const rows = parseCSV(text);
  if (rows.length < 2) { toast('CSV vazio ou inválido.'); return; }
  const head = rows[0].map(h => norm(h.trim()));
  const idx = {};
  for (const [k, names] of Object.entries(COLS)) idx[k] = head.findIndex(h => names.map(norm).includes(h));
  if (idx.password < 0) { await infoBox('CSV não reconhecido', 'Não encontrei a coluna de senha (password). Exporte do Google em passwords.google.com → Configurações → Exportar senhas.'); return; }
  const get = (r, k) => idx[k] >= 0 ? (r[idx[k]] || '').trim() : '';
  const existing = new Set(S.data.entries.map(e => norm(e.name) + '|' + e.username + '|' + e.password));
  const now = Date.now();
  let added = 0, skipped = 0;
  for (const r of rows.slice(1)) {
    const password = idx.password >= 0 ? (r[idx.password] || '') : '';
    const url = get(r, 'url'), username = get(r, 'username');
    if (!password && !username) { skipped++; continue; }
    let name = get(r, 'name') || hostOf(url) || username || 'Sem nome';
    const catRaw = get(r, 'category');
    const category = CATEGORIES.find(c => norm(c) === norm(catRaw)) || '';
    let totp = get(r, 'totp');
    if (totp) { try { parseTotp(totp); } catch (_) { totp = ''; } }
    const key = norm(name) + '|' + username + '|' + password;
    if (existing.has(key)) { skipped++; continue; }
    existing.add(key);
    S.data.entries.push(normalizeEntry({ id: uid(), name, url, username, password, notes: get(r, 'notes'), category, totp, fav: /^(1|true|sim|yes)$/i.test(get(r, 'fav')), createdAt: now, updatedAt: now, pwChangedAt: now }));
    added++;
  }
  await persist();
  if (S.tab !== 'vault') switchTab('vault'); else renderList();
  updateHealthBadge();
  await infoBox('Importação concluída', `${plural(added, 'senha importada', 'senhas importadas')}${skipped ? ` (${skipped} ignorada(s) por estarem vazias ou repetidas)` : ''}. Importante: o arquivo CSV não tem criptografia. Apague-o do celular e da lixeira agora.`);
}
const csvCell = v => /[",\n\r;]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
async function exportCSV() {
  const ok = await askFields({
    title: 'Exportar sem criptografia',
    text: 'O arquivo CSV mostra todas as senhas em texto aberto. Use só para levar a outro gerenciador e apague em seguida. Confirme com a senha mestra.',
    fields: [{ label: 'Senha mestra' }],
    okText: 'Exportar CSV', danger: true,
    validate: async ([pw]) => {
      busy(true, 'Verificando…');
      try { await openRecord(S.record, pw); return null; } catch (_) { return 'Senha mestra incorreta.'; } finally { busy(false); }
    }
  });
  if (!ok) return;
  const lines = [['name', 'url', 'username', 'password', 'note', 'totp', 'category'].join(',')];
  for (const e of sortEntries(S.data.entries)) lines.push([e.name, e.url, e.username, e.password, e.notes, e.totp, e.category].map(v => csvCell(v || '')).join(','));
  await deliverFile('﻿' + lines.join('\r\n'), `cofre-senhas-${stamp()}.csv`, 'text/csv');
}

/* ================= senha mestra / apagar ================= */
async function changeMasterPassword() {
  const vals = await askFields({
    title: 'Trocar senha mestra',
    text: 'Backups antigos continuam abrindo só com a senha antiga. Faça um backup novo em seguida.',
    fields: [{ label: 'Senha mestra atual' }, { label: 'Nova senha mestra' }, { label: 'Confirme a nova senha' }],
    okText: 'Trocar',
    validate: async ([cur, nw, nw2]) => {
      if (nw.length < 8 || strength(nw) < 2) return 'A nova senha é fraca demais. Use pelo menos 10 caracteres ou uma frase.';
      if (nw !== nw2) return 'As novas senhas não conferem.';
      busy(true, 'Verificando…');
      try { await openRecord(S.record, cur); return null; } catch (_) { return 'Senha atual incorreta.'; } finally { busy(false); }
    }
  });
  if (!vals) return;
  busy(true, 'Trocando senha…');
  try {
    S.salt = crypto.getRandomValues(new Uint8Array(16));
    S.iter = PBKDF2_ITER;
    S.key = await deriveKey(vals[1], S.salt, S.iter);
    S.data.settings.lastBackup = 0;
    await persist();
    renderSettings();
    toast('Senha mestra trocada. Faça um backup novo.', { ms: 3500 });
  } finally { busy(false); }
}
async function wipeVault() {
  const vals = await askFields({
    title: 'Apagar o cofre',
    text: 'Todas as senhas deste aparelho serão apagadas definitivamente. Para confirmar, digite APAGAR.',
    fields: [{ label: 'Confirmação', type: 'text', placeholder: 'APAGAR' }],
    okText: 'Apagar tudo', danger: true,
    validate: ([t]) => t.trim().toUpperCase() === 'APAGAR' ? null : 'Digite APAGAR para confirmar.'
  });
  if (!vals) return;
  await DB.del('vault');
  S.key = null; S.data = null;
  location.reload();
}

/* ================= eventos ================= */
function bind() {
  $('#btn-create').onclick = createVault;
  $('#setup-pw2').oninput = () => { $('#setup-msg').textContent = ''; };
  $('#setup-pw').oninput = () => {
    $('#setup-msg').textContent = '';
    paintMeter($('#setup-meter'), $('#setup-meter-text'), $('#setup-pw').value, 'Use pelo menos 10 caracteres. Uma frase com várias palavras é forte e fácil de lembrar.');
  };
  $('#setup-pw2').onkeydown = e => { if (e.key === 'Enter') createVault(); };
  $('#btn-restore').onclick = () => pickFile('restore');
  $('#btn-unlock').onclick = unlock;
  $('#unlock-pw').onkeydown = e => { if (e.key === 'Enter') unlock(); };
  $('#btn-lock').onclick = lock;
  $('#btn-lock-rail').onclick = lock;
  for (const b of $$('.nav-item[data-tab]')) b.onclick = () => switchTab(b.dataset.tab);
  $('#btn-add').onclick = () => openEdit(null);
  $('#empty-btn').onclick = () => openEdit(null);
  $('#empty-import').onclick = () => pickFile('csv');
  $('#search').oninput = renderList;
  $('#btn-sort').onclick = () => {
    S.data.settings.sort = S.data.settings.sort === 'name' ? 'recent' : 'name';
    persist().catch(() => {});
    renderList();
    toast(S.data.settings.sort === 'name' ? 'Ordem alfabética' : 'Usadas recentemente primeiro');
  };
  $('#btn-edit').onclick = () => openEdit(S.currentId);
  $('#btn-fav').onclick = toggleFav;
  $('#btn-delete').onclick = deleteCurrent;
  $('#btn-save').onclick = saveEdit;
  $('#e-pass').oninput = () => paintMeter($('#e-meter'), $('#e-meter-text'), $('#e-pass').value);
  $('#e-gen-toggle').onclick = () => { const g = $('#gen'); g.hidden = !g.hidden; if (!g.hidden) setGenMode(genMode); };
  for (const b of $$('#gen-mode button')) b.onclick = () => setGenMode(b.dataset.mode);
  $('#gen-refresh').onclick = refreshGen;
  $('#gen-len').oninput = refreshGen;
  for (const id of ['#gen-upper', '#gen-lower', '#gen-digits', '#gen-symbols', '#gen-amb']) $(id).onchange = refreshGen;
  $('#gen-use').onclick = () => {
    const p = $('#e-pass');
    p.value = $('#gen-out').textContent; p.type = 'text';
    $('[data-toggle-pw="e-pass"] use').setAttribute('href', '#i-eye-off');
    paintMeter($('#e-meter'), $('#e-meter-text'), p.value);
    $('#gen').hidden = true;
  };
  $('#big').onclick = closeBig;
  for (const id of ['#s-lock', '#s-idle', '#s-clip']) $(id).onchange = saveSettings;
  $('#s-theme').onchange = () => { store.set('cofre-theme', $('#s-theme').value); applyTheme(); };
  $('#btn-install').onclick = installApp;
  $('#btn-export').onclick = exportBackup;
  $('#btn-import').onclick = () => pickFile('import');
  $('#btn-import-csv').onclick = () => pickFile('csv');
  $('#btn-export-csv').onclick = exportCSV;
  $('#btn-change-pw').onclick = changeMasterPassword;
  $('#btn-wipe').onclick = wipeVault;
  $('#file-input').onchange = onFilePicked;
}

/* Correção para o modo "Site para computador" do Chrome no celular */
function fixDesktopModeOnPhone() {
  const touch = matchMedia('(pointer: coarse)').matches;
  const portrait = matchMedia('(orientation: portrait)').matches;
  const deviceW = portrait ? Math.min(screen.width, screen.height) : Math.max(screen.width, screen.height);
  const vw = document.documentElement.clientWidth || window.innerWidth;
  const zoomed = touch && deviceW > 0 && deviceW < 760 && vw > deviceW * 1.3;
  document.documentElement.style.zoom = zoomed ? String(vw / deviceW) : '';
  // Com zoom, a largura "vista" pelas media queries continua de PC: força o layout de celular.
  document.documentElement.classList.toggle('zoomed', zoomed);
}

async function init() {
  applyTheme();
  fixDesktopModeOnPhone();
  window.addEventListener('resize', () => { document.documentElement.style.zoom = ''; fixDesktopModeOnPhone(); });
  bind();
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js', { updateViaCache: 'none' }).then(reg => { reg.update().catch(() => {}); }).catch(() => {});
    // Recarrega só quando uma versão nova substitui uma antiga (não na primeira visita) e com o cofre bloqueado.
    const hadController = !!navigator.serviceWorker.controller;
    let reloaded = false;
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      const typing = document.activeElement && /INPUT|TEXTAREA/.test(document.activeElement.tagName) && document.activeElement.value;
      if (hadController && !reloaded && !S.key && !typing) { reloaded = true; location.reload(); }
    });
  }
  if (!window.crypto || !crypto.subtle || !window.indexedDB) {
    document.body.textContent = 'Este navegador não oferece criptografia segura. Abra o Cofre por um endereço https:// no Chrome ou Safari atualizado.';
    return;
  }
  let rec = null;
  try { rec = await DB.get('vault'); } catch (_) {}
  if (rec) { showView('unlock'); setTimeout(() => $('#unlock-pw').focus(), 100); }
  else showView('setup');
}
init();
