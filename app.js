/* Cofre — gerenciador de senhas 100% offline.
 * Criptografia: PBKDF2-SHA256 (600 mil iterações) -> chave AES-256-GCM.
 * O cofre inteiro é guardado cifrado no IndexedDB deste aparelho. Nenhum dado é enviado.
 */
'use strict';

const APP_VERSION = '1.0.2';
const PBKDF2_ITER = 600000;
const AAD = new TextEncoder().encode('cofre-offline-v1');
const enc = new TextEncoder();
const dec = new TextDecoder();
const DEFAULT_SETTINGS = { lockSec: 60, idleMin: 5, clipSec: 45, lastBackup: 0 };

const $ = (s, r = document) => r.querySelector(s);

/* ---------- utilidades ---------- */
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
const fmtDate = t => t ? new Date(t).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' }) : '—';
function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const k of kids) if (k != null) e.append(k);
  return e;
}

/* ---------- IndexedDB ---------- */
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

/* ---------- criptografia ---------- */
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
/** Abre um registro cifrado com a senha. Retorna {key, salt, iter, data} ou lança erro. */
async function openRecord(rec, password) {
  const salt = b64.dec(rec.salt);
  const key = await deriveKey(password, salt, Number(rec.iter));
  const data = await decryptObj(key, rec.iv, rec.ct);
  return { key, salt, iter: Number(rec.iter), data };
}

/* ---------- estado ---------- */
const S = { key: null, salt: null, iter: PBKDF2_ITER, data: null, record: null, currentId: null, editingId: null };

function normalizeData(d) {
  d = d && typeof d === 'object' ? d : {};
  d.entries = Array.isArray(d.entries) ? d.entries : [];
  d.settings = Object.assign({}, DEFAULT_SETTINGS, d.settings || {});
  return d;
}
async function persist() {
  const { iv, ct } = await encryptObj(S.key, S.data);
  const rec = { format: 'cofre-offline', v: 1, kdf: 'PBKDF2-SHA256', iter: S.iter, salt: b64.enc(S.salt), iv, ct };
  await DB.set('vault', rec);
  S.record = rec;
}

/* ---------- UI básica ---------- */
function showView(name) {
  for (const v of ['setup', 'unlock', 'main']) $('#view-' + v).hidden = v !== name;
}
let toastTimer;
function toast(msg, ms = 2600) {
  const t = $('#toast');
  t.textContent = msg; t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, ms);
}
function busy(on, text = 'Processando…') {
  $('#busy-text').textContent = text;
  $('#busy').hidden = !on;
}

/* Folhas (telas sobrepostas) com suporte ao botão Voltar do Android */
const sheetStack = [];
let ignorePop = 0;
function openSheet(id) {
  $('#' + id).hidden = false;
  $('#' + id).scrollTop = 0;
  sheetStack.push(id);
  history.pushState({ sheet: id }, '');
}
function closeTopSheet(fromPop = false) {
  const id = sheetStack.pop();
  if (!id) return;
  $('#' + id).hidden = true;
  if (!fromPop) { ignorePop++; history.back(); }
}
function closeAllSheets() {
  while (sheetStack.length) $('#' + sheetStack.pop()).hidden = true;
}
window.addEventListener('popstate', () => {
  if (ignorePop > 0) { ignorePop--; return; }
  if (!$('#modal').hidden) {
    modalResolve && modalResolve(null);
    if (sheetStack.length) history.pushState({ sheet: sheetStack[sheetStack.length - 1] }, '');
    return;
  }
  if (sheetStack.length) closeTopSheet(true);
});
document.addEventListener('click', e => {
  if (e.target.closest('[data-close]')) closeTopSheet();
});

/* Modal genérico: campos de senha */
let modalResolve = null;
function askFields({ title, text = '', fields, okText = 'OK', validate }) {
  return new Promise(resolve => {
    $('#m-title').textContent = title;
    $('#m-text').textContent = text;
    $('#m-msg').textContent = '';
    $('#m-ok').textContent = okText;
    const box = $('#m-inputs'); box.replaceChildren();
    const inputs = fields.map(f => {
      const inp = el('input', { type: f.type || 'password', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false' });
      box.append(el('label', {}, f.label, inp));
      return inp;
    });
    $('#modal').hidden = false;
    setTimeout(() => inputs[0] && inputs[0].focus(), 50);
    const finish = val => {
      $('#modal').hidden = true;
      $('#m-ok').onclick = $('#m-cancel').onclick = null;
      box.onkeydown = null;
      modalResolve = null;
      resolve(val);
    };
    modalResolve = finish;
    $('#m-cancel').onclick = () => finish(null);
    $('#m-ok').onclick = async () => {
      const vals = inputs.map(i => i.value);
      if (validate) {
        const err = await validate(vals);
        if (err) { $('#m-msg').textContent = err; return; }
      }
      finish(vals);
    };
    box.onkeydown = e => { if (e.key === 'Enter') $('#m-ok').click(); };
  });
}

/* ---------- criar / desbloquear / bloquear ---------- */
async function createVault() {
  const pw = $('#setup-pw').value, pw2 = $('#setup-pw2').value;
  const msg = $('#setup-msg');
  if (pw.length < 8) { msg.textContent = 'Use pelo menos 8 caracteres.'; return; }
  if (pw !== pw2) { msg.textContent = 'As senhas não conferem.'; return; }
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
    $('#unlock-pw').value = '';
    msg.textContent = '';
    enterMain();
  } catch (e) {
    failCount++;
    msg.textContent = 'Senha incorreta.';
    await sleep(Math.min(500 * failCount, 5000)); // freia tentativas seguidas
  } finally { busy(false); }
}

function lock() {
  S.key = null; S.data = null; S.currentId = null; S.editingId = null;
  closeAllSheets();
  $('#modal').hidden = true;
  $('#list').replaceChildren();
  $('#d-fields').replaceChildren();
  for (const id of ['#search', '#e-name', '#e-user', '#e-pass', '#e-url', '#e-notes']) $(id).value = '';
  $('#gen-out').textContent = '';
  clearTimeout(idleTimer);
  showView('unlock');
  setTimeout(() => $('#unlock-pw').focus(), 100);
}

function enterMain() {
  showView('main');
  renderList();
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

/* ---------- lista ---------- */
const COLORS = ['#0d9488', '#2563eb', '#7c3aed', '#db2777', '#ea580c', '#16a34a', '#0891b2', '#9333ea', '#c2410c', '#4f46e5'];
function colorFor(s) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) >>> 0; return COLORS[h % COLORS.length]; }
function avatar(name) {
  const a = el('span', { class: 'avatar', text: (name.trim()[0] || '?').toUpperCase() });
  a.style.background = colorFor(norm(name));
  return a;
}

function renderList() {
  if (!S.data) return;
  const q = norm($('#search').value.trim());
  const all = S.data.entries;
  const items = all
    .filter(e => !q || norm([e.name, e.username, e.url].join(' ')).includes(q))
    .sort((a, b) => a.name.localeCompare(b.name, 'pt-BR', { sensitivity: 'base' }));
  const list = $('#list');
  list.replaceChildren(...items.map(e => el('li', {},
    el('button', { class: 'item', onclick: () => openDetail(e.id) },
      avatar(e.name),
      el('span', { class: 'item-text' },
        el('div', { class: 'item-name', text: e.name }),
        el('div', { class: 'item-user', text: e.username || e.url || '—' }))),
    e.password ? el('button', {
      class: 'icon-btn copy-quick', 'aria-label': 'Copiar senha de ' + e.name, title: 'Copiar senha',
      onclick: () => copyText(e.password, 'Senha', e.id)
    }, '📋') : null
  )));
  $('#count').textContent = all.length;
  const empty = $('#empty');
  empty.hidden = items.length > 0;
  empty.textContent = all.length ? 'Nada encontrado.' : 'Nenhuma senha ainda. Toque em ＋ para adicionar a primeira.';
  renderBackupBanner();
}

function renderBackupBanner() {
  const st = S.data.settings, n = S.data.entries.length;
  const changedSince = S.data.entries.some(e => (e.updatedAt || 0) > (st.lastBackup || 0));
  const old = !st.lastBackup || Date.now() - st.lastBackup > 30 * 86400000;
  const show = n > 0 && changedSince && old;
  $('#backup-banner').hidden = !show;
  if (show) $('#backup-banner-text').textContent = st.lastBackup
    ? 'Último backup há mais de 30 dias.'
    : 'Você ainda não fez backup. Se perder o celular, perde as senhas.';
}

/* ---------- copiar ---------- */
let clipTimer;
async function copyText(text, label, entryId) {
  let ok = false;
  try { await navigator.clipboard.writeText(text); ok = true; } catch (_) {
    const ta = el('textarea', { readonly: '' });
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
  if (entryId && S.data) {
    const e = S.data.entries.find(x => x.id === entryId);
    if (e) { e.lastUsed = Date.now(); persist().catch(() => {}); }
  }
}

/* ---------- detalhe ---------- */
function field(label, value, { secret = false, mono = false, notes = false, copy = true, link = null, entryId } = {}) {
  const val = el('div', { class: 'field-value' + (mono ? ' mono' : '') + (notes ? ' notes' : '') });
  let shown = !secret;
  const paint = () => { val.textContent = shown ? value : '•'.repeat(Math.min(value.length, 14)); };
  paint();
  const row = el('div', { class: 'field' }, el('div', { class: 'field-body' }, el('div', { class: 'field-label', text: label }), val));
  if (secret) row.append(el('button', { class: 'icon-btn', 'aria-label': 'Mostrar/ocultar', onclick: () => { shown = !shown; paint(); } }, '👁'));
  if (link) row.append(el('a', { class: 'btn small', href: link, target: '_blank', rel: 'noopener noreferrer' }, 'Abrir'));
  if (copy) row.append(el('button', { class: 'btn small', onclick: () => copyText(value, label, entryId) }, 'Copiar'));
  return row;
}
function safeLink(url) {
  if (!url) return null;
  let u = url.trim();
  if (!/^[a-z][a-z0-9+.-]*:/i.test(u)) u = 'https://' + u;
  try { const p = new URL(u); return (p.protocol === 'https:' || p.protocol === 'http:') ? p.href : null; } catch (_) { return null; }
}
function openDetail(id, push = true) {
  const e = S.data.entries.find(x => x.id === id);
  if (!e) return;
  S.currentId = id;
  $('#d-name').textContent = e.name;
  const f = $('#d-fields'); f.replaceChildren();
  if (e.username) f.append(field('Usuário', e.username, { entryId: id }));
  if (e.password) f.append(field('Senha', e.password, { secret: true, mono: true, entryId: id }));
  if (e.url) f.append(field('Site / endereço', e.url, { link: safeLink(e.url) }));
  if (e.notes) f.append(field('Observações', e.notes, { notes: true }));
  if (!f.children.length) f.append(el('div', { class: 'field' }, el('span', { class: 'muted', text: 'Sem dados.' })));
  $('#d-meta').textContent = `Criada: ${fmtDate(e.createdAt)} · Alterada: ${fmtDate(e.updatedAt)}`;
  if (push) openSheet('sheet-detail');
}

/* ---------- editar ---------- */
function openEdit(id = null) {
  S.editingId = id;
  const e = id ? S.data.entries.find(x => x.id === id) : null;
  $('#e-title').textContent = e ? 'Editar' : 'Nova senha';
  $('#e-name').value = e ? e.name : '';
  $('#e-user').value = e ? e.username : '';
  $('#e-pass').value = e ? e.password : '';
  $('#e-url').value = e ? e.url : '';
  $('#e-notes').value = e ? e.notes : '';
  $('#e-pass').type = 'password';
  $('#e-msg').textContent = '';
  $('#gen').hidden = true;
  openSheet('sheet-edit');
  if (!e) setTimeout(() => $('#e-name').focus(), 80);
}
async function saveEdit() {
  const name = $('#e-name').value.trim();
  if (!name) { $('#e-msg').textContent = 'Informe o nome do app ou site.'; return; }
  const now = Date.now();
  const vals = {
    name, username: $('#e-user').value.trim(), password: $('#e-pass').value,
    url: $('#e-url').value.trim(), notes: $('#e-notes').value
  };
  let id = S.editingId;
  if (id) {
    const e = S.data.entries.find(x => x.id === id);
    Object.assign(e, vals, { updatedAt: now });
  } else {
    id = uid();
    S.data.entries.push(Object.assign({ id, createdAt: now, updatedAt: now }, vals));
  }
  try { await persist(); } catch (err) { $('#e-msg').textContent = 'Erro ao salvar: ' + err.message; return; }
  closeTopSheet();
  renderList();
  if (S.editingId) openDetail(id, false);
  else toast('Senha salva');
  S.editingId = null;
}
async function deleteCurrent() {
  const e = S.data.entries.find(x => x.id === S.currentId);
  if (!e) return;
  if (!confirm(`Excluir "${e.name}"? Isso não pode ser desfeito.`)) return;
  S.data.entries = S.data.entries.filter(x => x.id !== e.id);
  await persist();
  closeTopSheet();
  renderList();
  toast('Excluída');
}

/* ---------- gerador ---------- */
const POOLS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', lower: 'abcdefghijklmnopqrstuvwxyz',
  digits: '0123456789', symbols: '!@#$%&*()-_=+[]{};:,.?/'
};
function randInt(n) {
  const max = Math.floor(0x100000000 / n) * n, a = new Uint32Array(1);
  do crypto.getRandomValues(a); while (a[0] >= max);
  return a[0] % n;
}
function genPassword(len, opts) {
  const pools = Object.keys(POOLS).filter(k => opts[k]).map(k => POOLS[k]);
  if (!pools.length) pools.push(POOLS.lower);
  const all = pools.join('');
  const out = pools.map(p => p[randInt(p.length)]);
  while (out.length < len) out.push(all[randInt(all.length)]);
  for (let i = out.length - 1; i > 0; i--) { const j = randInt(i + 1); [out[i], out[j]] = [out[j], out[i]]; }
  return out.join('');
}
function refreshGen() {
  const len = +$('#gen-len').value;
  $('#gen-len-v').textContent = len;
  $('#gen-out').textContent = genPassword(len, {
    upper: $('#gen-upper').checked, lower: $('#gen-lower').checked,
    digits: $('#gen-digits').checked, symbols: $('#gen-symbols').checked
  });
}

/* ---------- configurações ---------- */
function openSettings() {
  const st = S.data.settings;
  $('#s-lock').value = String(st.lockSec);
  $('#s-idle').value = String(st.idleMin);
  $('#s-clip').value = String(st.clipSec);
  $('#s-backup-info').textContent = st.lastBackup ? 'Último backup exportado: ' + fmtDate(st.lastBackup) : 'Nenhum backup exportado ainda.';
  $('#s-version').textContent = `Cofre v${APP_VERSION} · ${S.data.entries.length} senha(s) · PBKDF2 ${S.iter.toLocaleString('pt-BR')} it. + AES-256-GCM`;
  storageStatus();
  openSheet('sheet-settings');
}
async function saveSettings() {
  const st = S.data.settings;
  st.lockSec = +$('#s-lock').value;
  st.idleMin = +$('#s-idle').value;
  st.clipSec = +$('#s-clip').value;
  await persist();
  resetIdle();
  toast('Configuração salva');
}
async function requestPersistentStorage() {
  try { if (navigator.storage && navigator.storage.persist) return await navigator.storage.persist(); } catch (_) {}
  return false;
}
async function storageStatus() {
  const p = $('#s-storage');
  let txt = '';
  try {
    const persisted = navigator.storage && navigator.storage.persisted ? await navigator.storage.persisted() : null;
    if (persisted === true) txt = 'Armazenamento protegido: o sistema não apaga os dados sozinho.';
    else if (persisted === false) txt = 'O sistema ainda não marcou o armazenamento como protegido. Instale o app na tela inicial e mantenha backups.';
  } catch (_) {}
  const standalone = matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
  if (!standalone) txt += ' Atenção: você está usando pelo navegador. Instale na tela inicial; no iPhone, o app instalado e o Safari têm dados separados.';
  p.textContent = txt.trim();
}

/* Backup: exporta o próprio registro cifrado (abre com a senha mestra atual) */
function backupFileName() {
  const d = new Date(), z = n => String(n).padStart(2, '0');
  return `cofre-backup-${d.getFullYear()}-${z(d.getMonth() + 1)}-${z(d.getDate())}.json`;
}
async function exportBackup() {
  // Usa o registro já cifrado em memória para não perder o "gesto do usuário" no iOS.
  const rec = Object.assign({}, S.record, { format: 'cofre-offline-backup', exportedAt: new Date().toISOString(), count: S.data.entries.length });
  const json = JSON.stringify(rec, null, 1);
  const name = backupFileName();
  let done = false;
  try {
    const file = new File([json], name, { type: 'application/json' });
    if (navigator.canShare && navigator.canShare({ files: [file] })) {
      await navigator.share({ files: [file], title: 'Backup do Cofre' });
      done = true;
    }
  } catch (e) {
    if (e && e.name === 'AbortError') return; // usuário cancelou
  }
  if (!done) {
    const url = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
    const a = el('a', { href: url, download: name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  }
  S.data.settings.lastBackup = Date.now();
  await persist();
  $('#s-backup-info').textContent = 'Último backup exportado: ' + fmtDate(S.data.settings.lastBackup);
  renderBackupBanner();
  toast('Backup gerado');
}

/* Leitura de arquivo de backup */
let fileMode = null; // 'restore' | 'import'
function pickFile(mode) {
  fileMode = mode;
  const fi = $('#file-input');
  fi.value = '';
  fi.click();
}
async function onFilePicked(ev) {
  const file = ev.target.files && ev.target.files[0];
  if (!file) return;
  let rec;
  try { rec = JSON.parse(await file.text()); } catch (_) { toast('Arquivo inválido.'); return; }
  if (!isVaultRecord(rec)) { toast('Este arquivo não é um backup do Cofre.'); return; }
  if (fileMode === 'restore') return restoreFromBackup(rec);
  if (fileMode === 'import') return importBackup(rec);
}
async function askBackupPassword(rec) {
  let opened = null;
  const vals = await askFields({
    title: 'Senha do backup',
    text: 'Digite a senha mestra que estava em uso quando este backup foi feito.',
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
  toast(`Cofre restaurado · ${S.data.entries.length} senha(s)`);
}
async function importBackup(rec) {
  let incoming;
  if (rec.salt === b64.enc(S.salt)) {
    try { incoming = await decryptObj(S.key, rec.iv, rec.ct); } catch (_) { incoming = null; }
  }
  if (!incoming) {
    const r = await askBackupPassword(rec);
    if (!r) return;
    incoming = r.data;
  }
  incoming = normalizeData(incoming);
  let added = 0, updated = 0;
  const byId = new Map(S.data.entries.map(e => [e.id, e]));
  for (const e of incoming.entries) {
    if (!e || !e.id || !e.name) continue;
    const cur = byId.get(e.id);
    if (!cur) { S.data.entries.push(e); byId.set(e.id, e); added++; }
    else if ((e.updatedAt || 0) > (cur.updatedAt || 0)) { Object.assign(cur, e); updated++; }
  }
  await persist();
  renderList();
  toast(`Importado: ${added} nova(s), ${updated} atualizada(s)`, 3500);
}

async function changeMasterPassword() {
  const vals = await askFields({
    title: 'Trocar senha mestra',
    text: 'Backups antigos continuam abrindo só com a senha antiga. Faça um backup novo depois.',
    fields: [{ label: 'Senha mestra atual' }, { label: 'Nova senha mestra' }, { label: 'Repita a nova senha' }],
    okText: 'Trocar',
    validate: async ([cur, nw, nw2]) => {
      if (nw.length < 8) return 'A nova senha precisa ter pelo menos 8 caracteres.';
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
    await persist();
    toast('Senha mestra trocada. Faça um backup novo.', 3500);
  } finally { busy(false); }
}

async function wipeVault() {
  const vals = await askFields({
    title: 'Apagar o cofre',
    text: 'Todas as senhas deste aparelho serão apagadas. Para confirmar, digite APAGAR.',
    fields: [{ label: 'Confirmação', type: 'text' }],
    okText: 'Apagar tudo',
    validate: ([t]) => t.trim().toUpperCase() === 'APAGAR' ? null : 'Digite APAGAR para confirmar.'
  });
  if (!vals) return;
  await DB.del('vault');
  S.key = null; S.data = null;
  location.reload();
}

/* ---------- eventos ---------- */
function bind() {
  $('#btn-create').onclick = createVault;
  $('#setup-pw2').onkeydown = e => { if (e.key === 'Enter') createVault(); };
  $('#btn-restore').onclick = () => pickFile('restore');
  $('#btn-unlock').onclick = unlock;
  $('#unlock-pw').onkeydown = e => { if (e.key === 'Enter') unlock(); };
  $('#btn-lock').onclick = lock;
  $('#btn-add').onclick = () => openEdit(null);
  $('#btn-settings').onclick = openSettings;
  $('#search').oninput = renderList;
  $('#btn-banner-backup').onclick = exportBackup;
  $('#btn-edit').onclick = () => openEdit(S.currentId);
  $('#btn-delete').onclick = deleteCurrent;
  $('#btn-save').onclick = saveEdit;
  $('#e-eye').onclick = () => { const p = $('#e-pass'); p.type = p.type === 'password' ? 'text' : 'password'; };
  $('#e-gen-toggle').onclick = () => { const g = $('#gen'); g.hidden = !g.hidden; if (!g.hidden) refreshGen(); };
  $('#gen-refresh').onclick = refreshGen;
  $('#gen-len').oninput = refreshGen;
  for (const id of ['#gen-upper', '#gen-lower', '#gen-digits', '#gen-symbols']) $(id).onchange = refreshGen;
  $('#gen-use').onclick = () => { $('#e-pass').value = $('#gen-out').textContent; $('#e-pass').type = 'text'; $('#gen').hidden = true; };
  for (const id of ['#s-lock', '#s-idle', '#s-clip']) $(id).onchange = saveSettings;
  $('#btn-export').onclick = exportBackup;
  $('#btn-import').onclick = () => pickFile('import');
  $('#btn-change-pw').onclick = changeMasterPassword;
  $('#btn-wipe').onclick = wipeVault;
  $('#file-input').onchange = onFilePicked;
}

/* Correção para o modo "Site para computador" do Chrome no celular:
 * nesse modo a página é desenhada com ~980px de largura e tudo fica minúsculo.
 * Detecta e aplica zoom para voltar à largura real da tela. */
function fixDesktopModeOnPhone() {
  const touch = matchMedia('(pointer: coarse)').matches;
  const real = Math.min(screen.width, screen.height) || 0;
  const vw = document.documentElement.clientWidth || window.innerWidth;
  const portrait = matchMedia('(orientation: portrait)').matches;
  const deviceW = portrait ? real : Math.max(screen.width, screen.height);
  if (touch && deviceW > 0 && deviceW < 760 && vw > deviceW * 1.3) {
    document.documentElement.style.zoom = String(vw / deviceW);
  } else {
    document.documentElement.style.zoom = '';
  }
}

async function init() {
  fixDesktopModeOnPhone();
  window.addEventListener('resize', () => { document.documentElement.style.zoom = ''; fixDesktopModeOnPhone(); });
  bind();
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js', { updateViaCache: 'none' })
      .then(reg => { reg.update().catch(() => {}); })
      .catch(() => {});
    // Quando sair versão nova do app, recarrega sozinho (só se o cofre estiver bloqueado).
    let reloaded = false;
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (!reloaded && !S.key) { reloaded = true; location.reload(); }
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
