import './styles.css';
import { audit, STALE_DAYS } from './lib/audit';
import { pwnedCount } from './lib/breach';
import { decryptRecord, deriveKey, encryptEntries, newSalt } from './lib/crypto';
import { csvToEntries, mergeEntries, type CsvImportBatch } from './lib/csv';
import { b64, uid } from './lib/encoding';
import { bits, DEFAULT_GEN, genAny, pwBits, rnd, SEPS, strength, type GenOptions } from './lib/generator';
import { cfg, lockLabel, LOCK_OPTS, setCfg } from './lib/settings';
import { initStorage, load, store, type StorageKind } from './lib/storage';
import { matchFilter, norm, parseTags, TYPE_FIELDS, TYPES } from './lib/tags';
import { parseTotp, totpCode } from './lib/totp';
import type { CustomField, Entry, EntryType, Flag, KdfParams, ProfileRecord } from './lib/types';
import { DEFAULT_KDF } from './lib/crypto';
import { WORDS } from './lib/words';

const $ = <T extends Element = HTMLElement>(s: string): T | null => document.querySelector<T>(s);
const esc = (s: unknown): string =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

export type ViewName = 'home' | 'detail' | 'form' | 'gen' | 'audit' | 'settings';

export interface FormDraft {
  id?: string;
  type: EntryType;
  service: string;
  username: string;
  email: string;
  password: string;
  totpSecret: string;
  recEmail: string;
  qa: string;
  notes: string;
  fields: CustomField[];
  tags: string[];
  fav: Flag;
  created?: number;
  pwChanged?: number;
  history?: Entry['history'];
}

export interface AppState {
  name: string | null;
  key: CryptoKey | null;
  salt: Uint8Array<ArrayBuffer> | null;
  kdf: KdfParams;
  master: string;
  entries: Entry[];
  sel: string | null;
  view: ViewName;
  open: Record<string, number>;
  fails: number;
  lockUntil: number;
  chal: number[] | null;
  last: number;
  storage?: StorageKind;
  filter: string;
  pending: CsvImportBatch | null;
  _f: FormDraft | null;
  _gp: string | null;
  g: GenOptions;
}

export const S: AppState = {
  name: null,
  key: null,
  salt: null,
  kdf: { ...DEFAULT_KDF },
  master: '',
  entries: [],
  sel: null,
  view: 'home',
  open: {},
  fails: 0,
  lockUntil: 0,
  chal: null,
  last: Date.now(),
  filter: 'all',
  pending: null,
  _f: null,
  _gp: null,
  g: { ...DEFAULT_GEN },
};

async function seal(): Promise<void> {
  if (!S.key || !S.name || !S.salt) return;
  const { iv, ct } = await encryptEntries(S.key, S.entries);
  const all = load();
  all[S.name] = {
    salt: b64(S.salt),
    iv,
    ct,
    created: all[S.name]?.created || Date.now(),
    ...S.kdf,
  };
  try {
    await store(all);
  } catch (err) {
    const name = err instanceof Error ? err.name : 'error';
    alert('Could not save to browser storage (' + name + '). Export a backup and use a normal browser window.');
    throw err;
  }
}

async function unlockProfile(name: string, pw: string): Promise<void> {
  const rec = load()[name];
  if (!rec) throw new Error('Profile not found');
  const { key, salt, kdf, entries } = await decryptRecord(rec, pw);
  let activeKey = key;
  let activeSalt = salt;
  let activeKdf = kdf;
  let upgraded = false;
  if (kdf.kdf !== 'argon2id') {
    const nextSalt = newSalt();
    const derived = await deriveKey(pw, nextSalt, DEFAULT_KDF);
    if (derived.kdf.kdf === 'argon2id') {
      activeKey = derived.key;
      activeSalt = nextSalt;
      activeKdf = derived.kdf;
      upgraded = true;
    }
  }
  Object.assign(S, {
    name,
    key: activeKey,
    salt: activeSalt,
    kdf: activeKdf,
    master: pw,
    entries,
    sel: null,
    view: 'home',
    open: {},
    fails: 0,
    lockUntil: 0,
    last: Date.now(),
  });
  if (upgraded) await seal();
}

const sel = (): Entry | undefined => S.entries.find((e) => e.id === S.sel);

async function copy(t: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(t);
    toast('Copied. Clipboard clears in 20 seconds.');
    setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 20000);
  } catch {
    toast('Copy blocked by the browser. Use Show instead.');
  }
}

function toast(m: string): void {
  const t = $('#toast');
  if (t) {
    t.textContent = m;
    setTimeout(() => {
      if (t.textContent === m) t.textContent = '';
    }, 4000);
  }
}

function lockApp(): void {
  Object.assign(S, {
    key: null,
    salt: null,
    master: '',
    entries: [],
    name: null,
    sel: null,
    view: 'home',
    open: {},
    chal: null,
    _f: null,
    _gp: null,
    filter: 'all',
    pending: null,
  });
  const kit = $('#kit');
  if (kit) kit.innerHTML = '';
  render();
}

(['click', 'keydown', 'mousemove', 'touchstart'] as const).forEach((ev) =>
  addEventListener(ev, () => (S.last = Date.now()), { passive: true }),
);
setInterval(() => {
  const m = cfg().lockMin;
  if (S.key && m && Date.now() - S.last > m * 60000) lockApp();
}, 5000);
addEventListener('keydown', (e) => {
  if (!S.key) return;
  const t = e.target as HTMLElement | null;
  const typing =
    t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
  if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === 'l') {
    e.preventDefault();
    lockApp();
    return;
  }
  if (e.key === 'Escape' && cfg().escLock) {
    if (typing) {
      t.blur();
      return;
    }
    e.preventDefault();
    lockApp();
  }
});

async function checkPwned(): Promise<void> {
  const e = sel();
  const box = $('#pwn');
  if (!e || !box) return;
  box.className = 'note';
  box.textContent = 'Checking… only a 5-character hash prefix is sent.';
  try {
    const n = await pwnedCount(e.password);
    if (sel()?.id !== e.id) return;
    box.className = 'note ' + (n ? 'no' : 'yes');
    box.textContent = n
      ? `This password appears in ${n.toLocaleString()} known data breaches. Change it on ${e.service} and here.`
      : 'Not found in any known breach.';
  } catch {
    box.className = 'note no';
    box.textContent = 'Could not reach the breach database. Check your connection and try again.';
  }
}

async function tickTotp(): Promise<void> {
  const e = S.key && S.view === 'detail' ? sel() : undefined;
  const el = document.getElementById('totp');
  if (!e || !e.totpSecret || !el || !el.isConnected) return;
  try {
    const t = await totpCode(e.totpSecret);
    el.textContent = t.code.replace(/^(\d{3,4})(\d{3,4})$/, '$1 $2');
    const r = document.getElementById('totp_ring') as SVGCircleElement | null;
    if (r) {
      r.style.strokeDashoffset = String(100 - (100 * t.left) / t.period);
      if (r.parentElement) r.parentElement.dataset.low = t.left <= 5 ? '1' : '';
    }
    const l = document.getElementById('totp_left');
    if (l) l.textContent = t.left + 's';
  } catch {
    el.textContent = 'Invalid secret';
  }
}
setInterval(tickTotp, 1000);

async function copyTotp(): Promise<void> {
  try {
    const s = sel()?.totpSecret;
    if (!s) return;
    await copy((await totpCode(s)).code);
  } catch {
    toast('This 2FA secret is invalid.');
  }
}

function totpHtml(e: Entry): string {
  if (!e.totpSecret) return '';
  return `<div class="kv"><span>2FA code</span><span class="mono totp" id="totp">······</span><span class="row">
  <svg class="ring" viewBox="0 0 36 36" width="28" height="28" aria-hidden="true"><circle cx="18" cy="18" r="15.9" pathLength="100"/><circle id="totp_ring" cx="18" cy="18" r="15.9" pathLength="100"/></svg>
  <span class="mute" id="totp_left" style="min-width:2.2em"></span><button onclick="copyTotp()">Copy</button></span></div>`;
}

function auditView(): string {
  const a = audit(S.entries);
  const link = (e: Entry) =>
    `<button class="item" onclick="S.sel='${e.id}';S.view='detail';render()">${esc(e.service)}<small>${esc(e.username || e.email || '')}</small></button>`;
  const sec = (t: string, d: string, items: unknown[], body: string) =>
    `<div class="note ${items.length ? 'no' : 'yes'}"><strong>${t} (${items.length})</strong><div class="mute" style="font-size:.85rem">${d}</div>${items.length ? body : ''}</div>`;
  return `<div class="card"><h2>Vault health</h2><p class="mute">Analysed on this device only. Nothing is sent anywhere.</p>
  <div class="bar"><i style="width:${a.score}%"></i></div><p><strong>${a.score}%</strong> of your ${S.entries.length} entries have no password issues.</p>
  ${sec('Reused passwords', 'The same password is used on more than one service. One breach exposes all of them.', a.reused, a.reused.map((g, i) => `<div style="margin-top:.5rem"><span class="mute">Group ${i + 1}</span>${g.map(link).join('')}</div>`).join(''))}
  ${sec('Weak passwords', 'Estimated under 60 bits of entropy. Replace with a generated password.', a.weak, a.weak.map((e) => link(e).replace('</small>', ` · ~${pwBits(e.password)} bits</small>`)).join(''))}
  ${sec('Not changed in ' + STALE_DAYS + '+ days', 'Old passwords are more likely to have leaked. Consider rotating them.', a.stale, a.stale.map((e) => link(e).replace('</small>', ` · since ${new Date(e.pwChanged || e.created).toLocaleDateString()}</small>`)).join(''))}
  ${sec('Missing username or email', 'You may not know which account this password belongs to.', a.noId, a.noId.map(link).join(''))}</div>`;
}

async function importCSV(file?: File, input?: HTMLInputElement): Promise<void> {
  if (!file) return;
  const box = $('#imp');
  try {
    const batch = csvToEntries(await file.text());
    if (!S.key) {
      S.pending = batch;
      render();
      return;
    }
    const { added, dup } = mergeEntries(S.entries, batch.entries);
    if (added) await seal();
    render();
    toast(
      `Imported ${added} entr${added === 1 ? 'y' : 'ies'} from ${batch.fmt}${dup ? `, skipped ${dup} duplicate${dup > 1 ? 's' : ''}` : ''}. Delete the CSV file now: it is unencrypted.`,
    );
  } catch (err) {
    if (box) {
      box.className = 'note no';
      box.textContent = 'Import failed: ' + (err instanceof Error ? err.message : String(err));
    }
  } finally {
    if (input) input.value = '';
  }
}

async function flushPending(): Promise<void> {
  if (!S.pending || !S.key) return;
  const p = S.pending;
  S.pending = null;
  const { added, dup } = mergeEntries(S.entries, p.entries);
  if (added) await seal();
  render();
  toast(
    `Imported ${added} entr${added === 1 ? 'y' : 'ies'} from ${p.fmt}${dup ? `, skipped ${dup} duplicates` : ''}. Delete the CSV file now: it is unencrypted.`,
  );
}

const importHtml = (): string =>
  `<label for="csv">Import passwords from CSV (Bitwarden, KeePass, 1Password, Chrome, Firefox)</label>
  <input id="csv" type="file" accept=".csv,text/csv" onchange="importCSV(this.files[0],this)"><div id="imp" role="status"></div>
  <p class="mute" style="font-size:.8rem">The file is parsed on this device only. Duplicates are skipped. Delete the unencrypted CSV afterwards.</p>`;

function render(): void {
  const app = $('#app');
  if (!app) return;
  app.innerHTML = S.key ? vault() : gate();
  if (S.key) drawRight();
}

function gate(): string {
  const names = Object.keys(load());
  return `<div class="gate"><h1>Vaultkeep</h1>
  <p class="mute">Your passwords stay encrypted on this device. Nothing is sent anywhere unless you run the optional breach check.</p>
  ${
    names.length
      ? `<h3>Open a profile</h3>
  <label for="pn">Profile</label><select id="pn">${names.map((n) => `<option>${esc(n)}</option>`).join('')}</select>
  <label for="pp">Master password</label><input id="pp" type="password" autocomplete="off" onkeydown="if(event.key==='Enter')doUnlock()">
  <p class="err" id="ge"></p><button class="p" onclick="doUnlock()">Unlock</button>
  <hr style="border:0;border-top:1px solid var(--line);margin:1.4rem 0">`
      : ''
  }
  <h3>Create a new profile</h3>
  <label for="nn">Profile name</label><input id="nn" autocomplete="off">
  <label for="n1">Master password (12+ characters)</label><input id="n1" type="password" autocomplete="off">
  <label for="n2">Repeat master password</label><input id="n2" type="password" autocomplete="off">
  <p class="mute" style="font-size:.85rem">There is no recovery. If you forget this password, the vault cannot be opened. That is what keeps it safe.</p>
  <p class="err" id="ce"></p><button class="p" onclick="doCreate()">Create profile</button>
  <p class="mute" style="margin-top:1.2rem"><label style="display:inline">Restore a backup: <input type="file" accept=".json" onchange="importBackup(this.files[0])" style="margin-top:.3rem"></label></p>
  ${importHtml()}${S.pending ? `<div class="note yes">${S.pending.entries.length} entries from ${esc(S.pending.fmt)} are waiting. Unlock or create a profile to import them. <button onclick="S.pending=null;render()">Discard</button></div>` : ''}</div>`;
}

async function doUnlock(): Promise<void> {
  const e = $('#ge');
  const pn = $<HTMLSelectElement>('#pn');
  const pp = $<HTMLInputElement>('#pp');
  if (!e || !pn || !pp) return;
  e.textContent = 'Checking…';
  try {
    await unlockProfile(pn.value, pp.value);
  } catch {
    e.textContent = 'Wrong master password for this profile.';
    return;
  }
  render();
  await flushPending();
}

async function doCreate(): Promise<void> {
  const nn = $<HTMLInputElement>('#nn');
  const n1 = $<HTMLInputElement>('#n1');
  const n2 = $<HTMLInputElement>('#n2');
  const e = $('#ce');
  if (!nn || !n1 || !n2 || !e) return;
  const n = nn.value.trim();
  const a = n1.value;
  const b = n2.value;
  if (!n) {
    e.textContent = 'Enter a profile name.';
    return;
  }
  if (load()[n]) {
    e.textContent = 'That profile name already exists.';
    return;
  }
  if (a.length < 12) {
    e.textContent = 'Use at least 12 characters.';
    return;
  }
  if (a !== b) {
    e.textContent = 'The two passwords do not match.';
    return;
  }
  e.textContent = 'Creating…';
  const salt = newSalt();
  const { key, kdf } = await deriveKey(a, salt, DEFAULT_KDF);
  Object.assign(S, { name: n, salt, key, kdf, master: a, entries: [], sel: null, view: 'home', open: {} });
  await seal();
  render();
  await flushPending();
}

function vault(): string {
  return `<div class="top"><div><h2 style="margin:0">Vaultkeep</h2><span class="mute">Profile: ${esc(S.name)} · ${lockLabel()} · <kbd>Ctrl/⌘+L</kbd> locks</span></div>
  <div class="row"><button onclick="S.view='gen';drawRight()">Generator</button><button onclick="S.view='audit';drawRight()">Health</button><button onclick="S.view='settings';drawRight()">Settings</button><button onclick="exportBackup()">Export backup</button><button onclick="printKit()">Emergency kit</button><button class="p" onclick="lockApp()">Lock</button></div></div>
  <div class="grid"><div class="card"><div class="row" id="pills" style="gap:.3rem;margin-bottom:.7rem">${pillsHtml()}</div><h3>Do I have an account?</h3>
  <input id="q" placeholder="Type a service, e.g. claude.ai" oninput="check(this.value)" autocomplete="off">
  <div id="chk"></div><div class="row" style="margin-top:.8rem;justify-content:space-between"><h3 style="margin:0">Saved services</h3><button onclick="newEntry()">Add</button></div>
  <div class="list" id="list">${listHtml()}</div></div><div id="right"></div></div><p class="mute" id="toast" role="status"></p>`;
}

function listHtml(): string {
  if (!S.entries.length)
    return '<p class="mute">Nothing saved yet. Use the box above to check a service, then create its password here.</p>';
  const shown = S.entries
    .filter((e) => matchFilter(e, S.filter))
    .sort((a, b) => (b.fav ? 1 : 0) - (a.fav ? 1 : 0) || a.service.localeCompare(b.service));
  if (!shown.length) return '<p class="mute">No entries match this filter.</p>';
  return shown
    .map(
      (e) =>
        `<button class="item ${e.id === S.sel ? 'on' : ''}" onclick="S.sel='${e.id}';S.view='detail';render()">${e.fav ? '<span class="star" aria-label="Favorite">★</span> ' : ''}${esc(e.service)}${(e.type || 'login') !== 'login' ? ` <span class="tag">${TYPES[e.type!]}</span>` : ''}<small>${esc(e.username || e.email || (e.tags || []).map((t) => '#' + t).join(' '))}</small></button>`,
    )
    .join('');
}

function pillsHtml(): string {
  const f = S.filter || 'all';
  const types = new Set<EntryType>(S.entries.map((e) => e.type || 'login'));
  const tags = [...new Set(S.entries.flatMap((e) => e.tags || []))].sort();
  const p = (k: string, l: string) =>
    `<button class="pill ${f === k ? 'on' : ''}" onclick="S.filter='${k}';document.getElementById('list').innerHTML=listHtml();document.getElementById('pills').innerHTML=pillsHtml()">${l}</button>`;
  return (
    p('all', 'All') +
    (S.entries.some((e) => e.fav) ? p('fav', '★ Favorites') : '') +
    (Object.keys(TYPES) as EntryType[])
      .filter((t) => types.has(t))
      .map((t) => p('type:' + t, TYPES[t] + 's'))
      .join('') +
    tags.map((t) => p('tag:' + t, '#' + esc(t))).join('')
  );
}

async function toggleFav(): Promise<void> {
  const e = sel();
  if (!e) return;
  e.fav = e.fav ? 0 : 1;
  await seal();
  render();
  toast(e.fav ? 'Pinned to the top.' : 'Removed from favorites.');
}

function applyType(t: EntryType): void {
  readForm();
  const f = S._f;
  if (!f) return;
  f.type = t;
  const tpl = TYPE_FIELDS[t];
  if (tpl && !(f.fields || []).some((c) => c.label || c.value)) {
    f.fields = tpl.map(([label, masked]) => ({ label, value: '', masked }));
  }
  drawRight();
}

function check(v: string): void {
  const q = norm(v);
  const box = $('#chk');
  if (!box) return;
  if (!q) {
    box.innerHTML = '';
    return;
  }
  const hits = S.entries.filter((e) => {
    const s = norm(e.service);
    return s.includes(q) || q.includes(s);
  });
  box.innerHTML = hits.length
    ? `<div class="note yes">Yes. You already have ${hits.length > 1 ? hits.length + ' accounts' : 'an account'} here:${hits.map((h) => `<div><button class="item" onclick="S.sel='${h.id}';S.view='detail';render()">${esc(h.service)} · saved ${new Date(h.created).toLocaleDateString()}</button></div>`).join('')}</div>`
    : `<div class="note no">No account saved for “${esc(v.trim())}”. If you sign up, create it here so the password is generated and stored together.<div style="margin-top:.6rem"><button class="p" onclick="newEntry(document.getElementById('q').value.trim())">Create with a generated password</button></div></div>`;
}

function drawRight(): void {
  const r = $('#right');
  if (!r) return;
  const list = $('#list');
  if (list) list.innerHTML = listHtml();
  const pl = $('#pills');
  if (pl) pl.innerHTML = pillsHtml();
  setTimeout(tickTotp, 0);
  const current = sel();
  r.innerHTML =
    S.view === 'gen'
      ? genView()
      : S.view === 'settings'
        ? settingsView()
        : S.view === 'audit'
          ? auditView()
          : S.view === 'form'
            ? formView()
            : S.view === 'detail' && current
              ? detailView(current)
              : `<div class="card"><h2>Welcome back</h2><p class="mute">Check a service on the left before you sign up anywhere. If you already have an account, you'll see it. If not, create one with a generated password and keep its recovery details together.</p></div>`;
}

function settingsView(): string {
  const c = cfg();
  return `<div class="card"><h2>Settings</h2><p class="mute">These preferences apply to this browser on this device.</p>
  <h3>Security</h3>
  <label for="s_lock">Auto-lock when idle</label><select id="s_lock" onchange="setCfg({lockMin:+this.value});S.last=Date.now();render()">
  ${LOCK_OPTS.map(([v, l]) => `<option value="${v}" ${c.lockMin === v ? 'selected' : ''}>${l}</option>`).join('')}</select>
  ${c.lockMin ? '' : '<p class="err" style="font-size:.85rem">With auto-lock off, anyone with access to this unlocked screen can read your vault.</p>'}
  <label style="display:flex;gap:.5rem;align-items:center"><input type="checkbox" style="width:auto" ${c.escLock ? 'checked' : ''} onchange="setCfg({escLock:this.checked?1:0})">Lock immediately with the Escape key</label>
  <p class="mute" style="font-size:.85rem">Ctrl+L (⌘+L on Mac) always locks the vault. Locking wipes the decrypted entries and key from memory.</p>
  <h3 style="margin-top:1.2rem">Import</h3>${importHtml()}
  <h3 style="margin-top:1.2rem">Storage &amp; cryptography</h3>
  <p class="mute" style="font-size:.85rem">${S.storage === 'indexeddb' ? 'Encrypted vaults are stored in IndexedDB on this device.' : 'IndexedDB is unavailable here, so vaults are stored in localStorage (about 5 MB limit). Export backups regularly.'} Key derivation: ${S.kdf.kdf === 'argon2id' ? `Argon2id (${Math.round((S.kdf.m || 65536) / 1024)} MiB, t=${S.kdf.t || 3}, p=${S.kdf.p || 4})` : `PBKDF2-SHA256 (${(S.kdf.t || 600000).toLocaleString()} iterations)`} → AES-256-GCM.</p></div>`;
}

function genView(): string {
  const g = S.g;
  const b = bits(g);
  const pw = S._gp || (S._gp = genAny(g));
  const W = g.mode === 'words';
  const cb = (k: 'lo' | 'up' | 'di' | 'sy' | 'am' | 'cap' | 'num', t: string) =>
    `<label style="display:inline-flex;gap:.3rem;margin-right:1rem"><input type="checkbox" style="width:auto" ${g[k] ? 'checked' : ''} onchange="S.g.${k}=this.checked?1:0;S._gp=null;drawRight()">${t}</label>`;
  const tab = (m: 'chars' | 'words', t: string) =>
    `<button class="${g.mode === m ? 'p' : ''}" onclick="S.g.mode='${m}';S._gp=null;drawRight()">${t}</button>`;
  return `<div class="card"><h2>Password generator</h2><div class="row">${tab('chars', 'Random characters')}${tab('words', 'Passphrase')}</div>
  <div class="mono note" style="font-size:1.1rem">${esc(pw)}</div>
  <div class="bar"><i style="width:${Math.min(100, b / 1.4)}%"></i></div><p class="mute">${strength(b)} · about ${b} bits of entropy</p>
  ${
    W
      ? `<label for="gw">Words: ${g.words}</label><input id="gw" type="range" min="4" max="10" value="${g.words}" oninput="S.g.words=+this.value;S._gp=null;drawRight()">
  <label for="gs">Separator</label><select id="gs" onchange="S.g.sep=this.value;S._gp=null;drawRight()">${SEPS.map(([v, l]) => `<option value="${v}" ${g.sep === v ? 'selected' : ''}>${l}</option>`).join('')}</select>
  <p>${cb('cap', 'Capitalize words')}${cb('num', 'Add a digit')}</p>
  <p class="mute" style="font-size:.85rem">Words are picked uniformly from the ${WORDS.length}-word EFF list (${Math.log2(WORDS.length).toFixed(1)} bits each). Easy to type and remember.</p>`
      : `<label for="gl">Length: ${g.len}</label><input id="gl" type="range" min="12" max="64" value="${g.len}" oninput="S.g.len=+this.value;S._gp=null;drawRight()">
  <p>${cb('lo', 'a–z')}${cb('up', 'A–Z')}${cb('di', '0–9')}${cb('sy', 'Symbols')}${cb('am', 'Skip look-alikes (l I 1 O 0)')}</p>`
  }
  <div class="row"><button onclick="S._gp=null;drawRight()">Regenerate</button><button class="p" onclick="copy(S._gp)">Copy</button></div>
  <p class="mute" style="font-size:.85rem">New entries use the mode selected here.</p></div>`;
}

function newEntry(svc = ''): void {
  S.sel = null;
  S._f = {
    type: 'login',
    service: svc,
    username: '',
    email: '',
    password: genAny(S.g),
    totpSecret: '',
    recEmail: '',
    qa: '',
    notes: '',
    fields: [],
    tags: [],
    fav: 0,
  };
  S.view = 'form';
  render();
}

function editEntry(): void {
  const e = sel();
  if (!e) return;
  S._f = {
    ...e,
    type: e.type || 'login',
    totpSecret: e.totpSecret || '',
    fav: e.fav || 0,
    history: [...(e.history || [])],
    fields: (e.fields || []).map((c) => ({ ...c })),
    tags: [...(e.tags || [])],
  };
  S.view = 'form';
  render();
}

const HISTORY_MAX = 20;

function historyHtml(e: Entry): string {
  const h = e.history || [];
  return `<details class="hist"><summary>Password history (${h.length})</summary>
  ${
    h.length
      ? h
          .map(
            (x, i) =>
              `<div class="kv"><span>${new Date(x.changedAt).toLocaleString()}</span><span class="mono" id="ph_${i}">••••••••••••</span><span class="row">
  <button onclick="const p=document.getElementById('ph_${i}');p.textContent=p.dataset.s?'••••••••••••':sel().history[${i}].password;p.dataset.s=p.dataset.s?'':1">Show</button><button onclick="copy(sel().history[${i}].password)">Copy</button></span></div>`,
          )
          .join('')
      : '<p class="mute" style="font-size:.85rem">Previous passwords appear here after you change this one. Useful if a password change fails on the website.</p>'
  }</details>`;
}

function formView(): string {
  const f = S._f;
  if (!f) return '';
  const editing = !!f.id;
  const T: EntryType = f.type || 'login';
  const inp = (k: 'service' | 'username' | 'email' | 'recEmail', l: string, t = 'text') =>
    `<label for="f_${k}">${l}</label><input id="f_${k}" type="${t}" value="${esc(f[k])}" autocomplete="off">`;
  return `<div class="card"><h2>${editing ? 'Edit' : 'New'} ${TYPES[T].toLowerCase()}</h2>
  <label for="f_type">Type</label><select id="f_type" onchange="applyType(this.value)">${Object.entries(TYPES)
    .map(([k, l]) => `<option value="${k}" ${T === k ? 'selected' : ''}>${l}</option>`)
    .join('')}</select>
  ${inp('service', T === 'login' ? 'Service' : 'Name')}${inp('username', 'Username')}${inp('email', 'Account email')}
  <label for="f_password">Password${T === 'login' ? '' : ' (optional)'}</label><div class="row"><input id="f_password" class="mono" style="flex:1" value="${esc(f.password)}"><button onclick="document.getElementById('f_password').value=genAny(S.g);">Generate</button></div>
  <label for="f_totpSecret">2FA secret (optional, base32 key or otpauth:// link)</label><input id="f_totpSecret" class="mono" value="${esc(f.totpSecret)}" autocomplete="off" spellcheck="false" placeholder="JBSW Y3DP EHPK 3PXP">
  <label for="f_tags">Tags (comma separated)</label><input id="f_tags" value="${esc((f.tags || []).join(', '))}" autocomplete="off" placeholder="work, finance">
  <label style="display:flex;gap:.5rem;align-items:center"><input id="f_fav" type="checkbox" style="width:auto" ${f.fav ? 'checked' : ''}>★ Favorite (pin to top)</label>

  <h3 style="margin-top:1.2rem">Protected details</h3><p class="mute" style="margin:0">Shown only after the master-password check.</p>
  ${inp('recEmail', 'Recovery email or phone')}
  <label for="f_qa">Security questions (one per line: question | answer)</label><textarea id="f_qa">${esc(f.qa)}</textarea>
  <label for="f_notes">Notes</label><textarea id="f_notes">${esc(f.notes)}</textarea>
  <h3 style="margin-top:1.2rem">Custom fields</h3><p class="mute" style="margin:0;font-size:.85rem">PINs, server ports, API tokens, license keys… Masked fields are hidden until you click Show.</p>
  ${(f.fields || [])
    .map(
      (c, i) => `<div class="cf"><input id="cf_l_${i}" placeholder="Label, e.g. PIN" value="${esc(c.label)}" autocomplete="off" aria-label="Field ${i + 1} label">
  <input id="cf_v_${i}" class="mono" placeholder="Value" value="${esc(c.value)}" type="${c.masked ? 'password' : 'text'}" autocomplete="off" aria-label="Field ${i + 1} value">
  <label class="cf-m"><input id="cf_m_${i}" type="checkbox" ${c.masked ? 'checked' : ''} onchange="document.getElementById('cf_v_${i}').type=this.checked?'password':'text'">Masked</label>
  <button class="d" onclick="readForm();S._f.fields.splice(${i},1);drawRight()" aria-label="Remove field ${i + 1}">✕</button></div>`,
    )
    .join('')}
  <button style="margin-top:.6rem" onclick="readForm();S._f.fields.push({label:'',value:'',masked:1});drawRight()">Add field</button>
  <div class="row" style="margin-top:1rem"><button class="p" onclick="saveEntry()">Save</button><button onclick="S.view=S._f.id?'detail':'home';render()">Cancel</button></div></div>`;
}

const FORM_KEYS = ['type', 'service', 'username', 'email', 'password', 'totpSecret', 'recEmail', 'qa', 'notes'] as const;

function readForm(): FormDraft | null {
  const f = S._f;
  if (!f) return null;
  const v = <T extends HTMLElement = HTMLInputElement>(id: string) => document.getElementById(id) as T | null;
  FORM_KEYS.forEach((k) => {
    const el = v('f_' + k);
    if (el) (f as unknown as Record<string, string>)[k] = el.value;
  });
  const tagsEl = v('f_tags');
  if (tagsEl) f.tags = parseTags(tagsEl.value);
  const favEl = v('f_fav');
  if (favEl) f.fav = favEl.checked ? 1 : 0;
  f.fields = (f.fields || []).map((c, i) => {
    const l = v('cf_l_' + i);
    const val = v('cf_v_' + i);
    const m = v('cf_m_' + i);
    return l && val && m ? { label: l.value, value: val.value, masked: m.checked ? 1 : 0 } : c;
  });
  return f;
}

async function saveEntry(): Promise<void> {
  const f = readForm();
  if (!f) return;
  if (!f.service.trim()) {
    toast('A name is required.');
    return;
  }
  if ((f.type || 'login') === 'login' && !f.password) {
    toast('Logins need a password.');
    return;
  }
  f.totpSecret = (f.totpSecret || '').trim();
  if (f.totpSecret) {
    try {
      parseTotp(f.totpSecret);
    } catch (err) {
      toast('2FA secret is not valid: ' + (err instanceof Error ? err.message : String(err)));
      return;
    }
  }
  const base = {
    ...f,
    service: f.service.trim(),
    username: f.username.trim(),
    email: f.email.trim(),
    recEmail: f.recEmail.trim(),
    fields: f.fields.map((c) => ({ ...c, label: c.label.trim() })).filter((c) => c.label || c.value),
  };
  const prev = base.id ? S.entries.find((x) => x.id === base.id) : undefined;
  let history = base.history ?? [];
  let pwChanged = base.pwChanged ?? base.created ?? Date.now();
  if (prev && prev.password && prev.password !== base.password) {
    history = [{ password: prev.password, changedAt: Date.now() }, ...(prev.history || [])].slice(0, HISTORY_MAX);
    pwChanged = Date.now();
  }
  let saved: Entry;
  if (base.id) {
    saved = { ...base, id: base.id, created: base.created ?? Date.now(), pwChanged, history };
    S.entries = S.entries.map((x) => (x.id === saved.id ? saved : x));
  } else {
    const now = Date.now();
    saved = { ...base, id: uid(), created: now, pwChanged: now, history: [] };
    S.entries.push(saved);
  }
  await seal();
  S.sel = saved.id;
  S.view = 'detail';
  render();
  toast('Saved and encrypted.');
}

async function delEntry(): Promise<void> {
  if (!confirm('Delete this service permanently?')) return;
  S.entries = S.entries.filter((e) => e.id !== S.sel);
  S.sel = null;
  S.view = 'home';
  await seal();
  render();
}

function detailView(e: Entry): string {
  const open = (S.open[e.id] || 0) > Date.now();
  const kv = (l: string, v?: string, c?: string) =>
    `<div class="kv"><span>${l}</span><span class="mono">${esc(v || '—')}</span><span>${c || ''}</span></div>`;
  const cp = (id: 'username' | 'email') => `<button onclick="copy(sel().${id})">Copy</button>`;
  return `<div class="card"><div class="row" style="justify-content:space-between"><h2 style="margin:0">${esc(e.service)}</h2><div class="row"><button onclick="toggleFav()" aria-pressed="${e.fav ? 'true' : 'false'}" title="Pin to the top of the list">${e.fav ? '★ Favorite' : '☆ Favorite'}</button><button onclick="editEntry()">Edit</button><button class="d" onclick="delEntry()">Delete</button></div></div>
  ${(e.type || 'login') !== 'login' || (e.tags || []).length ? `<div class="row" style="gap:.3rem;margin-top:.4rem"><span class="tag">${TYPES[e.type || 'login']}</span>${(e.tags || []).map((t) => `<span class="tag">#${esc(t)}</span>`).join('')}</div>` : ''}
  <p class="mute">Saved ${new Date(e.created).toLocaleDateString()}</p>
  ${kv('Username', e.username, e.username ? cp('username') : '')}${kv('Account email', e.email, e.email ? cp('email') : '')}
  <div class="kv"><span>Password</span><span class="mono" id="pw">••••••••••••</span><span class="row"><button onclick="const p=document.getElementById('pw');p.textContent=p.dataset.s?'••••••••••••':sel().password;p.dataset.s=p.dataset.s?'':1">Show</button><button onclick="copy(sel().password)">Copy</button></span></div>
  ${totpHtml(e)}
  <div class="row" style="margin-top:.6rem"><button onclick="checkPwned()" title="Sends only the first 5 characters of the password's SHA-1 hash to api.pwnedpasswords.com">Check pwned</button><span class="mute" style="font-size:.85rem">Optional online check. Your password never leaves this device.</span></div><div id="pwn" role="status"></div>
  ${(e.fields || [])
    .map(
      (c, i) => `<div class="kv"><span>${esc(c.label || 'Field ' + (i + 1))}</span><span class="mono" id="cfv_${i}">${c.masked ? '••••••••' : esc(c.value || '—')}</span><span class="row">
  ${c.masked ? `<button onclick="const p=document.getElementById('cfv_${i}');p.textContent=p.dataset.s?'••••••••':sel().fields[${i}].value;p.dataset.s=p.dataset.s?'':1">Show</button>` : ''}${c.value ? `<button onclick="copy(sel().fields[${i}].value)">Copy</button>` : ''}</span></div>`,
    )
    .join('')}
  ${historyHtml(e)}
  ${
    open
      ? `<div class="lock"><h3>Protected details <span class="mute" style="font-size:.8rem">(open until ${new Date(S.open[e.id]!).toLocaleTimeString()})</span></h3>
  ${kv('Recovery', e.recEmail)}<div class="kv"><span>Security Q&amp;A</span><span class="mono" style="white-space:pre-wrap">${esc(e.qa || '—')}</span><span></span></div>${kv('Notes', e.notes)}
  <button onclick="delete S.open['${e.id}'];drawRight()">Hide now</button></div>`
      : challenge(e)
  }</div>`;
}

function challenge(e: Entry): string {
  const wait = Math.ceil((S.lockUntil - Date.now()) / 1000);
  if (wait > 0)
    return `<div class="lock"><h3>Protected details</h3><p class="err">Too many wrong answers. Try again in ${wait}s.</p><button onclick="drawRight()">Refresh</button></div>`;
  if (!S.chal) {
    const p = new Set<number>();
    while (p.size < 3) p.add(rnd(S.master.length));
    S.chal = [...p].sort((a, b) => a - b);
  }
  return `<div class="lock"><h3>Protected details are locked</h3><p class="mute">Recovery info and security answers need two checks: your full master password, and three of its characters at random positions.</p>
  <label for="c_m">Master password</label><input id="c_m" type="password" autocomplete="off">
  <div class="row" style="margin-top:.7rem">${S.chal.map((p, i) => `<label style="margin:0">#${p + 1} <input class="pos" id="c_${i}" maxlength="1" autocomplete="off"></label>`).join('')}</div>
  <p class="err" id="ce2"></p><button class="p" onclick="verify('${e.id}')">Unlock for 30 seconds</button></div>`;
}

function verify(id: string): void {
  const cm = $<HTMLInputElement>('#c_m');
  const chal = S.chal || [];
  const ok =
    !!cm &&
    cm.value === S.master &&
    chal.every((p, i) => (document.getElementById('c_' + i) as HTMLInputElement | null)?.value === S.master[p]);
  S.chal = null;
  if (ok) {
    S.fails = 0;
    S.open[id] = Date.now() + 30000;
    drawRight();
    setTimeout(drawRight, 30500);
    return;
  }
  S.fails++;
  if (S.fails >= 3) S.lockUntil = Date.now() + 30000 * 2 ** (S.fails - 3);
  drawRight();
  const e = $('#ce2');
  if (e) e.textContent = 'Those answers do not match.';
}

function exportBackup(): void {
  if (!S.name) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(
    new Blob([JSON.stringify({ vaultkeep: 1, profile: S.name, data: load()[S.name] })], { type: 'application/json' }),
  );
  a.download = `vaultkeep-${S.name}.json`;
  a.click();
  toast('Encrypted backup downloaded. It is useless without your master password.');
}

function kitHtml(): string {
  const rec: Partial<ProfileRecord> = (S.name && load()[S.name]) || {};
  const made = rec.created ? new Date(rec.created).toLocaleDateString() : 'Not recorded (profile predates this feature)';
  const row = (l: string, v: string) => `<tr><td>${l}</td><td${v ? '' : ' class="k-blank"'}>${v ? esc(v) : ''}</td></tr>`;
  return `<h1>Vaultkeep Emergency Kit</h1><p class="k-sub">Keep this sheet somewhere safe and offline. Anyone holding it and your backup file can open your vault.</p>
  <table>${row('Profile name', S.name || '')}${row('Profile created', made)}${row('Kit printed', new Date().toLocaleString())}${row('App', 'Vaultkeep (vaultkeep.html), runs offline in any modern browser')}</table>
  <div class="k-box"><strong>Master password</strong> (write by hand, never type it into a file)<table>${row('Master password', '')}${row('Hint (optional)', '')}</table></div>
  <div class="k-box"><strong>Where things are kept</strong><table>${row('Encrypted backup file location', '')}${row('Copy of vaultkeep.html location', '')}${row('Physical location of this kit', '')}</table></div>
  <h3>How to recover your vault</h3><ol>
  <li>Open a copy of <em>vaultkeep.html</em> in a modern browser (Chrome, Firefox, Edge, Safari). No internet connection is needed.</li>
  <li>On the start screen choose <em>Restore a backup</em> and select your <em>vaultkeep-${esc(S.name)}.json</em> file.</li>
  <li>Select the restored profile and enter the master password written above.</li>
  <li>Export a fresh backup after recovery and store it in at least two places.</li></ol>
  <p><strong>There is no password reset.</strong> Without the master password the backup cannot be decrypted by anyone, including the Vaultkeep authors.</p>
  <p class="k-foot">Generated locally by Vaultkeep. This sheet contains no stored passwords.</p>`;
}

function printKit(): void {
  const k = $('#kit');
  if (!k) return;
  k.innerHTML = kitHtml();
  window.print();
  setTimeout(() => (k.innerHTML = ''), 1000);
}

async function importBackup(f?: File): Promise<void> {
  if (!f) return;
  let j: { vaultkeep?: number; profile?: string; data?: ProfileRecord };
  try {
    j = JSON.parse(await f.text()) as typeof j;
    if (!j.vaultkeep || !j.data || !j.data.ct) throw new Error('Invalid backup');
  } catch {
    alert('That file is not a Vaultkeep backup.');
    return;
  }
  const all = load();
  let n = j.profile || 'Restored';
  while (all[n]) n += ' (restored)';
  all[n] = j.data;
  try {
    await store(all);
  } catch {
    alert('Could not save restored backup to storage.');
    return;
  }
  render();
  alert('Restored as profile “' + n + '”.');
}

/* Expose handlers used by inline onclick/oninput attributes while the template UI is in place (replaced in Phase 3). */
Object.assign(globalThis, {
  S,
  sel,
  copy,
  lockApp,
  checkPwned,
  copyTotp,
  importCSV,
  render,
  doUnlock,
  doCreate,
  listHtml,
  pillsHtml,
  toggleFav,
  applyType,
  check,
  drawRight,
  setCfg,
  genAny,
  newEntry,
  editEntry,
  readForm,
  saveEntry,
  delEntry,
  verify,
  exportBackup,
  printKit,
  importBackup,
});

const appEl = $('#app');
if (appEl) {
  appEl.innerHTML = '<p class="mute" style="text-align:center;margin-top:20vh">Opening vault storage…</p>';
  initStorage().then((k) => {
    S.storage = k;
    navigator.storage?.persist?.().catch(() => {});
    render();
  });
}
