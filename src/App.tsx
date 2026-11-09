import { useEffect, useState } from 'preact/hooks';
import { audit, STALE_DAYS } from './lib/audit';
import { pwnedCount } from './lib/breach';
import { decryptRecord, DEFAULT_KDF, deriveKey, encryptEntries, newSalt } from './lib/crypto';
import { csvToEntries, mergeEntries, type CsvImportBatch } from './lib/csv';
import { b64, uid } from './lib/encoding';
import { bits, DEFAULT_GEN, genAny, pwBits, rnd, SEPS, strength, type GenOptions } from './lib/generator';
import { cfg, lockLabel, LOCK_OPTS, setCfg, type DeviceSettings } from './lib/settings';
import { initStorage, load, store, type StorageKind } from './lib/storage';
import { matchFilter, norm, parseTags, TYPE_FIELDS, TYPES } from './lib/tags';
import { parseTotp, totpCode } from './lib/totp';
import type { CustomField, Entry, EntryType, Flag, KdfParams, ProfileRecord } from './lib/types';
import { WORDS } from './lib/words';

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
  tagsInput: string;
  fav: Flag;
  created?: number;
  pwChanged?: number;
  history?: Entry['history'];
}

const HISTORY_MAX = 20;

export function App() {
  const [ready, setReady] = useState(false);
  const [storage, setStorage] = useState<StorageKind>('indexeddb');
  const [profilesVersion, setProfilesVersion] = useState(0);
  const [name, setName] = useState<string | null>(null);
  const [key, setKey] = useState<CryptoKey | null>(null);
  const [salt, setSalt] = useState<Uint8Array<ArrayBuffer> | null>(null);
  const [kdf, setKdf] = useState<KdfParams>({ ...DEFAULT_KDF });
  const [master, setMaster] = useState('');
  const [entries, setEntries] = useState<Entry[]>([]);
  const [selId, setSelId] = useState<string | null>(null);
  const [view, setView] = useState<ViewName>('home');
  const [filter, setFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [pending, setPending] = useState<CsvImportBatch | null>(null);
  const [toastMsg, setToastMsg] = useState('');
  const [genOpts, setGenOpts] = useState<GenOptions>({ ...DEFAULT_GEN });
  const [genPreview, setGenPreview] = useState<string>(() => genAny(DEFAULT_GEN));
  const [draft, setDraft] = useState<FormDraft | null>(null);
  const [openMap, setOpenMap] = useState<Record<string, number>>({});
  const [fails, setFails] = useState(0);
  const [lockUntil, setLockUntil] = useState(0);
  const [settings, setSettings] = useState<DeviceSettings>(() => cfg());
  const [kitPrintedAt, setKitPrintedAt] = useState('');

  // Gate form state
  const [unlockProfileName, setUnlockProfileName] = useState('');
  const [unlockPw, setUnlockPw] = useState('');
  const [unlockErr, setUnlockErr] = useState('');
  const [newProfileName, setNewProfileName] = useState('');
  const [newPw1, setNewPw1] = useState('');
  const [newPw2, setNewPw2] = useState('');
  const [createErr, setCreateErr] = useState('');
  const [importErr, setImportErr] = useState('');

  function toast(m: string): void {
    setToastMsg(m);
    setTimeout(() => {
      setToastMsg((cur) => (cur === m ? '' : cur));
    }, 4000);
  }

  async function copy(t: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(t);
      toast('Copied. Clipboard clears in 20 seconds.');
      setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 20000);
    } catch {
      toast('Copy blocked by the browser. Use Show instead.');
    }
  }

  function lockApp(): void {
    setKey(null);
    setSalt(null);
    setMaster('');
    setEntries([]);
    setName(null);
    setSelId(null);
    setView('home');
    setOpenMap({});
    setDraft(null);
    setFilter('all');
    setSearchQuery('');
    setPending(null);
    setUnlockPw('');
    setUnlockErr('');
  }

  useEffect(() => {
    initStorage().then((k) => {
      setStorage(k);
      const names = Object.keys(load());
      if (names[0]) setUnlockProfileName(names[0]);
      setReady(true);
      navigator.storage?.persist?.().catch(() => {});
    });
  }, []);

  // Idle auto-lock & keyboard shortcuts (Ctrl/Cmd+L and Escape)
  useEffect(() => {
    if (!key) return;
    let last = Date.now();
    const bump = () => {
      last = Date.now();
    };
    const events = ['click', 'keydown', 'mousemove', 'touchstart'] as const;
    events.forEach((ev) => addEventListener(ev, bump, { passive: true }));
    const timer = setInterval(() => {
      const m = cfg().lockMin;
      if (m && Date.now() - last > m * 60000) lockApp();
    }, 5000);
    const onKey = (e: KeyboardEvent) => {
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
    };
    addEventListener('keydown', onKey);
    return () => {
      events.forEach((ev) => removeEventListener(ev, bump));
      clearInterval(timer);
      removeEventListener('keydown', onKey);
    };
  }, [key]);

  async function sealWith(
    nextEntries: Entry[],
    activeName = name,
    activeKey = key,
    activeSalt = salt,
    activeKdf = kdf,
  ): Promise<void> {
    if (!activeKey || !activeName || !activeSalt) return;
    const { iv, ct } = await encryptEntries(activeKey, nextEntries);
    const all = load();
    all[activeName] = {
      salt: b64(activeSalt),
      iv,
      ct,
      created: all[activeName]?.created || Date.now(),
      ...activeKdf,
    };
    try {
      await store(all);
      setProfilesVersion((v) => v + 1);
    } catch (err) {
      const errName = err instanceof Error ? err.name : 'error';
      alert('Could not save to browser storage (' + errName + '). Export a backup and use a normal browser window.');
      throw err;
    }
  }

  async function flushPendingInto(
    baseEntries: Entry[],
    activeName: string,
    activeKey: CryptoKey,
    activeSalt: Uint8Array<ArrayBuffer>,
    activeKdf: KdfParams,
  ): Promise<Entry[]> {
    if (!pending) return baseEntries;
    const p = pending;
    setPending(null);
    const merged = [...baseEntries];
    const { added, dup } = mergeEntries(merged, p.entries);
    if (added) await sealWith(merged, activeName, activeKey, activeSalt, activeKdf);
    toast(
      `Imported ${added} entr${added === 1 ? 'y' : 'ies'} from ${p.fmt}${dup ? `, skipped ${dup} duplicates` : ''}. Delete the CSV file now: it is unencrypted.`,
    );
    return merged;
  }

  async function handleUnlock(): Promise<void> {
    const all = load();
    const target = unlockProfileName || Object.keys(all)[0] || '';
    const rec = all[target];
    if (!rec) return;
    setUnlockErr('Checking…');
    try {
      const unlocked = await decryptRecord(rec, unlockPw);
      let activeKey = unlocked.key;
      let activeSalt = unlocked.salt;
      let activeKdf = unlocked.kdf;
      let upgraded = false;
      if (unlocked.kdf.kdf !== 'argon2id') {
        const nextSalt = newSalt();
        const derived = await deriveKey(unlockPw, nextSalt, DEFAULT_KDF);
        if (derived.kdf.kdf === 'argon2id') {
          activeKey = derived.key;
          activeSalt = nextSalt;
          activeKdf = derived.kdf;
          upgraded = true;
        }
      }
      if (upgraded) {
        await sealWith(unlocked.entries, target, activeKey, activeSalt, activeKdf);
      }
      const finalEntries = await flushPendingInto(unlocked.entries, target, activeKey, activeSalt, activeKdf);
      setName(target);
      setKey(activeKey);
      setSalt(activeSalt);
      setKdf(activeKdf);
      setMaster(unlockPw);
      setEntries(finalEntries);
      setSelId(null);
      setView('home');
      setOpenMap({});
      setFails(0);
      setLockUntil(0);
      setUnlockPw('');
      setUnlockErr('');
    } catch {
      setUnlockErr('Wrong master password for this profile.');
    }
  }

  async function handleCreate(): Promise<void> {
    const n = newProfileName.trim();
    if (!n) {
      setCreateErr('Enter a profile name.');
      return;
    }
    if (load()[n]) {
      setCreateErr('That profile name already exists.');
      return;
    }
    if (newPw1.length < 12) {
      setCreateErr('Use at least 12 characters.');
      return;
    }
    if (newPw1 !== newPw2) {
      setCreateErr('The two passwords do not match.');
      return;
    }
    setCreateErr('Creating…');
    const nextSalt = newSalt();
    const derived = await deriveKey(newPw1, nextSalt, DEFAULT_KDF);
    await sealWith([], n, derived.key, nextSalt, derived.kdf);
    const finalEntries = await flushPendingInto([], n, derived.key, nextSalt, derived.kdf);
    setName(n);
    setSalt(nextSalt);
    setKey(derived.key);
    setKdf(derived.kdf);
    setMaster(newPw1);
    setEntries(finalEntries);
    setSelId(null);
    setView('home');
    setOpenMap({});
    setNewProfileName('');
    setNewPw1('');
    setNewPw2('');
    setCreateErr('');
  }

  async function handleImportCSV(file?: File, input?: HTMLInputElement | null): Promise<void> {
    if (!file) return;
    setImportErr('');
    try {
      const batch = csvToEntries(await file.text());
      if (!key || !name || !salt) {
        setPending(batch);
        return;
      }
      const next = [...entries];
      const { added, dup } = mergeEntries(next, batch.entries);
      if (added) {
        await sealWith(next);
        setEntries(next);
      }
      toast(
        `Imported ${added} entr${added === 1 ? 'y' : 'ies'} from ${batch.fmt}${dup ? `, skipped ${dup} duplicate${dup > 1 ? 's' : ''}` : ''}. Delete the CSV file now: it is unencrypted.`,
      );
    } catch (err) {
      setImportErr('Import failed: ' + (err instanceof Error ? err.message : String(err)));
    } finally {
      if (input) input.value = '';
    }
  }

  async function handleImportBackup(f?: File): Promise<void> {
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
      setProfilesVersion((v) => v + 1);
      setUnlockProfileName(n);
    } catch {
      alert('Could not save restored backup to storage.');
      return;
    }
    alert('Restored as profile “' + n + '”.');
  }

  function exportBackup(): void {
    if (!name) return;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(
      new Blob([JSON.stringify({ vaultkeep: 1, profile: name, data: load()[name] })], { type: 'application/json' }),
    );
    a.download = `vaultkeep-${name}.json`;
    a.click();
    toast('Encrypted backup downloaded. It is useless without your master password.');
  }

  function printKit(): void {
    setKitPrintedAt(new Date().toLocaleString());
    setTimeout(() => window.print(), 20);
  }

  function startNewEntry(svc = ''): void {
    setSelId(null);
    setDraft({
      type: 'login',
      service: svc,
      username: '',
      email: '',
      password: genAny(genOpts),
      totpSecret: '',
      recEmail: '',
      qa: '',
      notes: '',
      fields: [],
      tagsInput: '',
      fav: 0,
    });
    setView('form');
  }

  function startEditEntry(e: Entry): void {
    setDraft({
      ...e,
      type: e.type || 'login',
      totpSecret: e.totpSecret || '',
      fav: e.fav || 0,
      history: [...(e.history || [])],
      fields: (e.fields || []).map((c) => ({ ...c })),
      tagsInput: (e.tags || []).join(', '),
    });
    setView('form');
  }

  async function saveDraft(): Promise<void> {
    if (!draft) return;
    if (!draft.service.trim()) {
      toast('A name is required.');
      return;
    }
    if ((draft.type || 'login') === 'login' && !draft.password) {
      toast('Logins need a password.');
      return;
    }
    const totpSecret = (draft.totpSecret || '').trim();
    if (totpSecret) {
      try {
        parseTotp(totpSecret);
      } catch (err) {
        toast('2FA secret is not valid: ' + (err instanceof Error ? err.message : String(err)));
        return;
      }
    }
    const tags = parseTags(draft.tagsInput);
    const cleanedFields = draft.fields
      .map((c) => ({ ...c, label: c.label.trim() }))
      .filter((c) => c.label || c.value);
    const prev = draft.id ? entries.find((x) => x.id === draft.id) : undefined;
    let history = draft.history ?? [];
    let pwChanged = draft.pwChanged ?? draft.created ?? Date.now();
    if (prev && prev.password && prev.password !== draft.password) {
      history = [{ password: prev.password, changedAt: Date.now() }, ...(prev.history || [])].slice(0, HISTORY_MAX);
      pwChanged = Date.now();
    }
    let saved: Entry;
    let nextEntries: Entry[];
    if (draft.id) {
      saved = {
        id: draft.id,
        type: draft.type,
        service: draft.service.trim(),
        username: draft.username.trim(),
        email: draft.email.trim(),
        password: draft.password,
        totpSecret,
        recEmail: draft.recEmail.trim(),
        qa: draft.qa,
        notes: draft.notes,
        fields: cleanedFields,
        tags,
        fav: draft.fav,
        created: draft.created ?? Date.now(),
        pwChanged,
        history,
      };
      nextEntries = entries.map((x) => (x.id === saved.id ? saved : x));
    } else {
      const now = Date.now();
      saved = {
        id: uid(),
        type: draft.type,
        service: draft.service.trim(),
        username: draft.username.trim(),
        email: draft.email.trim(),
        password: draft.password,
        totpSecret,
        recEmail: draft.recEmail.trim(),
        qa: draft.qa,
        notes: draft.notes,
        fields: cleanedFields,
        tags,
        fav: draft.fav,
        created: now,
        pwChanged: now,
        history: [],
      };
      nextEntries = [...entries, saved];
    }
    await sealWith(nextEntries);
    setEntries(nextEntries);
    setDraft(null);
    setSelId(saved.id);
    setView('detail');
    toast('Saved and encrypted.');
  }

  async function deleteSelected(): Promise<void> {
    if (!selId || !confirm('Delete this service permanently?')) return;
    const next = entries.filter((e) => e.id !== selId);
    await sealWith(next);
    setEntries(next);
    setSelId(null);
    setView('home');
  }

  async function toggleFavorite(e: Entry): Promise<void> {
    const nextFav: Flag = e.fav ? 0 : 1;
    const next = entries.map((x) => (x.id === e.id ? { ...x, fav: nextFav } : x));
    await sealWith(next);
    setEntries(next);
    toast(nextFav ? 'Pinned to the top.' : 'Removed from favorites.');
  }

  if (!ready) {
    return (
      <div class="wrap" id="app">
        <p class="mute" style="text-align:center;margin-top:20vh">
          Opening vault storage…
        </p>
      </div>
    );
  }

  const profileNames = Object.keys(load());
  void profilesVersion;

  if (!key) {
    return (
      <div class="wrap" id="app">
        <div class="gate">
          <h1>Vaultkeep</h1>
          <p class="mute">
            Your passwords stay encrypted on this device. Nothing is sent anywhere unless you run the optional breach
            check.
          </p>
          {profileNames.length > 0 && (
            <>
              <h3>Open a profile</h3>
              <label for="pn">Profile</label>
              <select
                id="pn"
                value={unlockProfileName || profileNames[0]}
                onChange={(e) => setUnlockProfileName(e.currentTarget.value)}
              >
                {profileNames.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
              <label for="pp">Master password</label>
              <input
                id="pp"
                type="password"
                autocomplete="off"
                value={unlockPw}
                onInput={(e) => setUnlockPw(e.currentTarget.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleUnlock();
                }}
              />
              <p class="err" id="ge">
                {unlockErr}
              </p>
              <button class="p" onClick={handleUnlock}>
                Unlock
              </button>
              <hr style="border:0;border-top:1px solid var(--line);margin:1.4rem 0" />
            </>
          )}
          <h3>Create a new profile</h3>
          <label for="nn">Profile name</label>
          <input
            id="nn"
            autocomplete="off"
            value={newProfileName}
            onInput={(e) => setNewProfileName(e.currentTarget.value)}
          />
          <label for="n1">Master password (12+ characters)</label>
          <input
            id="n1"
            type="password"
            autocomplete="off"
            value={newPw1}
            onInput={(e) => setNewPw1(e.currentTarget.value)}
          />
          <label for="n2">Repeat master password</label>
          <input
            id="n2"
            type="password"
            autocomplete="off"
            value={newPw2}
            onInput={(e) => setNewPw2(e.currentTarget.value)}
          />
          <p class="mute" style="font-size:.85rem">
            There is no recovery. If you forget this password, the vault cannot be opened. That is what keeps it safe.
          </p>
          <p class="err" id="ce">
            {createErr}
          </p>
          <button class="p" onClick={handleCreate}>
            Create profile
          </button>
          <p class="mute" style="margin-top:1.2rem">
            <label style="display:inline">
              Restore a backup:{' '}
              <input
                type="file"
                accept=".json"
                onChange={(e) => handleImportBackup(e.currentTarget.files?.[0])}
                style="margin-top:.3rem"
              />
            </label>
          </p>
          <CsvImportBox onFile={handleImportCSV} error={importErr} />
          {pending && (
            <div class="note yes">
              {pending.entries.length} entries from {pending.fmt} are waiting. Unlock or create a profile to import
              them. <button onClick={() => setPending(null)}>Discard</button>
            </div>
          )}
        </div>
      </div>
    );
  }

  const selectedEntry = entries.find((e) => e.id === selId);
  const shownEntries = entries
    .filter((e) => matchFilter(e, filter))
    .sort((a, b) => (b.fav ? 1 : 0) - (a.fav ? 1 : 0) || a.service.localeCompare(b.service));
  const presentTypes = new Set<EntryType>(entries.map((e) => e.type || 'login'));
  const presentTags = [...new Set(entries.flatMap((e) => e.tags || []))].sort();
  const qNorm = norm(searchQuery);
  const searchHits = qNorm
    ? entries.filter((e) => {
        const s = norm(e.service);
        return s.includes(qNorm) || qNorm.includes(s);
      })
    : [];

  return (
    <>
      <div class="wrap" id="app">
        <div class="top">
          <div>
            <h2 style="margin:0">Vaultkeep</h2>
            <span class="mute">
              Profile: {name} · {lockLabel()} · <kbd>Ctrl/⌘+L</kbd> locks
            </span>
          </div>
          <div class="row">
            <button onClick={() => setView('gen')}>Generator</button>
            <button onClick={() => setView('audit')}>Health</button>
            <button onClick={() => setView('settings')}>Settings</button>
            <button onClick={exportBackup}>Export backup</button>
            <button onClick={printKit}>Emergency kit</button>
            <button class="p" onClick={lockApp}>
              Lock
            </button>
          </div>
        </div>

        <div class="grid">
          <div class="card">
            <div class="row" id="pills" style="gap:.3rem;margin-bottom:.7rem">
              <button class={`pill ${filter === 'all' ? 'on' : ''}`} onClick={() => setFilter('all')}>
                All
              </button>
              {entries.some((e) => e.fav) && (
                <button class={`pill ${filter === 'fav' ? 'on' : ''}`} onClick={() => setFilter('fav')}>
                  ★ Favorites
                </button>
              )}
              {(Object.keys(TYPES) as EntryType[])
                .filter((t) => presentTypes.has(t))
                .map((t) => (
                  <button
                    key={t}
                    class={`pill ${filter === 'type:' + t ? 'on' : ''}`}
                    onClick={() => setFilter('type:' + t)}
                  >
                    {TYPES[t]}s
                  </button>
                ))}
              {presentTags.map((t) => (
                <button
                  key={t}
                  class={`pill ${filter === 'tag:' + t ? 'on' : ''}`}
                  onClick={() => setFilter('tag:' + t)}
                >
                  #{t}
                </button>
              ))}
            </div>

            <h3>Do I have an account?</h3>
            <input
              id="q"
              placeholder="Type a service, e.g. claude.ai"
              value={searchQuery}
              onInput={(e) => setSearchQuery(e.currentTarget.value)}
              autocomplete="off"
            />
            <div id="chk">
              {qNorm &&
                (searchHits.length ? (
                  <div class="note yes">
                    Yes. You already have {searchHits.length > 1 ? `${searchHits.length} accounts` : 'an account'} here:
                    {searchHits.map((h) => (
                      <div key={h.id}>
                        <button
                          class="item"
                          onClick={() => {
                            setSelId(h.id);
                            setView('detail');
                          }}
                        >
                          {h.service} · saved {new Date(h.created).toLocaleDateString()}
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div class="note no">
                    No account saved for “{searchQuery.trim()}”. If you sign up, create it here so the password is
                    generated and stored together.
                    <div style="margin-top:.6rem">
                      <button class="p" onClick={() => startNewEntry(searchQuery.trim())}>
                        Create with a generated password
                      </button>
                    </div>
                  </div>
                ))}
            </div>

            <div class="row" style="margin-top:.8rem;justify-content:space-between">
              <h3 style="margin:0">Saved services</h3>
              <button onClick={() => startNewEntry()}>Add</button>
            </div>

            <div class="list" id="list">
              {!entries.length ? (
                <p class="mute">
                  Nothing saved yet. Use the box above to check a service, then create its password here.
                </p>
              ) : !shownEntries.length ? (
                <p class="mute">No entries match this filter.</p>
              ) : (
                shownEntries.map((e) => (
                  <button
                    key={e.id}
                    class={`item ${e.id === selId ? 'on' : ''}`}
                    onClick={() => {
                      setSelId(e.id);
                      setView('detail');
                    }}
                  >
                    {e.fav ? (
                      <>
                        <span class="star" aria-label="Favorite">
                          ★
                        </span>{' '}
                      </>
                    ) : null}
                    {e.service}
                    {(e.type || 'login') !== 'login' && (
                      <>
                        {' '}
                        <span class="tag">{TYPES[e.type || 'login']}</span>
                      </>
                    )}
                    <small>{e.username || e.email || (e.tags || []).map((t) => '#' + t).join(' ')}</small>
                  </button>
                ))
              )}
            </div>
          </div>

          <div id="right">
            {view === 'gen' ? (
              <GeneratorCard
                opts={genOpts}
                preview={genPreview}
                onChange={(next) => {
                  setGenOpts(next);
                  setGenPreview(genAny(next));
                }}
                onRegenerate={() => setGenPreview(genAny(genOpts))}
                onCopy={() => copy(genPreview)}
              />
            ) : view === 'settings' ? (
              <SettingsCard
                settings={settings}
                storage={storage}
                kdf={kdf}
                importErr={importErr}
                onUpdate={(patch) => {
                  setCfg(patch);
                  setSettings(cfg());
                }}
                onImportCSV={handleImportCSV}
              />
            ) : view === 'audit' ? (
              <AuditCard
                entries={entries}
                onSelect={(id) => {
                  setSelId(id);
                  setView('detail');
                }}
              />
            ) : view === 'form' && draft ? (
              <EntryFormCard
                draft={draft}
                genOpts={genOpts}
                onChange={setDraft}
                onSave={saveDraft}
                onCancel={() => setView(draft.id ? 'detail' : 'home')}
              />
            ) : view === 'detail' && selectedEntry ? (
              <EntryDetailCard
                key={selectedEntry.id}
                entry={selectedEntry}
                master={master}
                openUntil={openMap[selectedEntry.id] || 0}
                fails={fails}
                lockUntil={lockUntil}
                onToggleFav={() => toggleFavorite(selectedEntry)}
                onEdit={() => startEditEntry(selectedEntry)}
                onDelete={deleteSelected}
                onCopy={copy}
                onToast={toast}
                onUnlockProtected={() => {
                  setFails(0);
                  const until = Date.now() + 30000;
                  setOpenMap((m) => ({ ...m, [selectedEntry.id]: until }));
                  setTimeout(() => setOpenMap((m) => ({ ...m })), 30500);
                }}
                onHideProtected={() =>
                  setOpenMap((m) => {
                    const copyMap = { ...m };
                    delete copyMap[selectedEntry.id];
                    return copyMap;
                  })
                }
                onFailChallenge={() => {
                  const nextFails = fails + 1;
                  setFails(nextFails);
                  if (nextFails >= 3) setLockUntil(Date.now() + 30000 * 2 ** (nextFails - 3));
                }}
              />
            ) : (
              <div class="card">
                <h2>Welcome back</h2>
                <p class="mute">
                  Check a service on the left before you sign up anywhere. If you already have an account, you'll see
                  it. If not, create one with a generated password and keep its recovery details together.
                </p>
              </div>
            )}
          </div>
        </div>
        <p class="mute" id="toast" role="status">
          {toastMsg}
        </p>
      </div>
      <EmergencyKit profileName={name || ''} printedAt={kitPrintedAt} />
    </>
  );
}

function CsvImportBox(props: {
  onFile: (f?: File, input?: HTMLInputElement | null) => void;
  error: string;
}) {
  return (
    <>
      <label for="csv">Import passwords from CSV (Bitwarden, KeePass, 1Password, Chrome, Firefox)</label>
      <input
        id="csv"
        type="file"
        accept=".csv,text/csv"
        onChange={(e) => props.onFile(e.currentTarget.files?.[0], e.currentTarget)}
      />
      <div id="imp" role="status" class={props.error ? 'note no' : ''}>
        {props.error}
      </div>
      <p class="mute" style="font-size:.8rem">
        The file is parsed on this device only. Duplicates are skipped. Delete the unencrypted CSV afterwards.
      </p>
    </>
  );
}

function GeneratorCard(props: {
  opts: GenOptions;
  preview: string;
  onChange: (next: GenOptions) => void;
  onRegenerate: () => void;
  onCopy: () => void;
}) {
  const g = props.opts;
  const b = bits(g);
  const W = g.mode === 'words';
  const toggle = (k: 'lo' | 'up' | 'di' | 'sy' | 'am' | 'cap' | 'num', label: string) => (
    <label style="display:inline-flex;gap:.3rem;margin-right:1rem">
      <input
        type="checkbox"
        style="width:auto"
        checked={!!g[k]}
        onChange={(e) => props.onChange({ ...g, [k]: (e.currentTarget.checked ? 1 : 0) as Flag })}
      />
      {label}
    </label>
  );
  return (
    <div class="card">
      <h2>Password generator</h2>
      <div class="row">
        <button class={g.mode === 'chars' ? 'p' : ''} onClick={() => props.onChange({ ...g, mode: 'chars' })}>
          Random characters
        </button>
        <button class={g.mode === 'words' ? 'p' : ''} onClick={() => props.onChange({ ...g, mode: 'words' })}>
          Passphrase
        </button>
      </div>
      <div class="mono note" style="font-size:1.1rem">
        {props.preview}
      </div>
      <div class="bar">
        <i style={`width:${Math.min(100, b / 1.4)}%`} />
      </div>
      <p class="mute">
        {strength(b)} · about {b} bits of entropy
      </p>
      {W ? (
        <>
          <label for="gw">Words: {g.words}</label>
          <input
            id="gw"
            type="range"
            min={4}
            max={10}
            value={g.words}
            onInput={(e) => props.onChange({ ...g, words: +e.currentTarget.value })}
          />
          <label for="gs">Separator</label>
          <select id="gs" value={g.sep} onChange={(e) => props.onChange({ ...g, sep: e.currentTarget.value })}>
            {SEPS.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
          <p>
            {toggle('cap', 'Capitalize words')}
            {toggle('num', 'Add a digit')}
          </p>
          <p class="mute" style="font-size:.85rem">
            Words are picked uniformly from the {WORDS.length}-word EFF list ({Math.log2(WORDS.length).toFixed(1)} bits
            each). Easy to type and remember.
          </p>
        </>
      ) : (
        <>
          <label for="gl">Length: {g.len}</label>
          <input
            id="gl"
            type="range"
            min={12}
            max={64}
            value={g.len}
            onInput={(e) => props.onChange({ ...g, len: +e.currentTarget.value })}
          />
          <p>
            {toggle('lo', 'a–z')}
            {toggle('up', 'A–Z')}
            {toggle('di', '0–9')}
            {toggle('sy', 'Symbols')}
            {toggle('am', 'Skip look-alikes (l I 1 O 0)')}
          </p>
        </>
      )}
      <div class="row">
        <button onClick={props.onRegenerate}>Regenerate</button>
        <button class="p" onClick={props.onCopy}>
          Copy
        </button>
      </div>
      <p class="mute" style="font-size:.85rem">
        New entries use the mode selected here.
      </p>
    </div>
  );
}

function SettingsCard(props: {
  settings: DeviceSettings;
  storage: StorageKind;
  kdf: KdfParams;
  importErr: string;
  onUpdate: (p: Partial<DeviceSettings>) => void;
  onImportCSV: (f?: File, input?: HTMLInputElement | null) => void;
}) {
  const c = props.settings;
  const k = props.kdf;
  return (
    <div class="card">
      <h2>Settings</h2>
      <p class="mute">These preferences apply to this browser on this device.</p>
      <h3>Security</h3>
      <label for="s_lock">Auto-lock when idle</label>
      <select id="s_lock" value={c.lockMin} onChange={(e) => props.onUpdate({ lockMin: +e.currentTarget.value })}>
        {LOCK_OPTS.map(([v, l]) => (
          <option key={v} value={v}>
            {l}
          </option>
        ))}
      </select>
      {!c.lockMin && (
        <p class="err" style="font-size:.85rem">
          With auto-lock off, anyone with access to this unlocked screen can read your vault.
        </p>
      )}
      <label style="display:flex;gap:.5rem;align-items:center">
        <input
          type="checkbox"
          style="width:auto"
          checked={!!c.escLock}
          onChange={(e) => props.onUpdate({ escLock: e.currentTarget.checked ? 1 : 0 })}
        />
        Lock immediately with the Escape key
      </label>
      <p class="mute" style="font-size:.85rem">
        Ctrl+L (⌘+L on Mac) always locks the vault. Locking wipes the decrypted entries and key from memory.
      </p>
      <h3 style="margin-top:1.2rem">Import</h3>
      <CsvImportBox onFile={props.onImportCSV} error={props.importErr} />
      <h3 style="margin-top:1.2rem">Storage &amp; cryptography</h3>
      <p class="mute" style="font-size:.85rem">
        {props.storage === 'indexeddb'
          ? 'Encrypted vaults are stored in IndexedDB on this device.'
          : 'IndexedDB is unavailable here, so vaults are stored in localStorage (about 5 MB limit). Export backups regularly.'}{' '}
        Key derivation:{' '}
        {k.kdf === 'argon2id'
          ? `Argon2id (${Math.round((k.m || 65536) / 1024)} MiB, t=${k.t || 3}, p=${k.p || 4})`
          : `PBKDF2-SHA256 (${(k.t || 600000).toLocaleString()} iterations)`}{' '}
        → AES-256-GCM.
      </p>
    </div>
  );
}

function AuditCard(props: { entries: Entry[]; onSelect: (id: string) => void }) {
  const a = audit(props.entries);
  const renderLink = (e: Entry, extra = '') => (
    <button key={e.id} class="item" onClick={() => props.onSelect(e.id)}>
      {e.service}
      <small>
        {e.username || e.email || ''}
        {extra}
      </small>
    </button>
  );
  return (
    <div class="card">
      <h2>Vault health</h2>
      <p class="mute">Analysed on this device only. Nothing is sent anywhere.</p>
      <div class="bar">
        <i style={`width:${a.score}%`} />
      </div>
      <p>
        <strong>{a.score}%</strong> of your {props.entries.length} entries have no password issues.
      </p>

      <div class={`note ${a.reused.length ? 'no' : 'yes'}`}>
        <strong>Reused passwords ({a.reused.length})</strong>
        <div class="mute" style="font-size:.85rem">
          The same password is used on more than one service. One breach exposes all of them.
        </div>
        {a.reused.map((g, i) => (
          <div key={i} style="margin-top:.5rem">
            <span class="mute">Group {i + 1}</span>
            {g.map((e) => renderLink(e))}
          </div>
        ))}
      </div>

      <div class={`note ${a.weak.length ? 'no' : 'yes'}`}>
        <strong>Weak passwords ({a.weak.length})</strong>
        <div class="mute" style="font-size:.85rem">
          Estimated under 60 bits of entropy. Replace with a generated password.
        </div>
        {a.weak.map((e) => renderLink(e, ` · ~${pwBits(e.password)} bits`))}
      </div>

      <div class={`note ${a.stale.length ? 'no' : 'yes'}`}>
        <strong>
          Not changed in {STALE_DAYS}+ days ({a.stale.length})
        </strong>
        <div class="mute" style="font-size:.85rem">
          Old passwords are more likely to have leaked. Consider rotating them.
        </div>
        {a.stale.map((e) => renderLink(e, ` · since ${new Date(e.pwChanged || e.created).toLocaleDateString()}`))}
      </div>

      <div class={`note ${a.noId.length ? 'no' : 'yes'}`}>
        <strong>Missing username or email ({a.noId.length})</strong>
        <div class="mute" style="font-size:.85rem">
          You may not know which account this password belongs to.
        </div>
        {a.noId.map((e) => renderLink(e))}
      </div>
    </div>
  );
}

function EntryFormCard(props: {
  draft: FormDraft;
  genOpts: GenOptions;
  onChange: (next: FormDraft) => void;
  onSave: () => void;
  onCancel: () => void;
}) {
  const f = props.draft;
  const editing = !!f.id;
  const T: EntryType = f.type || 'login';

  function handleTypeChange(nextType: EntryType): void {
    const tpl = TYPE_FIELDS[nextType];
    const shouldPrefill = tpl && !f.fields.some((c) => c.label || c.value);
    props.onChange({
      ...f,
      type: nextType,
      fields: shouldPrefill ? tpl.map(([label, masked]) => ({ label, value: '', masked })) : f.fields,
    });
  }

  return (
    <div class="card">
      <h2>
        {editing ? 'Edit' : 'New'} {TYPES[T].toLowerCase()}
      </h2>
      <label for="f_type">Type</label>
      <select id="f_type" value={T} onChange={(e) => handleTypeChange(e.currentTarget.value as EntryType)}>
        {(Object.entries(TYPES) as [EntryType, string][]).map(([k, l]) => (
          <option key={k} value={k}>
            {l}
          </option>
        ))}
      </select>

      <label for="f_service">{T === 'login' ? 'Service' : 'Name'}</label>
      <input
        id="f_service"
        value={f.service}
        onInput={(e) => props.onChange({ ...f, service: e.currentTarget.value })}
        autocomplete="off"
      />

      <label for="f_username">Username</label>
      <input
        id="f_username"
        value={f.username}
        onInput={(e) => props.onChange({ ...f, username: e.currentTarget.value })}
        autocomplete="off"
      />

      <label for="f_email">Account email</label>
      <input
        id="f_email"
        value={f.email}
        onInput={(e) => props.onChange({ ...f, email: e.currentTarget.value })}
        autocomplete="off"
      />

      <label for="f_password">Password{T === 'login' ? '' : ' (optional)'}</label>
      <div class="row">
        <input
          id="f_password"
          class="mono"
          style="flex:1"
          value={f.password}
          onInput={(e) => props.onChange({ ...f, password: e.currentTarget.value })}
        />
        <button onClick={() => props.onChange({ ...f, password: genAny(props.genOpts) })}>Generate</button>
      </div>

      <label for="f_totpSecret">2FA secret (optional, base32 key or otpauth:// link)</label>
      <input
        id="f_totpSecret"
        class="mono"
        value={f.totpSecret}
        onInput={(e) => props.onChange({ ...f, totpSecret: e.currentTarget.value })}
        autocomplete="off"
        spellcheck={false}
        placeholder="JBSW Y3DP EHPK 3PXP"
      />

      <label for="f_tags">Tags (comma separated)</label>
      <input
        id="f_tags"
        value={f.tagsInput}
        onInput={(e) => props.onChange({ ...f, tagsInput: e.currentTarget.value })}
        autocomplete="off"
        placeholder="work, finance"
      />

      <label style="display:flex;gap:.5rem;align-items:center">
        <input
          id="f_fav"
          type="checkbox"
          style="width:auto"
          checked={!!f.fav}
          onChange={(e) => props.onChange({ ...f, fav: e.currentTarget.checked ? 1 : 0 })}
        />
        ★ Favorite (pin to top)
      </label>

      <h3 style="margin-top:1.2rem">Protected details</h3>
      <p class="mute" style="margin:0">
        Shown only after the master-password check.
      </p>

      <label for="f_recEmail">Recovery email or phone</label>
      <input
        id="f_recEmail"
        value={f.recEmail}
        onInput={(e) => props.onChange({ ...f, recEmail: e.currentTarget.value })}
        autocomplete="off"
      />

      <label for="f_qa">Security questions (one per line: question | answer)</label>
      <textarea id="f_qa" value={f.qa} onInput={(e) => props.onChange({ ...f, qa: e.currentTarget.value })} />

      <label for="f_notes">Notes</label>
      <textarea
        id="f_notes"
        value={f.notes}
        onInput={(e) => props.onChange({ ...f, notes: e.currentTarget.value })}
      />

      <h3 style="margin-top:1.2rem">Custom fields</h3>
      <p class="mute" style="margin:0;font-size:.85rem">
        PINs, server ports, API tokens, license keys… Masked fields are hidden until you click Show.
      </p>
      {f.fields.map((c, i) => (
        <div key={i} class="cf">
          <input
            placeholder="Label, e.g. PIN"
            value={c.label}
            autocomplete="off"
            aria-label={`Field ${i + 1} label`}
            onInput={(e) => {
              const fields = f.fields.map((item, idx) => (idx === i ? { ...item, label: e.currentTarget.value } : item));
              props.onChange({ ...f, fields });
            }}
          />
          <input
            class="mono"
            placeholder="Value"
            value={c.value}
            type={c.masked ? 'password' : 'text'}
            autocomplete="off"
            aria-label={`Field ${i + 1} value`}
            onInput={(e) => {
              const fields = f.fields.map((item, idx) => (idx === i ? { ...item, value: e.currentTarget.value } : item));
              props.onChange({ ...f, fields });
            }}
          />
          <label class="cf-m">
            <input
              type="checkbox"
              checked={!!c.masked}
              onChange={(e) => {
                const masked: Flag = e.currentTarget.checked ? 1 : 0;
                const fields = f.fields.map((item, idx) => (idx === i ? { ...item, masked } : item));
                props.onChange({ ...f, fields });
              }}
            />
            Masked
          </label>
          <button
            class="d"
            aria-label={`Remove field ${i + 1}`}
            onClick={() => props.onChange({ ...f, fields: f.fields.filter((_, idx) => idx !== i) })}
          >
            ✕
          </button>
        </div>
      ))}
      <button
        style="margin-top:.6rem"
        onClick={() => props.onChange({ ...f, fields: [...f.fields, { label: '', value: '', masked: 1 }] })}
      >
        Add field
      </button>

      <div class="row" style="margin-top:1rem">
        <button class="p" onClick={props.onSave}>
          Save
        </button>
        <button onClick={props.onCancel}>Cancel</button>
      </div>
    </div>
  );
}

function EntryDetailCard(props: {
  entry: Entry;
  master: string;
  openUntil: number;
  fails: number;
  lockUntil: number;
  onToggleFav: () => void;
  onEdit: () => void;
  onDelete: () => void;
  onCopy: (text: string) => void;
  onToast: (msg: string) => void;
  onUnlockProtected: () => void;
  onHideProtected: () => void;
  onFailChallenge: () => void;
}) {
  const e = props.entry;
  const [showPw, setShowPw] = useState(false);
  const [shownFields, setShownFields] = useState<Record<number, boolean>>({});
  const [shownHistory, setShownHistory] = useState<Record<number, boolean>>({});
  const [pwnState, setPwnState] = useState<{ status: 'idle' | 'loading' | 'ok' | 'warn'; text: string }>({
    status: 'idle',
    text: '',
  });
  const [totpState, setTotpState] = useState<{ code: string; left: number; period: number; invalid?: boolean }>({
    code: '······',
    left: 30,
    period: 30,
  });

  // Challenge state
  const [chalPositions, setChalPositions] = useState<number[]>(() => pickChallenge(props.master.length));
  const [chalMaster, setChalMaster] = useState('');
  const [chalChars, setChalChars] = useState<[string, string, string]>(['', '', '']);
  const [chalErr, setChalErr] = useState('');
  const [, setNowTick] = useState(0);

  useEffect(() => {
    if (!e.totpSecret) return;
    let alive = true;
    const update = async () => {
      try {
        const r = await totpCode(e.totpSecret!);
        if (alive) {
          setTotpState({
            code: r.code.replace(/^(\d{3,4})(\d{3,4})$/, '$1 $2'),
            left: r.left,
            period: r.period,
          });
        }
      } catch {
        if (alive) setTotpState({ code: 'Invalid secret', left: 0, period: 30, invalid: true });
      }
    };
    update();
    const timer = setInterval(update, 1000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [e.totpSecret]);

  async function runPwnedCheck(): Promise<void> {
    setPwnState({ status: 'loading', text: 'Checking… only a 5-character hash prefix is sent.' });
    try {
      const n = await pwnedCount(e.password);
      setPwnState({
        status: n ? 'warn' : 'ok',
        text: n
          ? `This password appears in ${n.toLocaleString()} known data breaches. Change it on ${e.service} and here.`
          : 'Not found in any known breach.',
      });
    } catch {
      setPwnState({
        status: 'warn',
        text: 'Could not reach the breach database. Check your connection and try again.',
      });
    }
  }

  function verifyChallenge(): void {
    const ok =
      chalMaster === props.master && chalPositions.every((pos, idx) => chalChars[idx] === props.master[pos]);
    setChalPositions(pickChallenge(props.master.length));
    setChalMaster('');
    setChalChars(['', '', '']);
    if (ok) {
      setChalErr('');
      props.onUnlockProtected();
      return;
    }
    setChalErr('Those answers do not match.');
    props.onFailChallenge();
  }

  const isOpen = props.openUntil > Date.now();
  const waitSecs = Math.ceil((props.lockUntil - Date.now()) / 1000);
  const history = e.history || [];

  return (
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <h2 style="margin:0">{e.service}</h2>
        <div class="row">
          <button
            onClick={props.onToggleFav}
            aria-pressed={e.fav ? 'true' : 'false'}
            title="Pin to the top of the list"
          >
            {e.fav ? '★ Favorite' : '☆ Favorite'}
          </button>
          <button onClick={props.onEdit}>Edit</button>
          <button class="d" onClick={props.onDelete}>
            Delete
          </button>
        </div>
      </div>

      {((e.type || 'login') !== 'login' || (e.tags || []).length > 0) && (
        <div class="row" style="gap:.3rem;margin-top:.4rem">
          <span class="tag">{TYPES[e.type || 'login']}</span>
          {(e.tags || []).map((t) => (
            <span key={t} class="tag">
              #{t}
            </span>
          ))}
        </div>
      )}

      <p class="mute">Saved {new Date(e.created).toLocaleDateString()}</p>

      <div class="kv">
        <span>Username</span>
        <span class="mono">{e.username || '—'}</span>
        <span>{e.username ? <button onClick={() => props.onCopy(e.username)}>Copy</button> : null}</span>
      </div>

      <div class="kv">
        <span>Account email</span>
        <span class="mono">{e.email || '—'}</span>
        <span>{e.email ? <button onClick={() => props.onCopy(e.email)}>Copy</button> : null}</span>
      </div>

      <div class="kv">
        <span>Password</span>
        <span class="mono" id="pw">
          {showPw ? e.password : '••••••••••••'}
        </span>
        <span class="row">
          <button onClick={() => setShowPw((s) => !s)}>{showPw ? 'Hide' : 'Show'}</button>
          <button onClick={() => props.onCopy(e.password)}>Copy</button>
        </span>
      </div>

      {e.totpSecret && (
        <div class="kv">
          <span>2FA code</span>
          <span class="mono totp" id="totp">
            {totpState.code}
          </span>
          <span class="row">
            <svg
              class="ring"
              viewBox="0 0 36 36"
              width="28"
              height="28"
              aria-hidden="true"
              data-low={totpState.left <= 5 ? '1' : ''}
            >
              <circle cx="18" cy="18" r="15.9" pathLength={100} />
              <circle
                id="totp_ring"
                cx="18"
                cy="18"
                r="15.9"
                pathLength={100}
                style={`stroke-dashoffset:${100 - (100 * totpState.left) / totpState.period}`}
              />
            </svg>
            <span class="mute" id="totp_left" style="min-width:2.2em">
              {totpState.invalid ? '' : `${totpState.left}s`}
            </span>
            <button
              onClick={async () => {
                try {
                  props.onCopy((await totpCode(e.totpSecret!)).code);
                } catch {
                  props.onToast('This 2FA secret is invalid.');
                }
              }}
            >
              Copy
            </button>
          </span>
        </div>
      )}

      <div class="row" style="margin-top:.6rem">
        <button
          onClick={runPwnedCheck}
          title="Sends only the first 5 characters of the password's SHA-1 hash to api.pwnedpasswords.com"
        >
          Check pwned
        </button>
        <span class="mute" style="font-size:.85rem">
          Optional online check. Your password never leaves this device.
        </span>
      </div>
      {pwnState.status !== 'idle' && (
        <div
          id="pwn"
          role="status"
          class={`note ${pwnState.status === 'warn' ? 'no' : pwnState.status === 'ok' ? 'yes' : ''}`}
        >
          {pwnState.text}
        </div>
      )}

      {(e.fields || []).map((c, i) => {
        const revealed = !!shownFields[i];
        return (
          <div key={i} class="kv">
            <span>{c.label || `Field ${i + 1}`}</span>
            <span class="mono">{c.masked && !revealed ? '••••••••' : c.value || '—'}</span>
            <span class="row">
              {c.masked ? (
                <button onClick={() => setShownFields((m) => ({ ...m, [i]: !revealed }))}>
                  {revealed ? 'Hide' : 'Show'}
                </button>
              ) : null}
              {c.value ? <button onClick={() => props.onCopy(c.value)}>Copy</button> : null}
            </span>
          </div>
        );
      })}

      <details class="hist">
        <summary>Password history ({history.length})</summary>
        {history.length ? (
          history.map((x, i) => {
            const revealed = !!shownHistory[i];
            return (
              <div key={i} class="kv">
                <span>{new Date(x.changedAt).toLocaleString()}</span>
                <span class="mono">{revealed ? x.password : '••••••••••••'}</span>
                <span class="row">
                  <button onClick={() => setShownHistory((m) => ({ ...m, [i]: !revealed }))}>
                    {revealed ? 'Hide' : 'Show'}
                  </button>
                  <button onClick={() => props.onCopy(x.password)}>Copy</button>
                </span>
              </div>
            );
          })
        ) : (
          <p class="mute" style="font-size:.85rem">
            Previous passwords appear here after you change this one. Useful if a password change fails on the website.
          </p>
        )}
      </details>

      {isOpen ? (
        <div class="lock">
          <h3>
            Protected details{' '}
            <span class="mute" style="font-size:.8rem">
              (open until {new Date(props.openUntil).toLocaleTimeString()})
            </span>
          </h3>
          <div class="kv">
            <span>Recovery</span>
            <span class="mono">{e.recEmail || '—'}</span>
            <span />
          </div>
          <div class="kv">
            <span>Security Q&amp;A</span>
            <span class="mono" style="white-space:pre-wrap">
              {e.qa || '—'}
            </span>
            <span />
          </div>
          <div class="kv">
            <span>Notes</span>
            <span class="mono">{e.notes || '—'}</span>
            <span />
          </div>
          <button onClick={props.onHideProtected}>Hide now</button>
        </div>
      ) : waitSecs > 0 ? (
        <div class="lock">
          <h3>Protected details</h3>
          <p class="err">Too many wrong answers. Try again in {waitSecs}s.</p>
          <button onClick={() => setNowTick((n) => n + 1)}>Refresh</button>
        </div>
      ) : (
        <div class="lock">
          <h3>Protected details are locked</h3>
          <p class="mute">
            Recovery info and security answers need two checks: your full master password, and three of its characters
            at random positions.
          </p>
          <label for="c_m">Master password</label>
          <input
            id="c_m"
            type="password"
            autocomplete="off"
            value={chalMaster}
            onInput={(e) => setChalMaster(e.currentTarget.value)}
          />
          <div class="row" style="margin-top:.7rem">
            {chalPositions.map((p, i) => (
              <label key={i} style="margin:0">
                #{p + 1}{' '}
                <input
                  class="pos"
                  maxLength={1}
                  autocomplete="off"
                  value={chalChars[i]}
                  onInput={(ev) => {
                    const next: [string, string, string] = [...chalChars] as [string, string, string];
                    next[i] = ev.currentTarget.value;
                    setChalChars(next);
                  }}
                />
              </label>
            ))}
          </div>
          <p class="err" id="ce2">
            {chalErr}
          </p>
          <button class="p" onClick={verifyChallenge}>
            Unlock for 30 seconds
          </button>
        </div>
      )}
    </div>
  );
}

function pickChallenge(len: number): number[] {
  const p = new Set<number>();
  const bound = Math.max(3, len);
  while (p.size < 3) p.add(rnd(bound));
  return [...p].sort((a, b) => a - b);
}

function EmergencyKit(props: { profileName: string; printedAt: string }) {
  const rec: Partial<ProfileRecord> = (props.profileName && load()[props.profileName]) || {};
  const made = rec.created ? new Date(rec.created).toLocaleDateString() : 'Not recorded (profile predates this feature)';
  return (
    <div id="kit" aria-hidden="true">
      <h1>Vaultkeep Emergency Kit</h1>
      <p class="k-sub">
        Keep this sheet somewhere safe and offline. Anyone holding it and your backup file can open your vault.
      </p>
      <table>
        <tbody>
          <tr>
            <td>Profile name</td>
            <td>{props.profileName}</td>
          </tr>
          <tr>
            <td>Profile created</td>
            <td>{made}</td>
          </tr>
          <tr>
            <td>Kit printed</td>
            <td>{props.printedAt || new Date().toLocaleString()}</td>
          </tr>
          <tr>
            <td>App</td>
            <td>Vaultkeep (vaultkeep.html), runs offline in any modern browser</td>
          </tr>
        </tbody>
      </table>
      <div class="k-box">
        <strong>Master password</strong> (write by hand, never type it into a file)
        <table>
          <tbody>
            <tr>
              <td>Master password</td>
              <td class="k-blank" />
            </tr>
            <tr>
              <td>Hint (optional)</td>
              <td class="k-blank" />
            </tr>
          </tbody>
        </table>
      </div>
      <div class="k-box">
        <strong>Where things are kept</strong>
        <table>
          <tbody>
            <tr>
              <td>Encrypted backup file location</td>
              <td class="k-blank" />
            </tr>
            <tr>
              <td>Copy of vaultkeep.html location</td>
              <td class="k-blank" />
            </tr>
            <tr>
              <td>Physical location of this kit</td>
              <td class="k-blank" />
            </tr>
          </tbody>
        </table>
      </div>
      <h3>How to recover your vault</h3>
      <ol>
        <li>
          Open a copy of <em>vaultkeep.html</em> in a modern browser (Chrome, Firefox, Edge, Safari). No internet
          connection is needed.
        </li>
        <li>
          On the start screen choose <em>Restore a backup</em> and select your{' '}
          <em>vaultkeep-{props.profileName}.json</em> file.
        </li>
        <li>Select the restored profile and enter the master password written above.</li>
        <li>Export a fresh backup after recovery and store it in at least two places.</li>
      </ol>
      <p>
        <strong>There is no password reset.</strong> Without the master password the backup cannot be decrypted by
        anyone, including the Vaultkeep authors.
      </p>
      <p class="k-foot">Generated locally by Vaultkeep. This sheet contains no stored passwords.</p>
    </div>
  );
}
