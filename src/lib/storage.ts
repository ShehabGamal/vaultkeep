import type { ProfileMap } from './types';

/* Storage: IndexedDB with an in-memory mirror, localStorage fallback.
   All encrypted profile records live in IndexedDB (db "vaultkeep", store "profiles", key = profile name).
   load() is synchronous and reads the mirror; store() updates the mirror and persists atomically.
   Legacy "vaultkeep.v1" localStorage data is migrated once and removed only after a verified write. */
export const LEGACY_KEY = 'vaultkeep.v1';
const IDB_NAME = 'vaultkeep';
const IDB_STORE = 'profiles';

export type StorageKind = 'indexeddb' | 'localstorage';

let DB: ProfileMap = {};
let idb: IDBDatabase | null = null;
let kind: StorageKind = 'localstorage';

const idbReq = <T>(r: IDBRequest<T>): Promise<T> =>
  new Promise((ok, no) => {
    r.onsuccess = () => ok(r.result);
    r.onerror = () => no(r.error);
  });

function idbTx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => T): Promise<T> {
  return new Promise((ok, no) => {
    if (!idb) return no(new Error('IndexedDB not open'));
    const t = idb.transaction(IDB_STORE, mode);
    const out = fn(t.objectStore(IDB_STORE));
    t.oncomplete = () => ok(out);
    t.onerror = t.onabort = () => no(t.error ?? new Error('IndexedDB transaction failed'));
  });
}

async function idbOpen(): Promise<IDBDatabase> {
  if (typeof indexedDB === 'undefined') throw new Error('IndexedDB unavailable');
  const r = indexedDB.open(IDB_NAME, 1);
  r.onupgradeneeded = () => r.result.createObjectStore(IDB_STORE);
  const db = await idbReq(r);
  db.onversionchange = () => db.close();
  return db;
}

async function idbReadAll(): Promise<ProfileMap> {
  const o: ProfileMap = {};
  await idbTx('readonly', (s) => {
    const c = s.openCursor();
    c.onsuccess = () => {
      const k = c.result;
      if (k) {
        o[String(k.key)] = k.value as ProfileMap[string];
        k.continue();
      }
    };
  });
  return o;
}

function legacyLoad(): ProfileMap {
  try {
    return (JSON.parse(localStorage.getItem(LEGACY_KEY) ?? 'null') as ProfileMap | null) ?? {};
  } catch {
    return {};
  }
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

export async function initStorage(): Promise<StorageKind> {
  try {
    idb = await idbOpen();
    DB = await idbReadAll();
    const legacy = legacyLoad();
    const missing = Object.keys(legacy).filter((n) => !(n in DB));
    if (missing.length) {
      await idbTx('readwrite', (s) => missing.forEach((n) => s.put(legacy[n], n)));
      const check = await idbReadAll();
      if (missing.every((n) => same(check[n], legacy[n]))) {
        DB = check;
        localStorage.removeItem(LEGACY_KEY);
      } else throw new Error('Migration verification failed');
    } else if (localStorage.getItem(LEGACY_KEY) !== null && Object.keys(legacy).every((n) => same(DB[n], legacy[n]))) {
      localStorage.removeItem(LEGACY_KEY);
    }
    kind = 'indexeddb';
  } catch (err) {
    idb = null;
    DB = legacyLoad();
    kind = 'localstorage';
    console.warn('Vaultkeep: falling back to localStorage', err);
  }
  return kind;
}

export const storageKind = (): StorageKind => kind;

export const load = (): ProfileMap => structuredClone(DB);

/** Replace all profile records atomically. Restores the previous mirror and rethrows on failure. */
export async function store(o: ProfileMap): Promise<void> {
  const prev = DB;
  DB = structuredClone(o);
  try {
    if (idb)
      await idbTx('readwrite', (s) => {
        s.clear();
        for (const [n, v] of Object.entries(DB)) s.put(v, n);
      });
    else localStorage.setItem(LEGACY_KEY, JSON.stringify(DB));
  } catch (err) {
    DB = prev;
    throw err;
  }
}

/** Test helper: close the database and reset the mirror. */
export function _resetStorage(): void {
  idb?.close();
  idb = null;
  DB = {};
  kind = 'localstorage';
}
