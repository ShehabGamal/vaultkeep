import { uid } from './encoding';
import { parseTags } from './tags';
import { parseTotp } from './totp';
import type { CustomField, Entry, EntryType, NewEntry } from './types';

/* CSV importer (Bitwarden, KeePass/KeePassXC, 1Password, Chrome, Firefox, generic). */
export function parseCSV(raw: string): string[][] {
  const text = String(raw).replace(/^\uFEFF/, '');
  const rows: string[][] = [];
  let row: string[] = [];
  let f = '';
  let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (q) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          f += '"';
          i++;
        } else q = false;
      } else f += c;
    } else if (c === '"' && f === '') q = true;
    else if (c === ',') {
      row.push(f);
      f = '';
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(f);
      f = '';
      if (row.length > 1 || row[0] !== '') rows.push(row);
      row = [];
    } else f += c;
  }
  if (f !== '' || row.length) {
    row.push(f);
    if (row.length > 1 || row[0] !== '') rows.push(row);
  }
  return rows;
}

const CSV_COLS = {
  service: ['name', 'title', 'account'],
  url: ['url', 'login_uri', 'web site', 'website', 'login url'],
  username: ['username', 'login_username', 'login name', 'user name', 'login'],
  password: ['password', 'login_password'],
  totp: ['login_totp', 'totp', 'otpauth', 'one-time password'],
  notes: ['notes', 'note', 'comments', 'extra'],
  tags: ['folder', 'group', 'tags'],
  fav: ['favorite', 'favourite'],
  type: ['type'],
  fields: ['fields'],
  created: ['timecreated', 'created', 'creation time'],
  changed: ['timepasswordchanged', 'last modified', 'password last modified'],
} as const;

type ColKey = keyof typeof CSV_COLS;

export function detectFormat(h: readonly string[]): string {
  const has = (k: string) => h.includes(k);
  return has('login_password')
    ? 'Bitwarden'
    : has('httprealm') || has('formactionorigin')
      ? 'Firefox'
      : (has('group') && has('title')) || has('login name')
        ? 'KeePass'
        : has('otpauth') || has('archived')
          ? '1Password'
          : h.join() === 'name,url,username,password' || h.join() === 'name,url,username,password,note'
            ? 'Chrome'
            : 'Generic CSV';
}

const toTime = (v: string): number => {
  if (!v) return 0;
  const n = +v;
  if (n > 1e11) return n;
  const d = Date.parse(v);
  return isNaN(d) ? 0 : d;
};

export interface CsvImportBatch {
  fmt: string;
  entries: NewEntry[];
}

export function csvToEntries(text: string): CsvImportBatch {
  const rows = parseCSV(text);
  if (rows.length < 2) throw new Error('The file has no data rows.');
  const h = rows[0]!.map((x) => x.trim().toLowerCase());
  const fmt = detectFormat(h);
  const idx = {} as Record<ColKey, number>;
  (Object.keys(CSV_COLS) as ColKey[]).forEach((k) => {
    const aliases: readonly string[] = CSV_COLS[k];
    idx[k] = h.findIndex((x) => aliases.includes(x));
  });
  if (idx.password < 0 && idx.notes < 0) throw new Error('No password column found. Is this a password export?');
  const out: NewEntry[] = [];
  for (const r of rows.slice(1)) {
    const g = (k: ColKey) => (idx[k] >= 0 ? (r[idx[k]] ?? '').trim() : '');
    const pw = idx.password >= 0 ? (r[idx.password] ?? '') : '';
    const url = g('url');
    const bwType = g('type').toLowerCase();
    let host = '';
    try {
      host = url ? new URL(/^[a-z][\w+.-]*:\/\//i.test(url) ? url : 'https://' + url).hostname.replace(/^www\./, '') : '';
    } catch {
      /* ignore malformed URLs */
    }
    if (/^(chrome|about|moz-extension):/i.test(url)) continue;
    const type: EntryType =
      bwType === 'note' || bwType === 'securenote'
        ? 'note'
        : bwType === 'card'
          ? 'card'
          : bwType === 'identity'
            ? 'note'
            : 'login';
    const service = g('service') || host || url;
    if (!service && !pw) continue;
    const user = g('username');
    const isMail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(user);
    const fields: CustomField[] = [];
    if (url) fields.push({ label: 'URL', value: url, masked: 0 });
    if (g('fields')) {
      g('fields')
        .split(/\r?\n/)
        .forEach((l) => {
          const m = l.match(/^([^:]+):\s?(.*)$/);
          if (m) fields.push({ label: m[1]!.trim(), value: m[2] ?? '', masked: 1 });
        });
    }
    let totp = g('totp');
    if (totp) {
      try {
        parseTotp(totp);
      } catch {
        fields.push({ label: 'TOTP', value: totp, masked: 1 });
        totp = '';
      }
    }
    const created = toTime(g('created')) || Date.now();
    out.push({
      type,
      service: service || '(untitled)',
      username: isMail ? '' : user,
      email: isMail ? user : '',
      password: pw,
      totpSecret: totp,
      recEmail: '',
      qa: '',
      notes: g('notes'),
      fields,
      tags: parseTags(g('tags').replace(/[\\/]/g, ',')),
      fav: /^(1|true|yes)$/i.test(g('fav')) ? 1 : 0,
      created,
      pwChanged: toTime(g('changed')) || created,
      history: [],
    });
  }
  return { fmt, entries: out };
}

/** Merge new entries into `target` in place, skipping exact duplicates. Returns counts. */
export function mergeEntries(target: Entry[], list: readonly NewEntry[]): { added: number; dup: number } {
  const key = (e: NewEntry) => [e.service.toLowerCase(), e.username, e.email, e.password].join('\u0000');
  const seen = new Set(target.map(key));
  let added = 0;
  let dup = 0;
  for (const e of list) {
    if (seen.has(key(e))) {
      dup++;
      continue;
    }
    seen.add(key(e));
    target.push({ ...e, id: uid() });
    added++;
  }
  return { added, dup };
}
