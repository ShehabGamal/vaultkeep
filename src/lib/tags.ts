import type { Entry, EntryType, Flag } from './types';

export const TYPES: Record<EntryType, string> = {
  login: 'Login',
  note: 'Secure note',
  card: 'Credit card',
  api: 'API key',
};

export const TYPE_FIELDS: Partial<Record<EntryType, readonly [string, Flag][]>> = {
  card: [
    ['Cardholder name', 0],
    ['Card number', 1],
    ['Expiry (MM/YY)', 0],
    ['CVV', 1],
  ],
  api: [
    ['API key', 1],
    ['Endpoint', 0],
  ],
};

export const parseTags = (s: string): string[] => [
  ...new Set(
    String(s || '')
      .split(',')
      .map((t) =>
        t
          .trim()
          .toLowerCase()
          .replace(/[^\p{L}\p{N} _-]/gu, '')
          .trim(),
      )
      .filter(Boolean),
  ),
];

export function matchFilter(e: Entry, filter = 'all'): boolean {
  return (
    filter === 'all' ||
    (filter === 'fav' && !!e.fav) ||
    (filter.startsWith('type:') && (e.type ?? 'login') === filter.slice(5)) ||
    (filter.startsWith('tag:') && (e.tags ?? []).includes(filter.slice(4)))
  );
}

export const norm = (s: string): string =>
  String(s)
    .toLowerCase()
    .trim()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/\/.*$/, '')
    .replace(/\.(com|org|net|io|ai|app|co)$/, '');
