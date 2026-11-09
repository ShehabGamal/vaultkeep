import { WORDS } from './words';
import type { Flag } from './types';

export type GenMode = 'chars' | 'words';

export interface GenOptions {
  mode: GenMode;
  len: number;
  up: Flag;
  lo: Flag;
  di: Flag;
  sy: Flag;
  am: Flag;
  words: number;
  sep: string;
  cap: Flag;
  num: Flag;
}

export const DEFAULT_GEN: GenOptions = {
  mode: 'chars',
  len: 20,
  up: 1,
  lo: 1,
  di: 1,
  sy: 1,
  am: 1,
  words: 5,
  sep: '-',
  cap: 0,
  num: 0,
};

export const SEPS: readonly [string, string][] = [
  ['-', 'Hyphen -'],
  ['.', 'Dot .'],
  ['_', 'Underscore _'],
  [' ', 'Space'],
  ['', 'None'],
];

/** Rejection-sampled uniform random integer in [0, n). */
export function rnd(n: number): number {
  const m = Math.floor(2 ** 32 / n) * n;
  const buf = new Uint32Array(1);
  let x = 0;
  do {
    crypto.getRandomValues(buf);
    x = buf[0]!;
  } while (x >= m);
  return x % n;
}

export function genSets(o: GenOptions): string[] {
  const f = (s: string) => (o.am ? s.replace(/[lIO01|]/g, '') : s);
  const a: string[] = [];
  if (o.lo) a.push(f('abcdefghijklmnopqrstuvwxyz'));
  if (o.up) a.push(f('ABCDEFGHIJKLMNOPQRSTUVWXYZ'));
  if (o.di) a.push(f('0123456789'));
  if (o.sy) a.push('!@#$%^&*()-_=+[]{};:,.?');
  return a;
}

export function gen(o: GenOptions = DEFAULT_GEN): string {
  const sets = genSets(o);
  if (!sets.length) return '';
  const pool = sets.join('');
  const out = sets.map((s) => s[rnd(s.length)]!);
  while (out.length < o.len) out.push(pool[rnd(pool.length)]!);
  for (let i = out.length - 1; i > 0; i--) {
    const j = rnd(i + 1);
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out.slice(0, o.len).join('');
}

export function genPhrase(o: GenOptions = DEFAULT_GEN): string {
  const w = Array.from({ length: o.words }, () => WORDS[rnd(WORDS.length)]!).map((x) =>
    o.cap ? x[0]!.toUpperCase() + x.slice(1) : x,
  );
  if (o.num) {
    const i = rnd(w.length);
    w[i] += String(rnd(10));
  }
  return w.join(o.sep);
}

export const phraseBits = (o: GenOptions): number =>
  Math.round(o.words * Math.log2(WORDS.length) + (o.num ? Math.log2(10 * o.words) : 0));

export const bits = (o: GenOptions = DEFAULT_GEN): number =>
  o.mode === 'words' ? phraseBits(o) : Math.round(o.len * Math.log2(Math.max(2, genSets(o).join('').length)));

export const genAny = (o: GenOptions = DEFAULT_GEN): string => (o.mode === 'words' ? genPhrase(o) : gen(o));

export const strength = (b: number): 'Weak' | 'Fair' | 'Strong' | 'Excellent' =>
  b < 60 ? 'Weak' : b < 80 ? 'Fair' : b < 110 ? 'Strong' : 'Excellent';

/** Character-pool estimate for an arbitrary password (upper bound; repeated chars reduce it). */
export function pwBits(p: string): number {
  const s = String(p || '');
  if (!s) return 0;
  let n = 0;
  if (/[a-z]/.test(s)) n += 26;
  if (/[A-Z]/.test(s)) n += 26;
  if (/[0-9]/.test(s)) n += 10;
  if (/[^a-zA-Z0-9]/.test(s)) n += 33;
  const uniq = new Set(s).size;
  return Math.round(Math.min(s.length, uniq * 1.5) * Math.log2(Math.max(2, n)));
}
