import { pwBits } from './generator';
import type { Entry } from './types';

export const STALE_DAYS = 180;

export interface AuditReport {
  reused: Entry[][];
  weak: Entry[];
  noId: Entry[];
  stale: Entry[];
  score: number;
}

export function audit(entries: readonly Entry[], now = Date.now()): AuditReport {
  const by = new Map<string, Entry[]>();
  entries.forEach((e) => {
    if (e.password) {
      const a = by.get(e.password) ?? [];
      a.push(e);
      by.set(e.password, a);
    }
  });
  const reused = [...by.values()].filter((a) => a.length > 1);
  const weak = entries.filter((e) => e.password && pwBits(e.password) < 60);
  const noId = entries.filter((e) => (e.type ?? 'login') === 'login' && !e.username && !e.email);
  const cut = now - STALE_DAYS * 864e5;
  const stale = entries.filter((e) => e.password && (e.pwChanged ?? e.created ?? 0) < cut);
  const bad = new Set([...reused.flat(), ...weak, ...stale].map((e) => e.id));
  const score = entries.length ? Math.round((100 * (entries.length - bad.size)) / entries.length) : 100;
  return { reused, weak, noId, stale, score };
}
