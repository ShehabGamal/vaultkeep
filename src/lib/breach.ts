import { enc } from './encoding';

/**
 * Zero-knowledge breach check via Have I Been Pwned k-anonymity range API.
 * Only the first 5 hex characters of SHA-1(password) leave the device; suffix matching happens locally.
 */
export async function pwnedCount(password: string, fetchImpl: typeof fetch = fetch): Promise<number> {
  const digest = await crypto.subtle.digest('SHA-1', enc.encode(password));
  const h = Array.from(new Uint8Array(digest), (x) => x.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
  const pre = h.slice(0, 5);
  const suf = h.slice(5);
  const r = await fetchImpl('https://api.pwnedpasswords.com/range/' + pre, {
    headers: { 'Add-Padding': 'true' },
    cache: 'no-store',
    referrerPolicy: 'no-referrer',
    credentials: 'omit',
  });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  for (const line of (await r.text()).split('\n')) {
    const [s, c] = line.trim().split(':');
    if (s === suf) return parseInt(c ?? '0', 10) || 0;
  }
  return 0;
}
