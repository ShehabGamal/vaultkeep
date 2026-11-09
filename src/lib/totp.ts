/* TOTP / 2FA (RFC 6238 over RFC 4226 HOTP, Web Crypto HMAC). */
export type TotpAlgo = 'SHA-1' | 'SHA-256' | 'SHA-512';

export interface ParsedTotp {
  secret: string;
  digits: 6 | 7 | 8;
  period: number;
  algo: TotpAlgo;
  key: Uint8Array<ArrayBuffer>;
}

export interface TotpResult {
  code: string;
  left: number;
  period: number;
}

export function b32decode(input: string): Uint8Array<ArrayBuffer> {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const s = String(input).toUpperCase().replace(/[\s=-]/g, '');
  let bitsN = 0;
  let val = 0;
  const out: number[] = [];
  for (const ch of s) {
    const i = A.indexOf(ch);
    if (i < 0) throw new Error('Invalid base32');
    val = (val << 5) | i;
    bitsN += 5;
    if (bitsN >= 8) {
      out.push((val >>> (bitsN - 8)) & 255);
      bitsN -= 8;
    }
  }
  return new Uint8Array(out);
}

const VALID_ALGOS: readonly TotpAlgo[] = ['SHA-1', 'SHA-256', 'SHA-512'];
const VALID_DIGITS: readonly (6 | 7 | 8)[] = [6, 7, 8];

/** Accepts a raw base32 secret or an otpauth://totp/... URI. */
export function parseTotp(input: string): ParsedTotp | null {
  const s = String(input || '').trim();
  if (!s) return null;
  let secret = s;
  let digits = 6;
  let period = 30;
  let algo = 'SHA-1';
  if (/^otpauth:\/\//i.test(s)) {
    const u = new URL(s);
    if (u.host.toLowerCase() !== 'totp') throw new Error('Only TOTP is supported');
    const p = u.searchParams;
    algo = (p.get('algorithm') || 'SHA1').toUpperCase().replace(/^SHA-?/, 'SHA-');
    secret = p.get('secret') || '';
    digits = +(p.get('digits') || 6);
    period = +(p.get('period') || 30);
  }
  if (
    !VALID_ALGOS.includes(algo as TotpAlgo) ||
    !VALID_DIGITS.includes(digits as 6 | 7 | 8) ||
    !(period > 0)
  ) {
    throw new Error('Unsupported TOTP parameters');
  }
  const key = b32decode(secret);
  if (!key.length) throw new Error('Empty secret');
  return { secret, digits: digits as 6 | 7 | 8, period, algo: algo as TotpAlgo, key };
}

export async function totpCode(input: string, now = Date.now()): Promise<TotpResult> {
  const o = parseTotp(input);
  if (!o) throw new Error('Empty secret');
  const ctr = Math.floor(now / 1000 / o.period);
  const msg = new Uint8Array(8);
  let c = ctr;
  for (let i = 7; i >= 0; i--) {
    msg[i] = c & 255;
    c = Math.floor(c / 256);
  }
  const k = await crypto.subtle.importKey('raw', o.key, { name: 'HMAC', hash: o.algo }, false, ['sign']);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', k, msg));
  const off = h[h.length - 1]! & 15;
  const bin = ((h[off]! & 127) << 24) | (h[off + 1]! << 16) | (h[off + 2]! << 8) | h[off + 3]!;
  return {
    code: String(bin % 10 ** o.digits).padStart(o.digits, '0'),
    left: o.period - (Math.floor(now / 1000) % o.period),
    period: o.period,
  };
}
