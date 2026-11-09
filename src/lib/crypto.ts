import { b64, dec, enc, ub64 } from './encoding';
import type { Entry, ProfileRecord } from './types';

/* Key derivation: PBKDF2-SHA256 (600k iterations) -> AES-256-GCM via the Web Crypto API. */
export const PBKDF2_ITERATIONS = 600_000;

export const newSalt = (): Uint8Array<ArrayBuffer> => crypto.getRandomValues(new Uint8Array(16));

export async function deriveKey(password: string, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  const k = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    k,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Encrypt the full entry list with a fresh 96-bit IV. */
export async function encryptEntries(key: CryptoKey, entries: Entry[]): Promise<{ iv: string; ct: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(entries)));
  return { iv: b64(iv), ct: b64(ct) };
}

export interface Unlocked {
  key: CryptoKey;
  salt: Uint8Array<ArrayBuffer>;
  entries: Entry[];
}

/** Derive the key and decrypt a profile record. Throws if the password is wrong (GCM tag mismatch). */
export async function decryptRecord(rec: ProfileRecord, password: string): Promise<Unlocked> {
  const salt = ub64(rec.salt);
  const key = await deriveKey(password, salt);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(rec.iv) }, key, ub64(rec.ct));
  return { key, salt, entries: JSON.parse(dec.decode(pt)) as Entry[] };
}
