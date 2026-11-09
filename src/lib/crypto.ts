import { argon2id } from 'hash-wasm';
import { b64, dec, enc, ub64 } from './encoding';
import type { Entry, KdfParams, ProfileRecord } from './types';

/* Primary KDF: Argon2id (RFC 9106) via audited WebAssembly (hash-wasm), 64 MiB RAM, 3 iterations, 4 lanes -> 256-bit AES-GCM key.
   Fallback / legacy KDF: PBKDF2-SHA256 (600,000 iterations) via Web Crypto API for backward compatibility with existing vaults. */
export const PBKDF2_ITERATIONS = 600_000;
export const ARGON2_MEMORY_KIB = 65_536; // 64 MiB
export const ARGON2_ITERATIONS = 3;
export const ARGON2_PARALLELISM = 4;

export const DEFAULT_KDF: KdfParams = {
  kdf: 'argon2id',
  m: ARGON2_MEMORY_KIB,
  t: ARGON2_ITERATIONS,
  p: ARGON2_PARALLELISM,
};

export const newSalt = (): Uint8Array<ArrayBuffer> => crypto.getRandomValues(new Uint8Array(16));

export async function derivePbkdf2Key(
  password: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations = PBKDF2_ITERATIONS,
): Promise<CryptoKey> {
  const k = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    k,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function deriveArgon2idKey(
  password: string,
  salt: Uint8Array<ArrayBuffer>,
  params: { m?: number; t?: number; p?: number } = {},
): Promise<CryptoKey> {
  const raw = await argon2id({
    password,
    salt,
    memorySize: params.m ?? ARGON2_MEMORY_KIB,
    iterations: params.t ?? ARGON2_ITERATIONS,
    parallelism: params.p ?? ARGON2_PARALLELISM,
    hashLength: 32,
    outputType: 'binary',
  });
  const keyBytes = new Uint8Array(32);
  keyBytes.set(raw);
  try {
    return await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM', length: 256 }, false, [
      'encrypt',
      'decrypt',
    ]);
  } finally {
    keyBytes.fill(0);
    raw.fill(0);
  }
}

export interface DerivedKeyResult {
  key: CryptoKey;
  kdf: KdfParams;
}

/**
 * Derive an AES-256-GCM key using Argon2id by default (or PBKDF2 when specified),
 * falling back to PBKDF2 only if WebAssembly execution is blocked by the environment.
 */
export async function deriveKey(
  password: string,
  salt: Uint8Array<ArrayBuffer>,
  params: KdfParams = DEFAULT_KDF,
): Promise<DerivedKeyResult> {
  if (params.kdf === 'pbkdf2') {
    const t = params.t ?? PBKDF2_ITERATIONS;
    return { key: await derivePbkdf2Key(password, salt, t), kdf: { kdf: 'pbkdf2', t } };
  }
  const m = params.m ?? ARGON2_MEMORY_KIB;
  const t = params.t ?? ARGON2_ITERATIONS;
  const p = params.p ?? ARGON2_PARALLELISM;
  try {
    return { key: await deriveArgon2idKey(password, salt, { m, t, p }), kdf: { kdf: 'argon2id', m, t, p } };
  } catch {
    return {
      key: await derivePbkdf2Key(password, salt, PBKDF2_ITERATIONS),
      kdf: { kdf: 'pbkdf2', t: PBKDF2_ITERATIONS },
    };
  }
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
  kdf: KdfParams;
  entries: Entry[];
}

/**
 * Derive the key according to the record's KDF metadata (defaulting to PBKDF2 for legacy v1 records
 * that predate Argon2id) and decrypt the profile record.
 */
export async function decryptRecord(rec: ProfileRecord, password: string): Promise<Unlocked> {
  const salt = ub64(rec.salt);
  const reqKdf: KdfParams =
    rec.kdf === 'argon2id'
      ? { kdf: 'argon2id', m: rec.m ?? ARGON2_MEMORY_KIB, t: rec.t ?? ARGON2_ITERATIONS, p: rec.p ?? ARGON2_PARALLELISM }
      : { kdf: 'pbkdf2', t: rec.t ?? PBKDF2_ITERATIONS };
  const { key, kdf } = await deriveKey(password, salt, reqKdf);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(rec.iv) }, key, ub64(rec.ct));
  return { key, salt, kdf, entries: JSON.parse(dec.decode(pt)) as Entry[] };
}
