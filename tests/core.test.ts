import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import 'fake-indexeddb/auto';
import { audit } from '../src/lib/audit';
import { pwnedCount } from '../src/lib/breach';
import { decryptRecord, deriveKey, encryptEntries, newSalt } from '../src/lib/crypto';
import { csvToEntries, mergeEntries, parseCSV } from '../src/lib/csv';
import { b64, hex, ub64, uid } from '../src/lib/encoding';
import { bits, DEFAULT_GEN, gen, genPhrase, pwBits, strength } from '../src/lib/generator';
import { _resetStorage, initStorage, LEGACY_KEY, load, storageKind, store } from '../src/lib/storage';
import { matchFilter, norm, parseTags } from '../src/lib/tags';
import { parseTotp, totpCode } from '../src/lib/totp';
import type { Entry } from '../src/lib/types';

// Minimal localStorage mock for Node test environment
const mem = new Map<string, string>();
Object.defineProperty(globalThis, 'localStorage', {
  value: {
    getItem: (k: string) => mem.get(k) ?? null,
    setItem: (k: string, v: string) => mem.set(k, String(v)),
    removeItem: (k: string) => mem.delete(k),
    clear: () => mem.clear(),
  },
  configurable: true,
});

describe('encoding', () => {
  it('roundtrips base64 and generates 16-hex uids', () => {
    const raw = new Uint8Array([0, 1, 2, 128, 255]);
    assert.deepEqual(ub64(b64(raw)), raw);
    assert.equal(hex(new Uint8Array([15, 255])), '0fff');
    assert.match(uid(), /^[0-9a-f]{16}$/);
  });
});

describe('crypto (Argon2id + PBKDF2 legacy + AES-GCM)', () => {
  it('seals and decrypts entries with Argon2id, supports legacy PBKDF2 records, and rejects wrong passwords', async () => {
    const salt = newSalt();
    const { key, kdf } = await deriveKey('correct-horse-battery-staple', salt, { kdf: 'argon2id', m: 4096, t: 2, p: 1 });
    assert.equal(kdf.kdf, 'argon2id');
    const sample: Entry[] = [
      {
        id: '1',
        service: 'example.com',
        username: 'alice',
        email: 'a@example.com',
        password: 'secret',
        recEmail: '',
        qa: '',
        notes: 'hi',
        created: 1000,
      },
    ];
    const { iv, ct } = await encryptEntries(key, sample);
    const unlocked = await decryptRecord({ salt: b64(salt), iv, ct, ...kdf }, 'correct-horse-battery-staple');
    assert.equal(unlocked.kdf.kdf, 'argon2id');
    assert.deepEqual(unlocked.entries, sample);
    await assert.rejects(() => decryptRecord({ salt: b64(salt), iv, ct, ...kdf }, 'wrong-password'));

    // Legacy PBKDF2 record without kdf field
    const legacyKey = (await deriveKey('legacy-pw-123456', salt, { kdf: 'pbkdf2' })).key;
    const legacyEnc = await encryptEntries(legacyKey, sample);
    const legacyUnlocked = await decryptRecord({ salt: b64(salt), ...legacyEnc }, 'legacy-pw-123456');
    assert.equal(legacyUnlocked.kdf.kdf, 'pbkdf2');
    assert.deepEqual(legacyUnlocked.entries, sample);
  });
});

describe('generator & entropy', () => {
  it('generates character passwords and EFF passphrases', () => {
    const pw = gen({ ...DEFAULT_GEN, len: 24 });
    assert.equal(pw.length, 24);
    assert.equal( /[lIO01|]/.test(pw), false);
    const phrase = genPhrase({ ...DEFAULT_GEN, mode: 'words', words: 6, sep: '-', cap: 1, num: 1 });
    assert.equal(phrase.split('-').length, 6);
    assert.match(phrase, /\d/);
    assert.equal(strength(bits({ ...DEFAULT_GEN, len: 20 })), 'Excellent');
    assert.ok(pwBits('correct-horse-battery-staple!') >= 80);
  });
});

describe('TOTP RFC 6238 vectors', () => {
  it('matches RFC 6238 SHA-1 / SHA-256 / SHA-512 test vectors', async () => {
    // Base32 of ASCII "12345678901234567890" (20 bytes)
    const s1 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    const r1 = await totpCode(`otpauth://totp/test?secret=${s1}&digits=8&algorithm=SHA1`, 59_000);
    assert.equal(r1.code, '94287082');
    // 32-byte SHA-256 seed from RFC 6238
    const s256 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====';
    const r2 = await totpCode(`otpauth://totp/test?secret=${s256}&digits=8&algorithm=SHA256`, 59_000);
    assert.equal(r2.code, '46119246');
    assert.throws(() => parseTotp('otpauth://hotp/test?secret=' + s1));
  });
});

describe('audit, tags & filters', () => {
  it('identifies reused, weak, stale, and missing-id entries while ignoring non-password notes', () => {
    const now = Date.now();
    const entries: Entry[] = [
      { id: '1', type: 'login', service: 'a', username: 'u', email: '', password: 'dup', recEmail: '', qa: '', notes: '', created: now },
      { id: '2', type: 'login', service: 'b', username: '', email: '', password: 'dup', recEmail: '', qa: '', notes: '', created: now - 200 * 864e5 },
      { id: '3', type: 'note', service: 'note1', username: '', email: '', password: '', recEmail: '', qa: '', notes: 'n', created: now },
    ];
    const rep = audit(entries, now);
    assert.equal(rep.reused.length, 1);
    assert.equal(rep.weak.length, 2);
    assert.equal(rep.stale.length, 1);
    assert.equal(rep.noId.length, 1);
    assert.deepEqual(parseTags(' Work, #Finance!, work '), ['work', 'finance']);
    assert.equal(matchFilter({ ...entries[0]!, fav: 1, tags: ['work'] }, 'fav'), true);
    assert.equal(matchFilter({ ...entries[0]!, tags: ['work'] }, 'tag:work'), true);
    assert.equal(norm('https://www.Claude.ai/login'), 'claude');
  });
});

describe('CSV importer', () => {
  it('parses RFC 4180 quotes and Bitwarden/Chrome formats, deduplicating on merge', () => {
    assert.deepEqual(parseCSV('\uFEFF"a,b","c""d"\r\n1,2'), [
      ['a,b', 'c"d'],
      ['1', '2'],
    ]);
    const csv = 'folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp\nWork/Dev,1,login,GitHub,hi,"PIN: 1234",https://github.com,alice@example.com,pw123,JBSWY3DPEHPK3PXP';
    const batch = csvToEntries(csv);
    assert.equal(batch.fmt, 'Bitwarden');
    assert.equal(batch.entries.length, 1);
    assert.equal(batch.entries[0]!.email, 'alice@example.com');
    assert.deepEqual(batch.entries[0]!.tags, ['work', 'dev']);
    const target: Entry[] = [];
    assert.deepEqual(mergeEntries(target, batch.entries), { added: 1, dup: 0 });
    assert.deepEqual(mergeEntries(target, batch.entries), { added: 0, dup: 1 });
  });
});

describe('IndexedDB storage & migration', () => {
  it('migrates legacy localStorage data into IndexedDB and persists updates', async () => {
    _resetStorage();
    localStorage.clear();
    const rec = { salt: 'aa==', iv: 'bb==', ct: 'cc==', created: 123 };
    localStorage.setItem(LEGACY_KEY, JSON.stringify({ work: rec }));
    const kind = await initStorage();
    assert.equal(kind, 'indexeddb');
    assert.equal(storageKind(), 'indexeddb');
    assert.equal(localStorage.getItem(LEGACY_KEY), null);
    assert.deepEqual(load(), { work: rec });
    await store({ work: rec, home: rec });
    assert.equal(Object.keys(load()).length, 2);
    _resetStorage();
  });
});

describe('HIBP k-anonymity breach check', () => {
  it('sends only 5-char SHA-1 prefix and matches suffix locally', async () => {
    let calledUrl = '';
    const fakeFetch = (async (url: string) => {
      calledUrl = url;
      // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
      return new Response('00000000000000000000000000000000000:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9999999\r\n', { status: 200 });
    }) as unknown as typeof fetch;
    const count = await pwnedCount('password', fakeFetch);
    assert.equal(calledUrl, 'https://api.pwnedpasswords.com/range/5BAA6');
    assert.equal(count, 9999999);
  });
});
