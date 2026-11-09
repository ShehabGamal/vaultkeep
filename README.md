# Vaultkeep

**Vaultkeep** is an open-source, local-first, zero-knowledge password manager and 2FA authenticator engineered to run 100% offline as a self-contained single HTML file (`vaultkeep.html`), an installable Progressive Web App (PWA), or a native desktop application powered by **Tauri v2 (Rust + WebView2/WebKit)**.

No accounts, no cloud sync servers, no telemetry, and no unencrypted secrets ever touch disk.

---

## Key Highlights

- **Memory-Hard Cryptography (`Argon2id` + `AES-256-GCM`)**: Derives 256-bit encryption keys via audited WebAssembly (`hash-wasm`) using RFC 9106 **Argon2id** (`64 MiB` RAM, `3` iterations, `4` parallel lanes) paired with hardware-accelerated **AES-256-GCM** (`window.crypto.subtle`) and a fresh 96-bit IV on every seal. Raw key buffers are zeroed in memory immediately after import.
- **Seamless Legacy Migration**: Existing **PBKDF2-SHA256** (`600,000` iterations) vaults unlock transparently and automatically re-seal under **Argon2id** with a fresh 128-bit salt.
- **Multi-Profile Isolation**: Each profile on a device has its own independent master password, salt, and encrypted ciphertext record.
- **"Do I Have an Account?" Instant Lookup**: Check whether you already have an account for a service before signing up anywhere, or generate and store a new credential in one step.
- **Two-Stage Protected Details Challenge**: Recovery emails/phones, security Q&A, and private notes stay locked behind a secondary challenge inside an already-unlocked vault—requiring both the full master password and 3 randomly sampled character positions with exponential backoff after failed attempts.
- **Integrated TOTP / 2FA Authenticator**: Built-in RFC 6238 / RFC 4226 TOTP generator (`SHA-1`, `SHA-256`, `SHA-512`; 6–8 digits; custom periods; `otpauth://` URI or Base32 secret support) with a live SVG countdown ring.
- **Zero-Knowledge Breach Check (HIBP k-Anonymity)**: Optional online check against Have I Been Pwned where only the first 5 hex characters of `SHA-1(password)` leave the device; full hash suffix matching happens locally.
- **Offline Vault Health & Security Audit**: 100% local analysis flagging reused passwords, weak entropy (<60 bits), stale passwords (180+ days old), and login entries missing an identifier, with an overall health score.
- **Cryptographic Password & EFF Passphrase Generator**: Rejection-sampled uniform random character generator (with look-alike filtering) and Diceware-style EFF wordlist passphrase generator with live bit-entropy estimation.
- **Rich Entry Schema**: Supports **Logins**, **Secure Notes**, **Credit Cards**, and **API Keys**, plus dynamic masked/visible custom key-value fields, encrypted per-entry password history (last 20 passwords with timestamps), comma-separated tags, favorites pinning, and quick filter pills.
- **Multi-Format CSV Importer**: RFC 4180 CSV parser with automatic format detection and schema mapping for **Bitwarden**, **KeePass / KeePassXC**, **1Password**, **Chrome**, **Firefox**, and generic CSV exports, including batch encryption and deduplication.
- **Printable Emergency Kit**: Media-print stylesheet (`@media print`) that formats a physical paper recovery sheet with profile metadata, recovery instructions, and handwritten spaces for the master password and backup locations—while hiding all vault contents.
- **Auto-Lock & Clipboard Hygiene**: Configurable idle auto-lock timer (`1`, `3`, `5`, `15` minutes, or `Never`), instant keyboard lock (`Ctrl/⌘ + L` or `Escape`), and automatic 20-second clipboard clearing after copying any secret.

---

## Architecture & Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Language** | TypeScript 5.7 (`strict: true`) | Static type safety across crypto, storage, parsers, and UI state |
| **UI Framework** | Preact 10 (TSX) + Native CSS Custom Properties | Near-zero bundle overhead (~3 kB), light/dark theme tokens, print stylesheet |
| **Cryptography** | `hash-wasm` (Argon2id WASM) + Web Crypto API (`AES-256-GCM`, `PBKDF2`, `HMAC`, `SHA-1`) | Memory-hard key derivation, authenticated encryption, TOTP signing, k-anonymity hashing |
| **Client Storage** | IndexedDB (`vaultkeep` / `profiles`) + `localStorage` fallback | Asynchronous high-quota storage with atomic transactions, verified v1 migration, and `navigator.storage.persist()` |
| **Build & Bundler** | Vite 6 + `vite-plugin-singlefile` | Compiles all TypeScript, Preact, CSS, and WASM into a standalone `vaultkeep.html` |
| **Offline Web** | PWA (`manifest.webmanifest` + Service Worker `sw.js`) | Installable browser app with offline-first app-shell caching |
| **Desktop Shell** | Tauri v2 (Rust + OS WebView) | Native desktop executable with strict Content Security Policy (CSP) |

---

## Project Structure

```text
vaultkeep/
├── index.html                  # Vite entry HTML (inline SVG favicon + PWA manifest link)
├── vaultkeep.html              # Self-contained single-file production build (runs directly from file://)
├── public/
│   ├── icon.svg                # Vector app icon
│   ├── manifest.webmanifest    # PWA manifest
│   └── sw.js                   # Offline-first Service Worker
├── src/
│   ├── main.tsx                # Preact root mount & Service Worker registration
│   ├── App.tsx                 # Preact UI components (Gate, Vault, Generator, Health, Form, Detail, Kit)
│   ├── styles.css              # Light/dark CSS custom properties & @media print Emergency Kit styles
│   └── lib/
│       ├── types.ts            # Core TypeScript interfaces (Entry, ProfileRecord, KdfParams, CustomField)
│       ├── encoding.ts         # UTF-8, Base64, Hex, and CSPRNG UID helpers
│       ├── crypto.ts           # Argon2id (WASM) + PBKDF2-SHA256 derivation & AES-256-GCM seal/open
│       ├── storage.ts          # IndexedDB engine, in-memory mirror, and verified localStorage migration
│       ├── generator.ts        # Rejection-sampled password & EFF passphrase generator + entropy math
│       ├── words.ts            # EFF Short Wordlist #1 (1,295 words)
│       ├── audit.ts            # Offline security audit (reused, weak, stale, missing username/email)
│       ├── breach.ts           # HIBP k-anonymity range API client
│       ├── totp.ts             # Base32 decoder, otpauth:// parser, and RFC 6238 TOTP HMAC engine
│       ├── tags.ts             # Entry types, tag sanitization, filter matching, and domain normalization
│       ├── csv.ts              # RFC 4180 CSV parser & multi-vendor schema mapper + deduplicator
│       └── settings.ts         # Device auto-lock preferences
├── src-tauri/                  # Tauri v2 Rust desktop shell, capabilities, and multi-platform icons
├── scripts/
│   └── tauri.mjs               # Auto-resolves ~/.cargo/bin for Tauri CLI scripts
└── tests/
    └── core.test.ts            # Automated Node test suite covering crypto, TOTP, CSV, IDB, audit, and HIBP
```

---

## Getting Started

### 1. Run the Standalone Single File (Zero Setup)
Open `vaultkeep.html` directly in any modern browser (Chrome, Edge, Firefox, Safari) from your local disk or a USB drive. No web server or internet connection is required.

### 2. Development & Web Build
**Prerequisites:** Node.js `>= 20` and `npm`.

```bash
# Install dependencies
npm install

# Start the Vite hot-reload dev server
npm run dev

# Run strict TypeScript check + automated unit tests
npm test

# Build dist/ (PWA) and regenerate the standalone vaultkeep.html
npm run build
```

### 3. Native Desktop App (Tauri v2)
**Prerequisites:** [Rust (`rustup`)](https://rustup.rs/) and platform build tools (Visual Studio C++ Build Tools + WebView2 on Windows, Xcode Command Line Tools on macOS, or `webkit2gtk` on Linux).

```bash
# Launch the native Tauri v2 desktop window in development mode
npm run tauri:dev

# Package a production native desktop executable / installer
npm run tauri:build
```

---

## Security Model & Threat Boundaries

1. **At-Rest Encryption**: Vault entries are serialized as JSON and encrypted as a single authenticated blob using `AES-256-GCM` with a random 12-byte IV on every write. Neither service names, usernames, TOTP secrets, nor password histories are stored in plaintext.
2. **Key Derivation**: New profiles derive their 256-bit key using `Argon2id` (`m=65536 KiB`, `t=3`, `p=4`) over a random 16-byte per-profile salt. Legacy profiles using `PBKDF2-SHA256` (`600,000` iterations) are automatically upgraded on next unlock.
3. **Memory & Lock Hygiene**: Locking the vault (`Lock` button, idle timeout, `Ctrl/⌘ + L`, or `Escape`) immediately drops references to the `CryptoKey`, master password, and decrypted entry array from application state.
4. **Network Isolation**: Vaultkeep makes **zero** network requests during normal operation. The only optional outbound request is the user-triggered **Check pwned** button, which sends only a 5-character `SHA-1` prefix (`GET https://api.pwnedpasswords.com/range/{5-hex}`) with `Add-Padding: true` and `credentials: 'omit'`.
5. **No Recovery by Design**: There is no master password reset or backdoor. Users are encouraged to export encrypted `.json` backups (`Export backup`) and print a physical **Emergency Kit**.

---

## License

Released under the **MIT License**. Audit it, fork it, improve it.
