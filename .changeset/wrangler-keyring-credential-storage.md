---
"wrangler": minor
"@cloudflare/workers-auth": minor
---

Add opt-in OS keychain storage for OAuth credentials

`wrangler login --use-keyring` now stores the OAuth access and refresh tokens in an encrypted file under the user's wrangler config directory, with the AES-256-GCM encryption key held in the OS keyring (macOS Keychain, libsecret on Linux, or Windows Credential Manager via `@napi-rs/keyring`). The legacy plaintext TOML file is migrated transparently on first use. Opting back out (`wrangler login --no-use-keyring`) **deletes** the encrypted file and the keyring entry without decrypting them onto disk — writing plaintext credentials during opt-out would defeat the at-rest protection the user just chose to disable. The subsequent login writes fresh credentials into the plaintext TOML file.

The choice is persisted across `wrangler` invocations. The environment variable `CLOUDFLARE_AUTH_USE_KEYRING=true|false` overrides the persistent preference for one-off use. The legacy plaintext file remains the default, so existing users see no behavior change.

### Per-platform backends

Wrangler ships with **zero native credential dependencies**. Each platform uses whatever is already there:

- **macOS**: `/usr/bin/security` (built-in; no install required).
- **Linux**: `secret-tool` from `libsecret-tools` (already installed on most Linux desktops; wrangler prints a per-distro install hint when missing).
- **Windows**: `@napi-rs/keyring` is lazy-installed via `npm install` on first opt-in (~1.9 MB one-time download). Non-interactive contexts (CI, scripts) get an actionable hard error with the option to install globally with `npm install -g @napi-rs/keyring@<pinned-version>` or to disable keyring storage entirely.

### Encryption details

- The encrypted file lives at `<wrangler-config>/config/<env>.enc`, alongside the legacy `<env>.toml` so migration is non-destructive.
- The on-disk format is a JSON envelope `{ v, alg: "AES-256-GCM", iv, tag, ciphertext }`. The auth tag prevents tampering — any corruption or wrong key is detected and treated as "not logged in".
- The keyring entry stores only a 32-byte symmetric key (wrapped in a small JSON envelope for forward-compat), well below the macOS Keychain ~2.5 KB per-item limit, so the encrypted credential blob is free to grow as the schema evolves.

### Internal architecture

The credential persistence layer has moved into `@cloudflare/workers-auth`. `createOAuthFlow(ctx)` now requires a `credentialStorage` block (`serviceName`, `isKeyringEnabled` callback, optional `cliName`) and returns a new `getCredentialStore()` accessor for `whoami`-style code. Future Cloudflare CLIs that reuse `workers-auth` get the same OS keyring–encrypted credential storage by providing their own `serviceName`.

`CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_API_KEY`/`CLOUDFLARE_EMAIL` continue to take priority over any stored OAuth credentials.
