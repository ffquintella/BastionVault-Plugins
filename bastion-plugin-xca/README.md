# bastion-plugin-xca

Process-runtime plugin that imports an [XCA](https://hohnstaedt.de/xca/)
database (`*.xdb`) into BastionVault's PKI engine.

See [`features/xca-import.md`](https://github.com/ffquintella/BastionVault/blob/main/features/xca-import.md)
in the host repo for the design.

## What it does

- Opens an XCA SQLite database (read-only).
- Walks the `items` table and joins per-type rows (`certs`,
  `requests`, `crls`, `templates`, `private_keys`, `public_keys`).
- Decrypts `private_keys.private` blobs with an operator-supplied
  password. Both XCA encryption envelopes are handled:
  - **Legacy** (XCA ≤ 2.0): OpenSSL `Salted__` + `EVP_BytesToKey(MD5)`
    + AES-256-CBC.
  - **Modern** (XCA ≥ 2.4): PBKDF2-HMAC-SHA512 + AES-256-CBC, with
    iteration count and salt read from the DER-encoded header.
- Returns a structured plan the BastionVault GUI walks via existing
  PKI / KV routes. The plugin **never** mutates vault state directly.

## What it doesn't do

- **No vault writes.** All PKI / KV writes happen on the host side
  via the regular policy-checked / audited route surface — the
  plugin only parses + decrypts.
- **No smartcard-resident keys.** XCA can reference PKCS#11 tokens;
  the actual key material isn't in the database.
- **No CMC / SCEP enrolment configs** (`authority` table).
- **No round-trip back to XCA.** One-way migration only.

## Operations

The host's GUI sends one JSON line per invocation. `op` selects the
behaviour:

| op | Purpose |
|---|---|
| `validate` | Cheap version sniff. Returns `{ok, format_version, requires_password, ownpass_keys}`. |
| `preview`  | Full parse + decrypt-what-we-can. Returns the structured item list with per-row decrypt status. |
| `import`   | Alias for `preview` in v1; the GUI walks the returned plan. |

Input shape:

```json
{
  "op": "preview",
  "file_path": "/abs/path/to/db.xdb",
  "master_password": "secret",
  "per_key_passwords": { "Per-Key Pinned Account": "other-secret" }
}
```

`file_b64` is accepted in place of `file_path` for GUIs that prefer
to keep the file off-disk; the plugin writes it to a self-cleaning
temp file (SQLite needs a real fd).

## Building

```bash
cargo build --release -p bastion-plugin-xca
# artefact: target/release/bastion-plugin-xca[.exe]

# package for upload
cargo run -p bv-plugin-pack -- \
  --plugin-toml plugins-ext/bastion-plugin-xca/plugin.toml \
  --bin         target/release/bastion-plugin-xca \
  --out         dist/bastion-plugin-xca.bvplugin
```

Then upload via `POST /v1/sys/plugins` (or the GUI's Plugins page).
