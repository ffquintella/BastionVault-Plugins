# bastion-plugin-self-accounts

Operator-registered accounts, picked at Connect. A **credential provider** for
BastionVault (WASM, ABI 1.3). Spec: [features/self-accounts.md](../../features/self-accounts.md).

An operator registers their own accounts (a login plus a password or an SSH
private key), tags each with the resource types, OS families, protocols and
target hosts it applies to, and later picks one when pressing **Connect**. The
host never learns what a self-account is; it only knows this plugin declared
itself a credential provider and that an administrator approved it.

> **Status.** Phase 2 of 5: the plugin itself. Connect does not use it yet (the
> `provider` credential source, the picker and the release paths are Phases 3
> and 4), so today it is a personal store with a management page, nothing more.

## Security model

- **The host, not this code, separates users.** The plugin declares
  `caller_identity` and `storage_scope = "entity"`; the host attests the caller
  from the token and rebases every `bv.storage_*` call onto
  `core/plugins/self-accounts/data/entity/<entity_id>/`. No path names a user,
  and a request with no identity entity is refused before the plugin runs.
- **Secrets are write-only.** No path returns a password, a key or a TOTP seed,
  to anyone. They leave only through `provider.release`, which no HTTP request
  can produce; the host calls it from Connect.
- **Metadata and secret are separate keys** (`accounts/<id>/meta`,
  `accounts/<id>/secret`), so listing and candidate matching never read a secret.
- **Where an account was used is kept as digests.** `accounts/<id>/seen` holds up
  to 64 domain-separated SHA-256 digests of the targets the account was released
  for (canonical dial host for SSH / RDP, port excluded; sorted origin set for
  web) with the time of the last release there, least recently used evicted
  first. Never the target text. Written only by a successful release; the
  picker's "First use on this host" badge and its preselection read it through
  `first_use_on_target` / `last_used_on_target` on each candidate. The badge is a
  hint; the target binding below is the protection.
- **No egress.** The manifest declares no network capability.
- **Targets bind an account to where it may be used** (below). Without them, a
  hostile resource definition could harvest a credential by naming a host it
  controls.
- A release is refused unless the account matches the resource type, OS,
  protocol *and* target, exactly as `provider.candidates` would have offered it,
  and (by default) unless the host attests a connect-time MFA ticket was redeemed.

## API

All paths are `v2/` under the mount (`self-accounts/` by convention; mount with
`type = "plugin:self-accounts"`).

| Path | Op | Behaviour |
|---|---|---|
| `v2/accounts` | `list` | The caller's accounts, as `data.entries` (metadata only). |
| `v2/accounts` | `write` | Create. Returns `data.id`; `warnings` lists accounts that would never be offered. |
| `v2/accounts/<id>` | `read` | Metadata plus `has_secret`. Never the secret. |
| `v2/accounts/<id>` | `write` | Update. Absent or empty secret fields keep the stored secret. Changing `secret_kind` needs the new secret in the same write. |
| `v2/accounts/<id>/totp` | `delete` | Clear the TOTP seed. |
| `v2/accounts/<id>` | `delete` | Delete the account. |
| `v2/settings` | `read` | The effective administrator settings. |

`list` returns `entries`, not `keys`, on purpose: the management table prefers
`keys` when it is present and would render bare ids.

Fields of a write: `label` (≤64), `username` (≤256), `domain` (≤256, RDP and
web), `description` (≤512), `secret_kind` (`password` or `ssh-key`), `password`
(≤1 KiB) or `private_key` (OpenSSH, unencrypted, ≤16 KiB), `totp_seed`
(base32; only when the administrator allows it), `resource_types` (required),
`os_types`, `protocols` and `targets`. Lists are JSON arrays, or comma- or
newline-separated strings, at most 32 entries.

### Targets

| Protocol | Entry | Matches |
|---|---|---|
| SSH, RDP | `dc01.corp.example.com` | that name |
| SSH, RDP | `*.corp.example.com` | exactly one label under the suffix (not the apex, not two labels) |
| SSH, RDP | `10.20.0.0/16`, `fd00::/8`, `10.0.0.5` | an IP in the range; names are never resolved |
| web | `https://grafana.corp.example.com[:port]` | that origin, HTTPS only, exact port |
| web | `https://*.corp.example.com[:port]` | exactly one label |

For web, **every** origin the recipe may fill must match. A wildcard is only
accepted as the whole left-most label with a real suffix (`*.com` is refused).

## Administrator settings

| Key | Default | Meaning |
|---|---|---|
| `allow_ssh_keys` | `true` | Accept `ssh-key` accounts. Turning it off stops existing ones being offered. |
| `allow_totp_seeds` | `false` | Accept a TOTP seed next to a password (it collapses two factors into one record). |
| `max_accounts_per_user` | `25` | Cap per person. |
| `require_connect_mfa` | `true` | Refuse a release without the host's MFA attestation. |
| `require_targets` | `web` | `web` or `all`: protocols that need a non-empty targets list. An unknown value is read as `all`. |
| `allowed_resource_types` | empty | Comma-separated type ids; empty allows all. |

## Install

```bash
make plugins-wasm        # builds this one for wasm32-unknown-unknown
```

It is **not** built for `wasm32-wasip1`: the host links only the `bv` import
module, and a `wasip1` build imports `wasi_snapshot_preview1`, which it cannot
instantiate (the catalog refuses such a module at registration).

Then, as an administrator:

1. Register the plugin (**Plugins → Register**, or `POST /v1/sys/plugins`) and
   mount it: `bvault write sys/mounts/self-accounts type=plugin:self-accounts`.
2. Approve it under **Plugins → Credentials**
   (`PUT v2/sys/plugins/self-accounts/grants/credential-provider`). Until you do,
   nothing can ask it for a credential.
3. Attach the policy below to the people who may keep accounts. It is not added
   to `default` automatically: installing a plugin must not silently widen a
   built-in policy.
4. To get the **My accounts** page, register `surface.json` with the plugin: add
   a `[surface]` table (`schema_version = 1`, the file's `sha256` and `size`) to
   `plugin.toml` before packing and signing, then send the file as `surface_b64`
   on `POST /v1/sys/plugins`. The packer cannot embed it yet, and the GUI's
   Register dialog does not send it; `surface_b64` without a `[surface]` table is
   ignored. See `docs/self-accounts.md` §2.3.

```hcl
# self-accounts-user
path "self-accounts/v2/accounts"   { capabilities = ["create", "read", "update", "delete", "list"] }
path "self-accounts/v2/accounts/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "self-accounts/v2/settings"   { capabilities = ["read"] }
```

Granting it broadly is safe because the host scopes storage per entity, not
because of the path.

## Known limits

- The management page adds and deletes accounts; **editing** one goes through the
  API (`write v2/accounts/<id>`), because a surface row action cannot open a form.
- Passphrase-protected SSH keys are refused. PKCS#8 keys are refused too: this
  version stores OpenSSH keys, the form the SSH session reads.
- The password form always shows a TOTP field; a seed is refused with a clear
  message unless the administrator allowed it (a static surface cannot hide it).
- A failed release is reported with a fixed message and no account detail.

## Tests

```bash
cd plugins-ext
cargo build --release --target wasm32-unknown-unknown -p bastion-plugin-self-accounts
cargo test  --release -p bastion-plugin-self-accounts --features host_test
```

`make plugins-test` also runs `engine_tests::self_accounts_host` in the main
workspace, which loads this wasm into the real host.
