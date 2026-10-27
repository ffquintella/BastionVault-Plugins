# BastionVault Reference Plugins

Reference plugins that exercise the BastionVault plugin system end-to-end
from outside the host tree. See
[`features/plugin-system.md`](https://github.com/ffquintella/BastionVault/blob/main/features/plugin-system.md)
in the host repo (Phase 4).

| Plugin | Runtime | Purpose |
|---|---|---|
| [`bastion-plugin-totp`](./bastion-plugin-totp/) | WASM | RFC 6238 TOTP code generation + validation. Demonstrates the WASM runtime, `bv.now_unix_ms`, and `bv.config_get`. |

These are usable as-is and as templates: copy the directory, change the
manifest, swap the handler, ship the artifact.

## Building

The SDK is consumed via a relative path. This repo is intended to be
mounted as a submodule under the host repo at `<host>/plugins-ext/`:

```bash
# from the host repo:
git submodule update --init plugins-ext

# build the WASM plugin
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1 -p bastion-plugin-totp
# artifact: target/wasm32-wasip1/release/bastion_plugin_totp.wasm

# build a process plugin
cargo build --release -p bastion-plugin-xca
# artifact: target/release/bastion-plugin-xca(.exe)
```

For standalone builds (cloning this repo on its own), point the SDK path
at a checked-out copy of the host repo via a top-level `[patch]` section
or by adjusting each plugin's `Cargo.toml`.

## Registering a Plugin

```bash
# WASM
curl -sk -H "X-BastionVault-Token: $BV_TOKEN" \
  -X POST https://localhost:8200/v1/sys/plugins/totp \
  -F manifest=@bastion-plugin-totp/plugin.toml \
  -F binary=@target/wasm32-wasip1/release/bastion_plugin_totp.wasm

# Process
curl -sk -H "X-BastionVault-Token: $BV_TOKEN" \
  -X POST https://localhost:8200/v1/sys/plugins/xca \
  -F manifest=@bastion-plugin-xca/plugin.toml \
  -F binary=@target/release/bastion-plugin-xca
```

## License

Apache-2.0.
