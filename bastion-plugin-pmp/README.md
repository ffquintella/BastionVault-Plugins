# bastion-plugin-pmp

Process-runtime plugin that imports a [ManageEngine Password Manager
Pro](https://www.manageengine.com/products/passwordmanagerpro/) (PMP)
`ExportPasswordView` spreadsheet into BastionVault's Resource and KV
engines.

See [`features/pmp-import.md`](https://github.com/ffquintella/BastionVault/blob/main/features/pmp-import.md)
in the host repo for the design.

## What it does

- Reads PMP `ExportPasswordView` spreadsheets (`.xls` BIFF and
  `.xlsx` OOXML) via `calamine`.
- Splits PMP's overloaded `OS Type` column into BV `type` (server /
  database / firewall / switch / website / application) and
  `os_type` (linux / windows / macos / …) per a fixed lookup table,
  overridable per call.
- Collapses multi-account rows into one resource with N secrets.
- Routes the non-resource-shaped row types (`Generic Keys`,
  `Application Passwords`, `License Store`) into the **KV engine**
  under `secret/pmp-import/<batch-id>/<kind>/<resource>/<account>`.
- Derives an asset group per PMP `Department` (slugified, merged
  not overwritten on re-run).
- Records the importing operator as owner — the plan deliberately
  carries no `owner` field.

## What it doesn't do

- **No vault writes.** All Resource / KV / Asset Group writes
  happen on the host side via the regular policy-checked / audited
  Tauri command surface — the plugin only parses + structures.
- **No PMP API live sync.** Only the static spreadsheet is
  consumed. A live REST connector would be a separate plugin.
- **No PMP encrypted exports.** Recent PMP versions can encrypt the
  export with a per-export key; that is out of scope.

## Operations

The host's GUI sends one JSON line per invocation. `op` selects the
behaviour:

| op | Purpose |
|---|---|
| `validate` | Cheap header sniff. Returns `{ok, format, sheet, row_count, columns, missing_required, unknown_columns}`. |
| `preview`  | Full parse + structuring with no host writes. Returns the import plan. |
| `import`   | Alias for `preview` — the GUI walks the returned plan and issues the writes. |

Input shape:

```json
{
  "op": "preview",
  "file_path": "/abs/path/to/ExportResources.xls",
  "batch_id": "2026-05-05T1530",
  "preserve_unknown_columns": true,
  "tag_columns": ["Ambiente"],
  "type_overrides": { "Cisco IOS": "firewall" },
  "existing_asset_groups": ["dba-team", "tic-infra"],
  "name_collision_policy": "skip"
}
```

`file_b64` is accepted in place of `file_path` for GUIs that prefer
to keep the file off-disk; the plugin writes it to a self-cleaning
temp file (calamine needs `Read + Seek`).

## Building

```bash
cargo build --release -p bastion-plugin-pmp
# artefact: target/release/bastion-plugin-pmp[.exe]

# package for upload
cargo run -p bv-plugin-pack -- \
  --plugin-toml plugins-ext/bastion-plugin-pmp/plugin.toml \
  --bin         target/release/bastion-plugin-pmp \
  --out         dist/bastion-plugin-pmp.bvplugin
```

Then upload via `POST /v1/sys/plugins` (or the GUI's Plugins page).
