# Migrating from Password Manager Pro to BastionVault

End-to-end runbook for moving an existing ManageEngine **Password
Manager Pro** (PMP) inventory into BastionVault using the
`pmp-import` plugin. The plugin parses PMP's `ExportPasswordView`
spreadsheet (`.xls` or `.xlsx`) and returns a structured plan; the
BastionVault GUI walks that plan against the existing Resource /
KV / Asset Group surfaces. **Nothing is written to the vault until
you click "Run import"** in the wizard's third step.

Tested end-to-end against PMP 11.x / 12.x (`.xls`) and PMP 13.x
(`.xlsx`) exports. See [the feature spec](https://github.com/ffquintella/BastionVault/blob/main/features/pmp-import.md)
for the design background.

---

## 1. Prerequisites

- BastionVault server with a mounted **Resource engine** (the
  default deployment auto-mounts at `resource/`) and at least one
  **KV-v2** mount (default `secret/`).
- An operator account with a token that can:
  - `write_resource` and `write_resource_secret` on the resource
    mount,
  - `write_secret` on the KV mount you'll use for KV-bound rows,
  - `list_asset_groups` / `read_asset_group` / `write_asset_group`.
  Root or any policy that includes the equivalents will do; see
  [`features/per-user-scoping.md`](https://github.com/ffquintella/BastionVault/blob/main/features/per-user-scoping.md).
- The `pmp-import` plugin installed: build from
  `plugins-ext/bastion-plugin-pmp`, pack with `bv-plugin-pack`, and
  upload via `Settings → Plugins`.

> **Heads-up:** ownership = the operator running the wizard. Every
> resource and KV entry the import creates is owned by your
> identity. PMP's `Department` column maps to an **asset group**,
> not to ownership. If a different team should own the imported
> resources, transfer ownership with `transfer_resource_owner`
> after the import.

---

## 2. Export from PMP

1. In PMP, go to **Resources → Export Resources**.
2. Pick the resources you want to migrate (or "All").
3. **Choose `.xls` or `.xlsx` format.** Both work.
4. **Do not enable per-export encryption.** The plugin rejects
   encrypted exports with a clear error — re-export without the
   password if you've already encrypted one. (The wizard's
   step-1 `validate` pass surfaces this on file pick.)
5. Save the file somewhere you can browse to from the workstation
   running BastionVault's GUI.

The expected sheet name is `ExportPasswordView`. If your PMP build
emits a differently-named sheet, the plugin falls back to the
first sheet whose header row contains every required column
(`Resource Name`, `User Account`, `Password`, `OS Type`).

---

## 3. Run the wizard

Open the BastionVault GUI, sign in, and navigate to **Resources →
Import from PMP** (the link only appears when the plugin is
installed). The wizard has three steps.

### Step 1 — Pick file

1. Click **Browse…** and select the PMP export.
2. The wizard runs `op = "validate"` and shows: format (`xls` /
   `xlsx`), sheet name, row count, plus any **unknown columns**
   (custom PMP fields like `Ambiente`, `Instância`, `AWS Account`,
   `Console URL`, `Role`).
3. For each unknown column you can choose:
   - **Preserve as metadata** (default on) — the value lands as a
     resource metadata field (lower-cased key, e.g. `aws_account`)
     or in the KV envelope.
   - **Use as tag** — the value becomes a tag on the resource (or
     enters the KV blob's `metadata.tags`).
4. Set:
   - **Batch ID** — appears in `pmp-import:<batch-id>` tags and in
     the KV path. Defaults to a timestamp; rename if you want a
     more meaningful identifier (e.g. `pmp-cutover-2026Q2`).
   - **KV mount** — pulled from `list_mounts`, filtered to KV-v2.
     The wizard defaults to the first mount whose name starts with
     `secret`.
   - **Collision policy** — what to do when a resource or KV path
     already exists:
     - `Skip` — leave the existing entry alone (idempotent on
       re-runs).
     - `Overwrite` — replace the existing entry's value with the
       PMP one. Resource metadata fields not mentioned in the PMP
       row are kept as-is by `write_resource`.
     - `Rename` — append `-2`, `-3`, … to the new name and create
       fresh.
5. Click **Build plan →**.

### Step 2 — Review

The wizard now has a parsed plan in memory. Walk through it before
running anything:

- **Summary metrics** — resource count, account-secret count, KV
  entry count, asset-group count, type distribution, KV
  distribution, and the count of skipped rows (with the first few
  reasons inline).
- **Asset groups** — every distinct PMP `Department` slugified
  into a BV asset-group name (`TIC/INFRA` → `tic-infra`,
  `Direção Geral` → `direção-geral`). Each group is tagged
  **will create** or **will update** based on the existing groups
  in your vault.
- **Resources** tree, grouped by inferred BV type (`server` /
  `database` / `firewall` / `switch` / `website` /
  `network_device` / `application`). **Click any row to expand
  and see the masked account list** — the import writes one
  resource secret per account under that resource, so this is
  where you confirm the resource-to-accounts linkage.
- **KV entries** — `Generic Keys` / `Application Passwords` /
  `License Store` rows, grouped by kind. The destination path
  uses the KV mount you picked in step 1.
- **Owner banner** at the top reminds you that you'll be the
  owner of everything created.

Use the per-tree **Select all** / **None** controls and the
per-row checkboxes to narrow the import. Deselected resources
also remove their members from the asset-group write at run time
— the wizard never creates an empty group.

Click **Run import →** when satisfied.

### Step 3 — Run

The wizard streams progress as it walks the plan in three passes:

1. **Asset groups** — for each derived department group:
   `read_asset_group` (when it exists) → merge in the new members
   and KV paths → `write_asset_group`. **Existing members are
   preserved.** New groups get a `description` of the form
   `Imported from PMP department "<value>" — created by
   <operator> on <YYYY-MM-DD>`.
2. **Resources + accounts** — for each selected resource:
   `write_resource(name, metadata)` once, then a `for` loop over
   the resource's `secrets[]` that calls `write_resource_secret`
   per account. Account writes that fail surface in the errors
   panel; a resource whose `write_resource` failed has its account
   writes skipped (no orphan secrets).
3. **KV blobs** — `write_secret` per entry under the chosen KV
   mount.

Final state shows `done` with three quick links:

- **View imported resources** — Resources page filtered to the
  `pmp-import:<batch-id>` tag.
- **View KV browser** — Secrets page rooted at
  `secret/pmp-import/<batch-id>/`.
- **View asset groups** — Asset Groups page.

---

## 4. After the import

- **Audit & verify.** From the Resources page, click any imported
  resource and check the **Secrets** tab — the account list
  should match the PMP rows for that resource.
- **Asset-group ACLs.** Asset groups are created without any
  policy attach. Bind your group policies from
  **Settings → Asset Groups → &lt;group&gt; → Policies**. The
  importer purposefully leaves this step to you — silently
  attaching policies based on imported names would surprise
  operators.
- **Ownership transfer.** If a different team should own the
  imported resources, use the standard
  `transfer_resource_owner` flow from the resource's
  **Sharing** tab. The importer never sets an owner derived from
  PMP data.
- **Re-run safely.** With `Skip` collision, re-running the wizard
  against the same file is a no-op (matching members are appended
  to existing asset groups; resources / KV paths stay untouched).
  Use this to migrate in waves: filter a subset of departments in
  step 2, run, then come back later for the rest.
- **Cleanup.** If something went wrong, the
  `pmp-import:<batch-id>` tag lets you locate the affected
  resources for bulk delete. KV entries created in this run all
  live under `secret/pmp-import/<batch-id>/` — you can drop the
  entire prefix with one operator action.

---

## 5. Things the importer deliberately doesn't do

- **PMP's per-resource ACLs** don't translate. You apply BV
  policies to the new asset groups by hand.
- **PMP's `Arquivos de Incidentes`** entries are skipped — the
  spreadsheet doesn't carry the actual attached blobs.
- **Passwords are preserved exactly** — including trailing
  whitespace and embedded control characters that PMP's UI
  silently trims when it shows them. If something doesn't look
  right post-import, check the raw PMP value first.
- **One-way migration only** — there's no round-trip back to PMP.

---

## 6. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Encrypted PMP exports are not supported (…)` on file pick | PMP's per-export encryption is on. | Re-export without the encryption checkbox. |
| `spreadsheet is missing required columns: …` | PMP build dropped a column from `ExportPasswordView`, or a renamed sheet doesn't carry it. | Add the missing column in PMP's export profile and re-export. The required four are `Resource Name`, `User Account`, `Password`, `OS Type`. |
| Some rows skipped with `missing User Account` / `missing Password` | PMP exports placeholders (`N/A`, `null`, blank) for these fields on a few rows — typical for license/key entries with no account. | Check the original rows; if they should have been KV-bound (`Generic Keys` / `Application Passwords` / `License Store`), ensure their `OS Type` matches one of those values. |
| Resource appears with the wrong BV type | PMP's `OS Type` value isn't in the default lookup, or you want to override `Cisco IOS` to `firewall` (Cisco ASA). | Use the per-row override in step 2, or pre-fill `type_overrides` if you call the plugin directly. |
| Asset group already exists with different content | Expected — collision policy `Skip` doesn't apply to groups; the import always merges members into existing groups. Pre-existing members survive. | If you don't want a merge, rename the conflicting department in PMP before exporting. |
| KV entries land under the wrong mount | KV mount in step 1 wasn't the one you wanted. | Re-run with the correct mount; the previous entries can be deleted by their `secret/pmp-import/<batch-id>/` prefix. |
