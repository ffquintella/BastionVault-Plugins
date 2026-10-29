# bastion-plugin-dbms-management

The server half of BastionVault's SQL browser (`features/sql-browser.md` in the
host repository, S109, T125 Phase 3): a long-lived, multiplexed process plugin
(ABI 1.4) that holds PostgreSQL sessions on `database` resources. The operator
never receives the database login; every statement is classified
(`bv-sql-classify`), authorized by the vault (`resource_sql_authorize`), run
through the plugin's one authorized-send path, and audited with the
host-stamped actor.

## Registering

1. Build: `make plugins-process` (host repository) or
   `cargo build --release -p bastion-plugin-dbms-management` here.
2. Register the binary with `plugin.toml`, mount it (suggested `dbms/`).
3. An administrator approves both grants, pinned to the manifest's capability
   block: `v2/sys/plugins/dbms-management/grants/sql-gate` and
   `…/grants/resource-credentials`.
4. Bind each database secret to its endpoint (`sql_endpoint`) and give the
   resource `sql` profiles with an honest `ceiling`; a read-only grant needs a
   profile whose ceiling is exactly `["sql_select"]` under `database-first`.
5. Optional: `v2/config` (admin) for limits and `allowed_networks`. The
   default dials private ranges only; add the vault's own listeners to
   `denied_networks`.

## Paths (mount-relative, all `v2`)

`config` · `sessions` · `sessions/<id>` · `sessions/<id>/execute` ·
`sessions/<id>/runs/<run>` · `sessions/<id>/runs/<run>/cancel` ·
`sessions/<id>/objects[/<schema>[/<object>]]` · `sessions/<id>/rows` ·
`sessions/<id>/ceiling` · `journal/self/…` · `journal/all/…`.
Scripts and exports arrive with T126.

## Tests

- `cargo nextest run -p bastion-plugin-dbms-management` and
  `cargo test -p bastion-plugin-dbms-management --doc` (no database).
- `make test-dbms` (host repository): live tests against throwaway
  `postgres:16` containers through docker, plus the `openssl-sys` /
  `aws-lc-sys` ban.

## Known limits

Process plugins are not OS-sandboxed: back `allowed_networks` with an
OS-level egress policy. Sessions are node-local and never fail over. See the
spec's *Phase 3, the plugin* for the residual risks.
