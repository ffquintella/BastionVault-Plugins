# bastion-plugin-dbms-management

The server half of BastionVault's SQL browser (`features/sql-browser.md` in the
host repository, S109, T125 Phase 3; MySQL and MariaDB T127 Phase 6; SQL
Server T128 Phase 7; Oracle T129 Phase 8): a long-lived, multiplexed process
plugin (ABI 1.4) that holds PostgreSQL, MySQL (8.0+), MariaDB (10.6+), SQL
Server (2016+, tested on 2022) and Oracle Database (23ai and later, TCPS only,
tested on Oracle AI Database 26ai Free) sessions on `database` resources.
Oracle runs on the plugin's own session layer (`src/oracle/tns.rs`) over the
Sans-I/O `oraclemcp-driver-cx-protocol` crate. MySQL and MariaDB profiles need TLS
`require` or `verify-full`; SQL Server profiles need any mode but `disable`,
and the server must present a configured X.509 v3 certificate (the one SQL
Server generates for itself is v1, which webpki refuses). The operator
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
`sessions/<id>/ceiling` · `sessions/<id>/script` · `sessions/<id>/export` ·
`sessions/<id>/exports/<job>[/<offset>|/cancel]` · `journal/self/…` ·
`journal/all/…`. Scripts need `sql_script`, exports `sql_export`, and a
profile's `step_up` list asks for an action-bound MFA ticket
(`step_up_ticket`) before a request uses one of its capabilities (T126,
Phase 5).

## Tests

- `cargo nextest run -p bastion-plugin-dbms-management` and
  `cargo test -p bastion-plugin-dbms-management --doc` (no database).
- `make test-dbms` (host repository): live tests against throwaway
  `postgres:16`, `mysql:8.4`, `mariadb:11.4` and
  `mcr.microsoft.com/mssql/server:2022-latest` (linux/amd64) and
  `gvenzl/oracle-free:23-full` containers through docker,
  plus the `openssl-sys` / `aws-lc-sys` / `native-tls` ban.

## Known limits

Process plugins are not OS-sandboxed: back `allowed_networks` with an
OS-level egress policy. Sessions are node-local and never fail over. See the
spec's *Phase 3, the plugin* for the residual risks.
