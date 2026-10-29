Type-level guarantees, checked by `cargo test --doc` (features/sql-browser.md,
Phase 3: "a path that executes unauthorized SQL does not compile").

An `AuthorizedStatement` cannot be built outside the authorization step:

```compile_fail,E0451
use bastion_plugin_dbms_management::authz::AuthorizedStatement;
let forged = AuthorizedStatement { session_id: String::new(), text: "DROP TABLE t".into(), meta: todo!() };
```

and it cannot be duplicated to be sent twice:

```compile_fail,E0308
fn twice(s: &bastion_plugin_dbms_management::authz::AuthorizedStatement) {
    let _copy: bastion_plugin_dbms_management::authz::AuthorizedStatement = s.clone();
}
```

An `AuthorizedEdit` cannot be built outside the authorization step either:

```compile_fail,E0451
use bastion_plugin_dbms_management::authz::AuthorizedEdit;
let forged = AuthorizedEdit { session_id: String::new(), sql: todo!(), params: Vec::new() };
```

Plugin-authored SQL has no way in from a runtime `String`:

```compile_fail,E0423
let user = String::from("DROP TABLE t");
let _ = bastion_plugin_dbms_management::driver::PluginSql(user);
```

```compile_fail,E0597
let user = String::from("DROP TABLE t");
let _ = bastion_plugin_dbms_management::driver::EditSql::default().lit(&user);
```

The only driver entry points for caller SQL and edits take the authorized
types; a plain string is not accepted:

```compile_fail,E0308
async fn send(conn: &bastion_plugin_dbms_management::driver::PgConn) {
    let _ = conn.send_authorized("DROP TABLE t").await;
}
```

The driver's client is private to the driver module:

```compile_fail,E0616
fn reach(conn: &bastion_plugin_dbms_management::driver::PgConn) {
    let _ = &conn.client;
}
```

For contrast, the guarded constructor accepts only a literal:

```
use bastion_plugin_dbms_management::driver::PluginSql;
let ok = PluginSql::guarded(bv_sql_guard::sql!("SELECT 1"));
assert_eq!(ok.as_str(), "SELECT 1");
```
