//! The object browser, describe, structured row edits and the ceiling probe
//! for Oracle sessions (§5.1, §7). Catalog reads are plugin-authored
//! `bv_sql_guard` literals over the `ALL_*` views, every name a bound value.
//! Object paths are `<SERVICE>/<OWNER>/<OBJECT>` (§3.2), with the names as
//! the dictionary stores them (the classifier's canonical form).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bv_sql_guard::sql;
use oraclemcp_driver_cx_protocol::thin::QueryValue;
use serde_json::{json, Map, Value};

use super::conn::OraConn;
use crate::api::ApiError;
use crate::authz::authorize_edit;
use crate::driver::{DbError, PluginSql};
use crate::host::Check;
use crate::objects::{catalog, decide, require, MAX_LISTED};
use crate::rows::Edit;
use crate::session::{Ctx, Session};
use crate::wire::TxStatus;
use crate::{ids, journal};

fn db(e: DbError) -> ApiError {
    ApiError::refused("database_error", e.message)
}

/// Column `i` of a catalog row as text.
fn col(row: &[Option<QueryValue>], i: usize) -> Option<String> {
    match row.get(i)?.as_ref()? {
        QueryValue::Text(s) => Some(s.clone()),
        QueryValue::Number(n) => Some(n.to_canonical_string()),
        _ => None,
    }
}

/// `LIST v2/sessions/<id>/objects`: the schemas that are not Oracle's own,
/// plus the session's current schema.
pub fn schemas(cx: &Ctx<'_>, s: &Arc<Session>, conn: &Arc<OraConn>) -> Result<Value, ApiError> {
    require(cx, s, Check::server("sql_select"))?;
    let q = PluginSql::guarded(sql!(
        "SELECT username FROM all_users \
         WHERE oracle_maintained = 'N' OR username = SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') ORDER BY username"
    ));
    let rows = cx.rt.block_on(conn.internal_query(&q, &[])).map_err(db)?;
    let names: Vec<String> = rows.iter().filter_map(|r| col(r, 0)).collect();
    Ok(json!({"catalog": catalog(s), "keys": names}))
}

fn kind(t: &str) -> &'static str {
    match t {
        "TABLE" => "table",
        "VIEW" => "view",
        "MATERIALIZED VIEW" => "materialized_view",
        "SEQUENCE" => "sequence",
        "SYNONYM" => "synonym",
        "PROCEDURE" | "FUNCTION" | "PACKAGE" => "routine",
        "TYPE" => "type",
        _ => "other",
    }
}

/// `LIST v2/sessions/<id>/objects/<schema>`: tables, views, sequences,
/// synonyms, routines and types of a schema, filtered by the caller's
/// grants.
pub fn list(cx: &Ctx<'_>, s: &Arc<Session>, conn: &Arc<OraConn>, schema: &str) -> Result<Value, ApiError> {
    let cat = catalog(s);
    let q = PluginSql::guarded(sql!(
        "SELECT object_name, object_type FROM all_objects WHERE owner = :1 AND subobject_name IS NULL \
           AND object_type IN ('TABLE','VIEW','MATERIALIZED VIEW','SEQUENCE','SYNONYM','PROCEDURE','FUNCTION','PACKAGE','TYPE') \
         ORDER BY object_name, object_type FETCH FIRST 2001 ROWS ONLY"
    ));
    let rows = cx.rt.block_on(conn.internal_query(&q, &[schema])).map_err(db)?;
    // A materialized view is listed once, as itself, not also as its table.
    let mut by_name: BTreeMap<String, String> = BTreeMap::new();
    for r in &rows {
        let (Some(n), Some(t)) = (col(r, 0), col(r, 1)) else { continue };
        match by_name.get(&n).map(String::as_str) {
            Some("MATERIALIZED VIEW") => {}
            _ => {
                by_name.insert(n, t);
            }
        }
    }
    let mut objects: Vec<(String, String)> = by_name.into_iter().collect();
    let truncated = objects.len() as i64 > MAX_LISTED;
    objects.truncate(MAX_LISTED as usize);
    let wide = decide(cx, s, &[Check::object("sql_select", &cat, "", "")])?;
    let visible: Vec<bool> = if wide.first() == Some(&true) {
        vec![true; objects.len()]
    } else {
        let asked: Vec<Check> = objects.iter().map(|(n, _)| Check::object("sql_select", &cat, schema, n)).collect();
        decide(cx, s, &asked)?
    };
    let out: Vec<Value> = objects
        .iter()
        .zip(visible)
        .filter(|(_, v)| *v)
        .map(|((name, k), _)| json!({"name": name, "kind": kind(k)}))
        .collect();
    Ok(json!({"catalog": cat, "schema": schema, "objects": out, "truncated": truncated}))
}

/// The key a grid edit addresses: the primary key, else the first enabled
/// unique constraint whose columns are all NOT NULL (§7).
pub async fn edit_key(conn: &OraConn, schema: &str, table: &str) -> Result<Option<Vec<String>>, DbError> {
    let q = PluginSql::guarded(sql!(
        "SELECT c.constraint_name, cc.column_name, c.constraint_type, tc.nullable \
         FROM all_constraints c \
         JOIN all_cons_columns cc ON cc.owner = c.owner AND cc.constraint_name = c.constraint_name \
         JOIN all_tab_cols tc ON tc.owner = c.owner AND tc.table_name = c.table_name AND tc.column_name = cc.column_name \
         WHERE c.owner = :1 AND c.table_name = :2 AND c.constraint_type IN ('P', 'U') AND c.status = 'ENABLED' \
         ORDER BY DECODE(c.constraint_type, 'P', 0, 1), c.constraint_name, cc.position"
    ));
    let rows = conn.internal_query(&q, &[schema, table]).await?;
    let mut keys: Vec<(String, Vec<String>, bool, bool)> = Vec::new();
    for r in &rows {
        let (Some(name), Some(column)) = (col(r, 0), col(r, 1)) else { continue };
        let primary = col(r, 2).as_deref() == Some("P");
        let not_null = col(r, 3).as_deref() == Some("N");
        match keys.last_mut() {
            Some((n, cols, all, _)) if *n == name => {
                cols.push(column);
                *all &= not_null;
            }
            _ => keys.push((name, vec![column], not_null, primary)),
        }
    }
    Ok(keys.into_iter().find(|(_, _, all, primary)| *primary || *all).map(|(_, cols, _, _)| cols))
}

/// Column types the grid can write back as text under the session's
/// pinned NLS formats.
fn editable_type(t: &str) -> bool {
    matches!(
        t,
        "VARCHAR2" | "NVARCHAR2" | "CHAR" | "NCHAR" | "NUMBER" | "FLOAT" | "BINARY_FLOAT" | "BINARY_DOUBLE" | "DATE"
    ) || (t.starts_with("TIMESTAMP(") && !t.contains("ZONE"))
}

/// `READ v2/sessions/<id>/objects/<schema>/<object>`.
pub fn describe(
    cx: &Ctx<'_>,
    s: &Arc<Session>,
    conn: &Arc<OraConn>,
    schema: &str,
    name: &str,
) -> Result<Value, ApiError> {
    let cat = catalog(s);
    require(cx, s, Check::object("sql_select", &cat, schema, name))?;
    let p = [schema, name];
    let obj = PluginSql::guarded(sql!(
        "SELECT o.object_type, (SELECT v.text_vc FROM all_views v WHERE v.owner = o.owner AND v.view_name = o.object_name) \
         FROM all_objects o WHERE o.owner = :1 AND o.object_name = :2 AND o.subobject_name IS NULL \
           AND o.object_type IN ('TABLE','VIEW','MATERIALIZED VIEW','SEQUENCE','SYNONYM','PROCEDURE','FUNCTION','PACKAGE','TYPE') \
         ORDER BY DECODE(o.object_type, 'MATERIALIZED VIEW', 0, 1)"
    ));
    let cols = PluginSql::guarded(sql!(
        "SELECT column_name, data_type, nullable, data_default_vc, identity_column, virtual_column \
         FROM all_tab_cols WHERE owner = :1 AND table_name = :2 AND hidden_column = 'NO' ORDER BY column_id"
    ));
    let cons = PluginSql::guarded(sql!(
        "SELECT constraint_name, constraint_type FROM all_constraints \
         WHERE owner = :1 AND table_name = :2 ORDER BY constraint_name"
    ));
    let idx = PluginSql::guarded(sql!(
        "SELECT i.index_name, i.uniqueness, c.column_name FROM all_indexes i \
         JOIN all_ind_columns c ON c.index_owner = i.owner AND c.index_name = i.index_name \
         WHERE i.table_owner = :1 AND i.table_name = :2 ORDER BY i.index_name, c.column_position"
    ));
    let trg = PluginSql::guarded(sql!(
        "SELECT trigger_name, trigger_type, triggering_event FROM all_triggers \
         WHERE table_owner = :1 AND table_name = :2 ORDER BY trigger_name"
    ));
    let (obj, cols, cons, idx, trg, key) = cx
        .rt
        .block_on(async {
            Ok::<_, DbError>((
                conn.internal_query(&obj, &p).await?,
                conn.internal_query(&cols, &p).await?,
                conn.internal_query(&cons, &p).await?,
                conn.internal_query(&idx, &p).await?,
                conn.internal_query(&trg, &p).await?,
                edit_key(conn, schema, name).await?,
            ))
        })
        .map_err(db)?;
    let Some(object_type) = obj.first().and_then(|r| col(r, 0)) else {
        return Err(ApiError::not_found("no such object, or the login cannot see it"));
    };
    let columns: Vec<Value> = cols
        .iter()
        .map(|r| {
            let mut extra = Vec::new();
            if col(r, 4).as_deref() == Some("YES") {
                extra.push("identity");
            }
            if col(r, 5).as_deref() == Some("YES") {
                extra.push("virtual");
            }
            json!({"name": col(r, 0), "type": col(r, 1), "not_null": col(r, 2).map(|n| n == "N"),
                "default": col(r, 3).map(|d| d.trim().to_string()), "extra": extra.join(" ")})
        })
        .collect();
    let mut indexes: BTreeMap<String, (bool, Vec<String>)> = BTreeMap::new();
    for r in &idx {
        let (Some(n), Some(c)) = (col(r, 0), col(r, 2)) else { continue };
        let e = indexes.entry(n).or_insert((col(r, 1).as_deref() == Some("UNIQUE"), Vec::new()));
        e.1.push(c);
    }
    let editable = editability(&object_type, schema, name, key.as_deref(), &columns);
    Ok(json!({
        "catalog": cat,
        "schema": schema,
        "name": name,
        "kind": kind(&object_type),
        "definition": obj.first().and_then(|r| col(r, 1)),
        "columns": columns,
        "constraints": cons.iter().map(|r| json!({"name": col(r, 0), "type": col(r, 1)})).collect::<Vec<_>>(),
        "indexes": indexes.into_iter().map(|(n, (unique, c))| json!({"name": n, "unique": unique, "columns": c})).collect::<Vec<_>>(),
        "triggers": trg.iter().map(|r| json!({"name": col(r, 0), "timing": col(r, 1), "event": col(r, 2)})).collect::<Vec<_>>(),
        "edit": editable,
    }))
}

fn editability(kind: &str, schema: &str, name: &str, key: Option<&[String]>, cols: &[Value]) -> Value {
    let ident = |s: &str| bv_sql_guard::SqlIdent::new(s).is_ok();
    let reason = if kind != "TABLE" {
        Some("only tables are editable in the grid")
    } else if key.is_none() {
        Some("the table has no primary key or non-null unique key")
    } else if !ident(schema) || !ident(name) || cols.iter().any(|c| !c["name"].as_str().is_some_and(ident)) {
        Some("a name is outside [A-Za-z_][A-Za-z0-9_]{0,62}: read-only in the grid; write the statement by hand")
    } else {
        None
    };
    json!({"editable": reason.is_none(), "key": key, "reason": reason})
}

/// The data types of a table's columns, for the edit's type check.
async fn column_types(conn: &OraConn, schema: &str, table: &str) -> Result<BTreeMap<String, String>, DbError> {
    let q = PluginSql::guarded(sql!(
        "SELECT column_name, data_type FROM all_tab_cols WHERE owner = :1 AND table_name = :2 AND hidden_column = 'NO'"
    ));
    let rows = conn.internal_query(&q, &[schema, table]).await?;
    Ok(rows.iter().filter_map(|r| Some((col(r, 0)?, col(r, 1)?))).collect())
}

/// `POST v2/sessions/<id>/rows` on an Oracle session: the edit committed on
/// its own, or under a savepoint inside the caller's transaction.
pub fn apply(
    cx: &Ctx<'_>,
    s: &Arc<Session>,
    conn: &Arc<OraConn>,
    edit: Edit,
    ticket: Option<&str>,
) -> Result<Value, ApiError> {
    if let Some(why) = conn.taint() {
        return Err(ApiError::refused("session_tainted", why));
    }
    let cat = catalog(s);
    let (schema, table) = (edit.schema.as_str().to_string(), edit.table.as_str().to_string());
    let (key_cols, types) = cx
        .rt
        .block_on(async {
            Ok::<_, DbError>((edit_key(conn, &schema, &table).await?, column_types(conn, &schema, &table).await?))
        })
        .map_err(db)?;
    let key_cols = key_cols
        .ok_or_else(|| ApiError::refused("not_editable", "the table has no primary key or non-null unique key"))?;
    let touched = edit.key.keys().chain(edit.values.keys()).chain(edit.original.keys());
    for c in touched {
        match types.get(c) {
            Some(t) if editable_type(t) => {}
            Some(t) => {
                return Err(ApiError::refused(
                    "read_only_in_grid",
                    format!("column `{c}` is {t}, which the grid does not write; write the statement by hand"),
                ))
            }
            None => return Err(ApiError::bad_request(format!("no column `{c}` in `{schema}.{table}`"))),
        }
    }
    let (sql, params) = edit.build_oracle(&key_cols)?;
    let key_json = serde_json::to_vec(&edit.key).unwrap_or_default();
    let key_hmac = ids::digest(cx.digest_key, "row-key", &key_json);
    let object = format!("{cat}.{schema}.{table}");
    let mut ev = crate::audit::base("dbms.row_edit", &s.id, &s.resource, &s.profile, s.info.db_enforced);
    ev["object"] = json!(object);
    ev["op"] = json!(edit.op.as_str());
    ev["key_hmac"] = json!(key_hmac);
    ev["columns"] = json!(edit.changed_columns());
    let authorized =
        authorize_edit(cx.host, &s.resource, &s.id, edit.op.capability(), (&cat, &schema, &table), sql, params)?;
    let edit_auth = match authorized {
        Ok(a) => a,
        Err(verdicts) => {
            ev["outcome"] = json!("refused");
            let _ = cx.host.audit(ev);
            let first = verdicts.iter().find(|v| !v.allowed).map(|v| v.capability.clone()).unwrap_or_default();
            return Ok(json!({"state": "refused", "message": format!("needs `{first}` on `{object}`"),
                "verdicts": verdicts.iter().map(|v| json!({"capability": v.capability, "allowed": v.allowed})).collect::<Vec<_>>()}));
        }
    };
    let caps: BTreeSet<&'static str> = [edit.op.capability(), "sql_select"].into_iter().collect();
    if let Some(reply) = crate::session::step_up(cx, s, &caps, ticket)? {
        return Ok(reply);
    }
    let in_tx = conn.tx() == TxStatus::InTransaction;
    let result: Result<(u64, bool), DbError> = cx.rt.block_on(async {
        if in_tx {
            conn.internal_execute(&PluginSql::guarded(sql!("SAVEPOINT bv_row_edit"))).await?;
        }
        let undo = if in_tx {
            PluginSql::guarded(sql!("ROLLBACK TO SAVEPOINT bv_row_edit"))
        } else {
            PluginSql::guarded(sql!("ROLLBACK"))
        };
        match conn.send_edit(edit_auth).await {
            Ok(1) => {
                if !in_tx {
                    conn.internal_execute(&PluginSql::guarded(sql!("COMMIT"))).await?;
                }
                Ok((1, true))
            }
            Ok(n) => {
                conn.internal_execute(&undo).await?;
                Ok((n, false))
            }
            Err(e) => {
                let _ = conn.internal_execute(&undo).await;
                Err(e)
            }
        }
    });
    let (outcome, reply) = match result {
        Ok((1, true)) => ("ok", json!({"state": "done", "rows_affected": 1})),
        Ok((n, _)) => (
            "conflict",
            json!({"state": "conflict", "rows_affected": n,
                "message": "the row changed (or is gone) since it was read; nothing was written"}),
        ),
        Err(e) => {
            ev["sqlstate"] = json!(e.sqlstate);
            ("error", json!({"state": "error", "error": {"sqlstate": e.sqlstate, "message": e.message}}))
        }
    };
    ev["outcome"] = json!(outcome);
    let _ = cx.host.audit(ev);
    s.journal_push(json!({"at_ms": journal::now_ms(), "kinds": ["RowEdit"], "op": edit.op.as_str(),
        "object": object, "columns": edit.changed_columns(), "key_hmac": key_hmac, "outcome": outcome}));
    Ok(reply)
}

// ── the ceiling probe (§5.1): SESSION_PRIVS, SESSION_ROLES, object grants ──

/// One system privilege to the §3.1 vocabulary. `CREATE SESSION` and the
/// `SELECT ANY DICTIONARY`-style reads are `sql_select` or nothing; unknown
/// privileges are `sql_admin`.
fn system_privilege(p: &str, out: &mut BTreeSet<&'static str>) {
    let p = p.trim().to_ascii_uppercase();
    let caps: &[&'static str] = match p.as_str() {
        "CREATE SESSION" | "SET CONTAINER" | "UNLIMITED TABLESPACE" | "" => &[],
        "SELECT ANY TABLE" | "READ ANY TABLE" | "SELECT ANY SEQUENCE" | "SELECT ANY DICTIONARY" => &["sql_select"],
        "INSERT ANY TABLE" => &["sql_insert"],
        "UPDATE ANY TABLE" | "LOCK ANY TABLE" => &["sql_update"],
        "DELETE ANY TABLE" => &["sql_delete"],
        "EXECUTE ANY PROCEDURE" | "EXECUTE ANY TYPE" => &["sql_execute"],
        "DROP ANY TABLE" | "DROP ANY VIEW" | "DROP ANY SEQUENCE" | "DROP ANY PROCEDURE" | "DROP ANY INDEX"
        | "DROP ANY TRIGGER" | "DROP ANY TYPE" | "DROP ANY SYNONYM" => &["sql_drop"],
        _ if p.starts_with("ALTER ANY ") => &["sql_alter"],
        "CREATE TABLE"
        | "CREATE VIEW"
        | "CREATE SEQUENCE"
        | "CREATE PROCEDURE"
        | "CREATE TRIGGER"
        | "CREATE TYPE"
        | "CREATE SYNONYM"
        | "CREATE MATERIALIZED VIEW" => {
            // Creating in the own schema: the owner may also change and drop
            // what it creates, and read and write its own tables.
            &[
                "sql_create",
                "sql_alter",
                "sql_drop",
                "sql_select",
                "sql_insert",
                "sql_update",
                "sql_delete",
                "sql_execute",
            ]
        }
        _ if p.starts_with("CREATE ANY ") => &["sql_create"],
        _ => &["sql_admin"],
    };
    out.extend(caps.iter().copied());
}

/// One object privilege (granted directly or through a role).
fn object_privilege(p: &str, out: &mut BTreeSet<&'static str>) {
    let caps: &[&'static str] = match p.trim().to_ascii_uppercase().as_str() {
        "SELECT" | "READ" => &["sql_select"],
        "INSERT" => &["sql_insert"],
        "UPDATE" => &["sql_update"],
        "DELETE" => &["sql_delete"],
        "EXECUTE" => &["sql_execute"],
        "ALTER" | "INDEX" | "REFERENCES" => &["sql_alter"],
        "DEBUG" | "FLASHBACK" | "ON COMMIT REFRESH" | "QUERY REWRITE" | "UNDER" | "KEEP SEQUENCE"
        | "INHERIT PRIVILEGES" => &[],
        _ => &["sql_admin"],
    };
    out.extend(caps.iter().copied());
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Privileges {
    pub capabilities: BTreeSet<&'static str>,
    pub superuser: bool,
}

pub fn map_privileges(system: &[String], roles: &[String], objects: &[String]) -> Privileges {
    let mut p = Privileges::default();
    for s in system {
        system_privilege(s, &mut p.capabilities);
    }
    for o in objects {
        object_privilege(o, &mut p.capabilities);
    }
    p.superuser = roles.iter().any(|r| r.eq_ignore_ascii_case("DBA"))
        || system.iter().any(|s| s.eq_ignore_ascii_case("GRANT ANY PRIVILEGE") || s.eq_ignore_ascii_case("SYSDBA"));
    if p.superuser {
        p.capabilities.extend(crate::profile::STATEMENT_CAPS.iter().copied());
    }
    p
}

/// `READ v2/sessions/<id>/ceiling`.
pub fn probe(cx: &Ctx<'_>, s: &Arc<Session>, conn: &Arc<OraConn>) -> Result<Value, ApiError> {
    require(cx, s, Check::server("sql_select"))?;
    let system = PluginSql::guarded(sql!("SELECT privilege FROM session_privs"));
    let roles = PluginSql::guarded(sql!("SELECT role FROM session_roles"));
    let objects = PluginSql::guarded(sql!(
        "SELECT DISTINCT privilege FROM ( \
           SELECT privilege FROM user_tab_privs WHERE grantee = SYS_CONTEXT('USERENV', 'SESSION_USER') \
           UNION ALL SELECT privilege FROM role_tab_privs WHERE role IN (SELECT role FROM session_roles))"
    ));
    let (sys, rol, obj) = cx
        .rt
        .block_on(async {
            Ok::<_, DbError>((
                conn.internal_query(&system, &[]).await?,
                conn.internal_query(&roles, &[]).await?,
                conn.internal_query(&objects, &[]).await?,
            ))
        })
        .map_err(db)?;
    let names = |rows: &[Vec<Option<QueryValue>>]| rows.iter().filter_map(|r| col(r, 0)).collect::<Vec<String>>();
    let p = map_privileges(&names(&sys), &names(&rol), &names(&obj));
    let declared: BTreeSet<&'static str> = s.info.ceiling.iter().copied().collect();
    let probed = &p.capabilities;
    let mut out = Map::new();
    out.insert("profile".into(), json!(s.profile));
    out.insert("declared".into(), json!(declared));
    out.insert("probed".into(), json!(probed));
    out.insert("undeclared".into(), json!(probed.difference(&declared).collect::<Vec<_>>()));
    out.insert("unused".into(), json!(declared.difference(probed).collect::<Vec<_>>()));
    out.insert("superuser".into(), json!(p.superuser));
    out.insert("roles".into(), json!(names(&rol)));
    // Object grants are mapped by privilege, not expanded per object
    // (advisory, §5.1).
    out.insert("scopes".into(), json!(["system", "object"]));
    out.insert("advisory".into(), json!(true));
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn privileges_map_onto_capabilities() {
        let reader = map_privileges(&v(&["CREATE SESSION"]), &v(&[]), &v(&["SELECT", "READ"]));
        assert_eq!(reader.capabilities, ["sql_select"].into_iter().collect());
        assert!(!reader.superuser);
        let writer = map_privileges(&v(&["CREATE SESSION"]), &v(&[]), &v(&["SELECT", "INSERT", "UPDATE", "DELETE"]));
        assert_eq!(writer.capabilities.len(), 4);
        let owner = map_privileges(&v(&["CREATE TABLE"]), &v(&[]), &v(&[]));
        assert!(owner.capabilities.contains("sql_create") && owner.capabilities.contains("sql_drop"));
        assert!(!owner.capabilities.contains("sql_admin"));
        let dba = map_privileges(&v(&["CREATE SESSION"]), &v(&["DBA"]), &v(&[]));
        assert!(dba.superuser && dba.capabilities.len() == 9);
        let odd = map_privileges(&v(&["BECOME USER"]), &v(&[]), &v(&[]));
        assert_eq!(odd.capabilities, ["sql_admin"].into_iter().collect());
    }

    #[test]
    fn only_tables_with_a_key_and_plain_names_are_editable() {
        let cols = vec![json!({"name": "ID"}), json!({"name": "NAME"})];
        let key = vec!["ID".to_string()];
        assert_eq!(editability("TABLE", "APP", "T", Some(&key), &cols)["editable"], true);
        assert_eq!(editability("VIEW", "APP", "V", Some(&key), &cols)["editable"], false);
        assert_eq!(editability("TABLE", "APP", "T", None, &cols)["editable"], false);
        assert_eq!(editability("TABLE", "APP", "T$1", Some(&key), &cols)["editable"], false);
        assert!(editable_type("NUMBER") && editable_type("TIMESTAMP(6)") && editable_type("DATE"));
        assert!(!editable_type("TIMESTAMP(6) WITH TIME ZONE") && !editable_type("CLOB") && !editable_type("RAW"));
    }
}
