//! The object browser, describe, structured row edits and the ceiling probe
//! for MySQL / MariaDB sessions (§5.1, §7). Catalog reads are plugin-authored
//! `bv_sql_guard` literals over `information_schema`, every name a bound
//! parameter. Object paths use the catalog `def` and the database as schema
//! (§3.2).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bv_sql_classify::MYSQL_CATALOG;
use bv_sql_guard::sql;
use mysql_async::{Row, Value as My};
use serde_json::{json, Map, Value};

use super::conn::MyConn;
use crate::api::ApiError;
use crate::authz::authorize_edit;
use crate::driver::{DbError, PluginSql, TextParam};
use crate::host::Check;
use crate::objects::{decide, require, MAX_LISTED};
use crate::rows::Edit;
use crate::session::{Ctx, Session};
use crate::wire::TxStatus;
use crate::{ids, journal};

fn db(e: DbError) -> ApiError {
    ApiError::refused("database_error", e.message)
}

fn text(s: &str) -> TextParam {
    TextParam(Some(s.to_string()))
}

/// Column `i` of a catalog row as text (`NULL` and non-text as `None`).
pub fn col(row: &Row, i: usize) -> Option<String> {
    match row.as_ref(i)? {
        My::Bytes(b) => String::from_utf8(b.clone()).ok(),
        My::Int(n) => Some(n.to_string()),
        My::UInt(n) => Some(n.to_string()),
        _ => None,
    }
}

/// `LIST v2/sessions/<id>/objects`: the databases the login can see.
pub fn schemas(cx: &Ctx<'_>, s: &Arc<Session>, conn: &Arc<MyConn>) -> Result<Value, ApiError> {
    require(cx, s, Check::server("sql_select"))?;
    let q = PluginSql::guarded(sql!("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA ORDER BY 1"));
    let rows = cx.rt.block_on(conn.internal_query(&q, &[])).map_err(db)?;
    let names: Vec<String> = rows.iter().filter_map(|r| col(r, 0)).collect();
    Ok(json!({"catalog": MYSQL_CATALOG, "keys": names}))
}

fn kind(t: &str) -> &'static str {
    match t {
        "BASE TABLE" => "table",
        "VIEW" | "SYSTEM VIEW" => "view",
        "SEQUENCE" => "sequence",
        "TEMPORARY" => "table",
        "ROUTINE" => "routine",
        _ => "other",
    }
}

/// `LIST v2/sessions/<id>/objects/<db>`: tables, views, sequences and
/// routines of a database, filtered by the caller's grants.
pub fn list(cx: &Ctx<'_>, s: &Arc<Session>, conn: &Arc<MyConn>, schema: &str) -> Result<Value, ApiError> {
    let q = PluginSql::guarded(sql!(
        "SELECT name, kind FROM ( \
           SELECT TABLE_NAME AS name, TABLE_TYPE AS kind FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? \
           UNION ALL \
           SELECT ROUTINE_NAME, 'ROUTINE' FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = ? \
         ) o ORDER BY name, kind LIMIT 2001"
    ));
    let rows = cx.rt.block_on(conn.internal_query(&q, &[text(schema), text(schema)])).map_err(db)?;
    let mut objects: Vec<(String, String)> = rows.iter().filter_map(|r| Some((col(r, 0)?, col(r, 1)?))).collect();
    let truncated = objects.len() as i64 > MAX_LISTED;
    objects.truncate(MAX_LISTED as usize);
    let wide = decide(cx, s, &[Check::object("sql_select", MYSQL_CATALOG, "", "")])?;
    let visible: Vec<bool> = if wide.first() == Some(&true) {
        vec![true; objects.len()]
    } else {
        let checks: Vec<Check> =
            objects.iter().map(|(n, _)| Check::object("sql_select", MYSQL_CATALOG, schema, n)).collect();
        decide(cx, s, &checks)?
    };
    let out: Vec<Value> = objects
        .iter()
        .zip(visible)
        .filter(|(_, v)| *v)
        .map(|((name, k), _)| json!({"name": name, "kind": kind(k)}))
        .collect();
    Ok(json!({"catalog": MYSQL_CATALOG, "schema": schema, "objects": out, "truncated": truncated}))
}

/// The key a grid edit addresses: the primary key, else the first unique
/// index whose columns are all NOT NULL (§7).
pub async fn edit_key(conn: &MyConn, schema: &str, table: &str) -> Result<Option<Vec<String>>, DbError> {
    let q = PluginSql::guarded(sql!(
        "SELECT s.INDEX_NAME, s.COLUMN_NAME, c.IS_NULLABLE FROM information_schema.STATISTICS s \
         JOIN information_schema.COLUMNS c ON c.TABLE_SCHEMA = s.TABLE_SCHEMA AND c.TABLE_NAME = s.TABLE_NAME \
           AND c.COLUMN_NAME = s.COLUMN_NAME \
         WHERE s.TABLE_SCHEMA = ? AND s.TABLE_NAME = ? AND s.NON_UNIQUE = 0 \
         ORDER BY s.INDEX_NAME <> 'PRIMARY', s.INDEX_NAME, s.SEQ_IN_INDEX"
    ));
    let rows = conn.internal_query(&q, &[text(schema), text(table)]).await?;
    let mut keys: Vec<(String, Vec<String>, bool)> = Vec::new();
    for r in &rows {
        let (Some(index), Some(column)) = (col(r, 0), col(r, 1)) else { continue };
        let not_null = col(r, 2).as_deref() == Some("NO");
        match keys.last_mut() {
            Some((name, cols, all)) if *name == index => {
                cols.push(column);
                *all &= not_null;
            }
            _ => keys.push((index, vec![column], not_null)),
        }
    }
    Ok(keys.into_iter().find(|(name, _, all)| name == "PRIMARY" || *all).map(|(_, cols, _)| cols))
}

/// `READ v2/sessions/<id>/objects/<db>/<object>`.
pub fn describe(
    cx: &Ctx<'_>,
    s: &Arc<Session>,
    conn: &Arc<MyConn>,
    schema: &str,
    name: &str,
) -> Result<Value, ApiError> {
    require(cx, s, Check::object("sql_select", MYSQL_CATALOG, schema, name))?;
    let p = [text(schema), text(name)];
    let rel = PluginSql::guarded(sql!(
        "SELECT t.TABLE_TYPE, v.VIEW_DEFINITION FROM information_schema.TABLES t \
         LEFT JOIN information_schema.VIEWS v ON v.TABLE_SCHEMA = t.TABLE_SCHEMA AND v.TABLE_NAME = t.TABLE_NAME \
         WHERE t.TABLE_SCHEMA = ? AND t.TABLE_NAME = ?"
    ));
    let cols = PluginSql::guarded(sql!(
        "SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT, EXTRA FROM information_schema.COLUMNS \
         WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION"
    ));
    let cons = PluginSql::guarded(sql!(
        "SELECT CONSTRAINT_NAME, CONSTRAINT_TYPE FROM information_schema.TABLE_CONSTRAINTS \
         WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? ORDER BY CONSTRAINT_NAME"
    ));
    let idx = PluginSql::guarded(sql!(
        "SELECT INDEX_NAME, NON_UNIQUE, COLUMN_NAME FROM information_schema.STATISTICS \
         WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? ORDER BY INDEX_NAME, SEQ_IN_INDEX"
    ));
    let trg = PluginSql::guarded(sql!(
        "SELECT TRIGGER_NAME, ACTION_TIMING, EVENT_MANIPULATION, ACTION_STATEMENT FROM information_schema.TRIGGERS \
         WHERE EVENT_OBJECT_SCHEMA = ? AND EVENT_OBJECT_TABLE = ? ORDER BY TRIGGER_NAME"
    ));
    let fun = PluginSql::guarded(sql!(
        "SELECT ROUTINE_TYPE, ROUTINE_DEFINITION FROM information_schema.ROUTINES \
         WHERE ROUTINE_SCHEMA = ? AND ROUTINE_NAME = ?"
    ));
    let (rel, cols, cons, idx, trg, fun, key) = cx
        .rt
        .block_on(async {
            Ok::<_, DbError>((
                conn.internal_query(&rel, &p).await?,
                conn.internal_query(&cols, &p).await?,
                conn.internal_query(&cons, &p).await?,
                conn.internal_query(&idx, &p).await?,
                conn.internal_query(&trg, &p).await?,
                conn.internal_query(&fun, &p).await?,
                edit_key(conn, schema, name).await?,
            ))
        })
        .map_err(db)?;
    let table_type = rel.first().and_then(|r| col(r, 0));
    if table_type.is_none() && fun.is_empty() {
        return Err(ApiError::not_found("no such object, or the login cannot see it"));
    }
    let columns: Vec<Value> = cols
        .iter()
        .map(|r| {
            json!({"name": col(r, 0), "type": col(r, 1), "not_null": col(r, 2).map(|n| n == "NO"),
                "default": col(r, 3), "extra": col(r, 4)})
        })
        .collect();
    let mut indexes: BTreeMap<String, (bool, Vec<String>)> = BTreeMap::new();
    for r in &idx {
        let (Some(n), Some(c)) = (col(r, 0), col(r, 2)) else { continue };
        let e = indexes.entry(n).or_insert((col(r, 1).as_deref() == Some("0"), Vec::new()));
        e.1.push(c);
    }
    let editable = editability(table_type.as_deref(), schema, name, key.as_deref(), &columns);
    Ok(json!({
        "catalog": MYSQL_CATALOG,
        "schema": schema,
        "name": name,
        "kind": table_type.as_deref().map(kind).unwrap_or("routine"),
        "definition": rel.first().and_then(|r| col(r, 1)),
        "columns": columns,
        "constraints": cons.iter().map(|r| json!({"name": col(r, 0), "type": col(r, 1)})).collect::<Vec<_>>(),
        "indexes": indexes.into_iter().map(|(n, (unique, c))| json!({"name": n, "unique": unique, "columns": c})).collect::<Vec<_>>(),
        "triggers": trg.iter().map(|r| json!({"name": col(r, 0), "timing": col(r, 1), "event": col(r, 2),
            "definition": col(r, 3)})).collect::<Vec<_>>(),
        "routines": fun.iter().map(|r| json!({"kind": col(r, 0), "definition": col(r, 1)})).collect::<Vec<_>>(),
        "edit": editable,
    }))
}

fn editability(kind: Option<&str>, schema: &str, name: &str, key: Option<&[String]>, cols: &[Value]) -> Value {
    let ident = |s: &str| bv_sql_guard::SqlIdent::new(s).is_ok();
    let reason = if kind != Some("BASE TABLE") {
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

/// `POST v2/sessions/<id>/rows` on a MySQL / MariaDB session: the edit in
/// its own transaction, or a savepoint inside the caller's.
pub fn apply(
    cx: &Ctx<'_>,
    s: &Arc<Session>,
    conn: &Arc<MyConn>,
    edit: Edit,
    ticket: Option<&str>,
) -> Result<Value, ApiError> {
    if let Some(why) = conn.taint() {
        return Err(ApiError::refused("session_tainted", why));
    }
    let tx = conn.tx();
    let (schema, table) = (edit.schema.as_str().to_string(), edit.table.as_str().to_string());
    let key_cols = cx
        .rt
        .block_on(edit_key(conn, &schema, &table))
        .map_err(db)?
        .ok_or_else(|| ApiError::refused("not_editable", "the table has no primary key or non-null unique key"))?;
    let (sql, params) = edit.build_mysql(&key_cols)?;
    let key_json = serde_json::to_vec(&edit.key).unwrap_or_default();
    let key_hmac = ids::digest(cx.digest_key, "row-key", &key_json);
    let object = format!("{MYSQL_CATALOG}.{schema}.{table}");
    let mut ev = crate::audit::base("dbms.row_edit", &s.id, &s.resource, &s.profile, s.info.db_enforced);
    ev["object"] = json!(object);
    ev["op"] = json!(edit.op.as_str());
    ev["key_hmac"] = json!(key_hmac);
    ev["columns"] = json!(edit.changed_columns());
    let authorized = authorize_edit(
        cx.host,
        &s.resource,
        &s.id,
        edit.op.capability(),
        (MYSQL_CATALOG, &schema, &table),
        sql,
        params,
    )?;
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
    let in_tx = tx == TxStatus::InTransaction;
    let (open, keep, undo) = if in_tx {
        (
            PluginSql::guarded(sql!("SAVEPOINT bv_row_edit")),
            PluginSql::guarded(sql!("RELEASE SAVEPOINT bv_row_edit")),
            PluginSql::guarded(sql!("ROLLBACK TO SAVEPOINT bv_row_edit")),
        )
    } else {
        (PluginSql::guarded(sql!("BEGIN")), PluginSql::guarded(sql!("COMMIT")), PluginSql::guarded(sql!("ROLLBACK")))
    };
    let result: Result<(u64, bool), DbError> = cx.rt.block_on(async {
        conn.internal_execute(&open).await?;
        match conn.send_edit(edit_auth).await {
            Ok(1) => {
                conn.internal_execute(&keep).await?;
                Ok((1, true))
            }
            Ok(n) => {
                conn.internal_execute(&undo).await?;
                if in_tx {
                    conn.internal_execute(&keep).await?;
                }
                Ok((n, false))
            }
            Err(e) => {
                let _ = conn.internal_execute(&undo).await;
                if in_tx {
                    let _ = conn.internal_execute(&keep).await;
                }
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

// ── the ceiling probe (§5.1): SHOW GRANTS ─────────────────────────────────

/// What one `GRANT` line of `SHOW GRANTS` gives.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Grants {
    pub capabilities: BTreeSet<&'static str>,
    pub global_all: bool,
    pub roles: Vec<String>,
    /// Lines the parser did not read (advisory output says so).
    pub unread: usize,
}

/// Privileges to the §3.1 vocabulary. Administrative and dynamic
/// (`*_ADMIN`) privileges are `sql_admin`; `USAGE` is nothing.
fn privilege(p: &str, out: &mut BTreeSet<&'static str>) {
    let p = p.trim().to_ascii_uppercase();
    let name = p.split('(').next().unwrap_or("").trim().to_string();
    let caps: &[&'static str] = match name.as_str() {
        "ALL" | "ALL PRIVILEGES" => &crate::profile::STATEMENT_CAPS,
        "USAGE" => &[],
        "SELECT" | "SHOW VIEW" | "SHOW DATABASES" | "LOCK TABLES" => &["sql_select"],
        "INSERT" => &["sql_insert"],
        "UPDATE" => &["sql_update"],
        "DELETE" | "DELETE HISTORY" => &["sql_delete"],
        "CREATE" | "CREATE VIEW" | "CREATE ROUTINE" | "CREATE TEMPORARY TABLES" | "INDEX" | "TRIGGER" => {
            &["sql_create"]
        }
        "ALTER" | "ALTER ROUTINE" | "REFERENCES" => &["sql_alter"],
        "DROP" => &["sql_drop"],
        "EXECUTE" => &["sql_execute"],
        "" => &[],
        _ => &["sql_admin"],
    };
    out.extend(caps.iter().copied());
}

/// Split at top-level commas (column lists hold their own).
fn split_top(s: &str) -> Vec<&str> {
    let (mut out, mut depth, mut from) = (Vec::new(), 0i32, 0usize);
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&s[from..i]);
                from = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[from..]);
    out
}

pub fn parse_grants(lines: &[String]) -> Grants {
    let mut g = Grants::default();
    for line in lines {
        let Some(rest) = line.strip_prefix("GRANT ") else {
            g.unread += 1;
            continue;
        };
        match rest.find(" ON ") {
            Some(at) => {
                let privs = &rest[..at];
                let level = rest[at + 4..].split(" TO ").next().unwrap_or("").trim();
                let mut caps = BTreeSet::new();
                for p in split_top(privs) {
                    privilege(p, &mut caps);
                }
                if level == "*.*" && privs.trim().to_ascii_uppercase().starts_with("ALL") {
                    g.global_all = true;
                }
                if line.contains(" WITH GRANT OPTION") || line.contains(" WITH ADMIN OPTION") {
                    caps.insert("sql_admin");
                }
                g.capabilities.extend(caps);
            }
            // `GRANT role TO user`: the role's own privileges are not expanded.
            None => g.roles.extend(rest.split(" TO ").next().map(|r| r.trim().to_string())),
        }
    }
    g
}

/// `READ v2/sessions/<id>/ceiling`.
pub fn probe(cx: &Ctx<'_>, s: &Arc<Session>, conn: &Arc<MyConn>) -> Result<Value, ApiError> {
    require(cx, s, Check::server("sql_select"))?;
    let q = PluginSql::guarded(sql!("SHOW GRANTS"));
    let rows =
        cx.rt.block_on(conn.internal_query(&q, &[])).map_err(|e| ApiError::refused("database_error", e.message))?;
    let lines: Vec<String> = rows.iter().filter_map(|r| col(r, 0)).collect();
    let g = parse_grants(&lines);
    let declared: BTreeSet<&'static str> = s.info.ceiling.iter().copied().collect();
    let probed = &g.capabilities;
    let mut out = Map::new();
    out.insert("profile".into(), json!(s.profile));
    out.insert("declared".into(), json!(declared));
    out.insert("probed".into(), json!(probed));
    out.insert("undeclared".into(), json!(probed.difference(&declared).collect::<Vec<_>>()));
    out.insert("unused".into(), json!(declared.difference(probed).collect::<Vec<_>>()));
    out.insert("superuser".into(), json!(g.global_all));
    out.insert("member_of".into(), json!(g.roles));
    out.insert("unread_grants".into(), json!(g.unread));
    out.insert("advisory".into(), json!(true));
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_grants_maps_onto_capabilities() {
        let lines: Vec<String> = [
            "GRANT USAGE ON *.* TO `ro`@`%`",
            "GRANT SELECT, SHOW VIEW ON `app`.* TO `ro`@`%`",
            "GRANT SELECT (`a`, `b`), UPDATE (`a`) ON `app`.`t` TO `ro`@`%`",
            "GRANT `reporting`@`%` TO `ro`@`%`",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let g = parse_grants(&lines);
        assert_eq!(g.capabilities, ["sql_select", "sql_update"].into_iter().collect());
        assert_eq!(g.roles, vec!["`reporting`@`%`".to_string()]);
        assert!(!g.global_all);
        let admin = parse_grants(&["GRANT ALL PRIVILEGES ON *.* TO `root`@`%` WITH GRANT OPTION".to_string()]);
        assert!(admin.global_all && admin.capabilities.contains("sql_admin") && admin.capabilities.len() == 9);
        let dynamic = parse_grants(&["GRANT SYSTEM_VARIABLES_ADMIN,CONNECTION_ADMIN ON *.* TO `x`@`%`".to_string()]);
        assert_eq!(dynamic.capabilities, ["sql_admin"].into_iter().collect());
        let ddl = parse_grants(&["GRANT CREATE, DROP, ALTER, INDEX, EXECUTE ON `app`.* TO `x`@`%`".to_string()]);
        assert_eq!(ddl.capabilities, ["sql_alter", "sql_create", "sql_drop", "sql_execute"].into_iter().collect());
        assert_eq!(parse_grants(&["REVOKE x".to_string()]).unread, 1);
    }

    #[test]
    fn only_base_tables_with_a_key_and_plain_names_are_editable() {
        let cols = vec![json!({"name": "id"}), json!({"name": "name"})];
        let key = vec!["id".to_string()];
        assert_eq!(editability(Some("BASE TABLE"), "app", "t", Some(&key), &cols)["editable"], true);
        assert_eq!(editability(Some("VIEW"), "app", "v", Some(&key), &cols)["editable"], false);
        assert_eq!(editability(Some("BASE TABLE"), "app", "t", None, &cols)["editable"], false);
        assert_eq!(editability(Some("BASE TABLE"), "app", "t-1", Some(&key), &cols)["editable"], false);
    }
}
