//! The object browser, describe, structured row edits and the ceiling probe
//! for SQL Server sessions (§5.1, §7). Catalog reads are plugin-authored
//! `bv_sql_guard` literals over `sys.*`, every name a bound parameter.
//! Object paths are `<database>/<schema>/<object>` (§3.2), named the way the
//! classifier names them (the collation's folding, `conn::canon`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use bv_sql_classify::NameMatch;
use bv_sql_guard::sql;
use serde_json::{json, Map, Value};
use tiberius::Row;

use super::conn::{canon, MsConn};
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
    match row.cells().nth(i).map(|(_, d)| d) {
        Some(tiberius::ColumnData::String(Some(s))) => Some(s.to_string()),
        Some(tiberius::ColumnData::I32(Some(n))) => Some(n.to_string()),
        Some(tiberius::ColumnData::I16(Some(n))) => Some(n.to_string()),
        Some(tiberius::ColumnData::U8(Some(n))) => Some(n.to_string()),
        Some(tiberius::ColumnData::I64(Some(n))) => Some(n.to_string()),
        Some(tiberius::ColumnData::Bit(Some(b))) => Some(if *b { "1" } else { "0" }.to_string()),
        _ => None,
    }
}

/// The session's name rules: `(catalog path, schema / object folding)`.
fn rules(s: &Session) -> Result<(String, NameMatch), ApiError> {
    match s.lexer() {
        bv_sql_classify::LexerSettings::MsSql { names, catalogs, .. } => {
            let cat = canon(catalogs, &s.current_catalog())
                .ok_or_else(|| ApiError::refused("unaddressable", "the database name cannot be named exactly"))?;
            Ok((cat, names))
        }
        _ => Err(ApiError::internal("a non-SQL Server session reached the SQL Server browser")),
    }
}

/// An object check, or `None` when the name cannot be named exactly (it is
/// then hidden: no object-scoped rule can match it).
fn check(cap: &'static str, cat: &str, names: NameMatch, schema: &str, name: &str) -> Option<Check> {
    Some(Check::object(cap, cat, &canon(names, schema)?, &canon(names, name)?))
}

/// `LIST v2/sessions/<id>/objects`: the schemas of the session's database.
pub fn schemas(cx: &Ctx<'_>, s: &Arc<Session>, conn: &Arc<MsConn>) -> Result<Value, ApiError> {
    require(cx, s, Check::server("sql_select"))?;
    let (cat, _) = rules(s)?;
    let q = PluginSql::guarded(sql!("SELECT name FROM sys.schemas ORDER BY name"));
    let rows = cx.rt.block_on(conn.internal_query(&q, &[])).map_err(db)?;
    let names: Vec<String> = rows.iter().filter_map(|r| col(r, 0)).collect();
    Ok(json!({"catalog": cat, "keys": names}))
}

fn kind(t: &str) -> &'static str {
    match t.trim() {
        "U" => "table",
        "V" => "view",
        "SO" => "sequence",
        "SN" => "synonym",
        "P" | "PC" | "FN" | "IF" | "TF" | "FS" | "FT" | "AF" => "routine",
        _ => "other",
    }
}

/// `LIST v2/sessions/<id>/objects/<schema>`: tables, views, sequences,
/// synonyms and routines of a schema, filtered by the caller's grants.
pub fn list(cx: &Ctx<'_>, s: &Arc<Session>, conn: &Arc<MsConn>, schema: &str) -> Result<Value, ApiError> {
    let (cat, names) = rules(s)?;
    let q = PluginSql::guarded(sql!(
        "SELECT TOP (2001) o.name, o.type FROM sys.objects o JOIN sys.schemas s ON s.schema_id = o.schema_id \
         WHERE s.name = @P1 AND o.type IN ('U','V','SO','SN','P','PC','FN','IF','TF','FS','FT','AF') \
         ORDER BY o.name, o.type"
    ));
    let rows = cx.rt.block_on(conn.internal_query(&q, &[text(schema)])).map_err(db)?;
    let mut objects: Vec<(String, String)> = rows.iter().filter_map(|r| Some((col(r, 0)?, col(r, 1)?))).collect();
    let truncated = objects.len() as i64 > MAX_LISTED;
    objects.truncate(MAX_LISTED as usize);
    let wide = decide(cx, s, &[Check::object("sql_select", &cat, "", "")])?;
    let visible: Vec<bool> = if wide.first() == Some(&true) {
        vec![true; objects.len()]
    } else {
        // Names that cannot be named exactly are hidden from object grants.
        let checks: Vec<Option<Check>> =
            objects.iter().map(|(n, _)| check("sql_select", &cat, names, schema, n)).collect();
        let asked: Vec<Check> = checks.iter().flatten().cloned().collect();
        let mut verdicts = decide(cx, s, &asked)?.into_iter();
        checks.iter().map(|c| c.is_some() && verdicts.next().unwrap_or(false)).collect()
    };
    let out: Vec<Value> = objects
        .iter()
        .zip(visible)
        .filter(|(_, v)| *v)
        .map(|((name, k), _)| json!({"name": name, "kind": kind(k)}))
        .collect();
    Ok(json!({"catalog": cat, "schema": schema, "objects": out, "truncated": truncated}))
}

/// The key a grid edit addresses: the primary key, else the first unique
/// index whose columns are all NOT NULL (§7).
pub async fn edit_key(conn: &MsConn, schema: &str, table: &str) -> Result<Option<Vec<String>>, DbError> {
    let q = PluginSql::guarded(sql!(
        "SELECT i.name, c.name, CAST(c.is_nullable AS int), CAST(i.is_primary_key AS int) \
         FROM sys.indexes i JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id \
         JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id \
         WHERE i.object_id = OBJECT_ID(QUOTENAME(@P1) + N'.' + QUOTENAME(@P2)) AND i.is_unique = 1 \
           AND ic.is_included_column = 0 AND i.has_filter = 0 \
         ORDER BY i.is_primary_key DESC, i.name, ic.key_ordinal"
    ));
    let rows = conn.internal_query(&q, &[text(schema), text(table)]).await?;
    let mut keys: Vec<(String, Vec<String>, bool, bool)> = Vec::new();
    for r in &rows {
        let (Some(index), Some(column)) = (col(r, 0), col(r, 1)) else { continue };
        let not_null = col(r, 2).as_deref() == Some("0");
        let primary = col(r, 3).as_deref() == Some("1");
        match keys.last_mut() {
            Some((name, cols, all, _)) if *name == index => {
                cols.push(column);
                *all &= not_null;
            }
            _ => keys.push((index, vec![column], not_null, primary)),
        }
    }
    Ok(keys.into_iter().find(|(_, _, all, primary)| *primary || *all).map(|(_, cols, _, _)| cols))
}

/// `READ v2/sessions/<id>/objects/<schema>/<object>`.
pub fn describe(
    cx: &Ctx<'_>,
    s: &Arc<Session>,
    conn: &Arc<MsConn>,
    schema: &str,
    name: &str,
) -> Result<Value, ApiError> {
    let (cat, names) = rules(s)?;
    let c = check("sql_select", &cat, names, schema, name)
        .ok_or_else(|| ApiError::refused("unaddressable", "the object's name cannot be named exactly"))?;
    require(cx, s, c)?;
    let p = [text(schema), text(name)];
    let obj = PluginSql::guarded(sql!(
        "SELECT o.type, OBJECT_DEFINITION(o.object_id) FROM sys.objects o \
         WHERE o.object_id = OBJECT_ID(QUOTENAME(@P1) + N'.' + QUOTENAME(@P2))"
    ));
    let cols = PluginSql::guarded(sql!(
        "SELECT c.name, TYPE_NAME(c.user_type_id), CAST(c.is_nullable AS int), OBJECT_DEFINITION(c.default_object_id), \
         CAST(c.is_identity AS int), CAST(c.is_computed AS int) FROM sys.columns c \
         WHERE c.object_id = OBJECT_ID(QUOTENAME(@P1) + N'.' + QUOTENAME(@P2)) ORDER BY c.column_id"
    ));
    let cons = PluginSql::guarded(sql!(
        "SELECT o.name, o.type_desc FROM sys.objects o \
         WHERE o.parent_object_id = OBJECT_ID(QUOTENAME(@P1) + N'.' + QUOTENAME(@P2)) \
           AND o.type IN ('PK','UQ','F','C','D') ORDER BY o.name"
    ));
    let idx = PluginSql::guarded(sql!(
        "SELECT i.name, CAST(i.is_unique AS int), c.name FROM sys.indexes i \
         JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id \
         JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id \
         WHERE i.object_id = OBJECT_ID(QUOTENAME(@P1) + N'.' + QUOTENAME(@P2)) AND i.name IS NOT NULL \
         ORDER BY i.name, ic.key_ordinal"
    ));
    let trg = PluginSql::guarded(sql!(
        "SELECT t.name, CAST(t.is_instead_of_trigger AS int), OBJECT_DEFINITION(t.object_id) FROM sys.triggers t \
         WHERE t.parent_id = OBJECT_ID(QUOTENAME(@P1) + N'.' + QUOTENAME(@P2)) ORDER BY t.name"
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
            if col(r, 4).as_deref() == Some("1") {
                extra.push("identity");
            }
            if col(r, 5).as_deref() == Some("1") {
                extra.push("computed");
            }
            json!({"name": col(r, 0), "type": col(r, 1), "not_null": col(r, 2).map(|n| n == "0"),
                "default": col(r, 3), "extra": extra.join(" ")})
        })
        .collect();
    let mut indexes: BTreeMap<String, (bool, Vec<String>)> = BTreeMap::new();
    for r in &idx {
        let (Some(n), Some(c)) = (col(r, 0), col(r, 2)) else { continue };
        let e = indexes.entry(n).or_insert((col(r, 1).as_deref() == Some("1"), Vec::new()));
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
        "triggers": trg.iter().map(|r| json!({"name": col(r, 0), "timing": if col(r, 1).as_deref() == Some("1") { "INSTEAD OF" } else { "AFTER" },
            "definition": col(r, 2)})).collect::<Vec<_>>(),
        "edit": editable,
    }))
}

fn editability(kind: &str, schema: &str, name: &str, key: Option<&[String]>, cols: &[Value]) -> Value {
    let ident = |s: &str| bv_sql_guard::SqlIdent::new(s).is_ok();
    let reason = if kind.trim() != "U" {
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

/// `POST v2/sessions/<id>/rows` on a SQL Server session: the edit in its own
/// transaction, or a savepoint inside the caller's.
pub fn apply(
    cx: &Ctx<'_>,
    s: &Arc<Session>,
    conn: &Arc<MsConn>,
    edit: Edit,
    ticket: Option<&str>,
) -> Result<Value, ApiError> {
    if let Some(why) = conn.taint() {
        return Err(ApiError::refused("session_tainted", why));
    }
    let tx = conn.tx();
    if tx == TxStatus::Failed {
        return Err(ApiError::refused("transaction_aborted", "the open transaction failed; roll it back first"));
    }
    let (cat, names) = rules(s)?;
    let (schema, table) = (edit.schema.as_str().to_string(), edit.table.as_str().to_string());
    let (cschema, ctable) = (
        canon(names, &schema).ok_or_else(|| ApiError::bad_request("schema"))?,
        canon(names, &table).ok_or_else(|| ApiError::bad_request("table"))?,
    );
    let key_cols = cx
        .rt
        .block_on(edit_key(conn, &schema, &table))
        .map_err(db)?
        .ok_or_else(|| ApiError::refused("not_editable", "the table has no primary key or non-null unique key"))?;
    let (sql, params) = edit.build_mssql(&key_cols)?;
    let key_json = serde_json::to_vec(&edit.key).unwrap_or_default();
    let key_hmac = ids::digest(cx.digest_key, "row-key", &key_json);
    let object = format!("{cat}.{cschema}.{ctable}");
    let mut ev = crate::audit::base("dbms.row_edit", &s.id, &s.resource, &s.profile, s.info.db_enforced);
    ev["object"] = json!(object);
    ev["op"] = json!(edit.op.as_str());
    ev["key_hmac"] = json!(key_hmac);
    ev["columns"] = json!(edit.changed_columns());
    let authorized =
        authorize_edit(cx.host, &s.resource, &s.id, edit.op.capability(), (&cat, &cschema, &ctable), sql, params)?;
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
    // T-SQL has no RELEASE SAVEPOINT: a kept savepoint simply stays.
    let (open, keep, undo) = if in_tx {
        (
            PluginSql::guarded(sql!("SAVE TRANSACTION bv_row_edit")),
            None,
            PluginSql::guarded(sql!("ROLLBACK TRANSACTION bv_row_edit")),
        )
    } else {
        (
            PluginSql::guarded(sql!("BEGIN TRANSACTION")),
            Some(PluginSql::guarded(sql!("COMMIT"))),
            PluginSql::guarded(sql!("ROLLBACK")),
        )
    };
    let result: Result<(u64, bool), DbError> = cx.rt.block_on(async {
        conn.internal_execute(&open).await?;
        match conn.send_edit(edit_auth).await {
            Ok(1) => {
                if let Some(k) = &keep {
                    conn.internal_execute(k).await?;
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

// ── the ceiling probe (§5.1): fn_my_permissions ───────────────────────────

/// One effective permission name to the §3.1 vocabulary. `CONTROL` (and
/// `CONTROL SERVER`) is every statement capability; administrative and
/// unknown permissions are `sql_admin`; `CONNECT` and the `VIEW …` family
/// are nothing.
fn permission(p: &str, out: &mut BTreeSet<&'static str>) {
    let p = p.trim().to_ascii_uppercase();
    let caps: &[&'static str] = match p.as_str() {
        "CONTROL" | "CONTROL SERVER" => &crate::profile::STATEMENT_CAPS,
        "SELECT" => &["sql_select"],
        "INSERT" => &["sql_insert"],
        "UPDATE" => &["sql_update"],
        "DELETE" => &["sql_delete"],
        "EXECUTE" => &["sql_execute"],
        "ALTER" | "ALTER ANY SCHEMA" => &["sql_alter", "sql_drop"],
        "REFERENCES" => &["sql_alter"],
        "CREATE TABLE" | "CREATE VIEW" | "CREATE PROCEDURE" | "CREATE FUNCTION" | "CREATE TYPE" | "CREATE SEQUENCE"
        | "CREATE SYNONYM" | "CREATE DEFAULT" | "CREATE RULE" => &["sql_create"],
        "CONNECT"
        | "CONNECT SQL"
        | "CONNECT ANY DATABASE"
        | "SHOWPLAN"
        | "VIEW DEFINITION"
        | "VIEW DATABASE STATE"
        | "VIEW ANY DEFINITION"
        | "VIEW ANY DATABASE"
        | "VIEW SERVER STATE"
        | "VIEW DATABASE PERFORMANCE STATE"
        | "VIEW DATABASE SECURITY STATE"
        | "VIEW SECURITY DEFINITION"
        | "VIEW CHANGE TRACKING"
        | "VIEW ANY COLUMN ENCRYPTION KEY DEFINITION"
        | "VIEW ANY COLUMN MASTER KEY DEFINITION"
        | "" => &[],
        _ => &["sql_admin"],
    };
    out.extend(caps.iter().copied());
}

/// What `fn_my_permissions` gives at server and database scope.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Permissions {
    pub capabilities: BTreeSet<&'static str>,
    pub superuser: bool,
}

pub fn map_permissions(server: &[String], database: &[String]) -> Permissions {
    let mut p = Permissions::default();
    for name in server.iter().chain(database) {
        permission(name, &mut p.capabilities);
    }
    p.superuser = server.iter().any(|n| n.eq_ignore_ascii_case("CONTROL SERVER"));
    p
}

/// `READ v2/sessions/<id>/ceiling`.
pub fn probe(cx: &Ctx<'_>, s: &Arc<Session>, conn: &Arc<MsConn>) -> Result<Value, ApiError> {
    require(cx, s, Check::server("sql_select"))?;
    let server = PluginSql::guarded(sql!("SELECT permission_name FROM fn_my_permissions(NULL, 'SERVER')"));
    let database = PluginSql::guarded(sql!("SELECT permission_name FROM fn_my_permissions(NULL, 'DATABASE')"));
    let (srv, dbp) = cx
        .rt
        .block_on(async {
            Ok::<_, DbError>((conn.internal_query(&server, &[]).await?, conn.internal_query(&database, &[]).await?))
        })
        .map_err(|e| ApiError::refused("database_error", e.message))?;
    let srv: Vec<String> = srv.iter().filter_map(|r| col(r, 0)).collect();
    let dbp: Vec<String> = dbp.iter().filter_map(|r| col(r, 0)).collect();
    let p = map_permissions(&srv, &dbp);
    let declared: BTreeSet<&'static str> = s.info.ceiling.iter().copied().collect();
    let probed = &p.capabilities;
    let mut out = Map::new();
    out.insert("profile".into(), json!(s.profile));
    out.insert("declared".into(), json!(declared));
    out.insert("probed".into(), json!(probed));
    out.insert("undeclared".into(), json!(probed.difference(&declared).collect::<Vec<_>>()));
    out.insert("unused".into(), json!(declared.difference(probed).collect::<Vec<_>>()));
    out.insert("superuser".into(), json!(p.superuser));
    // Object- and schema-level grants are not expanded (advisory, §5.1).
    out.insert("scopes".into(), json!(["server", "database"]));
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
    fn effective_permissions_map_onto_capabilities() {
        let reader = map_permissions(&v(&["CONNECT SQL", "VIEW ANY DATABASE"]), &v(&["CONNECT", "SELECT"]));
        assert_eq!(reader.capabilities, ["sql_select"].into_iter().collect());
        assert!(!reader.superuser);
        let writer = map_permissions(&v(&[]), &v(&["SELECT", "INSERT", "UPDATE", "DELETE", "EXECUTE"]));
        assert_eq!(writer.capabilities.len(), 5);
        let ddl = map_permissions(&v(&[]), &v(&["CREATE TABLE", "ALTER", "REFERENCES"]));
        assert_eq!(ddl.capabilities, ["sql_alter", "sql_create", "sql_drop"].into_iter().collect());
        let sa = map_permissions(&v(&["CONTROL SERVER", "ALTER ANY LOGIN"]), &v(&[]));
        assert!(sa.superuser && sa.capabilities.len() == 9);
        let odd = map_permissions(&v(&["ALTER ANY CREDENTIAL"]), &v(&[]));
        assert_eq!(odd.capabilities, ["sql_admin"].into_iter().collect());
    }

    #[test]
    fn only_tables_with_a_key_and_plain_names_are_editable() {
        let cols = vec![json!({"name": "id"}), json!({"name": "name"})];
        let key = vec!["id".to_string()];
        assert_eq!(editability("U ", "dbo", "t", Some(&key), &cols)["editable"], true);
        assert_eq!(editability("V ", "dbo", "v", Some(&key), &cols)["editable"], false);
        assert_eq!(editability("U ", "dbo", "t", None, &cols)["editable"], false);
        assert_eq!(editability("U ", "dbo", "t-1", Some(&key), &cols)["editable"], false);
    }
}
