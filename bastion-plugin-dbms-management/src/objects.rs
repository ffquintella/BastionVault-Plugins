//! Object browser and describe (§7). Catalog reads are plugin-authored
//! `bv_sql_guard` literals with every name bound as a parameter. Browsing
//! needs `sql_select` on what is shown: resource-wide holders see everything,
//! others see the objects their object-scoped grants cover (best effort:
//! hiding is not a confidentiality boundary for metadata).

use std::sync::Arc;

use bv_sql_guard::sql;
use serde_json::{json, Value};

use crate::api::ApiError;
use crate::driver::{DbError, PgConn, PluginSql, TextParam};
use crate::engine::DbConn;
use crate::host::{verdicts_match, Check};
use crate::session::{Ctx, Session};

/// Most objects listed per schema request.
pub const MAX_LISTED: i64 = 2_000;

fn db(e: DbError) -> ApiError {
    ApiError::refused("database_error", e.message)
}

fn text(s: &str) -> TextParam {
    TextParam(Some(s.to_string()))
}

/// Ask the host; `Ok(verdict per check)`, refusing a malformed reply.
pub(crate) fn decide(cx: &Ctx<'_>, s: &Session, checks: &[Check]) -> Result<Vec<bool>, ApiError> {
    let mut out = Vec::with_capacity(checks.len());
    for chunk in checks.chunks(crate::authz::MAX_CHECKS) {
        let v = cx.host.sql_authorize(&s.resource, chunk)?;
        if !verdicts_match(chunk, &v) {
            return Err(ApiError::internal("the host's verdicts do not match the checks; refused"));
        }
        out.extend(v.iter().map(|x| x.allowed));
    }
    Ok(out)
}

pub(crate) fn require(cx: &Ctx<'_>, s: &Session, check: Check) -> Result<(), ApiError> {
    if decide(cx, s, std::slice::from_ref(&check))?.first() == Some(&true) {
        Ok(())
    } else {
        Err(ApiError::refused("refused", format!("needs `{}` on `{}`", check.capability, check.target_label())))
    }
}

/// The session's database, as object paths name it.
pub fn catalog(s: &Session) -> String {
    match s.conn() {
        DbConn::Pg(_) => s.catalog.clone(),
        // MySQL / MariaDB paths name the catalog `def` (§3.2).
        DbConn::My(_) => bv_sql_classify::MYSQL_CATALOG.to_string(),
        // SQL Server paths name the database as the classifier folds it.
        DbConn::Ms(_) => match s.lexer() {
            bv_sql_classify::LexerSettings::MsSql { catalogs, .. } => {
                crate::mssql::conn::canon(catalogs, &s.current_catalog()).unwrap_or_default()
            }
            _ => String::new(),
        },
        // Oracle paths name the service in upper case (§3.2).
        DbConn::Ora(_) => s.current_catalog(),
    }
}

/// The PostgreSQL connection; MySQL / MariaDB sessions are dispatched to
/// `mysql::browse` before any caller of this is reached.
fn pg(s: &Session) -> Result<&Arc<PgConn>, ApiError> {
    match s.conn() {
        DbConn::Pg(c) => Ok(c),
        DbConn::My(_) => Err(ApiError::internal("a MySQL session reached the PostgreSQL browser")),
        DbConn::Ms(_) => Err(ApiError::internal("a SQL Server session reached the PostgreSQL browser")),
        DbConn::Ora(_) => Err(ApiError::internal("an Oracle session reached the PostgreSQL browser")),
    }
}

/// `LIST v2/sessions/<id>/objects`: the schemas the login can use.
pub fn schemas(cx: &Ctx<'_>, s: &Arc<Session>) -> Result<Value, ApiError> {
    if let DbConn::My(c) = s.conn() {
        return crate::mysql::browse::schemas(cx, s, c);
    }
    if let DbConn::Ms(c) = s.conn() {
        return crate::mssql::browse::schemas(cx, s, c);
    }
    if let DbConn::Ora(c) = s.conn() {
        return crate::oracle::browse::schemas(cx, s, c);
    }
    require(cx, s, Check::server("sql_select"))?;
    let q = PluginSql::guarded(sql!(
        "SELECT n.nspname::text FROM pg_catalog.pg_namespace n \
         WHERE n.nspname OPERATOR(pg_catalog.!~) '^pg_toast' AND n.nspname OPERATOR(pg_catalog.!~) '^pg_temp_' \
         AND pg_catalog.has_schema_privilege(n.oid, 'USAGE') ORDER BY 1"
    ));
    let rows = cx.rt.block_on(pg(s)?.internal_query(&q, &[])).map_err(db)?;
    let names: Vec<String> = rows.iter().filter_map(|r| r.try_get::<_, String>(0).ok()).collect();
    Ok(json!({"catalog": catalog(s), "keys": names}))
}

fn relkind(k: &str) -> &'static str {
    match k {
        "r" | "p" => "table",
        "v" => "view",
        "m" => "materialized_view",
        "f" => "foreign_table",
        "S" => "sequence",
        "i" | "I" => "index",
        _ => "other",
    }
}

/// `LIST v2/sessions/<id>/objects/<schema>`: relations, sequences, indexes
/// and routines in a schema, filtered by the caller's grants.
pub fn list(cx: &Ctx<'_>, s: &Arc<Session>, schema: &str) -> Result<Value, ApiError> {
    if let DbConn::My(c) = s.conn() {
        return crate::mysql::browse::list(cx, s, c, schema);
    }
    if let DbConn::Ms(c) = s.conn() {
        return crate::mssql::browse::list(cx, s, c, schema);
    }
    if let DbConn::Ora(c) = s.conn() {
        return crate::oracle::browse::list(cx, s, c, schema);
    }
    let cat = catalog(s);
    let q = PluginSql::guarded(sql!(
        "SELECT name, kind FROM ( \
           SELECT c.relname::text AS name, c.relkind::text AS kind FROM pg_catalog.pg_class c \
             JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace \
             WHERE n.nspname OPERATOR(pg_catalog.=) $1::text AND c.relkind OPERATOR(pg_catalog.=) ANY (ARRAY['r','p','v','m','f','S','i','I']::pg_catalog.\"char\"[]) \
           UNION \
           SELECT DISTINCT p.proname::text, 'routine' FROM pg_catalog.pg_proc p \
             JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) p.pronamespace WHERE n.nspname OPERATOR(pg_catalog.=) $1::text \
         ) o ORDER BY name, kind LIMIT 2001"
    ));
    let rows = cx.rt.block_on(pg(s)?.internal_query(&q, &[text(schema)])).map_err(db)?;
    let mut objects: Vec<(String, String)> =
        rows.iter().filter_map(|r| Some((r.try_get::<_, String>(0).ok()?, r.try_get::<_, String>(1).ok()?))).collect();
    let truncated = objects.len() as i64 > MAX_LISTED;
    objects.truncate(MAX_LISTED as usize);
    // Resource-wide holders (a check on the objects root) see everything.
    let wide = decide(cx, s, &[Check::object("sql_select", &cat, "", "")])?;
    let visible: Vec<bool> = if wide.first() == Some(&true) {
        vec![true; objects.len()]
    } else {
        let checks: Vec<Check> = objects.iter().map(|(n, _)| Check::object("sql_select", &cat, schema, n)).collect();
        decide(cx, s, &checks)?
    };
    let out: Vec<Value> = objects
        .iter()
        .zip(visible)
        .filter(|(_, v)| *v)
        .map(|((name, kind), _)| {
            let kind = if kind == "routine" { "routine" } else { relkind(kind) };
            json!({"name": name, "kind": kind})
        })
        .collect();
    Ok(json!({"catalog": cat, "schema": schema, "objects": out, "truncated": truncated}))
}

/// The key a grid edit addresses: the primary key, else the first unique
/// constraint whose columns are all NOT NULL (§7).
pub async fn edit_key(conn: &PgConn, schema: &str, table: &str) -> Result<Option<Vec<String>>, DbError> {
    let q = PluginSql::guarded(sql!(
        "SELECT con.contype::text, \
           ARRAY(SELECT a.attname::text FROM pg_catalog.unnest(con.conkey) WITH ORDINALITY k(att, ord) \
                 JOIN pg_catalog.pg_attribute a ON a.attrelid OPERATOR(pg_catalog.=) con.conrelid AND a.attnum OPERATOR(pg_catalog.=) k.att ORDER BY k.ord), \
           NOT EXISTS (SELECT 1 FROM pg_catalog.unnest(con.conkey) k(att) \
                 JOIN pg_catalog.pg_attribute a ON a.attrelid OPERATOR(pg_catalog.=) con.conrelid AND a.attnum OPERATOR(pg_catalog.=) k.att WHERE NOT a.attnotnull) \
         FROM pg_catalog.pg_constraint con JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) con.conrelid \
         JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace \
         WHERE n.nspname OPERATOR(pg_catalog.=) $1::text AND c.relname OPERATOR(pg_catalog.=) $2::text AND c.relkind OPERATOR(pg_catalog.=) ANY (ARRAY['r','p']::pg_catalog.\"char\"[]) AND con.contype OPERATOR(pg_catalog.=) ANY (ARRAY['p','u']::pg_catalog.\"char\"[]) \
         ORDER BY con.contype, con.conname"
    ));
    let rows = conn.internal_query(&q, &[text(schema), text(table)]).await?;
    for r in &rows {
        let kind: String = r.try_get(0).map_err(DbError::from)?;
        let cols: Vec<String> = r.try_get(1).map_err(DbError::from)?;
        let not_null: bool = r.try_get(2).map_err(DbError::from)?;
        if kind == "p" || not_null {
            return Ok(Some(cols));
        }
    }
    Ok(None)
}

/// `READ v2/sessions/<id>/objects/<schema>/<object>`: columns, keys,
/// indexes, triggers and the definition text where the login can read it.
pub fn describe(cx: &Ctx<'_>, s: &Arc<Session>, schema: &str, name: &str) -> Result<Value, ApiError> {
    if let DbConn::My(c) = s.conn() {
        return crate::mysql::browse::describe(cx, s, c, schema, name);
    }
    if let DbConn::Ms(c) = s.conn() {
        return crate::mssql::browse::describe(cx, s, c, schema, name);
    }
    if let DbConn::Ora(c) = s.conn() {
        return crate::oracle::browse::describe(cx, s, c, schema, name);
    }
    let cat = catalog(s);
    require(cx, s, Check::object("sql_select", &cat, schema, name))?;
    let p = [text(schema), text(name)];
    let rel = PluginSql::guarded(sql!(
        "SELECT c.relkind::text, \
           CASE WHEN c.relkind OPERATOR(pg_catalog.=) ANY (ARRAY['v','m']::pg_catalog.\"char\"[]) THEN pg_catalog.pg_get_viewdef(c.oid, true) END \
         FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace \
         WHERE n.nspname OPERATOR(pg_catalog.=) $1::text AND c.relname OPERATOR(pg_catalog.=) $2::text"
    ));
    let cols = PluginSql::guarded(sql!(
        "SELECT a.attname::text, pg_catalog.format_type(a.atttypid, a.atttypmod), a.attnotnull, \
           pg_catalog.pg_get_expr(d.adbin, d.adrelid) \
         FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) a.attrelid \
         JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace \
         LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid OPERATOR(pg_catalog.=) a.attrelid AND d.adnum OPERATOR(pg_catalog.=) a.attnum \
         WHERE n.nspname OPERATOR(pg_catalog.=) $1::text AND c.relname OPERATOR(pg_catalog.=) $2::text AND a.attnum OPERATOR(pg_catalog.>) 0 AND NOT a.attisdropped \
         ORDER BY a.attnum"
    ));
    let cons = PluginSql::guarded(sql!(
        "SELECT con.conname::text, con.contype::text, pg_catalog.pg_get_constraintdef(con.oid) \
         FROM pg_catalog.pg_constraint con JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) con.conrelid \
         JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace \
         WHERE n.nspname OPERATOR(pg_catalog.=) $1::text AND c.relname OPERATOR(pg_catalog.=) $2::text ORDER BY con.conname"
    ));
    let idx = PluginSql::guarded(sql!(
        "SELECT i.relname::text, pg_catalog.pg_get_indexdef(i.oid) FROM pg_catalog.pg_index x \
         JOIN pg_catalog.pg_class i ON i.oid OPERATOR(pg_catalog.=) x.indexrelid JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) x.indrelid \
         JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace \
         WHERE n.nspname OPERATOR(pg_catalog.=) $1::text AND c.relname OPERATOR(pg_catalog.=) $2::text ORDER BY 1"
    ));
    let trg = PluginSql::guarded(sql!(
        "SELECT t.tgname::text, pg_catalog.pg_get_triggerdef(t.oid) FROM pg_catalog.pg_trigger t \
         JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace \
         WHERE n.nspname OPERATOR(pg_catalog.=) $1::text AND c.relname OPERATOR(pg_catalog.=) $2::text AND NOT t.tgisinternal ORDER BY 1"
    ));
    let fun = PluginSql::guarded(sql!(
        "SELECT p.prokind::text, CASE WHEN p.prokind OPERATOR(pg_catalog.=) ANY (ARRAY['f','p','w']::pg_catalog.\"char\"[]) THEN pg_catalog.pg_get_functiondef(p.oid) END \
         FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) p.pronamespace \
         WHERE n.nspname OPERATOR(pg_catalog.=) $1::text AND p.proname OPERATOR(pg_catalog.=) $2::text ORDER BY p.oid"
    ));
    let conn = pg(s)?.clone();
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
                edit_key(&conn, schema, name).await?,
            ))
        })
        .map_err(db)?;
    let pair = |r: &tokio_postgres::Row| json!({"name": r.try_get::<_, String>(0).ok(), "definition": r.try_get::<_, Option<String>>(1).ok().flatten()});
    let kind = rel.first().and_then(|r| r.try_get::<_, String>(0).ok());
    if kind.is_none() && fun.is_empty() {
        return Err(ApiError::not_found("no such object, or the login cannot see it"));
    }
    let columns: Vec<Value> = cols
        .iter()
        .map(|r| {
            json!({"name": r.try_get::<_, String>(0).ok(), "type": r.try_get::<_, String>(1).ok(),
                "not_null": r.try_get::<_, bool>(2).ok(), "default": r.try_get::<_, Option<String>>(3).ok().flatten()})
        })
        .collect();
    let editable = editability(kind.as_deref(), schema, name, key.as_deref(), &columns);
    Ok(json!({
        "catalog": cat,
        "schema": schema,
        "name": name,
        "kind": kind.as_deref().map(relkind).unwrap_or("routine"),
        "definition": rel.first().and_then(|r| r.try_get::<_, Option<String>>(1).ok().flatten()),
        "columns": columns,
        "constraints": cons.iter().map(|r| json!({"name": r.try_get::<_, String>(0).ok(),
            "type": r.try_get::<_, String>(1).ok(), "definition": r.try_get::<_, String>(2).ok()})).collect::<Vec<_>>(),
        "indexes": idx.iter().map(pair).collect::<Vec<_>>(),
        "triggers": trg.iter().map(pair).collect::<Vec<_>>(),
        "routines": fun.iter().map(|r| json!({"kind": r.try_get::<_, String>(0).ok(),
            "definition": r.try_get::<_, Option<String>>(1).ok().flatten()})).collect::<Vec<_>>(),
        "edit": editable,
    }))
}

/// Whether the grid may edit this object, and why not (§7).
fn editability(kind: Option<&str>, schema: &str, name: &str, key: Option<&[String]>, cols: &[Value]) -> Value {
    let ident = |s: &str| bv_sql_guard::SqlIdent::new(s).is_ok();
    let reason = if !matches!(kind, Some("r" | "p")) {
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
