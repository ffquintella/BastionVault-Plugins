//! Structured grid edits (§7): `{object, op, key, values, original}`, never
//! SQL text. Identifiers come from the catalog and must be `SqlIdent`s; values
//! are always bound. Exactly one row must change, or nothing does and the
//! edit reports a conflict. The audit records an HMAC of the key, never values.

use std::collections::BTreeMap;
use std::sync::Arc;

use bv_sql_guard::{sql, SqlIdent};
use serde_json::{json, Map, Value};

use crate::api::ApiError;
use crate::authz::authorize_edit;
use crate::driver::{DbError, EditSql, PluginSql, TextParam};
use crate::engine::DbConn;
use crate::ids;
use crate::journal;
use crate::session::{Ctx, Session};
use crate::wire::TxStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditOp {
    Insert,
    Update,
    Delete,
}

impl EditOp {
    pub(crate) fn capability(self) -> &'static str {
        match self {
            Self::Insert => "sql_insert",
            Self::Update => "sql_update",
            Self::Delete => "sql_delete",
        }
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }
}

/// A parsed edit request.
#[derive(Debug, Clone)]
pub struct Edit {
    pub schema: SqlIdent,
    pub table: SqlIdent,
    pub op: EditOp,
    pub key: BTreeMap<String, Value>,
    pub values: BTreeMap<String, Value>,
    pub original: BTreeMap<String, Value>,
}

const KEYS: [&str; 6] = ["object", "op", "key", "values", "original", "step_up_ticket"];

fn ident(s: &str, what: &str) -> Result<SqlIdent, ApiError> {
    SqlIdent::new(s).map_err(|_| {
        ApiError::refused(
            "read_only_in_grid",
            format!("{what} `{s}` is outside [A-Za-z_][A-Za-z0-9_]{{0,62}}; write the statement by hand"),
        )
    })
}

fn map(v: Option<&Value>, what: &str) -> Result<BTreeMap<String, Value>, ApiError> {
    match v {
        None | Some(Value::Null) => Ok(BTreeMap::new()),
        Some(Value::Object(m)) => {
            if m.len() > 1_600 {
                return Err(ApiError::bad_request(format!("`{what}` has too many columns")));
            }
            for k in m.keys() {
                ident(k, "column")?;
            }
            Ok(m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        }
        Some(_) => Err(ApiError::bad_request(format!("`{what}` must be an object of column → value"))),
    }
}

impl Edit {
    pub fn parse(data: &Map<String, Value>) -> Result<Self, ApiError> {
        if let Some(k) = data.keys().find(|k| !KEYS.contains(&k.as_str())) {
            return Err(ApiError::bad_request(format!("unknown field `{k}`")));
        }
        let object = data
            .get("object")
            .and_then(Value::as_object)
            .ok_or_else(|| ApiError::bad_request("`object` {schema, name} is required"))?;
        let s = |k: &str| {
            object
                .get(k)
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::bad_request(format!("`object.{k}` is required")))
        };
        let op = match data.get("op").and_then(Value::as_str) {
            Some("insert") => EditOp::Insert,
            Some("update") => EditOp::Update,
            Some("delete") => EditOp::Delete,
            _ => return Err(ApiError::bad_request("`op` is insert, update or delete")),
        };
        let e = Self {
            schema: ident(s("schema")?, "schema")?,
            table: ident(s("name")?, "table")?,
            op,
            key: map(data.get("key"), "key")?,
            values: map(data.get("values"), "values")?,
            original: map(data.get("original"), "original")?,
        };
        match op {
            EditOp::Insert if e.values.is_empty() => Err(ApiError::bad_request("an insert needs `values`")),
            EditOp::Update if e.values.is_empty() => Err(ApiError::bad_request("an update needs `values`")),
            EditOp::Update if e.values.keys().any(|k| !e.original.contains_key(k)) => {
                Err(ApiError::bad_request("an update carries the original value of every edited column in `original`"))
            }
            EditOp::Update | EditOp::Delete if e.key.is_empty() => Err(ApiError::bad_request("`key` is required")),
            _ if e.key.values().any(Value::is_null) => Err(ApiError::bad_request("key values cannot be null")),
            _ => Ok(e),
        }
    }

    /// The statement and its bound values. `key_cols` is the table's edit
    /// key from the catalog; the request's key must name exactly it.
    pub fn build(&self, key_cols: &[String]) -> Result<(PluginSql, Vec<TextParam>), ApiError> {
        let mut params = Vec::new();
        let target = |b: EditSql| b.ident(&self.schema).lit(".").ident(&self.table);
        let sql = match self.op {
            EditOp::Insert => {
                let mut b = target(EditSql::default().lit("INSERT INTO ")).lit(" (");
                for (i, c) in self.values.keys().enumerate() {
                    b = if i > 0 { b.lit(", ") } else { b };
                    b = b.ident(&SqlIdent::new(c).map_err(|_| ApiError::bad_request("column"))?);
                }
                b = b.lit(") VALUES (");
                for (i, v) in self.values.values().enumerate() {
                    b = if i > 0 { b.lit(", ") } else { b };
                    b = b.param();
                    params.push(param(v));
                }
                b.lit(")")
            }
            EditOp::Update | EditOp::Delete => {
                let mut want: Vec<&String> = self.key.keys().collect();
                let mut have: Vec<&String> = key_cols.iter().collect();
                want.sort();
                have.sort();
                if want != have {
                    return Err(ApiError::bad_request(format!("`key` must name exactly the key columns {key_cols:?}")));
                }
                let mut b = if self.op == EditOp::Update {
                    let mut b = target(EditSql::default().lit("UPDATE ")).lit(" SET ");
                    for (i, (c, v)) in self.values.iter().enumerate() {
                        b = if i > 0 { b.lit(", ") } else { b };
                        b = b.ident(&SqlIdent::new(c).map_err(|_| ApiError::bad_request("column"))?).lit(" = ").param();
                        params.push(param(v));
                    }
                    b
                } else {
                    target(EditSql::default().lit("DELETE FROM "))
                };
                b = b.lit(" WHERE ");
                let mut first = true;
                for (c, v) in &self.key {
                    b = if first { b } else { b.lit(" AND ") };
                    first = false;
                    b = b.ident(&SqlIdent::new(c).map_err(|_| ApiError::bad_request("column"))?).lit(" = ").param();
                    params.push(param(v));
                }
                // The original values guard against overwriting someone
                // else's change: zero rows is a conflict, not a retry.
                for (c, v) in &self.original {
                    b = b.lit(" AND ").ident(&SqlIdent::new(c).map_err(|_| ApiError::bad_request("column"))?);
                    b = b.lit(" IS NOT DISTINCT FROM ").param();
                    params.push(param(v));
                }
                b
            }
        };
        Ok((sql.build(), params))
    }

    /// The MySQL / MariaDB statement: backtick identifiers, `?` values, and
    /// `<=>` (NULL-safe equality) guarding the original values.
    pub fn build_mysql(&self, key_cols: &[String]) -> Result<(PluginSql, Vec<TextParam>), ApiError> {
        let mut params = Vec::new();
        let target = |b: EditSql| b.ident(&self.schema).lit(".").ident(&self.table);
        let column = |c: &str| SqlIdent::new(c).map_err(|_| ApiError::bad_request("column"));
        let sql = match self.op {
            EditOp::Insert => {
                let mut b = target(EditSql::mysql().lit("INSERT INTO ")).lit(" (");
                for (i, c) in self.values.keys().enumerate() {
                    b = if i > 0 { b.lit(", ") } else { b };
                    b = b.ident(&column(c)?);
                }
                b = b.lit(") VALUES (");
                for (i, v) in self.values.values().enumerate() {
                    b = if i > 0 { b.lit(", ") } else { b };
                    b = b.param();
                    params.push(param_mysql(v));
                }
                b.lit(")")
            }
            EditOp::Update | EditOp::Delete => {
                let mut want: Vec<&String> = self.key.keys().collect();
                let mut have: Vec<&String> = key_cols.iter().collect();
                want.sort();
                have.sort();
                if want != have {
                    return Err(ApiError::bad_request(format!("`key` must name exactly the key columns {key_cols:?}")));
                }
                let mut b = if self.op == EditOp::Update {
                    let mut b = target(EditSql::mysql().lit("UPDATE ")).lit(" SET ");
                    for (i, (c, v)) in self.values.iter().enumerate() {
                        b = if i > 0 { b.lit(", ") } else { b };
                        b = b.ident(&column(c)?).lit(" = ").param();
                        params.push(param_mysql(v));
                    }
                    b
                } else {
                    target(EditSql::mysql().lit("DELETE FROM "))
                };
                b = b.lit(" WHERE ");
                let mut first = true;
                for (c, v) in &self.key {
                    b = if first { b } else { b.lit(" AND ") };
                    first = false;
                    b = b.ident(&column(c)?).lit(" = ").param();
                    params.push(param_mysql(v));
                }
                for (c, v) in &self.original {
                    b = b.lit(" AND ").ident(&column(c)?).lit(" <=> ").param();
                    params.push(param_mysql(v));
                }
                b
            }
        };
        Ok((sql.build(), params))
    }

    /// The SQL Server statement: bracketed identifiers, `@Pn` values, and
    /// a NULL-safe guard on the original values (each placeholder named
    /// twice). Values are bound as text; the server converts them to the
    /// column's type.
    pub fn build_mssql(&self, key_cols: &[String]) -> Result<(PluginSql, Vec<TextParam>), ApiError> {
        let mut params = Vec::new();
        let target = |b: EditSql| b.ident(&self.schema).lit(".").ident(&self.table);
        let column = |c: &str| SqlIdent::new(c).map_err(|_| ApiError::bad_request("column"));
        let sql = match self.op {
            EditOp::Insert => {
                let mut b = target(EditSql::mssql().lit("INSERT INTO ")).lit(" (");
                for (i, c) in self.values.keys().enumerate() {
                    b = if i > 0 { b.lit(", ") } else { b };
                    b = b.ident(&column(c)?);
                }
                b = b.lit(") VALUES (");
                for (i, v) in self.values.values().enumerate() {
                    b = if i > 0 { b.lit(", ") } else { b };
                    b = b.param();
                    params.push(param(v));
                }
                b.lit(")")
            }
            EditOp::Update | EditOp::Delete => {
                let mut want: Vec<&String> = self.key.keys().collect();
                let mut have: Vec<&String> = key_cols.iter().collect();
                want.sort();
                have.sort();
                if want != have {
                    return Err(ApiError::bad_request(format!("`key` must name exactly the key columns {key_cols:?}")));
                }
                let mut b = if self.op == EditOp::Update {
                    let mut b = target(EditSql::mssql().lit("UPDATE ")).lit(" SET ");
                    for (i, (c, v)) in self.values.iter().enumerate() {
                        b = if i > 0 { b.lit(", ") } else { b };
                        b = b.ident(&column(c)?).lit(" = ").param();
                        params.push(param(v));
                    }
                    b
                } else {
                    target(EditSql::mssql().lit("DELETE FROM "))
                };
                b = b.lit(" WHERE ");
                let mut first = true;
                for (c, v) in &self.key {
                    b = if first { b } else { b.lit(" AND ") };
                    first = false;
                    b = b.ident(&column(c)?).lit(" = ").param();
                    params.push(param(v));
                }
                for (c, v) in &self.original {
                    let id = column(c)?;
                    b = b.lit(" AND (").ident(&id).lit(" = ").param();
                    params.push(param(v));
                    let n = b.params();
                    b = b.lit(" OR (").ident(&id).lit(" IS NULL AND ").param_again(n).lit(" IS NULL))");
                }
                b
            }
        };
        Ok((sql.build(), params))
    }

    /// The Oracle statement (T129): double-quoted identifiers (the
    /// dictionary's exact names), `:n` values each bound once, and a
    /// NULL-safe guard on the original values. Values are bound as text and
    /// converted by the server under the session's pinned NLS formats.
    pub fn build_oracle(&self, key_cols: &[String]) -> Result<(PluginSql, Vec<TextParam>), ApiError> {
        let mut params = Vec::new();
        let target = |b: EditSql| b.ident(&self.schema).lit(".").ident(&self.table);
        let column = |c: &str| SqlIdent::new(c).map_err(|_| ApiError::bad_request("column"));
        let sql = match self.op {
            EditOp::Insert => {
                let mut b = target(EditSql::oracle().lit("INSERT INTO ")).lit(" (");
                for (i, c) in self.values.keys().enumerate() {
                    b = if i > 0 { b.lit(", ") } else { b };
                    b = b.ident(&column(c)?);
                }
                b = b.lit(") VALUES (");
                for (i, v) in self.values.values().enumerate() {
                    b = if i > 0 { b.lit(", ") } else { b };
                    b = b.param();
                    params.push(param(v));
                }
                b.lit(")")
            }
            EditOp::Update | EditOp::Delete => {
                let mut want: Vec<&String> = self.key.keys().collect();
                let mut have: Vec<&String> = key_cols.iter().collect();
                want.sort();
                have.sort();
                if want != have {
                    return Err(ApiError::bad_request(format!("`key` must name exactly the key columns {key_cols:?}")));
                }
                let mut b = if self.op == EditOp::Update {
                    let mut b = target(EditSql::oracle().lit("UPDATE ")).lit(" SET ");
                    for (i, (c, v)) in self.values.iter().enumerate() {
                        b = if i > 0 { b.lit(", ") } else { b };
                        b = b.ident(&column(c)?).lit(" = ").param();
                        params.push(param(v));
                    }
                    b
                } else {
                    target(EditSql::oracle().lit("DELETE FROM "))
                };
                b = b.lit(" WHERE ");
                let mut first = true;
                for (c, v) in &self.key {
                    b = if first { b } else { b.lit(" AND ") };
                    first = false;
                    b = b.ident(&column(c)?).lit(" = ").param();
                    params.push(param(v));
                }
                for (c, v) in &self.original {
                    let id = column(c)?;
                    b = b.lit(" AND (").ident(&id).lit(" = ").param();
                    params.push(param(v));
                    b = b.lit(" OR (").ident(&id).lit(" IS NULL AND ").param().lit(" IS NULL))");
                    params.push(param(v));
                }
                b
            }
        };
        Ok((sql.build(), params))
    }

    pub fn changed_columns(&self) -> Vec<String> {
        self.values.keys().cloned().collect()
    }
}

/// A JSON value bound as text; the column type parses it.
fn param(v: &Value) -> TextParam {
    TextParam(match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        other => Some(other.to_string()),
    })
}

/// A JSON value bound for MySQL / MariaDB: booleans as 1 / 0 (MySQL's
/// BOOLEAN is TINYINT, and `'true'` is not a number to it).
fn param_mysql(v: &Value) -> TextParam {
    match v {
        Value::Bool(b) => TextParam(Some(if *b { "1" } else { "0" }.to_string())),
        other => param(other),
    }
}

fn db(e: DbError) -> ApiError {
    ApiError::refused("database_error", e.message)
}

/// `POST v2/sessions/<id>/rows`.
pub fn apply(cx: &Ctx<'_>, s: &Arc<Session>, data: &Map<String, Value>) -> Result<Value, ApiError> {
    let edit = Edit::parse(data)?;
    let ticket = match data.get("step_up_ticket") {
        None | Some(Value::Null) => None,
        Some(Value::String(t)) if !t.is_empty() && t.len() <= 256 && !t.chars().any(char::is_control) => {
            Some(t.as_str())
        }
        Some(_) => return Err(ApiError::bad_request("`step_up_ticket` must be 1-256 printable characters")),
    };
    s.touch();
    // Exclusive: no run or other edit may interleave with the edit's
    // BEGIN … COMMIT (or savepoint) bracket on the session's connection.
    let _op = s.begin_op()?;
    let conn = match s.conn() {
        DbConn::Pg(c) => c.clone(),
        DbConn::My(c) => return crate::mysql::browse::apply(cx, s, c, edit, ticket),
        DbConn::Ms(c) => return crate::mssql::browse::apply(cx, s, c, edit, ticket),
        DbConn::Ora(c) => return crate::oracle::browse::apply(cx, s, c, edit, ticket),
    };
    if let Some(why) = conn.wire().taint() {
        return Err(ApiError::refused("session_tainted", why));
    }
    let tx = conn.wire().tx();
    if tx == TxStatus::Failed {
        return Err(ApiError::refused("transaction_aborted", "the open transaction failed; roll it back first"));
    }
    let (schema, table) = (edit.schema.as_str().to_string(), edit.table.as_str().to_string());
    let key_cols = cx
        .rt
        .block_on(crate::objects::edit_key(&conn, &schema, &table))
        .map_err(db)?
        .ok_or_else(|| ApiError::refused("not_editable", "the table has no primary key or non-null unique key"))?;
    for c in &key_cols {
        ident(c, "key column")?;
    }
    let (sql, params) = edit.build(&key_cols)?;
    let catalog = s.catalog.clone();
    let key_json = serde_json::to_vec(&edit.key).unwrap_or_default();
    let key_hmac = ids::digest(cx.digest_key, "row-key", &key_json);
    let mut ev = crate::audit::base("dbms.row_edit", &s.id, &s.resource, &s.profile, s.info.db_enforced);
    ev["object"] = json!(format!("{catalog}.{schema}.{table}"));
    ev["op"] = json!(edit.op.as_str());
    ev["key_hmac"] = json!(key_hmac);
    ev["columns"] = json!(edit.changed_columns());
    let authorized =
        authorize_edit(cx.host, &s.resource, &s.id, edit.op.capability(), (&catalog, &schema, &table), sql, params)?;
    let edit_auth = match authorized {
        Ok(a) => a,
        Err(verdicts) => {
            ev["outcome"] = json!("refused");
            let _ = cx.host.audit(ev);
            let first = verdicts.iter().find(|v| !v.allowed).map(|v| v.capability.clone()).unwrap_or_default();
            return Ok(
                json!({"state": "refused", "message": format!("needs `{first}` on `{catalog}.{schema}.{table}`"),
                "verdicts": verdicts.iter().map(|v| json!({"capability": v.capability, "allowed": v.allowed})).collect::<Vec<_>>()}),
            );
        }
    };
    // Per-action step-up (§8.3): the edit's capability and `sql_select`.
    let caps: std::collections::BTreeSet<&'static str> = [edit.op.capability(), "sql_select"].into_iter().collect();
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
    // The edit's `=` / `IS NOT DISTINCT FROM` resolve through the search
    // path; for the edit's duration it is pg_catalog only, so an operator a
    // user schema puts first is never what runs (a column whose equality
    // lives elsewhere fails the edit instead).
    let saved_path = PluginSql::guarded(sql!("SELECT pg_catalog.current_setting('search_path')"));
    let pin_path = PluginSql::guarded(sql!("SELECT pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true)"));
    let restore_path = PluginSql::guarded(sql!("SELECT pg_catalog.set_config('search_path', $1::text, true)"));
    let result: Result<(u64, bool), DbError> = cx.rt.block_on(async {
        conn.internal_execute(&open).await?;
        let saved = if in_tx {
            let rows = conn.internal_query(&saved_path, &[]).await?;
            Some(rows.first().and_then(|r| r.try_get::<_, String>(0).ok()).unwrap_or_default())
        } else {
            None
        };
        if let Err(e) = conn.internal_query(&pin_path, &[]).await {
            let _ = conn.internal_execute(&undo).await;
            if in_tx {
                let _ = conn.internal_execute(&keep).await;
            }
            return Err(e);
        }
        match conn.send_edit(edit_auth).await {
            Ok(1) => {
                if let Some(path) = saved {
                    conn.internal_query(&restore_path, &[TextParam(Some(path))]).await?;
                }
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
        "object": format!("{catalog}.{schema}.{table}"), "columns": edit.changed_columns(), "key_hmac": key_hmac,
        "outcome": outcome}));
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn updates_bind_every_value_and_guard_with_the_original() {
        let e = Edit::parse(&data(json!({"object": {"schema": "public", "name": "Users"}, "op": "update",
            "key": {"id": 7}, "values": {"email": "new@example.com"}, "original": {"email": "old@example.com"}})))
        .unwrap();
        let (sql, params) = e.build(&["id".into()]).unwrap();
        assert_eq!(
            sql.as_str(),
            "UPDATE \"public\".\"Users\" SET \"email\" = $1 WHERE \"id\" = $2 AND \"email\" IS NOT DISTINCT FROM $3"
        );
        let p: Vec<Option<String>> = params.into_iter().map(|p| p.0).collect();
        assert_eq!(p, vec![Some("new@example.com".into()), Some("7".into()), Some("old@example.com".into())]);
    }

    #[test]
    fn oracle_edits_quote_exactly_and_bind_each_value_once() {
        let e = Edit::parse(&data(json!({"object": {"schema": "APP", "name": "T"}, "op": "update",
            "key": {"ID": 7}, "values": {"NAME": "new"}, "original": {"NAME": null}})))
        .unwrap();
        let (sql, params) = e.build_oracle(&["ID".into()]).unwrap();
        assert_eq!(
            sql.as_str(),
            "UPDATE \"APP\".\"T\" SET \"NAME\" = :1 WHERE \"ID\" = :2 AND (\"NAME\" = :3 OR (\"NAME\" IS NULL AND :4 IS NULL))"
        );
        let p: Vec<Option<String>> = params.into_iter().map(|p| p.0).collect();
        assert_eq!(p, vec![Some("new".into()), Some("7".into()), None, None]);
        let e = Edit::parse(&data(json!({"object": {"schema": "APP", "name": "T"}, "op": "insert",
            "values": {"ID": 1, "NAME": "x"}})))
        .unwrap();
        assert_eq!(
            e.build_oracle(&[]).unwrap().0.as_str(),
            "INSERT INTO \"APP\".\"T\" (\"ID\", \"NAME\") VALUES (:1, :2)"
        );
    }

    #[test]
    fn inserts_and_deletes() {
        let e = Edit::parse(&data(json!({"object": {"schema": "s", "name": "t"}, "op": "insert",
            "values": {"a": null, "b": true}})))
        .unwrap();
        assert_eq!(e.build(&[]).unwrap().0.as_str(), "INSERT INTO \"s\".\"t\" (\"a\", \"b\") VALUES ($1, $2)");
        let e = Edit::parse(&data(
            json!({"object": {"schema": "s", "name": "t"}, "op": "delete", "key": {"a": 1, "b": "x"}}),
        ))
        .unwrap();
        assert_eq!(
            e.build(&["b".into(), "a".into()]).unwrap().0.as_str(),
            "DELETE FROM \"s\".\"t\" WHERE \"a\" = $1 AND \"b\" = $2"
        );
    }

    #[test]
    fn injection_shaped_names_are_refused_not_escaped() {
        for (schema, table, col) in [
            ("public", "t\"; DROP TABLE x; --", "a"),
            ("pub lic", "t", "a"),
            ("public", "t", "a = 1 OR 1=1 --"),
            ("public", "café", "a"),
        ] {
            let r = Edit::parse(&data(json!({"object": {"schema": schema, "name": table}, "op": "update",
                "key": {"id": 1}, "values": {col: "x"}, "original": {col: "y"}})));
            assert_eq!(r.unwrap_err().code, "read_only_in_grid", "{schema}.{table}.{col}");
        }
    }

    #[test]
    fn malformed_edits_are_refused() {
        let base = json!({"object": {"schema": "s", "name": "t"}, "op": "update", "key": {"id": 1},
            "values": {"a": 1}, "original": {"a": 0}});
        let bad = |patch: &dyn Fn(&mut Value)| {
            let mut v = base.clone();
            patch(&mut v);
            Edit::parse(&data(v))
        };
        assert!(bad(&|v| v["op"] = json!("merge")).is_err());
        assert!(bad(&|v| v["original"] = json!({})).is_err(), "the original of an edited column is required");
        assert!(bad(&|v| v["key"] = json!({})).is_err());
        assert!(bad(&|v| v["key"] = json!({"id": null})).is_err());
        assert!(bad(&|v| v["sql"] = json!("DROP TABLE t")).is_err(), "no SQL text, ever");
        let e = Edit::parse(&data(base.clone())).unwrap();
        assert!(e.build(&["id".into(), "tenant".into()]).is_err(), "the key must be the whole key");
        assert!(e.build(&["other".into()]).is_err());
    }
}
