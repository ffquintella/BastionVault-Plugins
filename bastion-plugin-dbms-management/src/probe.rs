//! The ceiling probe (§5.1): what the session's login can really do, from
//! `has_*_privilege`, ownership and role attributes, compared with the
//! profile's declared ceiling. Advisory only: it never changes what runs.

use std::collections::BTreeSet;
use std::sync::Arc;

use bv_sql_guard::sql;
use serde_json::{json, Value};

use crate::api::ApiError;
use crate::driver::PluginSql;
use crate::host::Check;
use crate::session::{Ctx, Session};

/// The probe's answers, one boolean per question.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    pub superuser: bool,
    pub create_role: bool,
    pub create_db: bool,
    pub replication: bool,
    pub bypass_rls: bool,
    pub select: bool,
    pub insert: bool,
    pub update: bool,
    pub delete: bool,
    pub truncate: bool,
    pub owns_objects: bool,
    pub create: bool,
    pub execute: bool,
}

/// Capabilities the facts imply (§3.1 vocabulary).
pub fn capabilities(f: &Facts) -> BTreeSet<&'static str> {
    if f.superuser {
        return crate::profile::STATEMENT_CAPS.into_iter().collect();
    }
    let mut out = BTreeSet::new();
    let mut add = |on: bool, cap| {
        if on {
            out.insert(cap);
        }
    };
    add(f.select, "sql_select");
    add(f.insert, "sql_insert");
    add(f.update, "sql_update");
    add(f.delete, "sql_delete");
    add(f.truncate || f.owns_objects, "sql_drop");
    add(f.owns_objects, "sql_alter");
    add(f.create, "sql_create");
    add(f.execute, "sql_execute");
    add(f.create_role || f.create_db || f.replication || f.bypass_rls, "sql_admin");
    out
}

/// `READ v2/sessions/<id>/ceiling`.
pub fn probe(cx: &Ctx<'_>, s: &Arc<Session>) -> Result<Value, ApiError> {
    let conn = match s.conn() {
        crate::engine::DbConn::Pg(c) => c,
        crate::engine::DbConn::My(c) => return crate::mysql::browse::probe(cx, s, c),
        crate::engine::DbConn::Ms(c) => return crate::mssql::browse::probe(cx, s, c),
        crate::engine::DbConn::Ora(c) => return crate::oracle::browse::probe(cx, s, c),
    };
    let check = Check::server("sql_select");
    let v = cx.host.sql_authorize(&s.resource, std::slice::from_ref(&check))?;
    if !crate::host::verdicts_match(std::slice::from_ref(&check), &v) || !v[0].allowed {
        return Err(ApiError::refused("refused", "needs `sql_select` on `server`"));
    }
    let q = PluginSql::guarded(sql!(
        "WITH rel AS (SELECT c.oid, c.relowner FROM pg_catalog.pg_class c \
           JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace \
           WHERE c.relkind OPERATOR(pg_catalog.=) ANY (ARRAY['r','p','v','m','f']::pg_catalog.\"char\"[]) AND n.nspname OPERATOR(pg_catalog.<>) ALL (ARRAY['pg_catalog', 'information_schema']::pg_catalog.name[]) \
           AND n.nspname OPERATOR(pg_catalog.!~) '^pg_toast') \
         SELECT r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls, \
           EXISTS (SELECT 1 FROM rel WHERE pg_catalog.has_table_privilege(rel.oid, 'SELECT')), \
           EXISTS (SELECT 1 FROM rel WHERE pg_catalog.has_table_privilege(rel.oid, 'INSERT')), \
           EXISTS (SELECT 1 FROM rel WHERE pg_catalog.has_table_privilege(rel.oid, 'UPDATE')), \
           EXISTS (SELECT 1 FROM rel WHERE pg_catalog.has_table_privilege(rel.oid, 'DELETE')), \
           EXISTS (SELECT 1 FROM rel WHERE pg_catalog.has_table_privilege(rel.oid, 'TRUNCATE')), \
           EXISTS (SELECT 1 FROM rel WHERE pg_catalog.pg_has_role(rel.relowner, 'USAGE')), \
           pg_catalog.has_database_privilege(pg_catalog.current_database(), 'CREATE') OR EXISTS ( \
             SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname OPERATOR(pg_catalog.<>) ALL (ARRAY['pg_catalog', 'information_schema']::pg_catalog.name[]) \
             AND n.nspname OPERATOR(pg_catalog.!~) '^pg_' AND pg_catalog.has_schema_privilege(n.oid, 'CREATE')), \
           EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) p.pronamespace \
             WHERE n.nspname OPERATOR(pg_catalog.<>) ALL (ARRAY['pg_catalog', 'information_schema']::pg_catalog.name[]) \
             AND pg_catalog.has_function_privilege(p.oid, 'EXECUTE')), \
           ARRAY(SELECT b.rolname::text FROM pg_catalog.pg_roles b \
             WHERE b.oid OPERATOR(pg_catalog.<>) r.oid AND pg_catalog.pg_has_role(r.oid, b.oid, 'MEMBER') ORDER BY 1) \
         FROM pg_catalog.pg_roles r WHERE r.rolname OPERATOR(pg_catalog.=) CURRENT_USER"
    ));
    let rows =
        cx.rt.block_on(conn.internal_query(&q, &[])).map_err(|e| ApiError::refused("database_error", e.message))?;
    let r = rows.first().ok_or_else(|| ApiError::internal("the login's role is not visible"))?;
    let b = |i: usize| r.try_get::<_, bool>(i).unwrap_or(false);
    let facts = Facts {
        superuser: b(0),
        create_role: b(1),
        create_db: b(2),
        replication: b(3),
        bypass_rls: b(4),
        select: b(5),
        insert: b(6),
        update: b(7),
        delete: b(8),
        truncate: b(9),
        owns_objects: b(10),
        create: b(11),
        execute: b(12),
    };
    let roles: Vec<String> = r.try_get(13).unwrap_or_default();
    let probed = capabilities(&facts);
    let declared: BTreeSet<&'static str> = s.info.ceiling.iter().copied().collect();
    Ok(json!({
        "profile": s.profile,
        "declared": declared,
        "probed": probed,
        // A ceiling narrower than the truth is what the probe flags (§5.1).
        "undeclared": probed.difference(&declared).collect::<Vec<_>>(),
        "unused": declared.difference(&probed).collect::<Vec<_>>(),
        "superuser": facts.superuser,
        "member_of": roles,
        "advisory": true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facts_map_onto_capabilities() {
        let ro = Facts { select: true, execute: true, ..Facts::default() };
        assert_eq!(capabilities(&ro), ["sql_execute", "sql_select"].into_iter().collect());
        let owner = Facts { select: true, owns_objects: true, ..Facts::default() };
        assert!(capabilities(&owner).is_superset(&["sql_alter", "sql_drop"].into_iter().collect()));
        let su = Facts { superuser: true, ..Facts::default() };
        assert_eq!(capabilities(&su).len(), 9);
        assert!(capabilities(&Facts { create_role: true, ..Facts::default() }).contains("sql_admin"));
    }
}
