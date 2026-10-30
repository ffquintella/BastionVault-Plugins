//! The authorization step (§Phase 3): classify, resolve names, ask the host.
//! [`AuthorizedStatement`] and [`AuthorizedEdit`] have private fields and are
//! built only by [`authorize`] / [`authorize_edit`] once every check came
//! back allowed; `driver::PgConn` sends nothing else.

use std::collections::{BTreeMap, BTreeSet};

use bv_sql_classify::{
    classify_each, ClassifiedStatement, Dialect, LexerSettings, NameContext, ObjectKind, ObjectRef, Refusal, SqlTarget,
    StatementKind, Unclassifiable,
};
use serde_json::{json, Value};

use crate::api::ApiError;
use crate::driver::{PluginSql, TextParam};
use crate::host::{verdicts_match, Check, Host, Verdict};

/// Largest check batch sent in one host call (the host's `SQL_MAX_CHECKS`).
pub const MAX_CHECKS: usize = 1024;

/// One statement of caller SQL that the vault authorized for one session.
/// Not `Clone`: it is consumed by the one send it was authorized for.
#[derive(Debug)]
pub struct AuthorizedStatement {
    session_id: String,
    text: String,
    meta: StatementMeta,
}

impl AuthorizedStatement {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn text(&self) -> &str {
        &self.text
    }
    pub fn meta(&self) -> &StatementMeta {
        &self.meta
    }
}

/// What the run, the audit and the journal need about a statement.
#[derive(Debug, Clone)]
pub struct StatementMeta {
    pub index: usize,
    pub kind: Option<StatementKind>,
    pub tx_control: bool,
    pub opaque: bool,
    /// Ran as `unclassified` under `sql_admin` (§4.2).
    pub unclassified: bool,
    /// Why the classifier could not classify it (no statement text).
    pub unclassified_reason: Option<&'static str>,
    pub checks: Vec<Check>,
}

impl StatementMeta {
    pub fn kind_name(&self) -> String {
        match self.kind {
            Some(k) => format!("{k:?}"),
            None => "Unclassified".into(),
        }
    }

    /// The statement may change the name context (search path, current
    /// schema) or a session setting (Phase 2 obligation: re-read after).
    pub fn changes_context(&self) -> bool {
        self.opaque || self.unclassified || matches!(self.kind, Some(StatementKind::SetSession))
    }

    pub fn objects(&self) -> Vec<String> {
        let set: BTreeSet<String> =
            self.checks.iter().filter(|c| c.target_label() != "server").map(Check::target_label).collect();
        set.into_iter().collect()
    }

    pub fn required_json(&self) -> Vec<Value> {
        self.checks.iter().map(|c| json!({"capability": c.capability, "target": c.target_json()})).collect()
    }
}

/// A structured row edit authorized for one session (§7).
pub struct AuthorizedEdit {
    session_id: String,
    sql: PluginSql,
    params: Vec<TextParam>,
}

impl AuthorizedEdit {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn into_parts(self) -> (PluginSql, Vec<TextParam>) {
        (self.sql, self.params)
    }
}

/// One statement after classification, before the host decides.
#[derive(Debug, Clone)]
enum Classified {
    Ok(ClassifiedStatement),
    /// `Refusal::Unknown`: may run as `unclassified` for a `sql_admin` holder.
    Unknown(Unclassifiable),
}

/// The classified input, opaque outside this module.
#[derive(Debug)]
pub struct Prepared {
    text: String,
    statements: Vec<(std::ops::Range<usize>, Classified)>,
}

/// A refusal decided before the host is asked (no denial record: nothing
/// was checked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EarlyRefusal {
    pub code: &'static str,
    pub message: String,
    pub statement: Option<usize>,
}

/// Classify `text`. `single`: the `execute` rule (§8.2), one statement not
/// counting transaction control.
pub fn prepare(
    dialect: Dialect,
    text: &str,
    lexer: LexerSettings,
    ctx: &NameContext,
    single: bool,
) -> Result<Prepared, EarlyRefusal> {
    let each = classify_each(dialect, lexer, text, ctx).map_err(|u| EarlyRefusal {
        code: "unclassifiable",
        message: format!("the input cannot be split into statements: {}", u.reason),
        statement: None,
    })?;
    if each.is_empty() {
        return Err(EarlyRefusal { code: "empty", message: "no statement to run".into(), statement: None });
    }
    let mut statements = Vec::with_capacity(each.len());
    for (i, r) in each.into_iter().enumerate() {
        match r {
            Ok(c) => {
                if matches!(c.kind, StatementKind::CopyTo | StatementKind::CopyFrom) {
                    return Err(EarlyRefusal {
                        code: "unsupported_statement",
                        message: "COPY is not run by the SQL browser's execute endpoint".into(),
                        statement: Some(i),
                    });
                }
                statements.push((c.span.clone(), Classified::Ok(c)));
            }
            Err(u) if u.refusal == Refusal::Unknown && u.span.is_some() => {
                let span = u.span.clone().unwrap_or_default();
                statements.push((span, Classified::Unknown(u)));
            }
            Err(u) => {
                return Err(EarlyRefusal {
                    code: "refused_statement",
                    message: format!("statement {} is always refused: {}", i + 1, u.reason),
                    statement: Some(i),
                })
            }
        }
    }
    let counted = statements.iter().filter(|(_, c)| !matches!(c, Classified::Ok(s) if s.tx_control)).count();
    if single && counted > 1 {
        return Err(EarlyRefusal {
            code: "use_script",
            message: "execute runs one statement (plus transaction control); use the script endpoint".into(),
            statement: None,
        });
    }
    Ok(Prepared { text: text.to_string(), statements })
}

impl Prepared {
    /// Unqualified references the session must resolve through the catalog
    /// (§4.4: `schema: None`).
    pub fn unresolved(&self) -> Vec<ObjectRef> {
        let mut out = BTreeSet::new();
        for (_, c) in &self.statements {
            if let Classified::Ok(s) = c {
                for (_, t) in &s.required {
                    if let SqlTarget::Object(o) = t {
                        if o.schema.is_none() {
                            out.insert(o.clone());
                        }
                    }
                }
            }
        }
        out.into_iter().collect()
    }

    pub fn len(&self) -> usize {
        self.statements.len()
    }

    /// Every statement is transaction control (needs no name context).
    pub fn only_tx_control(&self) -> bool {
        self.statements.iter().all(|(_, c)| matches!(c, Classified::Ok(s) if s.tx_control))
    }

    pub fn is_empty(&self) -> bool {
        self.statements.is_empty()
    }

    /// Statements that are transaction control.
    pub fn tx_control_count(&self) -> usize {
        self.statements.iter().filter(|(_, c)| matches!(c, Classified::Ok(s) if s.tx_control)).count()
    }

    /// §8.1: an export is exactly one row-returning statement that needs
    /// only `sql_select`. DML with `RETURNING`, a data-modifying CTE,
    /// `FOR UPDATE`, a sequence write, an opaque call or an unclassifiable
    /// statement needs more and is refused here, before the host is asked.
    pub fn check_export(&self) -> Result<(), EarlyRefusal> {
        let refuse = |code: &'static str, message: String| EarlyRefusal { code, message, statement: Some(0) };
        let [(_, only)] = self.statements.as_slice() else {
            return Err(EarlyRefusal {
                code: "export_one_statement",
                message: "an export runs exactly one statement, without transaction control".into(),
                statement: None,
            });
        };
        let c = match only {
            Classified::Ok(c) => c,
            Classified::Unknown(u) => {
                return Err(refuse("export_not_select", format!("the statement cannot be classified ({})", u.reason)))
            }
        };
        if c.tx_control || !EXPORT_KINDS.contains(&c.kind) || c.opaque {
            return Err(refuse(
                "export_not_select",
                format!("only a SELECT, VALUES, SHOW or EXPLAIN can be exported (this is {:?})", c.kind),
            ));
        }
        if let Some((cap, _)) = c.required.iter().find(|(cap, _)| cap.as_str() != "sql_select") {
            return Err(refuse(
                "export_not_select",
                format!("an export may need only sql_select; this statement needs `{}`", cap.as_str()),
            ));
        }
        Ok(())
    }
}

/// Statement kinds an export may run (§8.1): they return rows and read only.
const EXPORT_KINDS: [StatementKind; 4] =
    [StatementKind::Select, StatementKind::Values, StatementKind::Show, StatementKind::Explain];

/// What the batch is for. It decides the extra checks and how unqualified
/// names are resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `execute`: one statement plus transaction control.
    Execute,
    /// `script` (§8.2): adds `sql_script` on `sql/server`; names after the
    /// first statement that may change the name context are checked as
    /// unaddressable, because the classification-time resolution no
    /// longer describes what the server will resolve.
    Script,
    /// `export` (§8.1): every `sql_select` check gains `sql_export` on the
    /// same target.
    Export,
}

/// Names resolved through the catalog: `Some(schema)` when the reference
/// resolves to exactly one schema, else `None` (checked as unaddressable).
pub type Resolutions = BTreeMap<ObjectRef, Option<String>>;

fn checks_for(c: &ClassifiedStatement, res: &Resolutions) -> Vec<Check> {
    let mut set = BTreeSet::new();
    for (cap, target) in &c.required {
        let cap = cap.as_str();
        let check = match target {
            SqlTarget::Server => Check::server(cap),
            SqlTarget::Object(o) => {
                let schema = match &o.schema {
                    Some(s) => s.clone(),
                    // Unresolved: an empty schema is unaddressable, so only a
                    // resource-wide grant can allow it (fail closed, §3.2).
                    None => res.get(o).cloned().flatten().unwrap_or_default(),
                };
                Check::object(cap, &o.catalog, &schema, &o.name)
            }
        };
        set.insert(check);
    }
    set.into_iter().collect()
}

/// The host's decision for a batch, statement by statement, plus the
/// checks of the request itself (`sql_script` on `sql/server`).
#[derive(Debug, Clone)]
pub struct Decision {
    pub statements: Vec<(StatementMeta, Vec<Verdict>)>,
    pub request: Vec<Verdict>,
}

impl Decision {
    pub fn allowed(&self) -> bool {
        self.request.iter().all(|x| x.allowed) && self.statements.iter().all(|(_, v)| v.iter().all(|x| x.allowed))
    }

    /// Every capability the batch uses (statements and request), for the
    /// per-action step-up (§8.3).
    pub fn capabilities(&self) -> BTreeSet<&'static str> {
        let request = self.request.iter().filter_map(|v| crate::profile::cap_static(&v.capability));
        let statements = self.statements.iter().flat_map(|(m, _)| m.checks.iter().map(|c| c.capability));
        request.chain(statements).collect()
    }

    /// The request-level verdicts, for the reply.
    pub fn request_report(&self) -> Vec<Value> {
        self.request
            .iter()
            .map(|v| {
                json!({"capability": v.capability, "target": v.target, "allowed": v.allowed,
                "denied_by_deny": v.denied_by_deny})
            })
            .collect()
    }

    /// `{index, kinds, required, verdict}` per statement (§6.2).
    pub fn report(&self) -> Vec<Value> {
        self.statements
            .iter()
            .map(|(m, vs)| {
                let ok = vs.iter().all(|v| v.allowed);
                json!({
                    "index": m.index,
                    "kinds": [m.kind_name()],
                    "unclassified": m.unclassified,
                    "required": vs.iter().map(|v| json!({"capability": v.capability, "target": v.target,
                        "allowed": v.allowed, "denied_by_deny": v.denied_by_deny})).collect::<Vec<_>>(),
                    "verdict": if ok { "allowed" } else { "refused" },
                })
            })
            .collect()
    }

    /// "needs `sql_update` on `app.public.t`" for the first refusal.
    pub fn message(&self) -> String {
        if let Some(v) = self.request.iter().find(|v| !v.allowed) {
            let deny = if v.denied_by_deny { " (an explicit deny applies)" } else { "" };
            return format!("the script needs `{}` on the server{deny}", v.capability);
        }
        for (m, vs) in &self.statements {
            if let Some(v) = vs.iter().find(|v| !v.allowed) {
                let target = match &v.target {
                    Value::Object(o) => format!(
                        "{}.{}.{}",
                        o.get("catalog").and_then(Value::as_str).unwrap_or(""),
                        o.get("schema").and_then(Value::as_str).unwrap_or(""),
                        o.get("object").and_then(Value::as_str).unwrap_or("")
                    ),
                    _ => "the server".into(),
                };
                let why = if m.unclassified {
                    format!(
                        " (the statement could not be classified: {}; only sql_admin may run it as unclassified)",
                        m.unclassified_reason.unwrap_or("unknown")
                    )
                } else if v.denied_by_deny {
                    " (an explicit deny applies)".into()
                } else {
                    String::new()
                };
                return format!("statement {} needs `{}` on `{target}`{why}", m.index + 1, v.capability);
            }
        }
        String::new()
    }
}

/// Ask the host about every statement at once (all or nothing, §8.2) and,
/// when every check is allowed, mint the statements for `session_id`.
pub fn authorize(
    host: &dyn Host,
    resource: &str,
    session_id: &str,
    prepared: Prepared,
    res: &Resolutions,
    mode: Mode,
) -> Result<(Decision, Option<Vec<AuthorizedStatement>>), ApiError> {
    if mode == Mode::Export {
        prepared.check_export().map_err(|r| ApiError::refused(r.code, r.message))?;
    }
    let unresolved = Resolutions::new();
    let mut context_changed = false;
    let mut metas = Vec::with_capacity(prepared.statements.len());
    for (i, (_, c)) in prepared.statements.iter().enumerate() {
        // In a script, a statement after one that may move the search path
        // is checked without the classification-time resolution (§4.4).
        let res_here = if mode == Mode::Script && context_changed { &unresolved } else { res };
        let meta = match c {
            Classified::Ok(s) => {
                let mut checks = checks_for(s, res_here);
                if mode == Mode::Export {
                    let export: Vec<Check> =
                        checks.iter().map(|c| Check { capability: "sql_export", target: c.target.clone() }).collect();
                    checks.extend(export);
                    checks.sort();
                    checks.dedup();
                }
                StatementMeta {
                    index: i,
                    kind: Some(s.kind),
                    tx_control: s.tx_control,
                    opaque: s.opaque,
                    unclassified: false,
                    unclassified_reason: None,
                    checks,
                }
            }
            Classified::Unknown(u) => StatementMeta {
                index: i,
                kind: None,
                tx_control: false,
                opaque: true,
                unclassified: true,
                unclassified_reason: Some(u.reason.as_str()),
                checks: vec![Check::server("sql_admin")],
            },
        };
        // Defence in depth: the classifier never yields an empty set for a
        // statement that is not transaction control; refuse if it did.
        if meta.checks.is_empty() && !meta.tx_control {
            return Err(ApiError::refused("refused_statement", format!("statement {} has no requirement", i + 1)));
        }
        context_changed |= meta.changes_context();
        metas.push(meta);
    }
    let request_checks: Vec<Check> = if mode == Mode::Script { vec![Check::server("sql_script")] } else { Vec::new() };
    let mut batch: Vec<Check> = metas
        .iter()
        .flat_map(|m| m.checks.iter().cloned())
        .chain(request_checks.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if batch.len() > MAX_CHECKS {
        return Err(ApiError::refused("too_many_checks", "the statement references too many objects"));
    }
    let verdicts = if batch.is_empty() { Vec::new() } else { host.sql_authorize(resource, &batch)? };
    if !verdicts_match(&batch, &verdicts) {
        return Err(ApiError::internal("the host's verdicts do not match the checks; refused"));
    }
    let by_check: BTreeMap<Check, Verdict> = batch.drain(..).zip(verdicts).collect();
    let statements: Vec<(StatementMeta, Vec<Verdict>)> = metas
        .into_iter()
        .map(|m| {
            let vs = m.checks.iter().filter_map(|c| by_check.get(c).cloned()).collect();
            (m, vs)
        })
        .collect();
    let request = request_checks.iter().filter_map(|c| by_check.get(c).cloned()).collect();
    let decision = Decision { statements, request };
    if !decision.allowed() {
        return Ok((decision, None));
    }
    let minted = prepared
        .statements
        .iter()
        .zip(&decision.statements)
        .map(|((span, _), (meta, _))| AuthorizedStatement {
            session_id: session_id.to_string(),
            text: prepared.text[span.clone()].to_string(),
            meta: meta.clone(),
        })
        .collect();
    Ok((decision, Some(minted)))
}

/// Authorize one structured edit: the edit's capability and `sql_select`
/// on the object, exactly (§7: no parser involved).
pub fn authorize_edit(
    host: &dyn Host,
    resource: &str,
    session_id: &str,
    capability: &'static str,
    object: (&str, &str, &str),
    sql: PluginSql,
    params: Vec<TextParam>,
) -> Result<Result<AuthorizedEdit, Vec<Verdict>>, ApiError> {
    let (catalog, schema, name) = object;
    let checks =
        vec![Check::object(capability, catalog, schema, name), Check::object("sql_select", catalog, schema, name)];
    let verdicts = host.sql_authorize(resource, &checks)?;
    if !verdicts_match(&checks, &verdicts) {
        return Err(ApiError::internal("the host's verdicts do not match the checks; refused"));
    }
    if verdicts.iter().all(|v| v.allowed) {
        Ok(Ok(AuthorizedEdit { session_id: session_id.to_string(), sql, params }))
    } else {
        Ok(Err(verdicts))
    }
}

/// Whether an object kind is resolved through `pg_class` (relations,
/// sequences, indexes) rather than another catalog.
pub fn resolves_through_class(kind: ObjectKind) -> bool {
    matches!(kind, ObjectKind::Relation | ObjectKind::Sequence | ObjectKind::Index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::MockHost;

    fn ctx() -> NameContext {
        NameContext::postgres("app", Some("public".into()), vec!["pg_catalog".into(), "public".into()])
    }

    const SCS: LexerSettings = LexerSettings::PostgreSql { standard_conforming_strings: true };

    fn host() -> std::sync::Arc<MockHost> {
        MockHost::new(serde_json::json!({}))
    }

    fn run(
        h: &MockHost,
        text: &str,
        res: &Resolutions,
    ) -> Result<(Decision, Option<Vec<AuthorizedStatement>>), ApiError> {
        let p =
            prepare(Dialect::PostgreSql, text, SCS, &ctx(), true).map_err(|e| ApiError::refused(e.code, e.message))?;
        authorize(h, "db", "sess-1", p, res, Mode::Execute)
    }

    #[test]
    fn allowed_statements_carry_exactly_their_span_and_session() {
        let h = host();
        let (d, minted) =
            run(&h, "  BEGIN; UPDATE public.t SET a = 1 WHERE b = 2 ; COMMIT -- done", &Resolutions::new()).unwrap();
        assert!(d.allowed());
        let minted = minted.unwrap();
        let texts: Vec<&str> = minted.iter().map(AuthorizedStatement::text).collect();
        assert_eq!(texts, ["BEGIN", "UPDATE public.t SET a = 1 WHERE b = 2", "COMMIT"]);
        assert!(minted.iter().all(|m| m.session_id() == "sess-1"));
        let asked = &h.authorized.lock().unwrap()[0];
        assert!(asked.contains(&Check::object("sql_update", "app", "public", "t")));
        assert!(asked.contains(&Check::object("sql_select", "app", "public", "t")), "WHERE reads the table");
    }

    #[test]
    fn one_refused_check_mints_nothing() {
        let h = host();
        h.allow(|c| c.capability == "sql_select");
        let (d, minted) = run(&h, "UPDATE public.t SET a = 1 WHERE b = 2", &Resolutions::new()).unwrap();
        assert!(minted.is_none());
        assert!(!d.allowed());
        assert_eq!(d.message(), "statement 1 needs `sql_update` on `app.public.t`");
        assert_eq!(d.report()[0]["verdict"], "refused");
    }

    #[test]
    fn data_modifying_ctes_need_the_write_privilege() {
        let h = host();
        h.allow(|c| c.capability == "sql_select");
        let (_, minted) =
            run(&h, "WITH d AS (DELETE FROM public.t RETURNING *) SELECT * FROM d", &Resolutions::new()).unwrap();
        assert!(minted.is_none(), "a DELETE hidden in a CTE is not a SELECT");
    }

    #[test]
    fn unresolved_names_are_checked_as_unaddressable() {
        let h = host();
        run(&h, "SELECT * FROM t", &Resolutions::new()).unwrap();
        let asked = h.authorized.lock().unwrap()[0].clone();
        assert_eq!(asked, vec![Check::object("sql_select", "app", "", "t")], "no schema: the objects root decides");
        let p = prepare(Dialect::PostgreSql, "SELECT * FROM t", SCS, &ctx(), true).unwrap();
        let mut res = Resolutions::new();
        for r in p.unresolved() {
            res.insert(r, Some("sales".into()));
        }
        authorize(&*h, "db", "s", p, &res, Mode::Execute).unwrap();
        assert_eq!(h.authorized.lock().unwrap()[1], vec![Check::object("sql_select", "app", "sales", "t")]);
    }

    #[test]
    fn never_refusals_and_multi_statements_stop_before_the_host() {
        for (text, code) in [
            ("SELECT pg_read_file('/etc/passwd')", "refused_statement"),
            ("SET standard_conforming_strings = off", "refused_statement"),
            ("SELECT 1; SELECT 2", "use_script"),
            ("COPY t TO STDOUT", "unsupported_statement"),
            ("SELECT 'unterminated", "unclassifiable"),
            ("  -- only a comment", "empty"),
        ] {
            assert_eq!(prepare(Dialect::PostgreSql, text, SCS, &ctx(), true).unwrap_err().code, code, "{text}");
        }
        assert!(
            prepare(Dialect::PostgreSql, "SELECT 1; SELECT 2", SCS, &ctx(), false).is_ok(),
            "a script may hold several"
        );
    }

    /// §8.1: an export needs only `sql_select`, plus `sql_export` on every
    /// object it reads (on the server when it reads none); everything else
    /// is refused before the host is asked.
    #[test]
    fn exports_need_select_only_and_sql_export_on_what_they_read() {
        let h = host();
        let p =
            prepare(Dialect::PostgreSql, "SELECT a FROM public.t JOIN public.u USING (id)", SCS, &ctx(), true).unwrap();
        let (d, minted) = authorize(&*h, "db", "s", p, &Resolutions::new(), Mode::Export).unwrap();
        assert_eq!(minted.unwrap().len(), 1);
        let asked = h.authorized.lock().unwrap()[0].clone();
        for o in ["t", "u"] {
            assert!(asked.contains(&Check::object("sql_select", "app", "public", o)), "{asked:?}");
            assert!(asked.contains(&Check::object("sql_export", "app", "public", o)), "{asked:?}");
        }
        assert_eq!(d.capabilities(), ["sql_export", "sql_select"].into_iter().collect());
        let p = prepare(Dialect::PostgreSql, "SELECT now()", SCS, &ctx(), true).unwrap();
        authorize(&*h, "db", "s", p, &Resolutions::new(), Mode::Export).unwrap();
        assert!(h.authorized.lock().unwrap()[1].contains(&Check::server("sql_export")));

        h.allow(|c| c.capability == "sql_select");
        let p = prepare(Dialect::PostgreSql, "SELECT * FROM public.t", SCS, &ctx(), true).unwrap();
        let (d, minted) = authorize(&*h, "db", "s", p, &Resolutions::new(), Mode::Export).unwrap();
        assert!(minted.is_none(), "sql_select alone does not export");
        assert_eq!(d.message(), "statement 1 needs `sql_export` on `app.public.t`");

        h.allow(|_| true);
        for text in [
            "DELETE FROM public.t RETURNING *",
            "UPDATE public.t SET a = 1 RETURNING a",
            "INSERT INTO public.t VALUES (1) RETURNING *",
            "WITH d AS (DELETE FROM public.t RETURNING *) SELECT * FROM d",
            "SELECT * FROM public.t FOR UPDATE",
            "SELECT nextval('public.s')",
            "BEGIN; SELECT 1",
            "SET search_path = x",
            "TABLE t",
        ] {
            let asked_before = h.authorized.lock().unwrap().len();
            let p = prepare(Dialect::PostgreSql, text, SCS, &ctx(), true).unwrap();
            let e = authorize(&*h, "db", "s", p, &Resolutions::new(), Mode::Export).unwrap_err();
            assert!(e.code.starts_with("export_"), "{text}: {e}");
            assert_eq!(h.authorized.lock().unwrap().len(), asked_before, "{text}: the host was asked");
        }
    }

    /// §8.2: a script needs `sql_script` on the server on top of every
    /// statement's own privileges, and one refusal mints nothing.
    #[test]
    fn scripts_need_sql_script_and_are_all_or_nothing() {
        let h = host();
        h.allow(|c| c.capability != "sql_script");
        let p = prepare(Dialect::PostgreSql, "SELECT 1; UPDATE public.t SET a = 1 WHERE b = 2", SCS, &ctx(), false)
            .unwrap();
        let (d, minted) = authorize(&*h, "db", "s", p, &Resolutions::new(), Mode::Script).unwrap();
        assert!(minted.is_none());
        assert_eq!(d.message(), "the script needs `sql_script` on the server");
        assert!(h.authorized.lock().unwrap()[0].contains(&Check::server("sql_script")));
        assert_eq!(d.request_report()[0]["allowed"], false);

        h.allow(|c| c.capability != "sql_drop");
        let p = prepare(Dialect::PostgreSql, "SELECT 1; DROP TABLE public.t; SELECT 2", SCS, &ctx(), false).unwrap();
        let (d, minted) = authorize(&*h, "db", "s", p, &Resolutions::new(), Mode::Script).unwrap();
        assert!(minted.is_none(), "one refused statement refuses the script");
        assert!(d.message().starts_with("statement 2 needs `sql_drop`"), "{}", d.message());
        assert_eq!(d.report()[1]["verdict"], "refused");

        h.allow(|_| true);
        let p = prepare(Dialect::PostgreSql, "SELECT 1; DROP TABLE public.t; SELECT 2", SCS, &ctx(), false).unwrap();
        let (d, minted) = authorize(&*h, "db", "s", p, &Resolutions::new(), Mode::Script).unwrap();
        assert_eq!(minted.unwrap().len(), 3);
        assert!(d.capabilities().contains("sql_script") && d.capabilities().contains("sql_drop"));
    }

    /// A script's names after a statement that may move the search path are
    /// checked as unaddressable: the earlier resolution no longer holds.
    #[test]
    fn script_names_after_a_context_change_are_unaddressable() {
        let h = host();
        let p =
            prepare(Dialect::PostgreSql, "SELECT * FROM t; SET search_path = other; DROP TABLE t", SCS, &ctx(), false)
                .unwrap();
        let mut res = Resolutions::new();
        for r in p.unresolved() {
            res.insert(r, Some("public".into()));
        }
        authorize(&*h, "db", "s", p, &res, Mode::Script).unwrap();
        let asked = h.authorized.lock().unwrap()[0].clone();
        assert!(asked.contains(&Check::object("sql_select", "app", "public", "t")), "{asked:?}");
        assert!(asked.contains(&Check::object("sql_drop", "app", "", "t")), "{asked:?}");
        assert!(!asked.contains(&Check::object("sql_drop", "app", "public", "t")), "{asked:?}");
    }

    #[test]
    fn unclassifiable_statements_need_sql_admin() {
        let h = host();
        h.allow(|c| c.capability != "sql_admin");
        // sqlparser cannot parse `TABLE t`: Unknown, not Never.
        let (d, minted) = run(&h, "TABLE t", &Resolutions::new()).unwrap();
        assert!(minted.is_none());
        assert_eq!(h.authorized.lock().unwrap()[0], vec![Check::server("sql_admin")]);
        assert!(d.message().contains("could not be classified"), "{}", d.message());
        h.allow(|_| true);
        let (_, minted) = run(&h, "TABLE t", &Resolutions::new()).unwrap();
        assert!(minted.unwrap()[0].meta().unclassified);
    }

    struct Liar;
    impl Host for Liar {
        fn sql_target(&self, _: &str) -> Result<Value, crate::host::HostError> {
            unreachable!()
        }
        fn sql_authorize(&self, _: &str, checks: &[Check]) -> Result<Vec<Verdict>, crate::host::HostError> {
            // One verdict short, and for the wrong capability.
            Ok(checks
                .iter()
                .skip(1)
                .map(|_| Verdict {
                    capability: "sql_select".into(),
                    target: json!("server"),
                    path: String::new(),
                    allowed: true,
                    denied_by_deny: false,
                })
                .collect())
        }
        fn sql_credential(&self, _: &str, _: &str, _: &str) -> Result<crate::host::Credential, crate::host::HostError> {
            unreachable!()
        }
        fn ticket_redeem(&self, _: &str, _: &str, _: &str, _: Option<&str>) -> Result<bool, crate::host::HostError> {
            unreachable!()
        }
        fn audit(&self, _: Value) -> Result<(), crate::host::HostError> {
            Ok(())
        }
        fn storage_get(&self, _: &str) -> Result<Option<Vec<u8>>, crate::host::HostError> {
            Ok(None)
        }
        fn storage_put(&self, _: &str, _: &[u8]) -> Result<(), crate::host::HostError> {
            Ok(())
        }
        fn storage_delete(&self, _: &str) -> Result<(), crate::host::HostError> {
            Ok(())
        }
        fn storage_list(&self, _: &str) -> Result<Vec<String>, crate::host::HostError> {
            Ok(vec![])
        }
        fn log(&self, _: i32, _: &str) {}
    }

    #[test]
    fn a_reply_that_does_not_match_the_checks_refuses_everything() {
        let p = prepare(Dialect::PostgreSql, "UPDATE public.t SET a = 1 WHERE b = 2", SCS, &ctx(), true).unwrap();
        let e = authorize(&Liar, "db", "s", p, &Resolutions::new(), Mode::Execute).unwrap_err();
        assert_eq!(e.code, "internal");
        let edit = authorize_edit(
            &Liar,
            "db",
            "s",
            "sql_update",
            ("app", "public", "t"),
            crate::driver::PluginSql::guarded(bv_sql_guard::sql!("SELECT 1")),
            vec![],
        );
        assert!(edit.is_err());
    }

    #[test]
    fn edits_check_exactly_their_capability_and_select() {
        let h = host();
        h.allow(|c| c.capability == "sql_select");
        let sql = || crate::driver::PluginSql::guarded(bv_sql_guard::sql!("SELECT 1"));
        let r = authorize_edit(&*h, "db", "s", "sql_delete", ("app", "public", "t"), sql(), vec![]).unwrap();
        assert!(r.is_err(), "sql_delete is not held");
        assert_eq!(
            h.authorized.lock().unwrap()[0],
            vec![Check::object("sql_delete", "app", "public", "t"), Check::object("sql_select", "app", "public", "t"),]
        );
        h.allow(|_| true);
        let ok = authorize_edit(&*h, "db", "s", "sql_delete", ("app", "public", "t"), sql(), vec![]).unwrap();
        assert_eq!(ok.ok().unwrap().session_id(), "s");
    }
}
