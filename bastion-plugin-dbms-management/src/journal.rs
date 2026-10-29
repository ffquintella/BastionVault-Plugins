//! The statement journal (§11): one versioned record per session under
//! `dbms/journal/<namespace>/<date>/<session>`, listing every statement with
//! its outcome. Statement text follows `journal_text` (`redacted` by default:
//! literals replaced by `?`), and database errors are kept as SQLSTATE only.

use serde_json::{json, Value};

use crate::api::{ApiError, Owner};
use crate::config::JournalText;
use crate::host::Host;

pub const JOURNAL_PREFIX: &str = "dbms/journal";
pub const RECORD_VERSION: u64 = 1;
/// Statements kept per session record; later ones are counted only.
pub const MAX_STATEMENTS_PER_RECORD: usize = 2_000;

/// A namespace as one key segment: `root` for the root namespace, else its
/// path with `/` written as `~` (namespace paths never contain `~`).
pub fn ns_segment(namespace: &str) -> String {
    let ns = namespace.trim_matches('/');
    if ns.is_empty() {
        "root".into()
    } else {
        ns.replace('/', "~")
    }
}

/// `YYYY-MM-DD` (UTC) for a Unix time in milliseconds.
pub fn date_of(ms: u64) -> String {
    let days = (ms / 86_400_000) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

pub fn key(namespace: &str, date: &str, session: &str) -> String {
    format!("{JOURNAL_PREFIX}/{}/{date}/{session}", ns_segment(namespace))
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// The in-memory record of one session.
#[derive(Debug, Clone)]
pub struct Record {
    pub key: String,
    pub body: Value,
    pub dirty: bool,
}

impl Record {
    pub fn new(owner: &Owner, session: &str, resource: &str, profile: &str, opened_ms: u64, namespace: &str) -> Self {
        let date = date_of(opened_ms);
        Self {
            key: key(namespace, &date, session),
            body: json!({
                "v": RECORD_VERSION,
                "session": session,
                "entity_id": owner.entity_id,
                "principal": {"mount": owner.principal_mount, "name": owner.principal_name},
                "namespace": namespace,
                "resource": resource,
                "profile": profile,
                "opened_at_ms": opened_ms,
                "closed_at_ms": null,
                "close_reason": null,
                "statements": [],
                "statements_dropped": 0,
            }),
            dirty: true,
        }
    }

    /// Append one statement entry. `text` is already per `journal_text`.
    pub fn push(&mut self, entry: Value) {
        let dropped = self.body["statements"].as_array().map(|a| a.len() >= MAX_STATEMENTS_PER_RECORD).unwrap_or(true);
        if dropped {
            let n = self.body["statements_dropped"].as_u64().unwrap_or(0);
            self.body["statements_dropped"] = json!(n + 1);
        } else if let Some(a) = self.body["statements"].as_array_mut() {
            a.push(entry);
        }
        self.dirty = true;
    }

    /// Set the outcome of the entry for (`run`, `index`).
    pub fn complete(&mut self, run: &str, index: usize, outcome: Value) {
        if let Some(a) = self.body["statements"].as_array_mut() {
            if let Some(e) = a.iter_mut().rev().find(|e| e["run"] == run && e["index"] == index) {
                if let (Some(dst), Some(src)) = (e.as_object_mut(), outcome.as_object()) {
                    for (k, v) in src {
                        dst.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        self.dirty = true;
    }

    pub fn close(&mut self, reason: &str) {
        self.body["closed_at_ms"] = json!(now_ms());
        self.body["close_reason"] = json!(reason);
        self.dirty = true;
    }

    /// Write the record if it changed. Called only inside an invocation.
    pub fn flush(&mut self, host: &dyn Host) {
        if !self.dirty {
            return;
        }
        if let Ok(b) = serde_json::to_vec(&self.body) {
            if host.storage_put(&self.key, &b).is_ok() {
                self.dirty = false;
            }
        }
    }
}

/// Statement text as the journal keeps it.
pub fn text_for(mode: &JournalText, text: &str, redacted: Option<String>) -> Value {
    match mode {
        JournalText::Full => json!(text),
        JournalText::Redacted => redacted.map(Value::String).unwrap_or(Value::Null),
        JournalText::None => Value::Null,
    }
}

/// Read a stored record, accepting only the versions this plugin knows
/// (read-old/write-new: v1 is the first).
pub fn parse_record(bytes: &[u8]) -> Option<Value> {
    let v: Value = serde_json::from_slice(bytes).ok()?;
    (v.get("v").and_then(Value::as_u64) == Some(RECORD_VERSION)).then_some(v)
}

fn valid_date(s: &str) -> bool {
    s.len() == 10 && s.bytes().enumerate().all(|(i, b)| if i == 4 || i == 7 { b == b'-' } else { b.is_ascii_digit() })
}

fn valid_session(s: &str) -> bool {
    crate::ids::instance_of(s).is_some()
}

/// `v2/journal/self/…`: dates, then the caller's sessions of a date, then
/// one record. Everything is filtered by the caller's entity.
pub fn read_self(host: &dyn Host, owner: &Owner, rest: &[&str]) -> Result<Value, ApiError> {
    let ns = ns_segment(&owner.namespace);
    let mine = |v: &Value| v["entity_id"] == owner.entity_id.as_str();
    match rest {
        [] => {
            let dates = host.storage_list(&format!("{JOURNAL_PREFIX}/{ns}"))?;
            let dates: Vec<String> =
                dates.into_iter().map(|d| d.trim_end_matches('/').to_string()).filter(|d| valid_date(d)).collect();
            Ok(json!({"keys": dates}))
        }
        [date] if valid_date(date) => {
            let mut out = Vec::new();
            for s in host.storage_list(&format!("{JOURNAL_PREFIX}/{ns}/{date}"))? {
                if !valid_session(&s) {
                    continue;
                }
                if let Some(v) =
                    host.storage_get(&format!("{JOURNAL_PREFIX}/{ns}/{date}/{s}"))?.and_then(|b| parse_record(&b))
                {
                    if mine(&v) {
                        out.push(json!({"session": s, "resource": v["resource"], "opened_at_ms": v["opened_at_ms"],
                            "closed_at_ms": v["closed_at_ms"], "statements": v["statements"].as_array().map(Vec::len)}));
                    }
                }
            }
            Ok(json!({"sessions": out}))
        }
        [date, session] if valid_date(date) && valid_session(session) => {
            let rec = host
                .storage_get(&format!("{JOURNAL_PREFIX}/{ns}/{date}/{session}"))?
                .and_then(|b| parse_record(&b))
                .filter(mine)
                .ok_or_else(|| ApiError::not_found("no such journal record"))?;
            Ok(rec)
        }
        _ => Err(ApiError::bad_request("expected v2/journal/self[/<YYYY-MM-DD>[/<session>]]")),
    }
}

/// `v2/journal/all/…` (auditors; the host's path ACL decides who):
/// namespaces, dates, sessions, records.
pub fn read_all(host: &dyn Host, rest: &[&str]) -> Result<Value, ApiError> {
    let seg_ok = |s: &str| !s.is_empty() && !s.contains("..") && !s.contains('/');
    match rest {
        [] => Ok(
            json!({"keys": host.storage_list(JOURNAL_PREFIX)?.into_iter().map(|k| k.trim_end_matches('/').to_string()).collect::<Vec<_>>()}),
        ),
        [ns] if seg_ok(ns) => Ok(
            json!({"keys": host.storage_list(&format!("{JOURNAL_PREFIX}/{ns}"))?.into_iter().map(|k| k.trim_end_matches('/').to_string()).collect::<Vec<_>>()}),
        ),
        [ns, date] if seg_ok(ns) && valid_date(date) => {
            Ok(json!({"keys": host.storage_list(&format!("{JOURNAL_PREFIX}/{ns}/{date}"))?}))
        }
        [ns, date, session] if seg_ok(ns) && valid_date(date) && valid_session(session) => host
            .storage_get(&format!("{JOURNAL_PREFIX}/{ns}/{date}/{session}"))?
            .and_then(|b| parse_record(&b))
            .ok_or_else(|| ApiError::not_found("no such journal record")),
        _ => Err(ApiError::bad_request("expected v2/journal/all[/<namespace>[/<YYYY-MM-DD>[/<session>]]]")),
    }
}

/// Delete dated folders older than the retention, at most `budget` keys per
/// call (run opportunistically, at most once a day per process).
pub fn purge(host: &dyn Host, retention_days: u64, now: u64, budget: usize) -> usize {
    let cutoff = date_of(now.saturating_sub(retention_days * 86_400_000));
    let mut deleted = 0;
    let Ok(namespaces) = host.storage_list(JOURNAL_PREFIX) else { return 0 };
    for ns in namespaces {
        let ns = ns.trim_end_matches('/');
        let Ok(dates) = host.storage_list(&format!("{JOURNAL_PREFIX}/{ns}")) else { continue };
        for date in dates {
            let date = date.trim_end_matches('/');
            if !valid_date(date) || date >= cutoff.as_str() {
                continue;
            }
            let Ok(sessions) = host.storage_list(&format!("{JOURNAL_PREFIX}/{ns}/{date}")) else { continue };
            for s in sessions {
                if deleted >= budget {
                    return deleted;
                }
                if host.storage_delete(&format!("{JOURNAL_PREFIX}/{ns}/{date}/{s}")).is_ok() {
                    deleted += 1;
                }
            }
        }
    }
    deleted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_keys() {
        assert_eq!(date_of(0), "1970-01-01");
        assert_eq!(date_of(951_782_400_000), "2000-02-29");
        assert_eq!(date_of(1_793_000_000_000), "2026-10-26");
        assert_eq!(ns_segment(""), "root");
        assert_eq!(ns_segment("team/a/"), "team~a");
        assert_eq!(key("", "2026-10-26", "s1"), "dbms/journal/root/2026-10-26/s1");
        assert!(valid_date("2026-10-26") && !valid_date("2026-1-26") && !valid_date("../../x"));
    }

    #[test]
    fn records_are_versioned_and_bounded() {
        let owner = Owner {
            entity_id: "e".into(),
            namespace: String::new(),
            principal_mount: "m/".into(),
            principal_name: "n".into(),
        };
        let mut r = Record::new(&owner, "s", "db", "ro", 0, "");
        for i in 0..(MAX_STATEMENTS_PER_RECORD + 3) {
            r.push(json!({"run": "r", "index": i}));
        }
        assert_eq!(r.body["statements_dropped"], 3);
        r.complete("r", 5, json!({"outcome": "ok"}));
        assert_eq!(r.body["statements"][5]["outcome"], "ok");
        let bytes = serde_json::to_vec(&r.body).unwrap();
        assert!(parse_record(&bytes).is_some());
        let mut v2 = r.body.clone();
        v2["v"] = json!(2);
        assert!(parse_record(&serde_json::to_vec(&v2).unwrap()).is_none(), "an unknown version is not read");
    }

    #[test]
    fn text_follows_the_mode() {
        assert_eq!(text_for(&JournalText::Full, "select 'x'", Some("select ?".into())), json!("select 'x'"));
        assert_eq!(text_for(&JournalText::Redacted, "select 'x'", Some("select ?".into())), json!("select ?"));
        assert_eq!(text_for(&JournalText::Redacted, "select 'x'", None), Value::Null);
        assert_eq!(text_for(&JournalText::None, "select 'x'", Some("select ?".into())), Value::Null);
    }

    fn owner(e: &str, ns: &str) -> Owner {
        Owner { entity_id: e.into(), namespace: ns.into(), principal_mount: "m/".into(), principal_name: e.into() }
    }

    fn store(h: &crate::testutil::MockHost, o: &Owner, session: &str, ms: u64) {
        let mut r = Record::new(o, session, "db", "ro", ms, &o.namespace);
        r.flush(h);
    }

    #[test]
    fn self_reads_are_filtered_by_entity_and_namespace() {
        let arc = crate::testutil::MockHost::new(json!({}));
        let h = &*arc;
        let (ana, bob, other_ns) = (owner("ana", ""), owner("bob", ""), owner("ana", "team"));
        let s = |c: char| format!("0123456789abcdef-{}", c.to_string().repeat(64));
        store(h, &ana, &s('a'), 1_793_000_000_000);
        store(h, &bob, &s('b'), 1_793_000_000_000);
        store(h, &other_ns, &s('c'), 1_793_000_000_000);
        assert_eq!(read_self(h, &ana, &[]).unwrap()["keys"], json!(["2026-10-26"]));
        let day = read_self(h, &ana, &["2026-10-26"]).unwrap();
        let sessions: Vec<&str> =
            day["sessions"].as_array().unwrap().iter().map(|v| v["session"].as_str().unwrap()).collect();
        assert_eq!(sessions, vec![s('a').as_str()], "bob's session and another namespace are not listed");
        assert!(read_self(h, &ana, &["2026-10-26", &s('b')]).is_err(), "bob's record is not readable as self");
        assert!(read_self(h, &ana, &["2026-10-26", &s('a')]).is_ok());
        assert!(read_self(h, &ana, &["../../keys"]).is_err());
        assert!(read_self(h, &ana, &["2026-10-26", "../../dbms/keys/digest"]).is_err());
        // Auditors read everyone's (the host's path ACL decides who may).
        assert_eq!(read_all(h, &[]).unwrap()["keys"], json!(["root", "team"]));
        assert!(read_all(h, &["root", "2026-10-26", &s('b')]).is_ok());
        assert!(read_all(h, &["..", "2026-10-26"]).is_err());
    }

    #[test]
    fn purge_removes_only_days_past_retention() {
        let arc = crate::testutil::MockHost::new(json!({}));
        let h = &*arc;
        let o = owner("ana", "");
        let day = 86_400_000u64;
        let now = 1_793_000_000_000u64;
        store(h, &o, "0123456789abcdef-old", now - 100 * day);
        store(h, &o, "0123456789abcdef-new", now - day);
        assert_eq!(purge(h, 90, now, 100), 1);
        let keys: Vec<String> = h.storage.lock().unwrap().keys().cloned().collect();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].ends_with("-new"));
    }
}
