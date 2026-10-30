//! Plugin limits and network policy (features/sql-browser.md §12), stored at
//! `dbms/config` as a versioned record and edited through `v2/config`.
//!
//! Parsing is strict: an unknown key, a wrong type or a value above its hard
//! maximum refuses the write. A stored record that does not parse is not
//! trusted; the defaults apply and the error is reported on read.
//!
//! Versions: `v: 1` (T125) had no script or export limits. It is still read
//! (read-old): the new limits take their defaults and the record becomes
//! `v: 2` in memory, which is what the next write stores (write-new).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::api::ApiError;
use crate::netpolicy::Cidr;

pub const CONFIG_KEY: &str = "dbms/config";
pub const CONFIG_VERSION: u32 = 2;
/// The T125 record, read and migrated (no script or export limits).
pub const CONFIG_VERSION_V1: u32 = 1;

/// The host's bounded line reader caps one stdio line at 4 MiB, and a reply
/// travels base64-encoded inside it, so a page's JSON must stay under 3 MiB.
/// The page cap is derived from that (Phase 0 item 8), not chosen freely.
pub const PAGE_BYTES_HARD_MAX: u64 = 2_750_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalText {
    Redacted,
    Full,
    None,
}

/// Every tunable, with its default (§12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub v: u32,
    pub run_timeout_secs: u64,
    pub page_rows: u64,
    pub page_bytes: u64,
    pub grid_rows: u64,
    /// Cumulative rows read through the grid per session; `None` = off.
    pub row_budget: Option<u64>,
    pub idle_secs: u64,
    pub idle_tx_secs: u64,
    pub lifetime_secs: u64,
    pub sessions_per_user: u64,
    pub sessions_per_resource: u64,
    pub sessions_per_node: u64,
    pub run_retention_secs: u64,
    pub connect_timeout_secs: u64,
    pub journal_text: JournalText,
    pub journal_retention_days: u64,
    /// Most statements in one script (§8.2, §12). v2.
    #[serde(default = "d_script_statements")]
    pub script_statements: u64,
    /// Largest script text in bytes. The hard maximum is the classifier's
    /// input cap (4 MiB), below §12's 32 MiB. v2.
    #[serde(default = "d_script_bytes")]
    pub script_bytes: u64,
    /// Most rows one export writes (§8.1). v2.
    #[serde(default = "d_export_rows")]
    pub export_rows: u64,
    /// Most bytes one export writes. v2.
    #[serde(default = "d_export_bytes")]
    pub export_bytes: u64,
    /// An export nobody pulled from for this long is cancelled. v2.
    #[serde(default = "d_export_idle_secs")]
    pub export_idle_secs: u64,
    /// The database statement timeout while an export streams. v2.
    #[serde(default = "d_export_timeout_secs")]
    pub export_timeout_secs: u64,
    /// CIDRs the plugin may dial (checked after DNS, §12).
    pub allowed_networks: Vec<String>,
    /// CIDRs never dialled, whatever `allowed_networks` says: loopback,
    /// link-local (cloud metadata), unspecified, multicast, and the vault's
    /// own listeners, which an administrator adds here.
    pub denied_networks: Vec<String>,
}

/// `(field, default, hard max)` for the numeric limits.
const LIMITS: &[(&str, u64, u64)] = &[
    ("run_timeout_secs", 60, 3_600),
    ("page_rows", 500, 5_000),
    ("page_bytes", 2_000_000, PAGE_BYTES_HARD_MAX),
    ("grid_rows", 10_000, 100_000),
    ("idle_secs", 900, 8 * 3_600),
    ("idle_tx_secs", 300, 3_600),
    ("lifetime_secs", 8 * 3_600, 24 * 3_600),
    ("sessions_per_user", 5, 50),
    ("sessions_per_resource", 20, 500),
    ("sessions_per_node", 200, 2_000),
    ("run_retention_secs", 600, 3_600),
    ("connect_timeout_secs", 10, 60),
    ("journal_retention_days", 90, 3_650),
    ("script_statements", 1_000, bv_sql_classify::MAX_STATEMENTS as u64),
    ("script_bytes", bv_sql_classify::MAX_TEXT_BYTES as u64, bv_sql_classify::MAX_TEXT_BYTES as u64),
    ("export_rows", 1_000_000, 10_000_000),
    ("export_bytes", 512 * 1024 * 1024, 4 * 1024 * 1024 * 1024),
    ("export_idle_secs", 300, 3_600),
    ("export_timeout_secs", 1_800, 3_600),
];

fn limit_default(k: &str) -> u64 {
    LIMITS.iter().find(|(n, _, _)| *n == k).map(|(_, d, _)| *d).unwrap_or(0)
}
fn d_script_statements() -> u64 {
    limit_default("script_statements")
}
fn d_script_bytes() -> u64 {
    limit_default("script_bytes")
}
fn d_export_rows() -> u64 {
    limit_default("export_rows")
}
fn d_export_bytes() -> u64 {
    limit_default("export_bytes")
}
fn d_export_idle_secs() -> u64 {
    limit_default("export_idle_secs")
}
fn d_export_timeout_secs() -> u64 {
    limit_default("export_timeout_secs")
}

impl Default for Config {
    fn default() -> Self {
        let d = limit_default;
        Self {
            v: CONFIG_VERSION,
            run_timeout_secs: d("run_timeout_secs"),
            page_rows: d("page_rows"),
            page_bytes: d("page_bytes"),
            grid_rows: d("grid_rows"),
            row_budget: None,
            idle_secs: d("idle_secs"),
            idle_tx_secs: d("idle_tx_secs"),
            lifetime_secs: d("lifetime_secs"),
            sessions_per_user: d("sessions_per_user"),
            sessions_per_resource: d("sessions_per_resource"),
            sessions_per_node: d("sessions_per_node"),
            run_retention_secs: d("run_retention_secs"),
            connect_timeout_secs: d("connect_timeout_secs"),
            journal_text: JournalText::Redacted,
            journal_retention_days: d("journal_retention_days"),
            script_statements: d("script_statements"),
            script_bytes: d("script_bytes"),
            export_rows: d("export_rows"),
            export_bytes: d("export_bytes"),
            export_idle_secs: d("export_idle_secs"),
            export_timeout_secs: d("export_timeout_secs"),
            allowed_networks: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"].map(String::from).to_vec(),
            denied_networks: [
                "127.0.0.0/8",
                "::1/128",
                "169.254.0.0/16",
                "fe80::/10",
                "0.0.0.0/8",
                "::/128",
                "224.0.0.0/4",
                "ff00::/8",
                "255.255.255.255/32",
            ]
            .map(String::from)
            .to_vec(),
        }
    }
}

impl Config {
    /// Parse a stored or submitted record strictly and check every bound.
    pub fn parse(v: &Value) -> Result<Self, ApiError> {
        let mut c: Config =
            serde_json::from_value(v.clone()).map_err(|e| ApiError::bad_request(format!("invalid config: {e}")))?;
        // Read-old: a v1 record has no script or export limits; serde gave
        // them their defaults, and it is a v2 record from here on.
        if c.v == CONFIG_VERSION_V1 {
            c.v = CONFIG_VERSION;
        }
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&self) -> Result<(), ApiError> {
        if self.v != CONFIG_VERSION {
            return Err(ApiError::bad_request(format!("config `v` must be {CONFIG_VERSION}")));
        }
        let obj = serde_json::to_value(self).map_err(|_| ApiError::internal("config serialise"))?;
        for (name, _, max) in LIMITS {
            let n = obj.get(*name).and_then(Value::as_u64).unwrap_or(0);
            if n == 0 || n > *max {
                return Err(ApiError::bad_request(format!("`{name}` must be between 1 and {max}")));
            }
        }
        if self.row_budget == Some(0) {
            return Err(ApiError::bad_request("`row_budget` must be positive, or null for off"));
        }
        if self.page_rows > self.grid_rows {
            return Err(ApiError::bad_request("`page_rows` cannot exceed `grid_rows`"));
        }
        for list in [&self.allowed_networks, &self.denied_networks] {
            if list.len() > 256 {
                return Err(ApiError::bad_request("at most 256 networks per list"));
            }
            for s in list {
                Cidr::parse(s).map_err(|e| ApiError::bad_request(format!("network `{s}`: {e}")))?;
            }
        }
        Ok(())
    }

    /// Apply a partial update (`v2/config` write): only known keys, then the
    /// full record is validated again.
    pub fn merged(&self, patch: &serde_json::Map<String, Value>) -> Result<Self, ApiError> {
        let mut obj = serde_json::to_value(self).map_err(|_| ApiError::internal("config serialise"))?;
        let target = obj.as_object_mut().ok_or_else(|| ApiError::internal("config shape"))?;
        for (k, v) in patch {
            if k == "v" {
                continue;
            }
            if !target.contains_key(k) {
                return Err(ApiError::bad_request(format!("unknown config key `{k}`")));
            }
            target.insert(k.clone(), v.clone());
        }
        Self::parse(&obj)
    }

    pub fn allowed(&self) -> Vec<Cidr> {
        self.allowed_networks.iter().filter_map(|s| Cidr::parse(s).ok()).collect()
    }

    pub fn denied(&self) -> Vec<Cidr> {
        self.denied_networks.iter().filter_map(|s| Cidr::parse(s).ok()).collect()
    }

    pub fn view(&self) -> Value {
        let mut v = serde_json::to_value(self).unwrap_or_else(|_| json!({}));
        v["hard_max"] = Value::Object(LIMITS.iter().map(|(n, _, m)| (n.to_string(), json!(m))).collect());
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_round_trip() {
        let c = Config::default();
        c.validate().unwrap();
        assert_eq!(Config::parse(&serde_json::to_value(&c).unwrap()).unwrap(), c);
        assert!(c.page_bytes <= PAGE_BYTES_HARD_MAX);
    }

    #[test]
    fn writes_are_strict_and_bounded() {
        let c = Config::default();
        let patch = |v: Value| c.merged(v.as_object().unwrap());
        assert_eq!(patch(json!({"page_rows": 100})).unwrap().page_rows, 100);
        assert!(patch(json!({"page_rows": 5_001})).is_err(), "above the hard maximum");
        assert!(patch(json!({"page_rows": 0})).is_err());
        assert!(patch(json!({"run_timeout_secs": "60"})).is_err(), "wrong type");
        assert!(patch(json!({"unknown": 1})).is_err());
        assert!(patch(json!({"allowed_networks": ["10.0.0.0/33"]})).is_err());
        assert!(patch(json!({"journal_text": "verbatim"})).is_err());
        assert!(patch(json!({"page_bytes": PAGE_BYTES_HARD_MAX + 1})).is_err());
        let mut stored = serde_json::to_value(&c).unwrap();
        stored["v"] = json!(3);
        assert!(Config::parse(&stored).is_err(), "another record version is not trusted");
        assert!(patch(json!({"script_statements": 10_001})).is_err());
        assert!(patch(json!({"script_bytes": bv_sql_classify::MAX_TEXT_BYTES + 1})).is_err());
        assert!(patch(json!({"export_bytes": 4u64 * 1024 * 1024 * 1024 + 1})).is_err());
        assert_eq!(patch(json!({"export_rows": 10})).unwrap().export_rows, 10);
    }

    /// Read-old/write-new: the record T125 wrote (v1, without the script
    /// and export limits) keeps every value it set, gains the defaults, and
    /// is written back as v2.
    #[test]
    fn a_v1_record_is_read_and_written_as_v2() {
        let v1 = json!({
            "v": 1, "run_timeout_secs": 120, "page_rows": 100, "page_bytes": 2_000_000, "grid_rows": 10_000,
            "row_budget": 50_000, "idle_secs": 900, "idle_tx_secs": 300, "lifetime_secs": 28_800,
            "sessions_per_user": 5, "sessions_per_resource": 20, "sessions_per_node": 200,
            "run_retention_secs": 600, "connect_timeout_secs": 10, "journal_text": "full",
            "journal_retention_days": 30, "allowed_networks": ["10.0.0.0/8"], "denied_networks": ["127.0.0.0/8"]
        });
        let c = Config::parse(&v1).unwrap();
        assert_eq!(c.v, CONFIG_VERSION);
        assert_eq!((c.run_timeout_secs, c.page_rows, c.row_budget), (120, 100, Some(50_000)));
        assert_eq!(c.journal_text, JournalText::Full);
        assert_eq!((c.script_statements, c.export_rows, c.export_idle_secs), (1_000, 1_000_000, 300));
        assert_eq!(c.export_bytes, 512 * 1024 * 1024);
        let written = serde_json::to_value(&c).unwrap();
        assert_eq!(written["v"], 2);
        assert_eq!(written["script_bytes"], json!(bv_sql_classify::MAX_TEXT_BYTES));
        assert_eq!(Config::parse(&written).unwrap(), c);
        // A v1 record that names a key no version knows is still refused.
        let mut bad = v1.clone();
        bad["export_everything"] = json!(true);
        assert!(Config::parse(&bad).is_err());
    }
}
