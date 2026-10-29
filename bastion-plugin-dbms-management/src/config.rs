//! Plugin limits and network policy (features/sql-browser.md §12), stored at
//! `dbms/config` as a versioned record and edited through `v2/config`.
//!
//! Parsing is strict: an unknown key, a wrong type or a value above its hard
//! maximum refuses the write. A stored record that does not parse is not
//! trusted; the defaults apply and the error is reported on read.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::api::ApiError;
use crate::netpolicy::Cidr;

pub const CONFIG_KEY: &str = "dbms/config";
pub const CONFIG_VERSION: u32 = 1;

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
];

impl Default for Config {
    fn default() -> Self {
        let d = |k: &str| LIMITS.iter().find(|(n, _, _)| *n == k).map(|(_, d, _)| *d).unwrap_or(0);
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
        let c: Config =
            serde_json::from_value(v.clone()).map_err(|e| ApiError::bad_request(format!("invalid config: {e}")))?;
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
        stored["v"] = json!(2);
        assert!(Config::parse(&stored).is_err(), "another record version is not trusted");
    }
}
