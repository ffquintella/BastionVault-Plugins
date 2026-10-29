//! The host calls this plugin makes, behind a trait so the session logic is
//! testable against the testkit's mock host and against scripted hosts.
//!
//! Every SQL call is caller-bound (ABI 1.4): the host decides it against the
//! token of the invocation in flight, so a call is only valid inside one.

use bastion_plugin_sdk::process::{HostCallError, Invocation, SqlCheck};
use serde_json::{json, Value};
use zeroize::Zeroizing;

/// A host call failed: the host's code (`no_sql_privilege`, `refused`, …)
/// and its detail. Never carries a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostError {
    pub code: String,
    pub detail: String,
}

impl HostError {
    pub fn new(code: &str, detail: impl Into<String>) -> Self {
        Self { code: code.to_string(), detail: detail.into() }
    }
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.detail.is_empty() {
            f.write_str(&self.code)
        } else {
            write!(f, "{}: {}", self.code, self.detail)
        }
    }
}

impl From<HostCallError> for HostError {
    fn from(e: HostCallError) -> Self {
        Self { code: e.code, detail: e.detail }
    }
}

/// One privilege the host decides: a capability on `sql/server` or on one
/// object. An object with an empty or unaddressable segment is checked by
/// the host on the objects root, where only resource-wide grants apply.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Check {
    pub capability: &'static str,
    pub target: CheckTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CheckTarget {
    Server,
    Object { catalog: String, schema: String, object: String },
}

impl Check {
    pub fn server(capability: &'static str) -> Self {
        Self { capability, target: CheckTarget::Server }
    }

    pub fn object(capability: &'static str, catalog: &str, schema: &str, object: &str) -> Self {
        Self {
            capability,
            target: CheckTarget::Object { catalog: catalog.into(), schema: schema.into(), object: object.into() },
        }
    }

    fn to_sdk(&self) -> SqlCheck {
        match &self.target {
            CheckTarget::Server => SqlCheck::server(self.capability),
            CheckTarget::Object { catalog, schema, object } => {
                SqlCheck::object(self.capability, catalog, schema, object)
            }
        }
    }

    /// `server` or `catalog.schema.object`, for messages and audit.
    pub fn target_label(&self) -> String {
        match &self.target {
            CheckTarget::Server => "server".into(),
            CheckTarget::Object { catalog, schema, object } => format!("{catalog}.{schema}.{object}"),
        }
    }

    pub fn target_json(&self) -> Value {
        match &self.target {
            CheckTarget::Server => json!("server"),
            CheckTarget::Object { catalog, schema, object } => {
                json!({"catalog": catalog, "schema": schema, "object": object})
            }
        }
    }
}

/// The host's decision for one [`Check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub capability: String,
    pub target: Value,
    pub path: String,
    pub allowed: bool,
    pub denied_by_deny: bool,
}

/// A database login the host released. The password is zeroized on drop,
/// redacted from `Debug`, and lives only until the connection is open.
pub struct Credential {
    pub secret_id: String,
    pub endpoint: String,
    pub username: String,
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("secret_id", &self.secret_id)
            .field("endpoint", &self.endpoint)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// The host calls the plugin uses. Implementations must answer for the
/// invocation in flight only.
pub trait Host {
    /// `resource_sql_target`: engine, endpoint fields, enforcement and the
    /// strictly parsed `sql` profiles, plus the caller's capabilities on
    /// `sql/server`. Refused when the caller holds none.
    fn sql_target(&self, resource: &str) -> Result<Value, HostError>;
    /// `resource_sql_authorize`: one verdict per check; refusals reach the
    /// host's denial store.
    fn sql_authorize(&self, resource: &str, checks: &[Check]) -> Result<Vec<Verdict>, HostError>;
    /// `resource_sql_credential`: the profile's login, released under the
    /// endpoint binding and audited by the host.
    fn sql_credential(&self, resource: &str, profile: &str, session_ref: &str) -> Result<Credential, HostError>;
    /// `connect_ticket_redeem`: `Ok(true)` when a ticket was burnt.
    fn ticket_redeem(&self, resource: &str, profile: &str, ticket: &str) -> Result<bool, HostError>;
    /// `audit_emit`: the host stamps the invocation's caller as the actor.
    fn audit(&self, payload: Value) -> Result<(), HostError>;
    /// `storage_get`: `Ok(None)` when the key is absent.
    fn storage_get(&self, key: &str) -> Result<Option<Vec<u8>>, HostError>;
    fn storage_put(&self, key: &str, value: &[u8]) -> Result<(), HostError>;
    fn storage_delete(&self, key: &str) -> Result<(), HostError>;
    fn storage_list(&self, prefix: &str) -> Result<Vec<String>, HostError>;
    /// Operational log line (1 = trace … 5 = error). Never statement text,
    /// values or credentials.
    fn log(&self, level: i32, msg: &str);
}

/// The production host: the SDK's typed wrappers over the invocation.
pub struct ProcessHostAdapter<'a> {
    pub inv: &'a Invocation,
}

impl Host for ProcessHostAdapter<'_> {
    fn sql_target(&self, resource: &str) -> Result<Value, HostError> {
        Ok(self.inv.host().resource_sql_target(resource)?)
    }

    fn sql_authorize(&self, resource: &str, checks: &[Check]) -> Result<Vec<Verdict>, HostError> {
        let sdk: Vec<SqlCheck> = checks.iter().map(Check::to_sdk).collect();
        let verdicts = self.inv.host().resource_sql_authorize(resource, &sdk)?;
        Ok(verdicts
            .into_iter()
            .map(|v| Verdict {
                capability: v.capability,
                target: v.target,
                path: v.path,
                allowed: v.allowed,
                denied_by_deny: v.denied_by_deny,
            })
            .collect())
    }

    fn sql_credential(&self, resource: &str, profile: &str, session_ref: &str) -> Result<Credential, HostError> {
        let c = self.inv.host().resource_sql_credential(resource, profile, session_ref)?;
        let bastion_plugin_sdk::process::SqlCredential { secret_id, endpoint, username, password, .. } = c;
        Ok(Credential { secret_id, endpoint, username, password })
    }

    fn ticket_redeem(&self, resource: &str, profile: &str, ticket: &str) -> Result<bool, HostError> {
        Ok(self.inv.host().connect_ticket_redeem(resource, profile, ticket)?)
    }

    fn audit(&self, payload: Value) -> Result<(), HostError> {
        Ok(self.inv.host().audit_emit(payload)?)
    }

    fn storage_get(&self, key: &str) -> Result<Option<Vec<u8>>, HostError> {
        match self.inv.host().storage_get(key) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.code == "not_found" => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn storage_put(&self, key: &str, value: &[u8]) -> Result<(), HostError> {
        Ok(self.inv.host().storage_put(key, value)?)
    }

    fn storage_delete(&self, key: &str) -> Result<(), HostError> {
        Ok(self.inv.host().storage_delete(key)?)
    }

    fn storage_list(&self, prefix: &str) -> Result<Vec<String>, HostError> {
        Ok(self.inv.host().storage_list(prefix)?)
    }

    fn log(&self, level: i32, msg: &str) {
        self.inv.host().log(level, msg);
    }
}

/// Check that a reply carries exactly one verdict per check, for the same
/// capability, in order. Anything else is a malformed reply and refuses the
/// whole batch (fail closed): a verdict is never matched to a check by
/// guessing.
pub fn verdicts_match(checks: &[Check], verdicts: &[Verdict]) -> bool {
    checks.len() == verdicts.len()
        && checks.iter().zip(verdicts).all(|(c, v)| c.capability == v.capability && c.target_json() == v.target)
}
