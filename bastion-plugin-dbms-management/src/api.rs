//! The request envelope the host sends (`{op, path, data, caller}`) and the
//! replies this plugin returns (`{data}` or `{error}`).

use bastion_plugin_sdk::Response;
use serde_json::{json, Map, Value};

use crate::host::HostError;

/// Largest request body accepted, in bytes: the classifier's input cap.
pub const MAX_INPUT_BYTES: usize = bv_sql_classify::MAX_TEXT_BYTES + 64 * 1024;

/// The attested caller (ABI 1.3 caller block). Built by the host from the
/// token, never from the request body.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Caller {
    pub entity_id: String,
    pub display_name: String,
    pub principal_mount: String,
    pub principal_name: String,
    pub namespace: String,
}

impl Caller {
    fn from_envelope(v: Option<&Value>) -> Option<Self> {
        let v = v?.as_object()?;
        let s = |o: &Map<String, Value>, k: &str| o.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let principal = v.get("principal").and_then(Value::as_object).cloned().unwrap_or_default();
        Some(Self {
            entity_id: s(v, "entity_id"),
            display_name: s(v, "display_name"),
            principal_mount: s(&principal, "mount"),
            principal_name: s(&principal, "name"),
            namespace: s(v, "namespace").trim_matches('/').to_string(),
        })
    }

    /// Who may use a session: the identity entity in its namespace, through
    /// the same login. The host supplies no token binding (see
    /// features/sql-browser.md, Phase 3 deviations).
    pub fn owner(&self) -> Owner {
        Owner {
            entity_id: self.entity_id.clone(),
            namespace: self.namespace.clone(),
            principal_mount: self.principal_mount.clone(),
            principal_name: self.principal_name.clone(),
        }
    }
}

/// The binding a session carries and every request re-checks (§6.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Owner {
    pub entity_id: String,
    pub namespace: String,
    pub principal_mount: String,
    pub principal_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Read,
    Write,
    Delete,
    List,
}

/// One decoded invocation.
#[derive(Debug, Clone)]
pub struct Request {
    pub op: Op,
    /// Mount-relative path, without leading or trailing `/`.
    pub path: String,
    pub data: Map<String, Value>,
    pub caller: Option<Caller>,
}

impl Request {
    pub fn parse(input: &[u8]) -> Result<Self, ApiError> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(ApiError::bad_request("request too large"));
        }
        let v: Value = serde_json::from_slice(input).map_err(|_| ApiError::bad_request("envelope is not JSON"))?;
        let op = match v.get("op").and_then(Value::as_str) {
            Some("read") => Op::Read,
            Some("write") => Op::Write,
            Some("delete") => Op::Delete,
            Some("list") => Op::List,
            _ => return Err(ApiError::unsupported("operation not supported")),
        };
        let path = v.get("path").and_then(Value::as_str).unwrap_or("").trim_matches('/').to_string();
        let data = match v.get("data") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(m)) => m.clone(),
            Some(_) => return Err(ApiError::bad_request("`data` must be an object")),
        };
        Ok(Self { op, path, data, caller: Caller::from_envelope(v.get("caller")) })
    }

    /// The caller, which every route except none requires. A caller without
    /// an identity entity cannot own a session (§6.1: bound to `entity_id`).
    pub fn caller(&self) -> Result<&Caller, ApiError> {
        match &self.caller {
            Some(c) if !c.entity_id.is_empty() => Ok(c),
            _ => Err(ApiError::forbidden("the SQL browser needs an identity-backed login (no entity on this token)")),
        }
    }

    pub fn str_field(&self, key: &str) -> Option<&str> {
        self.data.get(key).and_then(Value::as_str)
    }
}

/// A refusal or failure returned to the caller. `code` is stable and
/// machine-readable; `message` is for the operator and never carries a
/// credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub status: i32,
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub fn new(status: i32, code: &str, message: impl Into<String>) -> Self {
        Self { status, code: code.to_string(), message: message.into() }
    }
    pub fn bad_request(m: impl Into<String>) -> Self {
        Self::new(1, "bad_request", m)
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(2, "not_found", m)
    }
    pub fn forbidden(m: impl Into<String>) -> Self {
        Self::new(3, "forbidden", m)
    }
    pub fn refused(code: &str, m: impl Into<String>) -> Self {
        Self::new(4, code, m)
    }
    pub fn unavailable(m: impl Into<String>) -> Self {
        Self::new(5, "not_available", m)
    }
    pub fn unsupported(m: impl Into<String>) -> Self {
        Self::new(6, "unsupported", m)
    }
    pub fn internal(m: impl Into<String>) -> Self {
        Self::new(7, "internal", m)
    }

    pub fn into_response(self) -> Response {
        let body = json!({"error": format!("{}: {}", self.code, self.message)});
        Response::err(self.status, serde_json::to_vec(&body).unwrap_or_default())
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl From<HostError> for ApiError {
    fn from(e: HostError) -> Self {
        // The host's codes pass through; its detail never holds a value.
        ApiError::refused(&e.code, e.detail)
    }
}

pub fn ok(data: Value) -> Response {
    Response::ok(serde_json::to_vec(&json!({ "data": data })).unwrap_or_default())
}

/// Decode one `%XX`-encoded path segment (object names in browse paths).
/// Refuses malformed escapes and anything that does not decode to UTF-8.
pub fn decode_segment(s: &str) -> Result<String, ApiError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).ok_or_else(|| ApiError::bad_request("bad percent escape"))?;
            let hex = std::str::from_utf8(hex).map_err(|_| ApiError::bad_request("bad percent escape"))?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| ApiError::bad_request("bad percent escape"))?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| ApiError::bad_request("path segment is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_caller_comes_from_the_envelope_and_needs_an_entity() {
        let env = json!({"op": "read", "path": "/v2/sessions/", "data": {"caller": {"entity_id": "forged"}},
            "caller": {"entity_id": "e1", "display_name": "Ana", "principal": {"mount": "userpass/", "name": "ana"}, "namespace": "ns1/"}});
        let r = Request::parse(env.to_string().as_bytes()).unwrap();
        assert_eq!(r.path, "v2/sessions");
        let c = r.caller().unwrap();
        assert_eq!(c.entity_id, "e1");
        assert_eq!(c.namespace, "ns1");
        assert_eq!(c.principal_mount, "userpass/");
        let anon = json!({"op": "read", "path": "v2/sessions", "caller": {"entity_id": ""}});
        assert_eq!(Request::parse(anon.to_string().as_bytes()).unwrap().caller().unwrap_err().code, "forbidden");
        let none = json!({"op": "read", "path": "v2/sessions"});
        assert!(Request::parse(none.to_string().as_bytes()).unwrap().caller().is_err());
    }

    #[test]
    fn malformed_envelopes_are_refused() {
        assert!(Request::parse(b"not json").is_err());
        assert!(Request::parse(br#"{"op":"renew","path":"x"}"#).is_err());
        assert!(Request::parse(br#"{"op":"read","path":"x","data":[1]}"#).is_err());
        let big = vec![b' '; MAX_INPUT_BYTES + 1];
        assert!(Request::parse(&big).is_err());
    }

    #[test]
    fn segments_decode_strictly() {
        assert_eq!(decode_segment("my%20table").unwrap(), "my table");
        assert_eq!(decode_segment("a%2Fb").unwrap(), "a/b");
        assert!(decode_segment("bad%2").is_err());
        assert!(decode_segment("bad%zz").is_err());
        assert!(decode_segment("%ff").is_err());
    }
}
