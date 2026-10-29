//! Test doubles: a scripted host with the same contract as the real one,
//! and a fake PostgreSQL server that speaks just enough of the protocol to
//! test what the plugin sends before authentication completes.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::host::{Check, CheckTarget, Credential, Host, HostError, Verdict};

pub const PASSWORD: &str = "pw-Planted-7f3a9c41-never-leak";

type Decide = Box<dyn Fn(&Check) -> bool + Send + Sync>;

pub struct MockHost {
    pub target: Mutex<Result<Value, HostError>>,
    pub decide: Mutex<Decide>,
    /// `(endpoint, username)` released with [`PASSWORD`], or an error.
    pub credential: Mutex<Result<(String, String), HostError>>,
    pub tickets: Mutex<Vec<String>>,
    pub audit: Mutex<Vec<Value>>,
    pub storage: Mutex<BTreeMap<String, Vec<u8>>>,
    pub logs: Mutex<Vec<String>>,
    pub calls: Mutex<Vec<String>>,
    pub authorized: Mutex<Vec<Vec<Check>>>,
    /// Per-profile logins `(endpoint, username, password)`, for live tests.
    pub creds: Mutex<BTreeMap<String, (String, String, String)>>,
}

impl MockHost {
    pub fn new(target: Value) -> Arc<Self> {
        Arc::new(Self {
            target: Mutex::new(Ok(target)),
            decide: Mutex::new(Box::new(|_| true)),
            credential: Mutex::new(Ok(("10.0.0.5:5432".into(), "svc".into()))),
            tickets: Mutex::new(Vec::new()),
            audit: Mutex::new(Vec::new()),
            storage: Mutex::new(BTreeMap::new()),
            logs: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
            authorized: Mutex::new(Vec::new()),
            creds: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn allow(&self, f: impl Fn(&Check) -> bool + Send + Sync + 'static) {
        *self.decide.lock().unwrap() = Box::new(f);
    }

    pub fn set_config(&self, cfg: Value) {
        self.storage.lock().unwrap().insert("dbms/config".into(), serde_json::to_vec(&cfg).unwrap());
    }

    pub fn called(&self, method: &str) -> bool {
        self.calls.lock().unwrap().iter().any(|m| m == method)
    }

    pub fn audit_events(&self) -> Vec<Value> {
        self.audit.lock().unwrap().clone()
    }

    /// Every response, audit event, log line and stored value must be free
    /// of the planted password (§Security regressions).
    pub fn assert_no_leak(&self, response: &[u8]) {
        let mut secrets = vec![PASSWORD.to_string()];
        secrets.extend(self.creds.lock().unwrap().values().map(|c| c.2.clone()));
        let resp = String::from_utf8_lossy(response);
        for pw in &secrets {
            assert!(!resp.contains(pw.as_str()), "password in a response: {resp}");
            for e in self.audit.lock().unwrap().iter() {
                assert!(!e.to_string().contains(pw.as_str()), "password in audit: {e}");
            }
            for l in self.logs.lock().unwrap().iter() {
                assert!(!l.contains(pw.as_str()), "password in a log line: {l}");
            }
            for (k, v) in self.storage.lock().unwrap().iter() {
                assert!(!String::from_utf8_lossy(v).contains(pw.as_str()), "password stored under {k}");
            }
        }
    }
}

impl Host for MockHost {
    fn sql_target(&self, _resource: &str) -> Result<Value, HostError> {
        self.calls.lock().unwrap().push("resource_sql_target".into());
        self.target.lock().unwrap().clone()
    }

    fn sql_authorize(&self, _resource: &str, checks: &[Check]) -> Result<Vec<Verdict>, HostError> {
        self.calls.lock().unwrap().push("resource_sql_authorize".into());
        self.authorized.lock().unwrap().push(checks.to_vec());
        let decide = self.decide.lock().unwrap();
        Ok(checks
            .iter()
            .map(|c| Verdict {
                capability: c.capability.to_string(),
                target: c.target_json(),
                path: match &c.target {
                    CheckTarget::Server => "resources/resources/db/sql/server".into(),
                    CheckTarget::Object { catalog, schema, object } => {
                        format!("resources/resources/db/sql/objects/{catalog}/{schema}/{object}")
                    }
                },
                allowed: decide(c),
                denied_by_deny: false,
            })
            .collect())
    }

    fn sql_credential(&self, _resource: &str, profile: &str, session_ref: &str) -> Result<Credential, HostError> {
        self.calls.lock().unwrap().push("resource_sql_credential".into());
        assert!(crate::ids::instance_of(session_ref).is_some(), "the session ref is the session id");
        if let Some((endpoint, username, password)) = self.creds.lock().unwrap().get(profile).cloned() {
            return Ok(Credential {
                secret_id: format!("{profile}-secret"),
                endpoint,
                username,
                password: Zeroizing::new(password),
            });
        }
        let (endpoint, username) = self.credential.lock().unwrap().clone()?;
        Ok(Credential { secret_id: "s".into(), endpoint, username, password: Zeroizing::new(PASSWORD.into()) })
    }

    fn ticket_redeem(&self, _resource: &str, _profile: &str, ticket: &str) -> Result<bool, HostError> {
        self.calls.lock().unwrap().push("connect_ticket_redeem".into());
        let mut t = self.tickets.lock().unwrap();
        match t.iter().position(|x| x == ticket) {
            Some(i) => {
                t.remove(i);
                Ok(true)
            }
            None => Err(HostError::new("refused", "mfa_required: the ticket is unknown, used or expired")),
        }
    }

    fn audit(&self, payload: Value) -> Result<(), HostError> {
        self.audit.lock().unwrap().push(payload);
        Ok(())
    }

    fn storage_get(&self, key: &str) -> Result<Option<Vec<u8>>, HostError> {
        Ok(self.storage.lock().unwrap().get(key).cloned())
    }

    fn storage_put(&self, key: &str, value: &[u8]) -> Result<(), HostError> {
        self.storage.lock().unwrap().insert(key.into(), value.to_vec());
        Ok(())
    }

    fn storage_delete(&self, key: &str) -> Result<(), HostError> {
        self.storage.lock().unwrap().remove(key);
        Ok(())
    }

    fn storage_list(&self, prefix: &str) -> Result<Vec<String>, HostError> {
        let p = format!("{}/", prefix.trim_end_matches('/'));
        let mut out = std::collections::BTreeSet::new();
        for k in self.storage.lock().unwrap().keys() {
            if let Some(rest) = k.strip_prefix(&p) {
                match rest.split_once('/') {
                    Some((d, _)) => out.insert(format!("{d}/")),
                    None => out.insert(rest.to_string()),
                };
            }
        }
        Ok(out.into_iter().collect())
    }

    fn log(&self, _level: i32, msg: &str) {
        self.logs.lock().unwrap().push(msg.to_string());
    }
}

/// A caller envelope.
pub fn envelope(entity: &str, op: &str, path: &str, data: Value) -> Vec<u8> {
    json!({"op": op, "path": path, "data": data,
        "caller": {"entity_id": entity, "display_name": entity, "principal": {"mount": "userpass/", "name": entity}, "namespace": ""}})
    .to_string()
    .into_bytes()
}

/// The dispatch result as `(status, json)`.
pub fn call(p: &crate::Plugin, h: &MockHost, entity: &str, op: &str, path: &str, data: Value) -> (i32, Value, Vec<u8>) {
    let r = p.dispatch(h, &envelope(entity, op, path, data));
    let v = serde_json::from_slice(&r.bytes).unwrap_or(Value::Null);
    (r.status, v, r.bytes)
}

/// The error code of a failed dispatch (`code: message`).
pub fn code(v: &Value) -> String {
    v["error"].as_str().unwrap_or("").split(':').next().unwrap_or("").to_string()
}

/// A config that may dial loopback (tests only; the default refuses it).
pub fn loopback_config() -> Value {
    let mut c = serde_json::to_value(crate::config::Config::default()).unwrap();
    c["allowed_networks"] = json!(["127.0.0.0/8"]);
    c["denied_networks"] = json!(["169.254.0.0/16"]);
    c
}

/// What the fake server saw after it sent its scripted reply.
pub struct FakeServer {
    pub port: u16,
    pub received: Arc<Mutex<Vec<u8>>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl FakeServer {
    /// Accept one connection; answer an `SSLRequest` with `ssl_reply` when
    /// one comes, then answer the startup packet with `reply`, and record
    /// everything the client sends after it.
    pub fn start(ssl_reply: u8, reply: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let rec = received.clone();
        let handle = std::thread::spawn(move || {
            let Ok((mut s, _)) = listener.accept() else { return };
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut first = read_packet(&mut s);
            // SSLRequest: length 8, code 80877103.
            if first.len() == 8 && first[4..8] == 80_877_103u32.to_be_bytes() {
                s.write_all(&[ssl_reply]).unwrap();
                if ssl_reply != b'N' {
                    return;
                }
                first = read_packet(&mut s);
                if first.is_empty() {
                    return;
                }
                rec.lock().unwrap().extend_from_slice(&first);
                return;
            }
            let _ = s.write_all(&reply);
            let mut buf = [0u8; 4096];
            loop {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => rec.lock().unwrap().extend_from_slice(&buf[..n]),
                }
            }
        });
        Self { port, received, handle: Some(handle) }
    }

    pub fn finish(mut self) -> Vec<u8> {
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        self.received.lock().unwrap().clone()
    }
}

fn read_packet(s: &mut std::net::TcpStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    if s.read_exact(&mut len).is_err() {
        return Vec::new();
    }
    let n = u32::from_be_bytes(len) as usize;
    let mut rest = vec![0u8; n.saturating_sub(4).min(1 << 16)];
    if s.read_exact(&mut rest).is_err() {
        return Vec::new();
    }
    let mut out = len.to_vec();
    out.extend(rest);
    out
}
