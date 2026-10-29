//! A watcher on the decrypted PostgreSQL backend stream. It reads message
//! framing only, never row data, and enforces what the driver has no hook for:
//! weak authentication without TLS is refused before the password is sent
//! (§5.4); lexer-affecting `ParameterStatus` changes taint the session (Phase
//! 2 obligations); and the transaction state comes from `ReadyForQuery`.

use std::collections::BTreeMap;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Largest `ParameterStatus` body accepted; real ones are a few dozen bytes.
const MAX_PARAM_BODY: usize = 8 * 1024;

const AUTH_CLEARTEXT: i32 = 3;
const AUTH_MD5: i32 = 5;

/// Settings whose change after establishment taints the session.
/// `default_transaction_read_only` joins them on read-only sessions.
const WATCHED: [&str; 4] = ["standard_conforming_strings", "client_encoding", "session_authorization", "is_superuser"];

/// The transaction state the server last reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxStatus {
    Unknown,
    Idle,
    InTransaction,
    Failed,
}

#[derive(Debug)]
enum Phase {
    /// Collecting the 5-byte header (type, length).
    Header { buf: [u8; 5], have: usize },
    /// Inside a body: `left` bytes to go, captured into `body` when `keep`.
    Body { kind: u8, left: usize, keep: bool, body: Vec<u8> },
}

#[derive(Debug)]
struct State {
    encrypted: bool,
    phase: Phase,
    tx: TxStatus,
    params: BTreeMap<String, String>,
    /// Snapshot of the watched settings, set once the session is ready.
    baseline: Option<BTreeMap<String, Option<String>>>,
    taint: Option<String>,
    failed: Option<String>,
}

/// Shared between the stream wrapper (in the driver's connection task) and
/// the session.
#[derive(Debug)]
pub struct Wire(Mutex<State>);

impl Wire {
    /// `encrypted`: whether the observed bytes travel inside TLS.
    pub fn new(encrypted: bool) -> Arc<Self> {
        Arc::new(Self(Mutex::new(State {
            encrypted,
            phase: Phase::Header { buf: [0; 5], have: 0 },
            tx: TxStatus::Unknown,
            params: BTreeMap::new(),
            baseline: None,
            taint: None,
            failed: None,
        })))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Feed newly read backend bytes. `Err` withholds them from the driver.
    pub fn observe(&self, mut bytes: &[u8]) -> io::Result<()> {
        let mut st = self.lock();
        if let Some(f) = &st.failed {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, f.clone()));
        }
        while !bytes.is_empty() {
            match &mut st.phase {
                Phase::Header { buf, have } => {
                    let take = (5 - *have).min(bytes.len());
                    buf[*have..*have + take].copy_from_slice(&bytes[..take]);
                    *have += take;
                    bytes = &bytes[take..];
                    if *have == 5 {
                        let kind = buf[0];
                        let len = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
                        if len < 4 {
                            return st.fail("malformed backend message length");
                        }
                        let left = len as usize - 4;
                        let keep = matches!(kind, b'R' | b'S' | b'Z');
                        if kind == b'S' && left > MAX_PARAM_BODY {
                            st.taint.get_or_insert_with(|| "oversized ParameterStatus".into());
                        }
                        st.phase = Phase::Body { kind, left, keep, body: Vec::new() };
                        if left == 0 {
                            st.finish();
                        }
                    }
                }
                Phase::Body { kind, left, keep, body } => {
                    let take = (*left).min(bytes.len());
                    let cap = if *kind == b'R' { 4 } else { MAX_PARAM_BODY };
                    if *keep && body.len() < cap {
                        let room = (cap - body.len()).min(take);
                        body.extend_from_slice(&bytes[..room]);
                    }
                    *left -= take;
                    bytes = &bytes[take..];
                    // The authentication code is judged as soon as it is
                    // complete, before the rest of the message is passed on.
                    let auth_code = (*kind == b'R' && body.len() == 4)
                        .then(|| i32::from_be_bytes([body[0], body[1], body[2], body[3]]));
                    if let Some(code) = auth_code {
                        if !st.encrypted && (code == AUTH_CLEARTEXT || code == AUTH_MD5) {
                            let method = if code == AUTH_CLEARTEXT { "cleartext password" } else { "MD5" };
                            return st.fail(&format!(
                                "the server asked for {method} authentication on a connection without TLS; \
                                 refused before the password was sent (set the profile's TLS mode to require or stronger)"
                            ));
                        }
                    }
                    if matches!(st.phase, Phase::Body { left: 0, .. }) {
                        st.finish();
                    }
                }
            }
        }
        Ok(())
    }

    /// Record the watched settings as they are now. Later changes taint.
    pub fn establish(&self, read_only: bool) {
        let mut st = self.lock();
        let mut keys: Vec<&str> = WATCHED.to_vec();
        if read_only {
            keys.push("default_transaction_read_only");
        }
        st.baseline = Some(keys.into_iter().map(|k| (k.to_string(), st.params.get(k).cloned())).collect());
    }

    pub fn param(&self, name: &str) -> Option<String> {
        self.lock().params.get(name).cloned()
    }

    pub fn tx(&self) -> TxStatus {
        self.lock().tx
    }

    /// Why the session must stop classifying, if it must.
    pub fn taint(&self) -> Option<String> {
        let st = self.lock();
        st.taint.clone().or_else(|| st.failed.clone())
    }
}

impl State {
    fn fail(&mut self, why: &str) -> io::Result<()> {
        self.failed = Some(why.to_string());
        Err(io::Error::new(io::ErrorKind::PermissionDenied, why.to_string()))
    }

    fn finish(&mut self) {
        let done = std::mem::replace(&mut self.phase, Phase::Header { buf: [0; 5], have: 0 });
        let Phase::Body { kind, body, .. } = done else { return };
        match kind {
            b'Z' => {
                self.tx = match body.first() {
                    Some(b'I') => TxStatus::Idle,
                    Some(b'T') => TxStatus::InTransaction,
                    Some(b'E') => TxStatus::Failed,
                    _ => TxStatus::Unknown,
                };
            }
            b'S' => {
                let mut parts = body.split(|b| *b == 0);
                let (Some(name), Some(value)) = (parts.next(), parts.next()) else {
                    self.taint.get_or_insert_with(|| "malformed ParameterStatus".into());
                    return;
                };
                let name = String::from_utf8_lossy(name).to_string();
                let value = String::from_utf8_lossy(value).to_string();
                let changed = self
                    .baseline
                    .as_ref()
                    .and_then(|b| b.get(&name))
                    .is_some_and(|was| was.as_deref() != Some(value.as_str()));
                if changed {
                    self.taint.get_or_insert_with(|| {
                        format!("the server reported a change of `{name}`, which the classifier did not see")
                    });
                }
                self.params.insert(name, value);
            }
            _ => {}
        }
    }
}

/// A plaintext stream watched by a [`Wire`].
pub struct Watched<S> {
    inner: S,
    wire: Arc<Wire>,
}

impl<S> Watched<S> {
    pub fn new(inner: S, wire: Arc<Wire>) -> Self {
        Self { inner, wire }
    }
}

/// Read into `buf` through `inner`, then let `wire` judge the new bytes.
pub fn poll_read_watched<R: AsyncRead + Unpin>(
    inner: &mut R,
    wire: &Wire,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
) -> Poll<io::Result<()>> {
    let before = buf.filled().len();
    ready!(Pin::new(inner).poll_read(cx, buf))?;
    if let Err(e) = wire.observe(&buf.filled()[before..]) {
        buf.set_filled(before);
        return Poll::Ready(Err(e));
    }
    Poll::Ready(Ok(()))
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_read_watched(&mut this.inner, &this.wire, cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn msg(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut m = vec![kind];
        m.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
        m.extend_from_slice(body);
        m
    }

    pub fn auth(code: i32) -> Vec<u8> {
        msg(b'R', &code.to_be_bytes())
    }

    pub fn param(name: &str, value: &str) -> Vec<u8> {
        let mut b = name.as_bytes().to_vec();
        b.push(0);
        b.extend_from_slice(value.as_bytes());
        b.push(0);
        msg(b'S', &b)
    }

    fn feed_bytewise(w: &Wire, bytes: &[u8]) -> io::Result<()> {
        bytes.iter().try_for_each(|b| w.observe(std::slice::from_ref(b)))
    }

    #[test]
    fn cleartext_and_md5_are_refused_without_tls_even_split_bytewise() {
        for code in [AUTH_CLEARTEXT, AUTH_MD5] {
            let w = Wire::new(false);
            assert!(w.observe(&auth(code)).is_err(), "{code}");
            assert!(w.observe(b"x").is_err(), "a failed wire stays failed");
            let w = Wire::new(false);
            assert!(feed_bytewise(&w, &auth(code)).is_err());
        }
        // SCRAM (10) is fine in plaintext; anything is fine inside TLS.
        assert!(Wire::new(false).observe(&auth(10)).is_ok());
        assert!(Wire::new(true).observe(&auth(AUTH_CLEARTEXT)).is_ok());
    }

    #[test]
    fn the_refusal_comes_before_the_message_is_complete() {
        // The last byte of the code trips the guard, so the driver never
        // holds a complete cleartext request.
        let w = Wire::new(false);
        let m = auth(AUTH_CLEARTEXT);
        assert!(w.observe(&m[..m.len() - 1]).is_ok());
        assert!(w.observe(&m[m.len() - 1..]).is_err());
    }

    #[test]
    fn parameter_changes_after_establishment_taint() {
        let w = Wire::new(true);
        let mut start = param("standard_conforming_strings", "on");
        start.extend(param("client_encoding", "UTF8"));
        start.extend(param("session_authorization", "svc"));
        start.extend(msg(b'Z', b"I"));
        w.observe(&start).unwrap();
        assert_eq!(w.tx(), TxStatus::Idle);
        w.establish(false);
        w.observe(&param("TimeZone", "UTC")).unwrap();
        w.observe(&param("client_encoding", "UTF8")).unwrap();
        assert!(w.taint().is_none(), "unwatched or unchanged settings do not taint");
        feed_bytewise(&w, &param("standard_conforming_strings", "off")).unwrap();
        assert!(w.taint().unwrap().contains("standard_conforming_strings"));
    }

    #[test]
    fn read_only_sessions_also_watch_the_read_only_default() {
        let w = Wire::new(true);
        w.observe(&param("default_transaction_read_only", "on")).unwrap();
        w.establish(true);
        w.observe(&param("default_transaction_read_only", "off")).unwrap();
        assert!(w.taint().is_some());
        let w = Wire::new(true);
        w.observe(&param("default_transaction_read_only", "on")).unwrap();
        w.establish(false);
        w.observe(&param("default_transaction_read_only", "off")).unwrap();
        assert!(w.taint().is_none());
    }

    #[test]
    fn transaction_status_and_large_messages_are_tracked() {
        let w = Wire::new(true);
        let mut big = msg(b'D', &vec![7u8; 100_000]);
        big.extend(msg(b'Z', b"T"));
        for chunk in big.chunks(4093) {
            w.observe(chunk).unwrap();
        }
        assert_eq!(w.tx(), TxStatus::InTransaction);
        w.observe(&msg(b'Z', b"E")).unwrap();
        assert_eq!(w.tx(), TxStatus::Failed);
    }

    #[test]
    fn malformed_framing_fails_and_oversized_parameters_taint() {
        let w = Wire::new(true);
        assert!(w.observe(&[b'Z', 0, 0, 0, 2]).is_err());
        let w = Wire::new(true);
        w.observe(&msg(b'S', &vec![b'a'; MAX_PARAM_BODY + 10])).unwrap();
        assert!(w.taint().is_some());
    }
}
