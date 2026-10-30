//! The Oracle Net session layer (T129): the only hand-written protocol code
//! of the Oracle engine, kept small for a separate review. The protocol
//! crate builds and parses every TTC message and does the O5LOGON verifier
//! cryptography; this module frames TNS packets, runs CONNECT / ACCEPT and
//! the auth round trips in order, sends one request at a time, reads its
//! END_OF_RESPONSE-framed answer, runs the MARKER reset and sends the
//! in-band BREAK. Rationale and limits: features/sql-browser.md, "Phase 8".

// Refused, never guessed at: REDIRECT (it moves the dial off the endpoint
// the credential is bound to, §5.4), a second TLS renegotiation, servers
// without fast auth and END_OF_RESPONSE framing (before 23ai), pre-12c
// verifiers, any unexpected packet, FLUSH_OUT_BINDS, and responses the crate
// cannot parse. After the handshake such a refusal marks the session dead.

use std::sync::{Arc, Mutex as StdMutex};

use oraclemcp_driver_cx_protocol as proto;
use proto::thin::{self, BindValue, ClientCapabilities, ColumnMetadata, QueryResult, QueryValue};
use proto::wire::ProtocolLimits;
use proto::ProtocolError;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroize;

const PACKET_CONNECT: u8 = thin::TNS_PACKET_TYPE_CONNECT;
const PACKET_ACCEPT: u8 = thin::TNS_PACKET_TYPE_ACCEPT;
const PACKET_REFUSE: u8 = thin::TNS_PACKET_TYPE_REFUSE;
const PACKET_REDIRECT: u8 = thin::TNS_PACKET_TYPE_REDIRECT;
const PACKET_DATA: u8 = thin::TNS_PACKET_TYPE_DATA;
const PACKET_RESEND: u8 = thin::TNS_PACKET_TYPE_RESEND;
const PACKET_MARKER: u8 = 12;
const MARKER_BREAK: u8 = 1;
const MARKER_RESET: u8 = 2;
/// RESEND packet flag: the server wants a second TLS handshake.
const FLAG_TLS_RENEGOTIATE: u8 = 0x08;
const HEADER_LEN: usize = 8;

/// The transport: TCPS, TLS from the first byte.
pub type Stream = TlsStream<TcpStream>;
/// A DATA packet's header plus its two data-flag bytes.
const DATA_OVERHEAD: usize = HEADER_LEN + 2;
const SDU_REQUESTED: u16 = 8192;
const SDU_MIN: u32 = 512;
const SDU_MAX: u32 = 2 * 1024 * 1024;
/// RESEND answers tolerated before the handshake is abandoned.
const MAX_RESENDS: u8 = 4;
/// How long the server has to answer a BREAK that crossed the end of its
/// call.
const BREAK_ANSWER: std::time::Duration = std::time::Duration::from_secs(10);
/// MARKER packets drained in one reset before the peer is called broken.
const MAX_MARKERS: usize = 64;
/// The 23ai TTC protocol level: fast authentication and END_OF_RESPONSE.
const MIN_PROTOCOL_VERSION: u16 = 319;
/// The client version the auth message reports (the layout the protocol
/// crate's messages follow).
const CLIENT_VERSION: u32 = 0x0400_1000;
const DRIVER_NAME: &str = "bastionvault-sql-browser";
/// Identity shown in `V$SESSION`: fixed, so no host detail leaks.
const PROGRAM: &str = "bastionvault-sql-browser";
const MACHINE: &str = "bastionvault";
const OSUSER: &str = "bastionvault";
const TERMINAL: &str = "unknown";
/// ORA-01013, the answer to a BREAK.
pub const ORA_CANCELLED: u32 = 1013;

/// Rows are fetched in small arrays (§6.3), so one response stays far below
/// the crate's 256 MiB default.
pub const LIMITS: ProtocolLimits = ProtocolLimits { max_response_bytes: 64 * 1024 * 1024, ..ProtocolLimits::DEFAULT };

/// What went wrong. Messages never hold a credential or statement text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TnsError {
    /// The server answered with an `ORA-` error; the session is in step.
    Server { code: u32, message: String },
    /// The connection is unusable.
    Broken(String),
    /// Refused during the handshake, with the code the plugin reports.
    Refused { code: &'static str, message: String },
}

impl TnsError {
    fn broken(m: impl Into<String>) -> Self {
        Self::Broken(m.into())
    }
    fn refused(code: &'static str, m: impl Into<String>) -> Self {
        Self::Refused { code, message: m.into() }
    }
}

/// `ORA-NNNNN` at the start of a server message, else 0.
fn ora_code(message: &str) -> u32 {
    let m = message.trim_start();
    m.strip_prefix("ORA-").and_then(|r| r.get(..5)).and_then(|d| d.parse().ok()).unwrap_or(0)
}

/// An `ORA-` error is the server's answer; anything else means the bytes
/// could not be read as the protocol says.
fn from_protocol(e: ProtocolError) -> TnsError {
    match e {
        ProtocolError::ServerError(message) => TnsError::Server { code: ora_code(&message), message },
        ProtocolError::ServerErrorWithRowCount { message, .. } => {
            TnsError::Server { code: ora_code(&message), message }
        }
        ProtocolError::ServerErrorInfo(d) => TnsError::Server { code: d.code, message: d.message.clone() },
        other => TnsError::broken(format!("the server's response could not be read: {other}")),
    }
}

fn io(e: std::io::Error) -> TnsError {
    TnsError::broken(format!("the connection to the database failed: {}", e.kind()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Width {
    /// Until ACCEPT: a 16-bit length and two zero checksum bytes.
    Legacy16,
    /// After ACCEPT (protocol 315 and later): a 32-bit length.
    Large32,
}

fn encode(width: Width, kind: u8, flags: u8, data_flags: Option<u16>, payload: &[u8]) -> Result<Vec<u8>, TnsError> {
    let len = HEADER_LEN + data_flags.map_or(0, |_| 2) + payload.len();
    let too_large = || TnsError::broken("a packet too large for its header");
    let mut out = Vec::with_capacity(len);
    match width {
        Width::Legacy16 => {
            out.extend_from_slice(&u16::try_from(len).map_err(|_| too_large())?.to_be_bytes());
            out.extend_from_slice(&[0, 0]);
        }
        Width::Large32 => out.extend_from_slice(&u32::try_from(len).map_err(|_| too_large())?.to_be_bytes()),
    }
    out.extend_from_slice(&[kind, flags, 0, 0]);
    if let Some(f) = data_flags {
        out.extend_from_slice(&f.to_be_bytes());
    }
    out.extend_from_slice(payload);
    Ok(out)
}

#[derive(Debug)]
struct Packet {
    kind: u8,
    flags: u8,
    payload: Vec<u8>,
}

async fn read_packet<R: AsyncRead + Unpin>(rd: &mut R, width: Width) -> Result<Packet, TnsError> {
    let mut header = [0u8; HEADER_LEN];
    rd.read_exact(&mut header).await.map_err(io)?;
    let declared = match width {
        Width::Legacy16 => usize::from(u16::from_be_bytes([header[0], header[1]])),
        Width::Large32 => {
            usize::try_from(u32::from_be_bytes([header[0], header[1], header[2], header[3]])).unwrap_or(usize::MAX)
        }
    };
    if !(HEADER_LEN..=LIMITS.max_packet_bytes).contains(&declared) {
        return Err(TnsError::broken(format!("a packet of invalid length {declared}")));
    }
    let mut payload = vec![0u8; declared - HEADER_LEN];
    rd.read_exact(&mut payload).await.map_err(io)?;
    Ok(Packet { kind: header[4], flags: header[5], payload })
}

/// A value placed inside a connect descriptor: no character the descriptor
/// grammar gives a meaning (parentheses, `=`, quotes, spaces), so a profile
/// value can never add a clause.
pub fn descriptor_value_ok(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'$' | b'#'))
}

/// The CONNECT descriptor and the one the AUTH message carries.
fn descriptors(host: &str, port: u16, service: &str) -> (String, String) {
    let address = format!("(ADDRESS=(PROTOCOL=tcps)(HOST={host})(PORT={port}))");
    let security = "(SECURITY=(SSL_SERVER_DN_MATCH=ON))";
    let cid = format!("(CID=(PROGRAM={PROGRAM})(HOST={MACHINE})(USER={OSUSER}))");
    let listener = format!("(DESCRIPTION={address}(CONNECT_DATA=(SERVICE_NAME={service}){cid}){security})");
    let auth = format!("(DESCRIPTION={address}(CONNECT_DATA=(SERVICE_NAME={service})){security})");
    (listener, auth)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flight {
    Idle,
    InCall,
    BreakSent,
}

/// Sends the in-band BREAK for the call in flight (§6.2). Over TLS there is
/// no out-of-band channel: the server reads the MARKER on the connection,
/// answers with its own, and ends the call with ORA-01013.
#[derive(Clone)]
pub struct Breaker {
    wr: Arc<tokio::sync::Mutex<WriteHalf<Stream>>>,
    flight: Arc<StdMutex<Flight>>,
}

impl Breaker {
    /// Send a BREAK if a call is running; never otherwise, since a BREAK
    /// with nothing running would leave an answer nobody reads. Returns
    /// whether one was sent.
    pub async fn request(&self) -> Result<bool, TnsError> {
        {
            let mut f = self.flight.lock().unwrap_or_else(|p| p.into_inner());
            if *f != Flight::InCall {
                return Ok(false);
            }
            *f = Flight::BreakSent;
        }
        let packet = encode(Width::Large32, PACKET_MARKER, 0, None, &[1, 0, MARKER_BREAK])?;
        let mut wr = self.wr.lock().await;
        wr.write_all(&packet).await.map_err(io)?;
        wr.flush().await.map_err(io)?;
        Ok(true)
    }
}

/// What the server said about itself during authentication.
#[derive(Debug, Clone, Default)]
pub struct ServerInfo {
    pub version_string: Option<String>,
    pub version_number: Option<u32>,
}

/// An authenticated session over one TLS stream.
pub struct Session {
    rd: ReadHalf<Stream>,
    wr: Arc<tokio::sync::Mutex<WriteHalf<Stream>>>,
    flight: Arc<StdMutex<Flight>>,
    sdu: usize,
    caps: ClientCapabilities,
    seq: u8,
    /// Cursors closed by a piggyback on the next request.
    to_close: Vec<u32>,
    dead: Option<String>,
    pub server: ServerInfo,
}

/// The handshake's inputs. `host`, `port` and `service` go into the
/// connect descriptor and must pass [`descriptor_value_ok`].
pub struct Login<'a> {
    pub host: &'a str,
    pub port: u16,
    pub service: &'a str,
    pub user: &'a str,
    pub password: &'a [u8],
}

fn next_seq(seq: &mut u8) -> u8 {
    *seq = seq.wrapping_add(1);
    if *seq == 0 {
        *seq = 1;
    }
    *seq
}

/// How the session layer does TLS: the caller's rustls configuration (the
/// profile's mode, §5.1) and the name it checks.
pub struct TlsSetup {
    pub config: Arc<ClientConfig>,
    pub name: ServerName<'static>,
}

async fn tls_handshake(tcp: TcpStream, tls: &TlsSetup) -> Result<Stream, TnsError> {
    tokio_rustls::TlsConnector::from(tls.config.clone())
        .connect(tls.name.clone(), tcp)
        .await
        .map_err(|e| TnsError::refused("tls_failed", format!("TLS handshake with the database failed: {e}")))
}

async fn write_all(stream: &mut Stream, bytes: &[u8]) -> Result<(), TnsError> {
    stream.write_all(bytes).await.map_err(io)?;
    stream.flush().await.map_err(io)
}

/// CONNECT until ACCEPT, on the whole stream. RESEND repeats it (bounded).
/// A RESEND flagged for TLS renegotiation is the listener handing the
/// connection to a server process, which needs its own TLS handshake: the
/// first TLS session is dropped (no close_notify, as Oracle's clients do)
/// and a new one is made on the same socket, verified exactly as the first.
/// REDIRECT and REFUSE end it.
async fn connect_phase(mut stream: Stream, tls: &TlsSetup, descriptor: &str) -> Result<(Stream, usize), TnsError> {
    let mut resends = 0u8;
    let mut renegotiated = false;
    let accept = loop {
        let payload = thin::build_connect_packet_payload(descriptor, SDU_REQUESTED).map_err(from_protocol)?;
        let mut out = encode(Width::Legacy16, PACKET_CONNECT, 0, None, &payload)?;
        if !thin::connect_data_fits_inline(descriptor) {
            out.extend(encode(Width::Legacy16, PACKET_DATA, 0, Some(0), descriptor.as_bytes())?);
        }
        write_all(&mut stream, &out).await?;
        let reply = read_packet(&mut stream, Width::Legacy16).await?;
        match reply.kind {
            PACKET_ACCEPT => break reply,
            PACKET_RESEND if resends >= MAX_RESENDS => {
                return Err(TnsError::refused("connect_failed", "the listener kept asking to resend"))
            }
            PACKET_RESEND if reply.flags & FLAG_TLS_RENEGOTIATE != 0 => {
                if renegotiated {
                    return Err(TnsError::refused("connect_failed", "the listener asked for TLS renegotiation twice"));
                }
                renegotiated = true;
                resends += 1;
                let (tcp, _) = stream.into_inner();
                stream = tls_handshake(tcp, tls).await?;
            }
            PACKET_RESEND => resends += 1,
            PACKET_REDIRECT => {
                return Err(TnsError::refused(
                    "redirect_refused",
                    "the listener redirected the connection; a redirect would move the dial away from the \
                     endpoint the credential is bound to (connect to the instance's own listener port)",
                ))
            }
            PACKET_REFUSE => {
                // The reason is a descriptor such as `(ERR=12514)`; only
                // its number is kept.
                let text = String::from_utf8_lossy(&reply.payload);
                let err = text.split("(ERR=").nth(1).and_then(|r| r.split(')').next()).unwrap_or("?");
                let err: String = err.chars().filter(char::is_ascii_digit).take(6).collect();
                return Err(TnsError::refused(
                    "connect_failed",
                    format!("the listener refused the connection (TNS-{err}); check the service name"),
                ));
            }
            other => return Err(TnsError::broken(format!("an unexpected packet type {other} during connect"))),
        }
    };
    if accept.flags & FLAG_TLS_RENEGOTIATE != 0 {
        return Err(TnsError::refused("server_unsupported", "the listener asked for TLS renegotiation on ACCEPT"));
    }
    let info = thin::parse_accept_payload(&accept.payload)
        .map_err(|e| TnsError::refused("server_unsupported", format!("the server's ACCEPT was refused: {e}")))?;
    if info.protocol_version < MIN_PROTOCOL_VERSION || !info.supports_fast_auth || !info.supports_end_of_response {
        return Err(TnsError::refused(
            "server_unsupported",
            "Oracle Database 23ai or later is required (fast authentication and END_OF_RESPONSE framing)",
        ));
    }
    let sdu = usize::try_from(info.sdu.clamp(SDU_MIN, SDU_MAX)).unwrap_or(usize::from(SDU_REQUESTED));
    Ok((stream, sdu))
}

/// Open a session: TLS on `tcp` (the caller's configuration and name),
/// CONNECT / ACCEPT, then authentication. The password is only read here.
pub async fn connect(tcp: TcpStream, tls: &TlsSetup, login: &Login<'_>) -> Result<Session, TnsError> {
    if !descriptor_value_ok(login.host) || !descriptor_value_ok(login.service) {
        return Err(TnsError::refused(
            "bad_request",
            "the host or service name holds characters a connect descriptor cannot carry",
        ));
    }
    if login.user.is_empty()
        || login.user.len() > 128
        || login.user.chars().any(|c| c.is_control() || matches!(c, '[' | ']' | '"'))
    {
        return Err(TnsError::refused("bad_credential", "the released user name is not a plain Oracle user name"));
    }
    let (listener, auth_descriptor) = descriptors(login.host, login.port, login.service);
    let stream = tls_handshake(tcp, tls).await?;
    let (stream, sdu) = connect_phase(stream, tls, &listener).await?;
    let (rd, wr) = tokio::io::split(stream);
    let mut s = Session {
        rd,
        wr: Arc::new(tokio::sync::Mutex::new(wr)),
        flight: Arc::new(StdMutex::new(Flight::Idle)),
        sdu,
        caps: ClientCapabilities::default(),
        seq: 1,
        to_close: Vec::new(),
        dead: None,
        server: ServerInfo::default(),
    };
    s.authenticate(login, &auth_descriptor).await?;
    Ok(s)
}

impl Session {
    pub fn breaker(&self) -> Breaker {
        Breaker { wr: self.wr.clone(), flight: self.flight.clone() }
    }

    /// Why nothing more may be sent on this session, if so.
    pub fn dead(&self) -> Option<&str> {
        self.dead.as_deref()
    }

    pub fn capabilities(&self) -> ClientCapabilities {
        self.caps
    }

    async fn write(&self, bytes: &[u8]) -> Result<(), TnsError> {
        let mut wr = self.wr.lock().await;
        wr.write_all(bytes).await.map_err(io)?;
        wr.flush().await.map_err(io)
    }

    /// Fast authentication and O5LOGON. Only the 12c (PBKDF2) verifier is
    /// accepted, and the server must prove it knows it
    /// (`AUTH_SVR_RESPONSE`) before the session is used.
    async fn authenticate(&mut self, login: &Login<'_>, auth_descriptor: &str) -> Result<(), TnsError> {
        let pid = std::process::id();
        let one = thin::build_fast_auth_phase_one_payload(login.user, PROGRAM, MACHINE, OSUSER, TERMINAL, pid)
            .map_err(from_protocol)?;
        self.send_data(&one).await?;
        let (resp, _) = self.read_response().await?;
        let auth_one = thin::parse_auth_response_with_limits(&resp, LIMITS).map_err(login_error)?;
        self.caps = auth_one.capabilities.unwrap_or_default();
        let verifier = auth_one
            .verifier_type
            .ok_or_else(|| TnsError::refused("connect_failed", "the server sent no password verifier"))?;
        if verifier != thin::TNS_VERIFIER_TYPE_12C {
            // Refused before any password-derived value is sent (§5.4).
            return Err(TnsError::refused(
                "weak_auth",
                "the account has only a pre-12c password verifier; reset its password with \
                 SQLNET.ALLOWED_LOGON_VERSION_SERVER at 12 or later",
            ));
        }
        let mut enc = proto::crypto::generate_verifier(login.password, &auth_one.session_data, verifier)
            .map_err(|e| TnsError::refused("connect_failed", format!("authentication could not proceed: {e}")))?;
        let seq = next_seq(&mut self.seq);
        let outcome = match thin::build_auth_phase_two_payload_with_proxy_with_seq(
            login.user,
            &enc,
            DRIVER_NAME,
            CLIENT_VERSION,
            auth_descriptor,
            seq,
            &[],
            None,
            None,
            self.caps.ttc_field_version,
        ) {
            Ok(mut payload) => {
                let sent = self.send_data(&payload).await;
                payload.zeroize();
                match sent {
                    Ok(()) => self.read_response().await,
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(from_protocol(e)),
        };
        let auth_two =
            outcome.and_then(|(resp, _)| thin::parse_auth_response_with_limits(&resp, LIMITS).map_err(login_error));
        let proved = match &auth_two {
            Ok(a) => proto::crypto::verify_server_response(&enc.combo_key, &a.session_data).is_ok(),
            Err(_) => false,
        };
        enc.session_key.zeroize();
        enc.password.zeroize();
        enc.combo_key.zeroize();
        if let Some(k) = enc.speedy_key.as_mut() {
            k.zeroize();
        }
        let auth_two = auth_two?;
        if !proved {
            return Err(TnsError::refused(
                "server_auth_failed",
                "the server did not prove it knows the account's verifier (AUTH_SVR_RESPONSE)",
            ));
        }
        self.server = ServerInfo {
            version_string: auth_two.session_data.get("AUTH_VERSION_STRING").cloned(),
            version_number: auth_two.session_data.get("AUTH_VERSION_NO").and_then(|v| v.trim().parse().ok()),
        };
        Ok(())
    }

    /// One request as DATA packets of at most the negotiated SDU.
    async fn send_data(&self, payload: &[u8]) -> Result<(), TnsError> {
        let chunk = self.sdu.saturating_sub(DATA_OVERHEAD).max(1);
        let mut out = Vec::with_capacity(payload.len() + DATA_OVERHEAD * (payload.len() / chunk + 1));
        for piece in payload.chunks(chunk) {
            out.extend(encode(Width::Large32, PACKET_DATA, 0, Some(0), piece)?);
        }
        self.write(&out).await
    }

    /// Read one response: DATA packets until END_OF_RESPONSE. A MARKER (an
    /// error the server breaks off with, or its answer to a BREAK) runs the
    /// reset: send RESET, skip the server's markers, read on. Returns the
    /// TTC payload and whether a marker was seen. `seed` is a packet
    /// already read.
    async fn read_response_from(&mut self, seed: Option<Packet>) -> Result<(Vec<u8>, bool), TnsError> {
        let mut response = Vec::new();
        let mut saw_marker = false;
        let mut after_reset = false;
        let mut pending: Option<Packet> = seed;
        loop {
            let packet = match pending.take() {
                Some(p) => p,
                None => read_packet(&mut self.rd, Width::Large32).await?,
            };
            match packet.kind {
                PACKET_MARKER => {
                    saw_marker = true;
                    self.write(&encode(Width::Large32, PACKET_MARKER, 0, None, &[1, 0, MARKER_RESET])?).await?;
                    let mut markers = 0usize;
                    loop {
                        let p = read_packet(&mut self.rd, Width::Large32).await?;
                        if p.kind != PACKET_MARKER {
                            pending = Some(p);
                            break;
                        }
                        markers += 1;
                        if markers > MAX_MARKERS {
                            return Err(TnsError::broken("the server kept sending markers after a reset"));
                        }
                    }
                    after_reset = true;
                }
                PACKET_DATA => {
                    let Some((flags, body)) = packet.payload.split_at_checked(2) else {
                        return Err(TnsError::broken("a DATA packet without its flags"));
                    };
                    let flags = u16::from_be_bytes([flags[0], flags[1]]);
                    if flags & thin::TNS_DATA_FLAGS_EOF != 0 {
                        return Err(TnsError::broken("the server closed the session"));
                    }
                    if response.len() + body.len() > LIMITS.max_response_bytes {
                        return Err(TnsError::broken("a response larger than the plugin accepts"));
                    }
                    response.extend_from_slice(body);
                    let last = body.last().copied();
                    if flags & thin::TNS_DATA_FLAGS_END_OF_RESPONSE != 0
                        || body == [thin::TNS_MSG_TYPE_END_OF_RESPONSE]
                        || (after_reset && last == Some(thin::TNS_MSG_TYPE_END_OF_RESPONSE))
                    {
                        break;
                    }
                    if after_reset && last == Some(thin::TNS_MSG_TYPE_FLUSH_OUT_BINDS) {
                        // The plugin binds no outputs, so it cannot answer
                        // a request to flush them safely.
                        return Err(TnsError::broken("the server asked to flush output binds"));
                    }
                }
                other => return Err(TnsError::broken(format!("an unexpected packet type {other}"))),
            }
        }
        Ok((response, saw_marker))
    }

    async fn read_response(&mut self) -> Result<(Vec<u8>, bool), TnsError> {
        self.read_response_from(None).await
    }

    /// The answer to a BREAK that reached the server after its call ended:
    /// the server answers every BREAK with a MARKER, then (after the reset)
    /// with an error response, which is read and dropped here. Anything
    /// else, or nothing within the bound, leaves the session dead.
    async fn drain_break(&mut self) -> Result<(), TnsError> {
        let first = tokio::time::timeout(BREAK_ANSWER, read_packet(&mut self.rd, Width::Large32))
            .await
            .map_err(|_| TnsError::broken("the server did not answer a cancel"))??;
        if first.kind != PACKET_MARKER {
            return Err(TnsError::broken(format!("a packet of type {} where a cancel's answer was due", first.kind)));
        }
        let (resp, _) = self.read_response_from(Some(first)).await?;
        match thin::parse_plain_function_response_with_limits(&resp, self.caps, LIMITS).map_err(from_protocol) {
            Err(TnsError::Server { .. }) | Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Prefix the cursor-close piggyback, then build the message with the
    /// next sequence number. On a build error nothing changes.
    fn request(&mut self, build: impl FnOnce(u8, u8) -> Result<Vec<u8>, TnsError>) -> Result<Vec<u8>, TnsError> {
        if let Some(why) = &self.dead {
            return Err(TnsError::Broken(why.clone()));
        }
        let (seq_before, close_before) = (self.seq, self.to_close.clone());
        let mut payload = Vec::new();
        if !self.to_close.is_empty() {
            let ids = std::mem::take(&mut self.to_close);
            let s = next_seq(&mut self.seq);
            payload = thin::build_close_cursors_piggyback(&ids, s, self.caps.ttc_field_version);
        }
        let s = next_seq(&mut self.seq);
        match build(s, self.caps.ttc_field_version) {
            Ok(message) => {
                payload.extend(message);
                Ok(payload)
            }
            Err(e) => {
                self.seq = seq_before;
                self.to_close = close_before;
                Err(e)
            }
        }
    }

    /// Send a request and read its answer. A BREAK sent during the call is
    /// answered within it (a marker and ORA-01013), or, when it crossed the
    /// end of the call, right after it: that answer is drained before the
    /// session is used again, or the session is closed.
    async fn round_trip<T>(
        &mut self,
        payload: Vec<u8>,
        parse: impl FnOnce(&[u8], ClientCapabilities) -> Result<T, ProtocolError>,
    ) -> Result<T, TnsError> {
        if let Err(e) = self.send_data(&payload).await {
            self.dead = Some("the connection failed while sending".into());
            return Err(e);
        }
        *self.flight.lock().unwrap_or_else(|p| p.into_inner()) = Flight::InCall;
        let read = self.read_response().await;
        let broke = {
            let mut f = self.flight.lock().unwrap_or_else(|p| p.into_inner());
            let b = *f == Flight::BreakSent;
            *f = Flight::Idle;
            b
        };
        let (resp, saw_marker) = match read {
            Ok(r) => r,
            Err(e) => {
                self.dead = Some("the connection failed while reading".into());
                return Err(e);
            }
        };
        let parsed = parse(&resp, self.caps).map_err(from_protocol);
        let clean_cancel =
            matches!(&parsed, Err(TnsError::Server { code, .. }) if *code == ORA_CANCELLED) && saw_marker;
        if let Err(TnsError::Broken(m)) = &parsed {
            self.dead = Some(m.clone());
        } else if broke && !clean_cancel {
            if let Err(e) = self.drain_break().await {
                self.dead = Some(format!("a cancel crossed the end of its statement and was not answered: {e:?}"));
            }
        }
        parsed
    }

    /// Execute one statement, the caller's (already authorized) or the
    /// plugin's own. A query's first `prefetch` rows come with it.
    pub async fn execute(
        &mut self,
        sql: &str,
        is_query: bool,
        binds: &[BindValue],
        prefetch: u32,
    ) -> Result<QueryResult, TnsError> {
        let payload = self.request(|seq, ttc| {
            thin::build_execute_payload_with_binds_with_seq(sql, prefetch, seq, is_query, binds, ttc)
                .map_err(from_protocol)
        })?;
        self.round_trip(payload, |resp, caps| {
            thin::parse_query_response_with_binds_options_columns_and_limits(
                resp,
                caps,
                binds,
                thin::ExecuteOptions::default(),
                &[],
                LIMITS,
            )
        })
        .await
    }

    /// The next `arraysize` rows of an open cursor.
    pub async fn fetch(
        &mut self,
        cursor_id: u32,
        arraysize: u32,
        columns: &[ColumnMetadata],
        previous: Option<&[Option<QueryValue>]>,
    ) -> Result<QueryResult, TnsError> {
        let payload =
            self.request(|seq, ttc| Ok(thin::build_fetch_payload_with_seq(cursor_id, arraysize, seq, ttc)))?;
        self.round_trip(payload, |resp, caps| {
            thin::parse_fetch_response_with_context_and_limits(resp, caps, columns, previous, LIMITS)
        })
        .await
    }

    /// COMMIT, ROLLBACK or PING as a bare function call; returns whether a
    /// transaction is still in progress (the end-of-call status).
    pub async fn function(&mut self, code: u8) -> Result<bool, TnsError> {
        let payload = self.request(|seq, ttc| Ok(thin::build_function_payload_with_seq(code, seq, ttc)))?;
        self.round_trip(payload, |resp, caps| thin::parse_plain_function_response_with_limits(resp, caps, LIMITS)).await
    }

    /// Close this cursor with the next request.
    pub fn close_cursor(&mut self, cursor_id: u32) {
        if cursor_id != 0 && !self.to_close.contains(&cursor_id) {
            self.to_close.push(cursor_id);
        }
    }
}

/// A server error during the login is a refused login, never more detail
/// than its number (ORA-01017 does not say whether the user exists).
fn login_error(e: ProtocolError) -> TnsError {
    match from_protocol(e) {
        TnsError::Server { code, .. } => {
            TnsError::refused("login_failed", format!("the database refused the login (ORA-{code:05})"))
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packets_frame_as_the_protocol_says() {
        let p = encode(Width::Legacy16, PACKET_CONNECT, 0, None, b"abc").unwrap();
        assert_eq!(p, vec![0, 11, 0, 0, 1, 0, 0, 0, b'a', b'b', b'c']);
        let p = encode(Width::Large32, PACKET_DATA, 0, Some(0x2000), b"x").unwrap();
        assert_eq!(p, vec![0, 0, 0, 11, 6, 0, 0, 0, 0x20, 0x00, b'x']);
        let m = encode(Width::Large32, PACKET_MARKER, 0, None, &[1, 0, MARKER_BREAK]).unwrap();
        assert_eq!(m, vec![0, 0, 0, 11, 12, 0, 0, 0, 1, 0, 1]);
        assert!(encode(Width::Legacy16, PACKET_DATA, 0, None, &vec![0u8; 70_000]).is_err());
    }

    #[tokio::test]
    async fn invalid_lengths_are_refused() {
        let mut short: &[u8] = &[0, 4, 0, 0, 6, 0, 0, 0];
        assert!(matches!(read_packet(&mut short, Width::Legacy16).await, Err(TnsError::Broken(_))));
        let mut huge: &[u8] = &[0x7f, 0xff, 0xff, 0xff, 6, 0, 0, 0];
        assert!(matches!(read_packet(&mut huge, Width::Large32).await, Err(TnsError::Broken(_))));
        let mut truncated: &[u8] = &[0, 0, 0, 20, 6, 0, 0, 0, 1, 2];
        assert!(matches!(read_packet(&mut truncated, Width::Large32).await, Err(TnsError::Broken(_))));
        let mut ok: &[u8] = &[0, 0, 0, 10, 6, 7, 0, 0, 0x20, 0];
        let p = read_packet(&mut ok, Width::Large32).await.unwrap();
        assert_eq!((p.kind, p.flags, p.payload), (6, 7, vec![0x20, 0]));
    }

    #[test]
    fn descriptor_values_cannot_add_clauses() {
        for good in ["FREEPDB1", "orcl.example.com", "127.0.0.1", "db-1", "::1", "SYS$USERS"] {
            assert!(descriptor_value_ok(good), "{good}");
        }
        let long = "a".repeat(129);
        for bad in ["", "x)(SERVER=dedicated", "a=b", "a b", "svc'", "svc\"", "x\n", long.as_str()] {
            assert!(!descriptor_value_ok(bad), "{bad}");
        }
        let (listener, auth) = descriptors("db.example", 2484, "FREEPDB1");
        assert!(listener.starts_with("(DESCRIPTION=(ADDRESS=(PROTOCOL=tcps)(HOST=db.example)(PORT=2484))"));
        assert!(listener.contains("(SERVICE_NAME=FREEPDB1)(CID=(PROGRAM=bastionvault-sql-browser)"));
        assert!(auth.contains("(CONNECT_DATA=(SERVICE_NAME=FREEPDB1))"));
        assert_eq!(listener.matches('(').count(), listener.matches(')').count());
    }

    #[test]
    fn errors_keep_the_ora_code_only_from_the_server() {
        assert_eq!(ora_code("ORA-01013: user requested cancel of current operation"), 1013);
        assert_eq!(ora_code("no code"), 0);
        let e = from_protocol(ProtocolError::ServerError("ORA-00942: table or view does not exist".into()));
        assert_eq!(e, TnsError::Server { code: 942, message: "ORA-00942: table or view does not exist".into() });
        assert!(matches!(from_protocol(ProtocolError::TtcDecode("short")), TnsError::Broken(_)));
        let login = login_error(ProtocolError::ServerError("ORA-01017: invalid username/password".into()));
        assert_eq!(login, TnsError::refused("login_failed", "the database refused the login (ORA-01017)"));
    }

    #[test]
    fn sequence_numbers_skip_zero() {
        let mut s = 254u8;
        assert_eq!(next_seq(&mut s), 255);
        assert_eq!(next_seq(&mut s), 1);
    }
}
