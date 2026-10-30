//! TLS for SQL Server sessions with rustls on `ring` (T128). The driver
//! (`tiberius`) is built without a TLS backend: its rustls backend pins the
//! `aws_lc_rs` provider, which this workspace does not carry. The plugin
//! therefore does the TDS 7.x TLS negotiation itself, with the same
//! verifiers as every other engine (`crate::tls`).

// The sequence (MS-TDS 2.2.6.5, 3.2.5.2): a PRELOGIN asking for encryption;
// the server must answer ENCRYPT_ON or ENCRYPT_REQ (anything else, login-only
// encryption included, is refused: no downgrade); the TLS handshake records
// travel inside PRELOGIN packets; then every byte is TLS. The driver's own
// PRELOGIN is answered locally (`TdsTransport`), so its LOGIN7 and every
// later request go into the TLS stream.

// No cryptography is done here: only TDS packet framing around rustls.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const HEADER: usize = 8;
/// Largest packet sent during the handshake (the 4096-byte default).
const MAX_PACKET: usize = 4096;
const STATUS_EOM: u8 = 0x01;
const TYPE_PRELOGIN: u8 = 0x12;
const TYPE_TABULAR: u8 = 0x04;
/// Largest PRELOGIN response read; a real one is a few dozen bytes.
const MAX_PRELOGIN_RESPONSE: usize = 4096;

const OPT_VERSION: u8 = 0x00;
const OPT_ENCRYPTION: u8 = 0x01;
const OPT_INSTOPT: u8 = 0x02;
const OPT_THREADID: u8 = 0x03;
const OPT_MARS: u8 = 0x04;
const OPT_TERMINATOR: u8 = 0xff;

const ENCRYPT_ON: u8 = 0x01;
const ENCRYPT_NOT_SUP: u8 = 0x02;
const ENCRYPT_REQ: u8 = 0x03;

fn bad(m: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.into())
}

fn packet(ty: u8, payload: &[u8], id: u8) -> Vec<u8> {
    let len = (payload.len() + HEADER) as u16;
    let mut out = Vec::with_capacity(len as usize);
    out.extend_from_slice(&[ty, STATUS_EOM]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&[0, 0, id, 0]);
    out.extend_from_slice(payload);
    out
}

/// A PRELOGIN payload from `(option, data)` pairs.
fn prelogin_payload(options: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut offset = (options.len() * 5 + 1) as u16;
    let mut table = Vec::new();
    let mut data = Vec::new();
    for (token, bytes) in options {
        table.push(*token);
        table.extend_from_slice(&offset.to_be_bytes());
        table.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        offset += bytes.len() as u16;
        data.extend_from_slice(bytes);
    }
    table.push(OPT_TERMINATOR);
    table.extend_from_slice(&data);
    table
}

/// The plugin's PRELOGIN: encryption on, MARS off, and the named instance
/// the server must confirm (INSTOPT) before any credential is sent.
pub fn prelogin_request(instance: Option<&str>) -> Vec<u8> {
    let mut inst = instance.unwrap_or("").as_bytes().to_vec();
    inst.push(0);
    let payload = prelogin_payload(&[
        (OPT_VERSION, vec![0x10, 0, 0, 0, 0, 0]),
        (OPT_ENCRYPTION, vec![ENCRYPT_ON]),
        (OPT_INSTOPT, inst),
        (OPT_THREADID, vec![0, 0, 0, 0]),
        (OPT_MARS, vec![0]),
    ]);
    packet(TYPE_PRELOGIN, &payload, 1)
}

/// What the server answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreloginAnswer {
    pub encryption: u8,
    /// `true` when the server accepted the named instance (or none was named).
    pub instance_ok: bool,
}

/// Parse a PRELOGIN response payload, bounds-checked.
pub fn parse_prelogin(payload: &[u8]) -> Result<PreloginAnswer, String> {
    let mut encryption = None;
    let mut instance_ok = true;
    let mut i = 0;
    loop {
        let token = *payload.get(i).ok_or("PRELOGIN response ended before its terminator")?;
        if token == OPT_TERMINATOR {
            break;
        }
        let field = payload.get(i + 1..i + 5).ok_or("PRELOGIN option table is truncated")?;
        let offset = u16::from_be_bytes([field[0], field[1]]) as usize;
        let len = u16::from_be_bytes([field[2], field[3]]) as usize;
        let data = payload.get(offset..offset + len).ok_or("PRELOGIN option points outside the response")?;
        match token {
            OPT_ENCRYPTION => encryption = Some(*data.first().ok_or("empty ENCRYPTION option")?),
            OPT_INSTOPT => instance_ok = data.first().is_none_or(|b| *b == 0),
            _ => {}
        }
        i += 5;
    }
    Ok(PreloginAnswer { encryption: encryption.ok_or("PRELOGIN response has no ENCRYPTION option")?, instance_ok })
}

/// Whether the server's answer keeps the whole session encrypted.
pub fn full_encryption(answer: &PreloginAnswer) -> bool {
    matches!(answer.encryption, ENCRYPT_ON | ENCRYPT_REQ)
}

/// The response given to the driver's own PRELOGIN: no encryption at its
/// level (the stream underneath it is already TLS), no instance check (the
/// plugin made it), MARS off.
pub fn local_prelogin_response() -> Vec<u8> {
    let payload = prelogin_payload(&[
        (OPT_VERSION, vec![0x10, 0, 0, 0, 0, 0]),
        (OPT_ENCRYPTION, vec![ENCRYPT_NOT_SUP]),
        (OPT_INSTOPT, vec![0]),
        (OPT_MARS, vec![0]),
    ]);
    packet(TYPE_TABULAR, &payload, 1)
}

/// Read one TDS message (packets up to end-of-message), at most `max` bytes
/// of payload.
pub async fn read_message<S: AsyncRead + Unpin>(s: &mut S, max: usize) -> io::Result<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    loop {
        let mut h = [0u8; HEADER];
        s.read_exact(&mut h).await?;
        let len = u16::from_be_bytes([h[2], h[3]]) as usize;
        if len < HEADER || out.len() + len - HEADER > max {
            return Err(bad("malformed or oversized TDS packet"));
        }
        let start = out.len();
        out.resize(start + len - HEADER, 0);
        s.read_exact(&mut out[start..]).await?;
        if h[1] & STATUS_EOM != 0 {
            return Ok((h[0], out));
        }
    }
}

/// The PRELOGIN exchange on a fresh connection. Refuses a server that will
/// not encrypt the whole session (`tls_required`), or that does not confirm
/// the instance (`instance_mismatch`); `(code, message)` on refusal.
pub async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    instance: Option<&str>,
) -> Result<(), (&'static str, String)> {
    let io = |what: &str, e: io::Error| ("connect_failed", format!("{what}: {e}"));
    s.write_all(&prelogin_request(instance)).await.map_err(|e| io("sending PRELOGIN", e))?;
    s.flush().await.map_err(|e| io("sending PRELOGIN", e))?;
    let (ty, payload) =
        read_message(s, MAX_PRELOGIN_RESPONSE).await.map_err(|e| io("reading the PRELOGIN response", e))?;
    if ty != TYPE_TABULAR {
        return Err(("connect_failed", "the server did not answer PRELOGIN".into()));
    }
    let answer = parse_prelogin(&payload).map_err(|m| ("connect_failed", m))?;
    if !answer.instance_ok {
        return Err(("instance_mismatch", "the server is not the profile's named instance".into()));
    }
    if !full_encryption(&answer) {
        return Err((
            "tls_required",
            format!(
                "the server will not encrypt the session (PRELOGIN encryption {:#04x}); SQL authentication needs TLS",
                answer.encryption
            ),
        ));
    }
    Ok(())
}

/// TLS handshake records inside PRELOGIN packets, then the raw stream.
pub struct PreloginFraming<S> {
    inner: S,
    framing: bool,
    header: [u8; HEADER],
    header_pos: usize,
    remaining: usize,
    pending: Vec<u8>,
    out: Vec<u8>,
    out_pos: usize,
}

impl<S> PreloginFraming<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            framing: true,
            header: [0; HEADER],
            header_pos: 0,
            remaining: 0,
            pending: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
        }
    }

    /// The handshake is over: from now on bytes pass through unframed.
    pub fn handshake_complete(&mut self) -> io::Result<()> {
        if !self.pending.is_empty() || self.out_pos < self.out.len() || self.remaining != 0 || self.header_pos != 0 {
            return Err(bad("TLS handshake ended with framed bytes still pending"));
        }
        self.framing = false;
        Ok(())
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PreloginFraming<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.framing {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        while this.remaining == 0 {
            while this.header_pos < HEADER {
                let mut hb = ReadBuf::new(&mut this.header[this.header_pos..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut hb) {
                    Poll::Ready(Ok(())) if hb.filled().is_empty() => return Poll::Ready(Ok(())),
                    Poll::Ready(Ok(())) => this.header_pos += hb.filled().len(),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let len = u16::from_be_bytes([this.header[2], this.header[3]]) as usize;
            if this.header[0] != TYPE_PRELOGIN || len < HEADER {
                return Poll::Ready(Err(bad("unexpected TDS packet during the TLS handshake")));
            }
            this.header_pos = 0;
            this.remaining = len - HEADER;
        }
        let take = this.remaining.min(buf.remaining());
        let mut limited = ReadBuf::new(buf.initialize_unfilled_to(take));
        match Pin::new(&mut this.inner).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                let n = limited.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(bad("connection closed inside a TDS packet")));
                }
                buf.advance(n);
                this.remaining -= n;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> PreloginFraming<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.out_pos < self.out.len() {
                match Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Poll::Ready(Ok(n)) => self.out_pos += n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
                continue;
            }
            if self.pending.is_empty() {
                self.out.clear();
                self.out_pos = 0;
                return Poll::Ready(Ok(()));
            }
            let take = self.pending.len().min(MAX_PACKET - HEADER);
            let chunk: Vec<u8> = self.pending.drain(..take).collect();
            self.out = packet(TYPE_PRELOGIN, &chunk, 1);
            self.out_pos = 0;
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PreloginFraming<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.framing {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        this.pending.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.framing {
            match this.poll_drain(cx) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Largest packet accepted from the server after login (TDS caps the
/// negotiated packet size at 32,767 bytes).
const MAX_SERVER_PACKET: usize = 32_768;
const TYPE_ATTENTION: u8 = 0x06;
/// DONE, DONEPROC and DONEINPROC: one byte, status, command, row count.
const DONE_TOKEN_LEN: usize = 13;
const DONE_ATTN: u16 = 0x0020;

/// A cancellation request for the statement in flight (§6.2: the TDS
/// attention signal), shared between the session and its transport.
#[derive(Default)]
pub struct Attention {
    state: std::sync::Mutex<AttnState>,
}

#[derive(Default)]
struct AttnState {
    /// A user statement is in flight: only it may be cancelled, never the
    /// plugin's own bookkeeping batch.
    armed: bool,
    requested: bool,
    sent: bool,
    reader: Option<std::task::Waker>,
}

impl Attention {
    fn lock(&self) -> std::sync::MutexGuard<'_, AttnState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Ask the transport to send an attention on its next read. It is
    /// dropped if the driver writes a new request first (the statement it
    /// was meant for is over).
    pub fn request(&self) {
        let waker = {
            let mut st = self.lock();
            if st.sent || !st.armed {
                return;
            }
            st.requested = true;
            st.reader.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// Open (`true`) or close the window in which a cancel may be sent.
    /// Closing it drops a request not yet sent.
    pub fn arm(&self, on: bool) {
        let mut st = self.lock();
        st.armed = on;
        if !on {
            st.requested = false;
        }
    }

    /// An attention went out and its acknowledgement has not come back.
    pub fn outstanding(&self) -> bool {
        self.lock().sent
    }
}

/// Whether a server packet is exactly an attention acknowledgement: one
/// end-of-message packet of DONE tokens, the last with `DONE_ATTN`.
fn is_attention_ack(packet: &[u8]) -> bool {
    let payload = &packet[HEADER..];
    packet[0] == TYPE_TABULAR
        && packet[1] & STATUS_EOM != 0
        && !payload.is_empty()
        && payload.len().is_multiple_of(DONE_TOKEN_LEN)
        && payload.chunks(DONE_TOKEN_LEN).all(|t| matches!(t[0], 0xfd..=0xff))
        && payload.chunks(DONE_TOKEN_LEN).last().is_some_and(|t| u16::from_le_bytes([t[1], t[2]]) & DONE_ATTN != 0)
}

/// Whether a message's last packet ends with an acknowledged DONE token.
fn ends_with_attention_done(packet: &[u8]) -> bool {
    packet.len() >= HEADER + DONE_TOKEN_LEN && packet[1] & STATUS_EOM != 0 && {
        let t = &packet[packet.len() - DONE_TOKEN_LEN..];
        matches!(t[0], 0xfd..=0xff) && u16::from_le_bytes([t[1], t[2]]) & DONE_ATTN != 0
    }
}

enum Prelogin {
    /// Collecting the driver's PRELOGIN packet.
    Intercept(Vec<u8>),
    /// Serving the local answer.
    Answer(Vec<u8>, usize),
    Done,
}

/// The TDS transport above the TLS stream. The driver's first message (its
/// PRELOGIN) is answered here and never reaches the server, which already
/// negotiated; after that, packets pass through whole, and an attention
/// requested through [`Attention`] is sent between them, its separate
/// acknowledgement message swallowed so the driver stays in step.
pub struct TdsTransport<T> {
    inner: T,
    prelogin: Prelogin,
    attention: std::sync::Arc<Attention>,
    /// The server packet being handed to the driver.
    rbuf: Vec<u8>,
    rpos: usize,
    /// Filling the next server packet.
    next: Vec<u8>,
    /// The next server packet starts a message.
    at_message_start: bool,
    /// The attention packet on its way out.
    wout: Vec<u8>,
    wpos: usize,
}

impl<T> TdsTransport<T> {
    pub fn new(inner: T, attention: std::sync::Arc<Attention>) -> Self {
        Self {
            inner,
            prelogin: Prelogin::Intercept(Vec::new()),
            attention,
            rbuf: Vec::new(),
            rpos: 0,
            next: Vec::new(),
            at_message_start: true,
            wout: Vec::new(),
            wpos: 0,
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> TdsTransport<T> {
    /// Send a requested attention, if one is due.
    fn poll_attention(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.wout.is_empty() {
            let mut st = self.attention.lock();
            if !st.requested || st.sent {
                return Poll::Ready(Ok(()));
            }
            st.requested = false;
            st.sent = true;
            drop(st);
            self.wout = packet(TYPE_ATTENTION, &[], 1);
            self.wpos = 0;
        }
        while self.wpos < self.wout.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.wout[self.wpos..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => self.wpos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.wout.clear();
                self.wpos = 0;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }

    /// Read one whole server packet into `next`. `Ok(false)` at a clean end
    /// of stream.
    fn poll_packet(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            let want = if self.next.len() < HEADER {
                HEADER
            } else {
                let len = u16::from_be_bytes([self.next[2], self.next[3]]) as usize;
                if !(HEADER..=MAX_SERVER_PACKET).contains(&len) {
                    return Poll::Ready(Err(bad("malformed TDS packet from the server")));
                }
                len
            };
            if self.next.len() >= HEADER && self.next.len() == want {
                return Poll::Ready(Ok(true));
            }
            let start = self.next.len();
            self.next.resize(want, 0);
            let mut rb = ReadBuf::new(&mut self.next[start..]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    self.next.truncate(start + n);
                    if n == 0 {
                        if start == 0 {
                            return Poll::Ready(Ok(false));
                        }
                        return Poll::Ready(Err(bad("connection closed inside a TDS packet")));
                    }
                }
                Poll::Ready(Err(e)) => {
                    self.next.truncate(start);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    self.next.truncate(start);
                    self.attention.lock().reader = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for TdsTransport<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.prelogin {
            Prelogin::Intercept(_) => return Poll::Ready(Err(bad("the driver read before sending its PRELOGIN"))),
            Prelogin::Answer(bytes, pos) => {
                let n = (bytes.len() - *pos).min(buf.remaining());
                buf.put_slice(&bytes[*pos..*pos + n]);
                *pos += n;
                if *pos == bytes.len() {
                    this.prelogin = Prelogin::Done;
                }
                return Poll::Ready(Ok(()));
            }
            Prelogin::Done => {}
        }
        loop {
            if this.rpos < this.rbuf.len() {
                let n = (this.rbuf.len() - this.rpos).min(buf.remaining());
                buf.put_slice(&this.rbuf[this.rpos..this.rpos + n]);
                this.rpos += n;
                return Poll::Ready(Ok(()));
            }
            match this.poll_attention(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            match this.poll_packet(cx) {
                Poll::Ready(Ok(true)) => {}
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            let packet = std::mem::take(&mut this.next);
            let starts_message = this.at_message_start;
            this.at_message_start = packet[1] & STATUS_EOM != 0;
            let mut st = this.attention.lock();
            if st.sent && starts_message && is_attention_ack(&packet) {
                // The acknowledgement of our attention: the driver never
                // asked for it, so it never sees it.
                st.sent = false;
                continue;
            }
            if st.sent && ends_with_attention_done(&packet) {
                // Acknowledged inside the response the driver is reading.
                st.sent = false;
            }
            drop(st);
            this.rbuf = packet;
            this.rpos = 0;
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for TdsTransport<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match &mut this.prelogin {
            Prelogin::Intercept(got) => {
                got.extend_from_slice(buf);
                if got.len() > MAX_PACKET {
                    return Poll::Ready(Err(bad("the driver's PRELOGIN is too large")));
                }
                if got.len() >= HEADER {
                    let len = u16::from_be_bytes([got[2], got[3]]) as usize;
                    if got[0] != TYPE_PRELOGIN || got[1] & STATUS_EOM == 0 {
                        return Poll::Ready(Err(bad("the driver did not start with a PRELOGIN")));
                    }
                    if got.len() > len {
                        return Poll::Ready(Err(bad("the driver wrote past its PRELOGIN")));
                    }
                    if got.len() == len {
                        this.prelogin = Prelogin::Answer(local_prelogin_response(), 0);
                    }
                }
                Poll::Ready(Ok(buf.len()))
            }
            Prelogin::Answer(..) => Poll::Ready(Err(bad("the driver wrote before reading the PRELOGIN answer"))),
            Prelogin::Done => {
                {
                    // A new request: an attention not yet sent was meant for
                    // a statement that is over.
                    let mut st = this.attention.lock();
                    if st.requested && !st.sent {
                        st.requested = false;
                    }
                }
                Pin::new(&mut this.inner).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.prelogin {
            Prelogin::Done => Pin::new(&mut this.inner).poll_flush(cx),
            _ => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prelogin_round_trips_and_refuses_downgrades() {
        let req = prelogin_request(Some("SQLEXPRESS"));
        assert_eq!((req[0], req[1]), (TYPE_PRELOGIN, STATUS_EOM));
        assert_eq!(u16::from_be_bytes([req[2], req[3]]) as usize, req.len());
        let a = parse_prelogin(&req[HEADER..]).unwrap();
        assert_eq!(a.encryption, ENCRYPT_ON);
        // INSTOPT carries the name, so the request itself reads as "not 0".
        assert!(!a.instance_ok);
        let local = local_prelogin_response();
        let a = parse_prelogin(&local[HEADER..]).unwrap();
        assert_eq!(a, PreloginAnswer { encryption: ENCRYPT_NOT_SUP, instance_ok: true });
        for (enc, ok) in
            [(0u8, false), (ENCRYPT_ON, true), (ENCRYPT_NOT_SUP, false), (ENCRYPT_REQ, true), (0x20, false)]
        {
            assert_eq!(full_encryption(&PreloginAnswer { encryption: enc, instance_ok: true }), ok, "{enc}");
        }
    }

    #[test]
    fn malformed_prelogin_responses_are_errors_not_panics() {
        for bad in [&[][..], &[0x01][..], &[0x01, 0, 50, 0, 1, 0xff][..], &[0x00, 0, 6, 0, 0, 0xff][..]] {
            assert!(parse_prelogin(bad).is_err(), "{bad:?}");
        }
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    #[test]
    fn negotiation_refuses_login_only_encryption_and_a_wrong_instance() {
        rt().block_on(async {
            for (enc, instopt, want_ok) in
                [(ENCRYPT_ON, 0u8, true), (0x00, 0, false), (ENCRYPT_NOT_SUP, 0, false), (ENCRYPT_REQ, 1, false)]
            {
                let (mut client, mut server) = tokio::io::duplex(1 << 16);
                let answer = packet(
                    TYPE_TABULAR,
                    &prelogin_payload(&[(OPT_ENCRYPTION, vec![enc]), (OPT_INSTOPT, vec![instopt])]),
                    1,
                );
                let srv = tokio::spawn(async move {
                    let (ty, _) = read_message(&mut server, 4096).await.unwrap();
                    assert_eq!(ty, TYPE_PRELOGIN);
                    server.write_all(&answer).await.unwrap();
                    server
                });
                let r = negotiate(&mut client, Some("I")).await;
                assert_eq!(r.is_ok(), want_ok, "{enc} {instopt}: {r:?}");
                drop(srv.await.unwrap());
            }
        });
    }

    #[test]
    fn framing_wraps_and_unwraps_handshake_bytes_then_passes_through() {
        rt().block_on(async {
            let (a, mut b) = tokio::io::duplex(1 << 16);
            let mut f = PreloginFraming::new(a);
            let big = vec![7u8; 5000];
            f.write_all(&big).await.unwrap();
            f.flush().await.unwrap();
            // Two packets on the wire: 4088 + 912 bytes of payload.
            let mut got = Vec::new();
            for want in [4088usize, 912] {
                let mut h = [0u8; HEADER];
                b.read_exact(&mut h).await.unwrap();
                assert_eq!(h[0], TYPE_PRELOGIN);
                assert_eq!(u16::from_be_bytes([h[2], h[3]]) as usize, want + HEADER);
                let mut p = vec![0u8; want];
                b.read_exact(&mut p).await.unwrap();
                got.extend(p);
            }
            assert_eq!(got, big);
            // Server side: two packets, read back as one byte stream.
            b.write_all(&packet(TYPE_PRELOGIN, b"hello ", 1)).await.unwrap();
            b.write_all(&packet(TYPE_PRELOGIN, b"world", 2)).await.unwrap();
            let mut r = vec![0u8; 11];
            f.read_exact(&mut r).await.unwrap();
            assert_eq!(&r, b"hello world");
            // A packet of another type during the handshake is an error.
            b.write_all(&packet(TYPE_TABULAR, b"x", 3)).await.unwrap();
            let mut one = [0u8; 1];
            assert!(f.read_exact(&mut one).await.is_err());
            // Pending framed state refuses the switch to pass-through.
            assert!(f.handshake_complete().is_err());
            f.header_pos = 0;
            f.remaining = 0;
            f.handshake_complete().unwrap();
            f.write_all(b"raw").await.unwrap();
            f.flush().await.unwrap();
            let mut raw = [0u8; 3];
            b.read_exact(&mut raw).await.unwrap();
            assert_eq!(&raw, b"raw");
        });
    }

    #[test]
    fn the_drivers_prelogin_is_answered_locally() {
        rt().block_on(async {
            let (a, mut b) = tokio::io::duplex(1 << 16);
            let mut l = TdsTransport::new(a, Default::default());
            l.write_all(&prelogin_request(None)).await.unwrap();
            l.flush().await.unwrap();
            let (ty, payload) = read_message(&mut l, 4096).await.unwrap();
            assert_eq!(ty, TYPE_TABULAR);
            assert_eq!(parse_prelogin(&payload).unwrap().encryption, ENCRYPT_NOT_SUP);
            // Nothing reached the server; the next message does.
            l.write_all(b"LOGIN7").await.unwrap();
            l.flush().await.unwrap();
            let mut got = [0u8; 6];
            b.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"LOGIN7");
            // Anything but a PRELOGIN first is refused.
            let (c, _d) = tokio::io::duplex(64);
            let mut l = TdsTransport::new(c, Default::default());
            assert!(l.write_all(&packet(0x10, b"login", 1)).await.is_err());
        });
    }

    fn done(status: u16) -> Vec<u8> {
        let mut t = vec![0xfd];
        t.extend_from_slice(&status.to_le_bytes());
        t.extend_from_slice(&[0, 0]);
        t.extend_from_slice(&0u64.to_le_bytes());
        t
    }

    /// The attention goes out between packets; its separate acknowledgement
    /// never reaches the driver, which reads the next response in step.
    #[test]
    fn attention_is_sent_and_its_acknowledgement_swallowed() {
        rt().block_on(async {
            let (a, mut server) = tokio::io::duplex(1 << 16);
            let attn = std::sync::Arc::new(Attention::default());
            let mut l = TdsTransport::new(a, attn.clone());
            l.write_all(&prelogin_request(None)).await.unwrap();
            read_message(&mut l, 4096).await.unwrap();
            // A request goes out, then the cancel is asked for while the
            // driver waits for the response.
            l.write_all(&packet(0x01, b"batch", 1)).await.unwrap();
            l.flush().await.unwrap();
            let mut req = vec![0u8; 13];
            server.read_exact(&mut req).await.unwrap();
            let attn2 = attn.clone();
            let reader = tokio::spawn(async move {
                let first = read_message(&mut l, 4096).await.unwrap();
                l.write_all(&packet(0x01, b"next", 2)).await.unwrap();
                l.flush().await.unwrap();
                let second = read_message(&mut l, 4096).await.unwrap();
                (first, second)
            });
            tokio::task::yield_now().await;
            attn2.arm(true);
            attn2.request();
            let mut got = [0u8; HEADER];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(got[0], TYPE_ATTENTION);
            assert!(attn.outstanding());
            // The truncated response, then the separate acknowledgement.
            server.write_all(&packet(TYPE_TABULAR, &done(0x0002), 1)).await.unwrap();
            server.write_all(&packet(TYPE_TABULAR, &done(DONE_ATTN), 1)).await.unwrap();
            let mut next = vec![0u8; 12];
            server.read_exact(&mut next).await.unwrap();
            assert_eq!(&next[HEADER..], b"next");
            server.write_all(&packet(TYPE_TABULAR, b"answer", 2)).await.unwrap();
            let (first, second) = reader.await.unwrap();
            assert_eq!(first.1, done(0x0002));
            assert_eq!(second.1, b"answer", "the acknowledgement was swallowed");
            assert!(!attn.outstanding());
        });
    }

    #[test]
    fn a_stale_cancel_is_dropped_by_the_next_request() {
        rt().block_on(async {
            let (a, mut server) = tokio::io::duplex(1 << 16);
            let attn = std::sync::Arc::new(Attention::default());
            let mut l = TdsTransport::new(a, attn.clone());
            l.write_all(&prelogin_request(None)).await.unwrap();
            read_message(&mut l, 4096).await.unwrap();
            // Unarmed (no user statement in flight): nothing is requested.
            attn.request();
            assert!(!attn.lock().requested);
            attn.arm(true);
            attn.request();
            l.write_all(&packet(0x01, b"new", 1)).await.unwrap();
            l.flush().await.unwrap();
            server.write_all(&packet(TYPE_TABULAR, b"ok", 1)).await.unwrap();
            assert_eq!(read_message(&mut l, 4096).await.unwrap().1, b"ok");
            let mut sent = vec![0u8; 11];
            server.read_exact(&mut sent).await.unwrap();
            assert_eq!(sent[0], 0x01, "no attention went out");
            assert!(!attn.outstanding());
        });
    }
}
