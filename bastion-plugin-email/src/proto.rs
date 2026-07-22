//! Line-delimited JSON-RPC client over stdio. Mirrors
//! `crate::plugins::process_runtime` on the host side.
//!
//! All host_call IDs are a local sequence; the host's reply carries the
//! same ID. We don't pipeline calls — each `config_get` / `audit_emit`
//! awaits its reply before returning so the dispatcher logic stays
//! sequential and the JSON parser stays simple.

use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

pub struct Io<'a, R, W> {
    reader: &'a mut R,
    writer: &'a mut W,
    next_id: u64,
}

impl<'a, R, W> Io<'a, R, W>
where
    R: AsyncBufRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    pub fn new(reader: &'a mut R, writer: &'a mut W) -> Self {
        Self { reader, writer, next_id: 1 }
    }

    pub async fn config_get(&mut self, key: &str) -> std::io::Result<Option<String>> {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({
            "type": "host_call",
            "id": id,
            "method": "config_get",
            "params": {"key": key},
        });
        self.write_line(&msg).await?;
        let reply = self.read_reply(id).await?;
        if reply.get("error").is_some() {
            return Ok(None);
        }
        Ok(reply
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()))
    }

    pub async fn audit_emit(&mut self, payload: &[u8]) -> std::io::Result<()> {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({
            "type": "host_call",
            "id": id,
            "method": "audit_emit",
            "params": {
                "data_b64": base64::engine::general_purpose::STANDARD.encode(payload),
            },
        });
        self.write_line(&msg).await?;
        let _ = self.read_reply(id).await?;
        Ok(())
    }

    pub async fn set_response(&mut self, payload: &[u8]) -> std::io::Result<()> {
        let msg = json!({
            "type": "set_response",
            "data_b64": base64::engine::general_purpose::STANDARD.encode(payload),
        });
        self.write_line(&msg).await
    }

    pub async fn done(&mut self, status: i32) -> std::io::Result<()> {
        let msg = json!({"type": "done", "status": status});
        self.write_line(&msg).await
    }

    async fn write_line(&mut self, msg: &Value) -> std::io::Result<()> {
        let mut bytes = serde_json::to_vec(msg)?;
        bytes.push(b'\n');
        self.writer.write_all(&bytes).await?;
        self.writer.flush().await?;
        Ok(())
    }

    async fn read_reply(&mut self, expected_id: u64) -> std::io::Result<Value> {
        loop {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "host closed stdin before replying",
                ));
            }
            let v: Value = serde_json::from_str(line.trim()).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("bad reply: {e}"))
            })?;
            if v.get("id").and_then(|v| v.as_u64()) == Some(expected_id) {
                return Ok(v);
            }
            // Out-of-order replies are not expected in v1 (we don't
            // pipeline calls) — but ignore unrelated lines to stay
            // robust if the host evolves.
        }
    }
}

use base64::Engine as _;
