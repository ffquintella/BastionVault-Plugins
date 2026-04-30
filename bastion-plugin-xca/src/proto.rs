//! Line-delimited JSON-RPC client over stdio. Identical shape to the
//! postgres plugin's `proto.rs`; trimmed to the calls this plugin
//! actually uses (no `audit_emit` — we don't emit audit events
//! ourselves; the host audits the GUI's PKI / KV writes that consume
//! our plan).

use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

use base64::Engine as _;

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

    #[allow(dead_code)]
    pub async fn log(&mut self, level: &str, message: &str) -> std::io::Result<()> {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({
            "type": "host_call",
            "id": id,
            "method": "log",
            "params": {"level": level, "message": message},
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
        }
    }
}
