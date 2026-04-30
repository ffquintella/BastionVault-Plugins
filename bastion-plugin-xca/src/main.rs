//! XCA database importer plugin for BastionVault. Process runtime.
//!
//! See `features/xca-import.md` in the host repo for the spec.
//!
//! ## Wire protocol (recap — same as `bastion-plugin-postgres`)
//!
//! 1. Host writes one init line:
//!    `{"type":"init","token":"...","input":"<base64 JSON>","plugin_name":"..."}`
//! 2. Plugin writes zero or more host_call lines (we don't, beyond
//!    optional `log` calls), each followed by a host reply.
//! 3. Plugin writes a `set_response` line then a `done`.
//!
//! ## Operations (in `input.op`)
//!
//! - `validate` — cheap version sniff. Returns `{ok, format_version,
//!   requires_password, ownpass_keys}`.
//! - `preview` — full parse + decrypt-what-we-can. Returns the
//!   structured item list with per-row decrypt status and a
//!   `decryption_failures` list for the GUI to surface.
//! - `import` — alias for `preview` in v1: the GUI walks the returned
//!   plan and issues PKI / KV writes via the host's existing routes.
//!   The plugin never mutates vault state directly; this keeps the
//!   security model unchanged (all writes pass through the host's
//!   policy + audit pipeline).
//!
//! Input shape (all operations):
//!
//! ```json
//! {
//!   "op": "preview",
//!   "file_path": "/abs/path/to/db.xdb",   // OR "file_b64": "..."
//!   "master_password": "string?",
//!   "per_key_passwords": { "key-name": "string" }?
//! }
//! ```

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, BufReader};

mod crypto;
mod proto;
mod xca;

#[derive(Deserialize)]
struct Input {
    op: String,
    /// Path to the `.xdb` file. Mutually exclusive with `file_b64`.
    #[serde(default)]
    file_path: Option<String>,
    /// Inline file bytes (base64) — used by GUIs that want to keep
    /// the file off-disk.
    #[serde(default)]
    file_b64: Option<String>,
    #[serde(default)]
    master_password: Option<String>,
    #[serde(default)]
    per_key_passwords: BTreeMap<String, String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();

    let bootstrap_token = std::env::var("BV_PLUGIN_BOOTSTRAP_TOKEN").unwrap_or_default();

    let mut init_line = String::new();
    let n = reader.read_line(&mut init_line).await?;
    if n == 0 {
        eprintln!("xca-plugin: stdin closed before init");
        std::process::exit(90);
    }
    let init: Value = serde_json::from_str(init_line.trim()).unwrap_or_else(|e| {
        eprintln!("xca-plugin: init parse failed: {e}");
        std::process::exit(91);
    });

    let init_token = init.get("token").and_then(|v| v.as_str()).unwrap_or("");
    if init_token != bootstrap_token {
        eprintln!("xca-plugin: bootstrap token mismatch");
        std::process::exit(92);
    }

    let input_b64 = init.get("input").and_then(|v| v.as_str()).unwrap_or("");
    let input_bytes = base64::engine::general_purpose::STANDARD
        .decode(input_b64)
        .unwrap_or_default();

    let mut io = proto::Io::new(&mut reader, &mut stdout);

    let parsed: Input = match serde_json::from_slice(&input_bytes) {
        Ok(v) => v,
        Err(e) => {
            return reply_error(&mut io, format!("invalid input JSON: {e}")).await;
        }
    };

    let temp_holder; // keeps the temp file alive for the lifetime of `path`
    let path: PathBuf = match (parsed.file_path.as_deref(), parsed.file_b64.as_deref()) {
        (Some(p), None) => PathBuf::from(p),
        (None, Some(b64)) => match write_temp(b64) {
            Ok(t) => {
                let p = t.path().to_path_buf();
                temp_holder = Some(t);
                let _ = &temp_holder;
                p
            }
            Err(e) => return reply_error(&mut io, format!("decode file_b64: {e}")).await,
        },
        (Some(_), Some(_)) => {
            return reply_error(&mut io, "supply file_path OR file_b64, not both".into()).await
        }
        (None, None) => {
            return reply_error(&mut io, "file_path or file_b64 is required".into()).await
        }
    };

    let result: Result<Value, String> = match parsed.op.as_str() {
        "validate" => xca::validate(&path)
            .map(|v| serde_json::to_value(v).unwrap())
            .map_err(|e| e.to_string()),
        "preview" | "import" => xca::preview(
            &path,
            parsed.master_password.as_deref(),
            &parsed.per_key_passwords,
        )
        .map(|v| serde_json::to_value(v).unwrap())
        .map_err(|e| e.to_string()),
        other => Err(format!("unknown op `{other}`")),
    };

    match result {
        Ok(v) => {
            let body = serde_json::to_vec(&v)?;
            io.set_response(&body).await?;
            io.done(0).await?;
        }
        Err(e) => {
            let body = json!({"error": e}).to_string();
            io.set_response(body.as_bytes()).await?;
            io.done(1).await?;
        }
    }

    Ok(())
}

async fn reply_error<R, W>(io: &mut proto::Io<'_, R, W>, msg: String) -> io::Result<()>
where
    R: tokio::io::AsyncBufRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    let body = json!({"error": msg}).to_string();
    io.set_response(body.as_bytes()).await?;
    io.done(1).await?;
    Ok(())
}

/// Write the inline base64 bytes to a temp file so SQLite can open
/// it with normal file APIs. We don't try to do an in-memory
/// `:memory:` SQLite + `BACKUP` because rusqlite's bundled SQLite
/// requires the original file's pager state for some XCA reads.
fn write_temp(b64: &str) -> Result<TempFile, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| e.to_string())?;
    let dir = std::env::temp_dir();
    let nonce = std::process::id();
    let path = dir.join(format!("bv-xca-{nonce}-{}.xdb", random_suffix()));
    std::fs::write(&path, &bytes).map_err(|e| e.to_string())?;
    Ok(TempFile { path })
}

fn random_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{n:x}")
}

struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
