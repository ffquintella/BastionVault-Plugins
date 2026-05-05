//! Password Manager Pro importer plugin for BastionVault. Process
//! runtime. See `features/pmp-import.md` in the host repo.
//!
//! Wire protocol mirrors `bastion-plugin-xca`: line-delimited JSON
//! over stdin/stdout, single-shot per invocation. The plugin only
//! parses + structures; the host's GUI walks the returned plan
//! against existing Resource / KV / Asset Group Tauri commands.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use base64::Engine as _;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, BufReader};

mod proto;

use bastion_plugin_pmp::{plan::PlanOptions, preview, validate};

#[derive(Deserialize)]
struct Input {
    op: String,
    /// Path to the `.xls` / `.xlsx` file. Mutually exclusive with
    /// `file_b64`.
    #[serde(default)]
    file_path: Option<String>,
    /// Inline file bytes (base64). Used by GUIs that prefer to keep
    /// the file off-disk.
    #[serde(default)]
    file_b64: Option<String>,
    #[serde(default)]
    batch_id: Option<String>,
    #[serde(default)]
    type_overrides: BTreeMap<String, String>,
    #[serde(default)]
    name_collision_policy: Option<String>,
    #[serde(default)]
    preserve_unknown_columns: bool,
    #[serde(default)]
    tag_columns: Vec<String>,
    #[serde(default)]
    existing_asset_groups: Vec<String>,
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
        eprintln!("pmp-plugin: stdin closed before init");
        std::process::exit(90);
    }
    let init: Value = serde_json::from_str(init_line.trim()).unwrap_or_else(|e| {
        eprintln!("pmp-plugin: init parse failed: {e}");
        std::process::exit(91);
    });

    let init_token = init.get("token").and_then(|v| v.as_str()).unwrap_or("");
    if init_token != bootstrap_token {
        eprintln!("pmp-plugin: bootstrap token mismatch");
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

    let _temp_holder; // keeps the temp file alive for the lifetime of `path`
    let path: PathBuf = match (parsed.file_path.as_deref(), parsed.file_b64.as_deref()) {
        (Some(p), None) => PathBuf::from(p),
        (None, Some(b64)) => match write_temp(b64) {
            Ok(t) => {
                let p = t.path().to_path_buf();
                _temp_holder = Some(t);
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

    let opts = PlanOptions {
        batch_id: parsed.batch_id,
        type_overrides: parsed.type_overrides,
        name_collision_policy: parsed.name_collision_policy,
        preserve_unknown_columns: parsed.preserve_unknown_columns,
        tag_columns: parsed.tag_columns,
        existing_asset_groups: parsed.existing_asset_groups,
    };

    let result: Result<Value, String> = match parsed.op.as_str() {
        "validate" => validate(&path)
            .map(|v| serde_json::to_value(v).unwrap())
            .map_err(|e| e.to_string()),
        "preview" | "import" => preview(&path, &opts)
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

/// Write the inline base64 bytes to a temp file so calamine can open
/// it with normal file APIs (it needs `Read + Seek`).
fn write_temp(b64: &str) -> Result<TempFile, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| e.to_string())?;
    let dir = std::env::temp_dir();
    let nonce = std::process::id();
    let path = dir.join(format!("bv-pmp-{nonce}-{}.xls", random_suffix()));
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
