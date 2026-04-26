//! Reference Postgres dynamic-credential plugin for BastionVault.
//! Process runtime. Speaks the same line-delimited JSON-RPC protocol
//! over stdio that `crate::plugins::process_runtime` in the host
//! drives.
//!
//! ## Wire protocol (recap)
//!
//! 1. Host writes one init line:
//!    `{"type":"init","token":"...","input":"<base64>","plugin_name":"..."}`
//! 2. Plugin writes zero or more host_call lines, each followed by a
//!    matching host_reply / host_reply_error from the host.
//! 3. Plugin writes one `set_response` line then a `done`.
//!
//! ## Operations
//!
//! Input is JSON, dispatched on `op`:
//!
//! ```json
//! {"op":"create"}
//! → {"username":"bv-...","password":"...","valid_until":"..."}
//!
//! {"op":"revoke","username":"bv-..."}
//! → {"revoked":true}
//! ```
//!
//! `connection_string`, `ttl_seconds`, `role_prefix`, and `grants` come
//! from `bv.config_get` (set in the GUI Configure modal). All SQL
//! identifiers are quoted with `"..."` and double-quoted internally —
//! the random username is hex-only so it can't break out of the quote
//! even without escaping.

use std::io;

use base64::Engine as _;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_postgres::NoTls;

mod proto;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum PgRequest {
    Create,
    Revoke { username: String },
}

#[derive(Serialize)]
struct CreateResponse<'a> {
    username: &'a str,
    password: &'a str,
    valid_until_unix: i64,
}

#[derive(Serialize)]
struct RevokeResponse {
    revoked: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();

    let bootstrap_token =
        std::env::var("BV_PLUGIN_BOOTSTRAP_TOKEN").unwrap_or_default();

    // Read init.
    let mut init_line = String::new();
    let n = reader.read_line(&mut init_line).await?;
    if n == 0 {
        eprintln!("postgres-plugin: stdin closed before init");
        std::process::exit(90);
    }
    let init: Value = serde_json::from_str(init_line.trim()).unwrap_or_else(|e| {
        eprintln!("postgres-plugin: init parse failed: {e}");
        std::process::exit(91);
    });

    // Bootstrap-token check. Mirrors the WASM runtime's check on the
    // host side: a process that didn't get the token from the parent
    // can't impersonate the plugin.
    let init_token = init.get("token").and_then(|v| v.as_str()).unwrap_or("");
    if init_token != bootstrap_token {
        eprintln!("postgres-plugin: bootstrap token mismatch");
        std::process::exit(92);
    }

    let input_b64 = init.get("input").and_then(|v| v.as_str()).unwrap_or("");
    let input = base64::engine::general_purpose::STANDARD
        .decode(input_b64)
        .unwrap_or_default();

    // Ask the host for the operator's config. host_call IDs are a
    // local sequence; the parent matches `id` between calls and replies.
    let mut io = proto::Io::new(&mut reader, &mut stdout);
    let conn_str = match io.config_get("connection_string").await {
        Ok(Some(v)) => v,
        Ok(None) => {
            eprintln!("postgres-plugin: connection_string is required");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("postgres-plugin: config_get failed: {e}");
            std::process::exit(3);
        }
    };
    let ttl_seconds = io
        .config_get("ttl_seconds")
        .await
        .ok()
        .flatten()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(3600);
    let role_prefix = io
        .config_get("role_prefix")
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "bv-".to_string());
    let grants_template = io
        .config_get("grants")
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "GRANT CONNECT ON DATABASE postgres TO \"{{name}}\";".to_string());

    let parsed: PgRequest = match serde_json::from_slice(&input) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("postgres-plugin: input parse failed: {e}");
            io.set_response(format!(r#"{{"error":"invalid input: {e}"}}"#).as_bytes()).await?;
            io.done(1).await?;
            return Ok(());
        }
    };

    let result = match parsed {
        PgRequest::Create => {
            handle_create(&conn_str, &role_prefix, &grants_template, ttl_seconds, &mut io).await
        }
        PgRequest::Revoke { username } => handle_revoke(&conn_str, &username, &mut io).await,
    };

    match result {
        Ok((status, body)) => {
            io.set_response(&body).await?;
            io.done(status).await?;
        }
        Err(e) => {
            eprintln!("postgres-plugin: handler error: {e}");
            let body = json!({"error": e.to_string()}).to_string();
            io.set_response(body.as_bytes()).await?;
            io.done(1).await?;
        }
    }

    Ok(())
}

async fn handle_create<R, W>(
    conn_str: &str,
    role_prefix: &str,
    grants_template: &str,
    ttl_seconds: i64,
    io: &mut proto::Io<'_, R, W>,
) -> Result<(i32, Vec<u8>), Box<dyn std::error::Error>>
where
    R: tokio::io::AsyncBufRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    let username = generate_role_name(role_prefix);
    let password = generate_password();
    let valid_until_unix = current_unix_time() + ttl_seconds;

    let (client, connection) = tokio_postgres::connect(conn_str, NoTls).await?;
    let _conn_handle = tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("postgres-plugin: connection error: {e}");
        }
    });

    // CREATE ROLE — username is hex-derived so it can't break the
    // double-quoted identifier. Password is base64 (alphanumeric +
    // `+/`); we wrap it in single quotes and double up any literal
    // single quotes per the libpq escaping rule.
    let escaped_password = password.replace('\'', "''");
    let create_sql = format!(
        "CREATE ROLE \"{username}\" LOGIN PASSWORD '{escaped_password}' VALID UNTIL '{ts}';",
        username = username,
        escaped_password = escaped_password,
        ts = unix_to_pg_timestamp(valid_until_unix),
    );
    client.batch_execute(&create_sql).await?;

    let grants = grants_template.replace("{{name}}", &username);
    if !grants.trim().is_empty() {
        client.batch_execute(&grants).await?;
    }

    let _ = io
        .audit_emit(
            json!({
                "event": "postgres.credential.create",
                "username": &username,
                "valid_until_unix": valid_until_unix,
            })
            .to_string()
            .as_bytes(),
        )
        .await;

    let body = serde_json::to_vec(&CreateResponse {
        username: &username,
        password: &password,
        valid_until_unix,
    })?;
    Ok((0, body))
}

async fn handle_revoke<R, W>(
    conn_str: &str,
    username: &str,
    io: &mut proto::Io<'_, R, W>,
) -> Result<(i32, Vec<u8>), Box<dyn std::error::Error>>
where
    R: tokio::io::AsyncBufRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    if !is_safe_identifier(username) {
        return Err(format!("refusing unsafe username '{username}'").into());
    }

    let (client, connection) = tokio_postgres::connect(conn_str, NoTls).await?;
    let _conn_handle = tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("postgres-plugin: connection error: {e}");
        }
    });

    let drop_sql = format!(
        "REASSIGN OWNED BY \"{u}\" TO CURRENT_USER; \
         DROP OWNED BY \"{u}\"; \
         DROP ROLE IF EXISTS \"{u}\";",
        u = username,
    );
    client.batch_execute(&drop_sql).await?;

    let _ = io
        .audit_emit(
            json!({"event": "postgres.credential.revoke", "username": username})
                .to_string()
                .as_bytes(),
        )
        .await;

    let body = serde_json::to_vec(&RevokeResponse { revoked: true })?;
    Ok((0, body))
}

fn generate_role_name(prefix: &str) -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut s = String::with_capacity(prefix.len() + 16);
    s.push_str(prefix);
    for b in bytes {
        // pure hex — safe inside a "..." identifier without further
        // escaping.
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{:02x}", b));
    }
    s
}

fn generate_password() -> String {
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn current_unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn unix_to_pg_timestamp(unix_secs: i64) -> String {
    // Postgres accepts ISO-8601 UTC; format manually to avoid pulling
    // in chrono. We compute days/h/m/s by a fixed-epoch routine that's
    // good enough for VALID UNTIL strings.
    use std::fmt::Write;
    let secs_in_day: i64 = 86_400;
    let mut days = unix_secs.div_euclid(secs_in_day);
    let mut secs_of_day = unix_secs.rem_euclid(secs_in_day);
    let h = secs_of_day / 3600;
    secs_of_day -= h * 3600;
    let m = secs_of_day / 60;
    let s = secs_of_day - m * 60;

    // Civil-from-days (Howard Hinnant). Returns (year, month [1..12], day [1..31]).
    days += 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if mth <= 2 { y + 1 } else { y };

    let mut out = String::new();
    let _ = write!(out, "{:04}-{:02}-{:02} {:02}:{:02}:{:02}+00", year, mth, d, h, m, s);
    out
}

fn is_safe_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_name_uses_prefix_and_hex() {
        let n = generate_role_name("bv-");
        assert!(n.starts_with("bv-"));
        assert_eq!(n.len(), 3 + 16);
        assert!(n[3..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn password_is_url_safe_b64_no_pad() {
        let p = generate_password();
        assert!(!p.is_empty());
        assert!(!p.contains('='));
        assert!(p
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn safe_identifier_accepts_normal_names() {
        assert!(is_safe_identifier("bv-abc123"));
        assert!(is_safe_identifier("user_42"));
    }

    #[test]
    fn safe_identifier_rejects_quotes_and_semicolons() {
        assert!(!is_safe_identifier("a\"b"));
        assert!(!is_safe_identifier("a;DROP"));
        assert!(!is_safe_identifier(""));
        assert!(!is_safe_identifier(&"a".repeat(64)));
    }

    #[test]
    fn pg_timestamp_known_epochs() {
        assert_eq!(unix_to_pg_timestamp(0), "1970-01-01 00:00:00+00");
        // 2024-01-01 00:00:00 UTC = 1704067200
        assert_eq!(unix_to_pg_timestamp(1_704_067_200), "2024-01-01 00:00:00+00");
        // 2038-01-19 03:14:07 UTC = 2147483647 (i32 wrap point — we
        // use i64, so this should still format correctly).
        assert_eq!(unix_to_pg_timestamp(2_147_483_647), "2038-01-19 03:14:07+00");
    }
}
