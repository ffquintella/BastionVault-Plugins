//! Email notification channel plugin for BastionVault. Process runtime.
//!
//! Speaks the same line-delimited JSON-RPC protocol over stdio that
//! `crate::plugins::process_runtime` in the host drives (see
//! [`proto`]). The core notification service invokes this plugin with a
//! `notify_deliver` envelope for the `email` channel:
//!
//! ```json
//! {
//!   "op": "notify_deliver",
//!   "channel": "email",
//!   "notification": { "title": "...", "body": "...", "severity": "warning",
//!                     "action_url": "https://..." },
//!   "recipients": [ { "entity_id": "...", "display_name": "Alice",
//!                     "email": "alice@example.com" }, ... ]
//! }
//! ```
//!
//! It returns `{"delivered": <n>, "failed": [{"recipient": "...",
//! "error": "..."}]}`. Recipients with no email address are reported as
//! failed (nothing else can be done for them on an email channel).
//!
//! Two delivery modes, chosen by the `mode` config key:
//!   * `smtp`      — generic SMTP (STARTTLS / implicit TLS / none) with
//!                   optional SMTP AUTH, via `lettre` over rustls.
//!   * `office365` — OAuth2 client-credentials against Entra ID, then
//!                   Microsoft Graph `POST /users/{sender}/sendMail`.
//!
//! Secrets (`smtp_password`, `o365_client_secret`) are read via
//! `bv.config_get`; the host stores them barrier-encrypted and never
//! echoes them back. This plugin never logs credentials or message
//! bodies.

use std::io;

use base64::Engine as _;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, BufReader};

mod proto;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum EmailRequest {
    NotifyDeliver {
        #[serde(default)]
        notification: NotificationPayload,
        #[serde(default)]
        recipients: Vec<Recipient>,
    },
}

#[derive(Debug, Default, Deserialize)]
struct NotificationPayload {
    #[serde(default)]
    title: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    action_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Recipient {
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    email: String,
}

/// Resolved operator config for the chosen mode.
struct Config {
    mode: String,
    // smtp
    smtp_host: String,
    smtp_port: u16,
    smtp_tls: String,
    smtp_username: String,
    smtp_password: String,
    from_address: String,
    from_name: String,
    // office365
    o365_tenant_id: String,
    o365_client_id: String,
    o365_client_secret: String,
    o365_sender: String,
    // common
    subject_prefix: String,
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
        eprintln!("email-plugin: stdin closed before init");
        std::process::exit(90);
    }
    let init: Value = serde_json::from_str(init_line.trim()).unwrap_or_else(|e| {
        eprintln!("email-plugin: init parse failed: {e}");
        std::process::exit(91);
    });

    let init_token = init.get("token").and_then(|v| v.as_str()).unwrap_or("");
    if init_token != bootstrap_token {
        eprintln!("email-plugin: bootstrap token mismatch");
        std::process::exit(92);
    }

    let input_b64 = init.get("input").and_then(|v| v.as_str()).unwrap_or("");
    let input = base64::engine::general_purpose::STANDARD
        .decode(input_b64)
        .unwrap_or_default();

    let mut io = proto::Io::new(&mut reader, &mut stdout);

    let cfg = read_config(&mut io).await;

    let parsed: EmailRequest = match serde_json::from_slice(&input) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("email-plugin: input parse failed: {e}");
            io.set_response(json!({"error": format!("invalid input: {e}")}).to_string().as_bytes())
                .await?;
            io.done(1).await?;
            return Ok(());
        }
    };

    let EmailRequest::NotifyDeliver { notification, recipients } = parsed;

    let (delivered, failed) = deliver(&cfg, &notification, &recipients).await;

    // Audit the batch — counts only, never addresses or the body.
    let _ = io
        .audit_emit(
            json!({"channel": "email", "mode": cfg.mode, "delivered": delivered, "failed": failed.len()})
                .to_string()
                .as_bytes(),
        )
        .await;

    let body = json!({ "delivered": delivered, "failed": failed });
    io.set_response(body.to_string().as_bytes()).await?;
    io.done(0).await?;
    Ok(())
}

async fn read_config<R, W>(io: &mut proto::Io<'_, R, W>) -> Config
where
    R: tokio::io::AsyncBufRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    async fn get<R, W>(io: &mut proto::Io<'_, R, W>, key: &str) -> String
    where
        R: tokio::io::AsyncBufRead + Unpin + Send,
        W: tokio::io::AsyncWrite + Unpin + Send,
    {
        io.config_get(key).await.ok().flatten().unwrap_or_default()
    }

    let smtp_port = get(io, "smtp_port")
        .await
        .parse::<u16>()
        .unwrap_or(587);

    Config {
        mode: {
            let m = get(io, "mode").await;
            if m.is_empty() { "smtp".to_string() } else { m }
        },
        smtp_host: get(io, "smtp_host").await,
        smtp_port,
        smtp_tls: {
            let t = get(io, "smtp_tls").await;
            if t.is_empty() { "starttls".to_string() } else { t }
        },
        smtp_username: get(io, "smtp_username").await,
        smtp_password: get(io, "smtp_password").await,
        from_address: get(io, "from_address").await,
        from_name: get(io, "from_name").await,
        o365_tenant_id: get(io, "o365_tenant_id").await,
        o365_client_id: get(io, "o365_client_id").await,
        o365_client_secret: get(io, "o365_client_secret").await,
        o365_sender: get(io, "o365_sender").await,
        subject_prefix: get(io, "subject_prefix").await,
    }
}

/// Render the subject + plain-text body for a notification.
fn render(cfg: &Config, n: &NotificationPayload) -> (String, String) {
    let subject = format!("{}{}", cfg.subject_prefix, n.title);
    let mut body = n.body.clone();
    if let Some(url) = &n.action_url {
        if !url.is_empty() {
            body.push_str("\n\n");
            body.push_str(url);
        }
    }
    if !n.severity.is_empty() {
        body = format!("[{}] {}", n.severity, body);
    }
    (subject, body)
}

/// Deliver to every recipient, returning `(delivered_count, failures)`.
async fn deliver(
    cfg: &Config,
    notification: &NotificationPayload,
    recipients: &[Recipient],
) -> (u64, Vec<Value>) {
    let (subject, body) = render(cfg, notification);
    let mut delivered = 0u64;
    let mut failed: Vec<Value> = Vec::new();

    let with_email: Vec<&Recipient> = recipients.iter().filter(|r| !r.email.is_empty()).collect();
    for r in recipients.iter().filter(|r| r.email.is_empty()) {
        failed.push(json!({"recipient": r.display_name, "error": "no email address"}));
    }
    if with_email.is_empty() {
        return (delivered, failed);
    }

    match cfg.mode.as_str() {
        "office365" => {
            match o365_token(cfg).await {
                Ok(token) => {
                    for r in with_email {
                        match o365_send(cfg, &token, &r.email, &subject, &body).await {
                            Ok(()) => delivered += 1,
                            Err(e) => {
                                failed.push(json!({"recipient": r.email, "error": e}))
                            }
                        }
                    }
                }
                Err(e) => {
                    // Token acquisition failed → everyone fails with the
                    // same reason (don't leak the secret; `o365_token`
                    // already scrubs it).
                    for r in with_email {
                        failed.push(json!({"recipient": r.email, "error": e.clone()}));
                    }
                }
            }
        }
        // Default to SMTP for "smtp" or any unknown mode.
        _ => match smtp_transport(cfg) {
            Ok(transport) => {
                for r in with_email {
                    match smtp_send(cfg, &transport, r, &subject, &body).await {
                        Ok(()) => delivered += 1,
                        Err(e) => failed.push(json!({"recipient": r.email, "error": e})),
                    }
                }
            }
            Err(e) => {
                for r in with_email {
                    failed.push(json!({"recipient": r.email, "error": e.clone()}));
                }
            }
        },
    }

    (delivered, failed)
}

// ── SMTP ──────────────────────────────────────────────────────────────

fn smtp_transport(cfg: &Config) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
    if cfg.smtp_host.trim().is_empty() {
        return Err("smtp_host is not configured".to_string());
    }
    let host = cfg.smtp_host.trim();
    let mut builder = match cfg.smtp_tls.as_str() {
        "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(host)
            .map_err(|e| format!("smtp relay setup failed: {e}"))?,
        "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
        // Default STARTTLS.
        _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
            .map_err(|e| format!("smtp starttls setup failed: {e}"))?,
    }
    .port(cfg.smtp_port);

    if !cfg.smtp_username.is_empty() {
        builder = builder.credentials(Credentials::new(
            cfg.smtp_username.clone(),
            cfg.smtp_password.clone(),
        ));
    }
    Ok(builder.build())
}

async fn smtp_send(
    cfg: &Config,
    transport: &AsyncSmtpTransport<Tokio1Executor>,
    r: &Recipient,
    subject: &str,
    body: &str,
) -> Result<(), String> {
    let from = build_from(cfg)?;
    let to: Mailbox = if r.display_name.is_empty() {
        r.email.parse().map_err(|e| format!("bad recipient address: {e}"))?
    } else {
        format!("{} <{}>", r.display_name, r.email)
            .parse()
            .map_err(|e| format!("bad recipient address: {e}"))?
    };
    let message = Message::builder()
        .from(from)
        .to(to)
        .subject(subject)
        .body(body.to_string())
        .map_err(|e| format!("message build failed: {e}"))?;
    transport
        .send(message)
        .await
        .map_err(|e| format!("smtp send failed: {e}"))?;
    Ok(())
}

fn build_from(cfg: &Config) -> Result<Mailbox, String> {
    let addr = if cfg.from_address.is_empty() {
        cfg.smtp_username.clone()
    } else {
        cfg.from_address.clone()
    };
    if addr.is_empty() {
        return Err("from_address (or smtp_username) is required".to_string());
    }
    let spec = if cfg.from_name.is_empty() {
        addr
    } else {
        format!("{} <{}>", cfg.from_name, addr)
    };
    spec.parse().map_err(|e| format!("bad from address: {e}"))
}

// ── Office 365 (OAuth2 client-credentials + Graph sendMail) ────────────

async fn o365_token(cfg: &Config) -> Result<String, String> {
    if cfg.o365_tenant_id.is_empty()
        || cfg.o365_client_id.is_empty()
        || cfg.o365_client_secret.is_empty()
    {
        return Err("office365 mode requires tenant_id, client_id, and client_secret".to_string());
    }
    let url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        cfg.o365_tenant_id
    );
    let params = [
        ("grant_type", "client_credentials"),
        ("client_id", cfg.o365_client_id.as_str()),
        ("client_secret", cfg.o365_client_secret.as_str()),
        ("scope", "https://graph.microsoft.com/.default"),
    ];
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("token request failed: {}", scrub(&e.to_string(), cfg)))?;
    if !resp.status().is_success() {
        let status = resp.status();
        // Do not surface the raw error body — it can echo request params.
        return Err(format!("token endpoint returned {status}"));
    }
    let body: Value = resp
        .json()
        .await
        .map_err(|e| format!("token response parse failed: {e}"))?;
    body.get("access_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "token response missing access_token".to_string())
}

async fn o365_send(
    cfg: &Config,
    token: &str,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<(), String> {
    if cfg.o365_sender.is_empty() {
        return Err("o365_sender is required".to_string());
    }
    let url = format!(
        "https://graph.microsoft.com/v1.0/users/{}/sendMail",
        cfg.o365_sender
    );
    let payload = json!({
        "message": {
            "subject": subject,
            "body": { "contentType": "Text", "content": body },
            "toRecipients": [ { "emailAddress": { "address": to } } ]
        },
        "saveToSentItems": false
    });
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("graph sendMail failed: {e}"))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("graph sendMail returned {}", resp.status()))
    }
}

/// Best-effort scrub of the client secret from an error string so a
/// transport error can never leak it into logs / the response envelope.
fn scrub(s: &str, cfg: &Config) -> String {
    if cfg.o365_client_secret.is_empty() {
        s.to_string()
    } else {
        s.replace(&cfg.o365_client_secret, "<redacted>")
    }
}
