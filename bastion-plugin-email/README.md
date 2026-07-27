# bastion-plugin-email

Email **notification channel** plugin for BastionVault. Registers an
`email` channel with the core notification system and delivers
notifications either over a **generic SMTP server** or via **Office 365
(OAuth2 client-credentials + Microsoft Graph `sendMail`)**.

Process runtime (real OS network is required for SMTP / HTTPS, which the
WASM sandbox cannot provide). ABI `1.2` (notification capabilities).

## What it does

When an operator (or a plugin) sends a notification and selects the
`email:email` channel, the core notification service resolves each target
user's email address (from their userpass record) and invokes this plugin
with a `notify_deliver` envelope. The plugin sends one message per
recipient and reports `{delivered, failed[]}` back.

Recipients with no email on file are reported as failed for that channel;
they still receive the in-app notification.

## Configuration

Set via the Plugins → Configure modal (or `PUT /v1/sys/plugins/email/config`).

**Common**
- `mode` — `smtp` or `office365`.
- `subject_prefix` — optional prefix for every subject.

**SMTP mode**
- `smtp_host` (**required in this mode**), `smtp_port` (587 STARTTLS /
  465 TLS / 25 none)
- `smtp_tls` — `starttls` | `tls` | `none`
- `smtp_username`, `smtp_password` (**secret**)
- `from_address` (**required in this mode** — usually the same as
  `smtp_username`), `from_name`

**Office 365 mode**
- `o365_tenant_id`, `o365_client_id`, `o365_client_secret` (**secret**)
  — all **required in this mode**
- `o365_sender` (**required in this mode**) — the mailbox to send as
  (the app registration must hold the `Mail.Send` **application**
  permission, admin-consented)

The per-mode fields are marked with `required_if = { field = "mode",
equals = […] }` in `plugin.toml`, so the host rejects an incomplete
config when it is saved rather than at delivery time. Switching `mode`
in the Configure modal re-marks which fields are mandatory; values for
the other mode stay stored and are simply not required.

Passwords/secrets use the `secret` config kind: barrier-encrypted at rest
and never echoed back on config read.

## Security notes

- rustls only (no OpenSSL), matching the host crypto policy.
- The plugin never logs credentials or message bodies. The client secret
  is scrubbed from any transport error string.
- Office 365 basic-auth SMTP is widely disabled by Microsoft; prefer the
  `office365` (OAuth2 / Graph) mode for O365 tenants. The `smtp` mode with
  `smtp.office365.com` still works where SMTP AUTH is enabled.

## Build & register

```bash
cargo build --release -p bastion-plugin-email
# then pack + register the resulting binary with bv-plugin-pack, or
# register via POST /v1/sys/plugins with the process runtime.
```
