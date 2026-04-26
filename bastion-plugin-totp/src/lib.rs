//! RFC 6238 TOTP plugin for BastionVault. WASM runtime.
//!
//! ## Protocol
//!
//! Input is JSON; the wrapper deserialises and dispatches by `op`:
//!
//! ```json
//! {"op":"generate","secret_b32":"JBSWY3DPEHPK3PXP"}
//! → {"code":"123456","period":30,"digits":6,"now_ms":...,"step":...}
//!
//! {"op":"validate","secret_b32":"JBSWY3DPEHPK3PXP","code":"123456"}
//! → {"valid":true,"matched_offset":0}
//! ```
//!
//! Configuration (set via the Plugins → Configure modal): `digits`
//! (default 6), `period` (default 30), `skew` (default 1 step).
//!
//! Time comes from `bv.now_unix_ms` — always available, not
//! capability-gated. No storage, no audit channel. The plugin is a
//! pure compute capsule; the secret never leaves the request.

#![cfg_attr(all(target_arch = "wasm32", not(feature = "host_test")), no_std)]
extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use bastion_plugin_sdk::{register, Host, LogLevel, Plugin, Request, Response};
use serde::{Deserialize, Serialize};

mod base32;
mod totp;

/// Default RFC 6238 parameters. Overridable via plugin config.
const DEFAULT_DIGITS: u32 = 6;
const DEFAULT_PERIOD: u64 = 30;
const DEFAULT_SKEW: i64 = 1;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum TotpRequest {
    Generate { secret_b32: String },
    Validate { secret_b32: String, code: String },
}

#[derive(Serialize)]
struct GenerateResponse {
    code: String,
    period: u64,
    digits: u32,
    now_ms: i64,
    step: u64,
}

#[derive(Serialize)]
struct ValidateResponse {
    valid: bool,
    matched_offset: Option<i64>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

pub struct TotpPlugin;

impl Plugin for TotpPlugin {
    fn handle(req: Request<'_>, host: &Host) -> Response {
        let parsed: TotpRequest = match req.input_json() {
            Ok(p) => p,
            Err(e) => {
                host.log(LogLevel::Warn, &format!("invalid request: {e}"));
                return error_response(1, &format!("invalid request: {e}"));
            }
        };

        let digits = host
            .config_get_i64("digits")
            .map(|v| v as u32)
            .unwrap_or(DEFAULT_DIGITS);
        let period = host
            .config_get_i64("period")
            .map(|v| v as u64)
            .unwrap_or(DEFAULT_PERIOD);
        let skew = host.config_get_i64("skew").unwrap_or(DEFAULT_SKEW);

        if !(6..=10).contains(&digits) {
            return error_response(2, "digits must be in [6, 10]");
        }
        if period == 0 || period > 600 {
            return error_response(2, "period must be in (0, 600]");
        }
        if !(0..=10).contains(&skew) {
            return error_response(2, "skew must be in [0, 10]");
        }

        match parsed {
            TotpRequest::Generate { secret_b32 } => generate(host, &secret_b32, digits, period),
            TotpRequest::Validate { secret_b32, code } => {
                validate(host, &secret_b32, &code, digits, period, skew)
            }
        }
    }
}

fn generate(host: &Host, secret_b32: &str, digits: u32, period: u64) -> Response {
    let secret = match base32::decode(secret_b32) {
        Some(s) if !s.is_empty() => s,
        _ => return error_response(3, "secret_b32 is not valid base32"),
    };
    let now_ms = host.now_unix_ms();
    let step = step_for(now_ms, period);
    let code = totp::format_code(&secret, step, digits);
    json_response(&GenerateResponse { code, period, digits, now_ms, step })
}

fn validate(
    host: &Host,
    secret_b32: &str,
    code: &str,
    digits: u32,
    period: u64,
    skew: i64,
) -> Response {
    let secret = match base32::decode(secret_b32) {
        Some(s) if !s.is_empty() => s,
        _ => return error_response(3, "secret_b32 is not valid base32"),
    };
    let now_ms = host.now_unix_ms();
    let center = step_for(now_ms, period) as i64;
    for offset in -skew..=skew {
        let candidate_step = center + offset;
        if candidate_step < 0 {
            continue;
        }
        let candidate = totp::format_code(&secret, candidate_step as u64, digits);
        if constant_time_eq(candidate.as_bytes(), code.as_bytes()) {
            return json_response(&ValidateResponse { valid: true, matched_offset: Some(offset) });
        }
    }
    json_response(&ValidateResponse { valid: false, matched_offset: None })
}

fn step_for(now_ms: i64, period: u64) -> u64 {
    let secs = if now_ms < 0 { 0 } else { (now_ms / 1000) as u64 };
    secs / period
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn json_response<T: Serialize>(value: &T) -> Response {
    match serde_json::to_vec(value) {
        Ok(bytes) => Response::ok(bytes),
        Err(_) => error_response(99, "response serialisation failed"),
    }
}

fn error_response(code: i32, msg: &str) -> Response {
    let body = serde_json::to_vec(&ErrorResponse { error: msg.to_string() })
        .unwrap_or_else(|_| Vec::from(msg.as_bytes()));
    Response::err(code, body)
}

register!(TotpPlugin);

#[cfg(all(test, feature = "host_test"))]
mod tests {
    use super::*;
    use bastion_plugin_sdk::test_support;

    fn run(input: &[u8]) -> Response {
        let req = Request::new(input);
        let host = Host::new();
        TotpPlugin::handle(req, &host)
    }

    #[test]
    #[serial_test::serial]
    fn generate_then_validate_round_trip() {
        test_support::reset();
        // RFC 6238 Appendix B uses ASCII secret "12345678901234567890",
        // which encodes to base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        test_support::set_now_ms(Some(59_000));

        let gen_resp = run(format!(r#"{{"op":"generate","secret_b32":"{secret}"}}"#).as_bytes());
        assert_eq!(gen_resp.status, 0);
        let gen: serde_json::Value = serde_json::from_slice(&gen_resp.bytes).unwrap();
        let code = gen["code"].as_str().unwrap();
        // RFC 6238 Appendix B at T=59 with SHA-1 says 94287082 for 8
        // digits; the last 6 are 287082.
        assert_eq!(code, "287082");

        let val_resp = run(
            format!(r#"{{"op":"validate","secret_b32":"{secret}","code":"{code}"}}"#).as_bytes(),
        );
        assert_eq!(val_resp.status, 0);
        let val: serde_json::Value = serde_json::from_slice(&val_resp.bytes).unwrap();
        assert_eq!(val["valid"], serde_json::Value::Bool(true));
        assert_eq!(val["matched_offset"], serde_json::Value::Number(0.into()));

        test_support::set_now_ms(None);
    }

    #[test]
    #[serial_test::serial]
    fn validate_rejects_wrong_code() {
        test_support::reset();
        test_support::set_now_ms(Some(59_000));
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let resp =
            run(format!(r#"{{"op":"validate","secret_b32":"{secret}","code":"000000"}}"#).as_bytes());
        let val: serde_json::Value = serde_json::from_slice(&resp.bytes).unwrap();
        assert_eq!(val["valid"], serde_json::Value::Bool(false));
        test_support::set_now_ms(None);
    }

    #[test]
    #[serial_test::serial]
    fn skew_window_accepts_one_step_back() {
        test_support::reset();
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        // Generate code at T=59
        test_support::set_now_ms(Some(59_000));
        let gen = run(format!(r#"{{"op":"generate","secret_b32":"{secret}"}}"#).as_bytes());
        let code = serde_json::from_slice::<serde_json::Value>(&gen.bytes).unwrap()["code"]
            .as_str()
            .unwrap()
            .to_string();
        // Move the clock forward one step (period=30 → +30s) and validate
        // — should match offset -1 with default skew=1.
        test_support::set_now_ms(Some(89_000));
        let val_resp = run(
            format!(r#"{{"op":"validate","secret_b32":"{secret}","code":"{code}"}}"#).as_bytes(),
        );
        let val: serde_json::Value = serde_json::from_slice(&val_resp.bytes).unwrap();
        assert_eq!(val["valid"], serde_json::Value::Bool(true));
        assert_eq!(val["matched_offset"], serde_json::Value::Number((-1).into()));
        test_support::set_now_ms(None);
    }

    #[test]
    #[serial_test::serial]
    fn invalid_base32_rejected() {
        test_support::reset();
        let resp = run(br#"{"op":"generate","secret_b32":"!!!"}"#);
        assert_ne!(resp.status, 0);
        let err: serde_json::Value = serde_json::from_slice(&resp.bytes).unwrap();
        assert!(err["error"].as_str().unwrap().contains("base32"));
    }

    #[test]
    #[serial_test::serial]
    fn config_overrides_digits() {
        test_support::reset();
        test_support::set_config("digits", "8");
        test_support::set_now_ms(Some(59_000));
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let resp = run(format!(r#"{{"op":"generate","secret_b32":"{secret}"}}"#).as_bytes());
        let val: serde_json::Value = serde_json::from_slice(&resp.bytes).unwrap();
        assert_eq!(val["digits"], serde_json::Value::Number(8.into()));
        // RFC 6238 Appendix B at T=59 with SHA-1 expects "94287082".
        assert_eq!(val["code"].as_str().unwrap(), "94287082");
        test_support::set_now_ms(None);
    }
}
