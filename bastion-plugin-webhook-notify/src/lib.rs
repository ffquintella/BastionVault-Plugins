//! Reference **app-module** plugin for BastionVault — Extensibility v2.
//!
//! Demonstrates the full app-module surface end-to-end, including the
//! double-gated network path:
//!
//! * `bvx_init` seeds a dynamic sidebar menu with a live badge.
//! * `bvx_tick` (≥ 30 s cadence) refreshes the badge from the plugin's
//!   own mount via `bvx.api_request`.
//! * `bvx_menu_click` reads recent mount activity via `bvx.api_request`
//!   and POSTs a summary to an admin-granted webhook via `bvx.net_http`.
//!
//! The network call only works once an admin grants
//! `capabilities.app.net.hosts` (see `plugin.toml`) in the Plugins →
//! Network access panel; without the grant `host.http(...)` returns
//! `NetError::NotGranted` and the plugin degrades gracefully (it still
//! updates the badge, just doesn't notify).
//!
//! Handlers are unit-testable on the host via the SDK's `host_test`
//! stubs — see the tests at the bottom (no GUI, no wasmtime needed).

#![cfg_attr(all(target_arch = "wasm32", not(feature = "host_test")), no_std)]
extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};

use base64::Engine;
use bastion_plugin_sdk::app::{
    ApiOp, AppContext, AppHost, AppModule, HttpRequest, Menu, MenuClick, NetError,
};
use bastion_plugin_sdk::{app_module, LogLevel};

/// Where the badge/notify count comes from: the plugin lists its own
/// mount under `{mount}/events` and reports how many entries exist.
pub const EVENTS_PATH: &str = "{mount}/events";

pub struct WebhookNotify;

/// Parse the `{"data": {"keys": [...]}}` envelope `bvx.api_request`
/// returns for a `list`, yielding the entry count.
pub fn count_from_list(resp: &[u8]) -> usize {
    serde_json::from_slice::<serde_json::Value>(resp)
        .ok()
        .and_then(|v| {
            v.get("data")
                .and_then(|d| d.get("keys"))
                .and_then(|k| k.as_array())
                .map(|a| a.len())
        })
        .unwrap_or(0)
}

impl WebhookNotify {
    /// Read the current event count and upsert the status menu with a
    /// badge. Returns the count so callers can decide whether to notify.
    pub fn refresh_badge(plugin: &str, host: &AppHost) -> usize {
        let count = match host.api_request(ApiOp::List, EVENTS_PATH, None) {
            Ok(resp) => count_from_list(&resp),
            Err(_) => 0,
        };
        let _ = host.menu_upsert(&Menu {
            id: "webhook.status".to_string(),
            label: "Webhook activity".to_string(),
            icon: String::new(),
            section: "admin".to_string(),
            route: format!("/plugin/{plugin}/status"),
            min_policy: String::new(),
            badge: if count > 0 { Some(count.to_string()) } else { None },
        });
        count
    }
}

impl AppModule for WebhookNotify {
    fn init(ctx: &AppContext, host: &AppHost) -> i32 {
        host.log(LogLevel::Info, "webhook-notify: init");
        WebhookNotify::refresh_badge(&ctx.plugin, host);
        0
    }

    fn tick(_now_ms: i64, host: &AppHost) -> i32 {
        // The tick context doesn't carry the mount, but the menu route
        // prefix is fixed per plugin; re-derive from the existing menu
        // by refreshing with the well-known plugin name is not possible
        // here, so tick simply re-reads via the mount placeholder (the
        // host substitutes `{mount}`).
        let count = match host.api_request(ApiOp::List, EVENTS_PATH, None) {
            Ok(resp) => count_from_list(&resp),
            Err(_) => return 0,
        };
        // Update just the badge on the existing menu id.
        let _ = host.menu_upsert(&Menu {
            id: "webhook.status".to_string(),
            label: "Webhook activity".to_string(),
            icon: String::new(),
            section: "admin".to_string(),
            // Route is validated against the plugin prefix host-side; the
            // host rejects a mismatched prefix, so we keep the id stable
            // and let the init-set route stand (menu_upsert merges by id).
            route: "/plugin/webhook-notify/status".to_string(),
            min_policy: String::new(),
            badge: if count > 0 { Some(count.to_string()) } else { None },
        });
        0
    }

    fn menu_click(_ev: &MenuClick, host: &AppHost) -> i32 {
        let count = match host.api_request(ApiOp::List, EVENTS_PATH, None) {
            Ok(resp) => count_from_list(&resp),
            Err(_) => 0,
        };
        // Build a compact JSON summary and POST it to the granted host.
        let payload = format!("{{\"event\":\"summary\",\"count\":{count}}}");
        let req = HttpRequest {
            method: "POST".to_string(),
            url: "https://hooks.example.com/notify".to_string(),
            headers: {
                let mut h = alloc::collections::BTreeMap::new();
                h.insert("content-type".to_string(), "application/json".to_string());
                h
            },
            body_b64: Some(base64::engine::general_purpose::STANDARD.encode(payload.as_bytes())),
            timeout_ms: Some(10_000),
        };
        match host.http(&req) {
            Ok(resp) => {
                host.log(LogLevel::Info, &format!("webhook-notify: posted, status {}", resp.status));
                0
            }
            Err(NetError::NotGranted) => {
                // Degrade gracefully: no grant → skip the notify.
                host.log(LogLevel::Warn, "webhook-notify: network not granted; skipping");
                0
            }
            Err(_) => {
                host.log(LogLevel::Error, "webhook-notify: webhook post refused");
                1
            }
        }
    }
}

app_module!(WebhookNotify);

#[cfg(all(test, feature = "host_test"))]
mod tests {
    use super::*;
    use bastion_plugin_sdk::app::test_support;

    fn ctx() -> AppContext {
        AppContext {
            plugin: "webhook-notify".into(),
            version: "0.1.0".into(),
            mount: "secret/webhooks".into(),
            policies: alloc::vec![],
            locale: "en".into(),
        }
    }

    #[test]
    #[serial_test::serial]
    fn init_seeds_badge_from_mount() {
        test_support::reset();
        // The mount lists three events → badge "3".
        test_support::script_api(br#"{"data":{"keys":["a","b","c"]}}"#);
        assert_eq!(WebhookNotify::init(&ctx(), &AppHost::new()), 0);
        let menus = test_support::menus();
        assert_eq!(menus.len(), 1);
        assert_eq!(menus[0].0, "webhook.status");
        let json: serde_json::Value = serde_json::from_slice(&menus[0].1).unwrap();
        assert_eq!(json["badge"], "3");
    }

    #[test]
    #[serial_test::serial]
    fn click_posts_summary_when_granted() {
        test_support::reset();
        // First api_request (list) → 2 events; then net POST succeeds.
        test_support::script_api(br#"{"data":{"keys":["x","y"]}}"#);
        test_support::script_net_ok(br#"{"status":202,"bytes":0,"body_b64":""}"#);
        assert_eq!(WebhookNotify::menu_click(&MenuClick { id: "webhook.status".into() }, &AppHost::new()), 0);
    }

    #[test]
    #[serial_test::serial]
    fn click_degrades_when_not_granted() {
        test_support::reset();
        test_support::script_api(br#"{"data":{"keys":[]}}"#);
        // No net scripted → the stub returns NET_NOT_GRANTED, and the
        // handler swallows it (returns 0), demonstrating graceful degrade.
        assert_eq!(WebhookNotify::menu_click(&MenuClick { id: "webhook.status".into() }, &AppHost::new()), 0);
    }
}
