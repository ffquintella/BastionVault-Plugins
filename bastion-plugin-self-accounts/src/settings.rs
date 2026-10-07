//! Administrator settings (spec §3, "Plugin config"). Read per invocation from
//! the host config; every field has a safe default.

use bastion_plugin_sdk::Host;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequireTargets {
    /// Targets are never mandatory.
    None,
    /// Mandatory for web (the default).
    Web,
    /// Mandatory for SSH, RDP and web.
    All,
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub allow_ssh_keys: bool,
    pub allow_totp_seeds: bool,
    pub max_accounts_per_user: usize,
    pub require_connect_mfa: bool,
    pub require_targets: RequireTargets,
    pub allowed_resource_types: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            allow_ssh_keys: true,
            allow_totp_seeds: false,
            max_accounts_per_user: 25,
            require_connect_mfa: true,
            require_targets: RequireTargets::Web,
            allowed_resource_types: Vec::new(),
        }
    }
}

impl Settings {
    pub fn load(host: &Host) -> Self {
        let d = Settings::default();
        Settings {
            allow_ssh_keys: host.config_get_bool("allow_ssh_keys").unwrap_or(d.allow_ssh_keys),
            allow_totp_seeds: host.config_get_bool("allow_totp_seeds").unwrap_or(d.allow_totp_seeds),
            max_accounts_per_user: host
                .config_get_i64("max_accounts_per_user")
                .filter(|n| *n > 0)
                .map(|n| n.min(1000) as usize)
                .unwrap_or(d.max_accounts_per_user),
            require_connect_mfa: host
                .config_get_bool("require_connect_mfa")
                .unwrap_or(d.require_connect_mfa),
            // An unknown value fails toward the stricter reading, not the default.
            require_targets: match host.config_get("require_targets").as_deref() {
                Some("all") => RequireTargets::All,
                Some("web") | None | Some("") => RequireTargets::Web,
                Some(_) => RequireTargets::All,
            },
            allowed_resource_types: host
                .config_get("allowed_resource_types")
                .map(|s| {
                    s.split(',')
                        .map(|t| t.trim().to_string())
                        .filter(|t| !t.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    pub fn view(&self) -> SettingsView {
        SettingsView {
            allow_ssh_keys: self.allow_ssh_keys,
            allow_totp_seeds: self.allow_totp_seeds,
            max_accounts_per_user: self.max_accounts_per_user,
            require_connect_mfa: self.require_connect_mfa,
            require_targets: match self.require_targets {
                RequireTargets::All => "all",
                RequireTargets::Web => "web",
                RequireTargets::None => "none",
            },
            allowed_resource_types: self.allowed_resource_types.clone(),
        }
    }
}

/// What `v2/settings` returns. No secrets.
#[derive(Debug, Serialize)]
pub struct SettingsView {
    pub allow_ssh_keys: bool,
    pub allow_totp_seeds: bool,
    pub max_accounts_per_user: usize,
    pub require_connect_mfa: bool,
    pub require_targets: &'static str,
    pub allowed_resource_types: Vec<String>,
}
