//! `bastion-plugin-self-accounts`: operator-registered accounts, picked at
//! Connect. A credential provider for BastionVault (ABI 1.3).
//!
//! Spec: features/self-accounts.md. The host attests the caller and rebases
//! this plugin's storage onto that caller's entity, so nothing here can address
//! another user's records. Secrets are write-only: no path returns one, and the
//! only way out is `provider.release`, which the host reaches from Connect.

pub mod api;
pub mod matching;
pub mod model;
pub mod seen;
pub mod settings;
pub mod store;
pub mod timefmt;

#[cfg(all(test, feature = "host_test"))]
mod tests;

use bastion_plugin_sdk::provider::{
    Caller, CandidatesQuery, Candidate, CredentialProvider, LogicalOp, ProviderError, Released,
    ReleaseRequest, ReleasedSecret,
};
use bastion_plugin_sdk::{provider_module, Host, LogLevel, Response};

use crate::matching::account_matches;
use crate::model::{AccountMeta, KIND_PASSWORD, KIND_SSH_KEY};
use crate::seen::{Seen, SeenProblem};
use crate::settings::Settings;

pub struct SelfAccounts;

fn matching_accounts(host: &Host, settings: &Settings, protocol: &str, resource: &bastion_plugin_sdk::provider::Resource, target: &bastion_plugin_sdk::provider::Target) -> Result<Vec<AccountMeta>, ProviderError> {
    let ids = store::list_ids(host).map_err(|_| ProviderError::INTERNAL)?;
    let mut out = Vec::new();
    for id in ids {
        match store::load_meta(host, &id) {
            Ok(Some(m)) if account_matches(&m, settings, protocol, resource, target) => out.push(m),
            Ok(_) => {}
            // One unreadable record must not hide the others, but it is logged.
            Err(e) => host.log(LogLevel::Warn, &format!("skipping unreadable account {id}: {}", e.0)),
        }
    }
    Ok(out)
}

/// When `id` was last released for the target with digest `h`. Read-only: a
/// candidates call never records anything. An unreadable record reads as
/// "never", which errs toward showing the first-use caution.
fn last_use_on(host: &Host, id: &str, h: &str) -> Option<i64> {
    match store::load_seen(host, id) {
        Ok(s) => s.last_use(h),
        Err(_) => {
            host.log(LogLevel::Warn, &format!("ignoring the unreadable seen-target record of account {id}"));
            None
        }
    }
}

/// Remember that `id` was released for the target with digest `h`.
/// Bookkeeping only: a failure is logged and never fails the launch.
fn record_release(host: &Host, id: &str, h: String, now_ms: i64) {
    let mut seen = match store::load_seen(host, id) {
        Ok(s) => s,
        // Written by a newer plugin: leave it alone rather than downgrade it.
        Err(SeenProblem::Newer) => {
            host.log(LogLevel::Warn, &format!("not recording the target of account {id}: its record is from a newer version"));
            return;
        }
        Err(SeenProblem::Unreadable) => {
            host.log(LogLevel::Warn, &format!("replacing the unreadable seen-target record of account {id}"));
            Seen::default()
        }
    };
    seen.record(h, now_ms);
    if store::save_seen(host, id, &seen).is_err() {
        host.log(LogLevel::Warn, "could not record the released target");
    }
}

impl CredentialProvider for SelfAccounts {
    fn candidates(_caller: &Caller, q: &CandidatesQuery, host: &Host) -> Result<Vec<Candidate>, ProviderError> {
        let settings = Settings::load(host);
        let mut metas = matching_accounts(host, &settings, &q.protocol, &q.resource, &q.target)?;
        metas.sort_by(|a, b| a.label.to_lowercase().cmp(&b.label.to_lowercase()).then(a.id.cmp(&b.id)));
        let target = seen::target_hash(&q.target);
        Ok(metas
            .into_iter()
            .map(|m| {
                let last_here = last_use_on(host, &m.id, &target);
                Candidate {
                    // Only advertise a seed the administrator allows to be used.
                    has_totp: m.has_totp && settings.allow_totp_seeds,
                    first_use_on_target: last_here.is_none(),
                    last_used_on_target: last_here.map(timefmt::rfc3339),
                    id: m.id,
                    label: m.label,
                    username: m.username,
                    domain: m.domain,
                    secret_kind: m.secret_kind,
                    last_used_at: m.last_used_at,
                }
            })
            .collect())
    }

    fn release(_caller: &Caller, r: &ReleaseRequest, host: &Host) -> Result<Released, ProviderError> {
        let settings = Settings::load(host);
        // The same rule as `candidates`: a forged or stale id that would not
        // have been offered for this resource, protocol and target is refused.
        let Some(mut meta) = store::load_meta(host, &r.account_id).map_err(|_| ProviderError::INTERNAL)? else {
            return Err(ProviderError::NO_MATCH);
        };
        if !account_matches(&meta, &settings, &r.protocol, &r.resource, &r.target) {
            return Err(ProviderError::NO_MATCH);
        }
        if settings.require_connect_mfa && !r.connect.mfa_verified {
            return Err(ProviderError::MFA_REQUIRED);
        }
        let secret = store::load_secret(host, &meta.id)
            .map_err(|_| ProviderError::INTERNAL)?
            .ok_or(ProviderError::INTERNAL)?;
        if secret.kind != meta.secret_kind {
            return Err(ProviderError::INTERNAL);
        }
        // Only what the recipe asked for: a TOTP seed leaves only when it is
        // requested, stored, and still allowed by the administrator.
        let wants_totp = r.needs.totp;
        if wants_totp && !(meta.has_totp && settings.allow_totp_seeds && secret.totp_seed.is_some()) {
            return Err(ProviderError::BAD_REQUEST);
        }
        let released_secret = match meta.secret_kind.as_str() {
            KIND_PASSWORD => ReleasedSecret::Password {
                password: secret.password.clone().ok_or(ProviderError::INTERNAL)?,
                totp_seed: if wants_totp { secret.totp_seed.clone() } else { None },
            },
            KIND_SSH_KEY => ReleasedSecret::SshKey {
                private_key: secret.private_key.clone().ok_or(ProviderError::INTERNAL)?,
            },
            _ => return Err(ProviderError::INTERNAL),
        };
        let now = host.now_unix_ms();
        meta.last_used_at = Some(timefmt::rfc3339(now));
        if store::save_meta(host, &meta).is_err() {
            // Bookkeeping only; do not fail a launch for it.
            host.log(LogLevel::Warn, "could not record last_used_at");
        }
        // Only here, after every check passed: a refused release (no match,
        // no MFA, an unrequested TOTP) must not make a target look familiar.
        record_release(host, &meta.id, seen::target_hash(&r.target), now);
        Ok(Released { username: meta.username.clone(), domain: meta.domain.clone(), secret: released_secret })
    }

    fn handle_logical(caller: &Caller, op: LogicalOp, host: &Host) -> Response {
        api::handle(caller, op, host)
    }
}

provider_module!(SelfAccounts);
