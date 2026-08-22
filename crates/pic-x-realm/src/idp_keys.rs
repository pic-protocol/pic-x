// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The verification keys of the identity providers a realm exchanges tokens from.
//!
//! An Exchange Profile names its identity provider by `issuer` and nothing else, so the key set is
//! found the way every OpenID Connect client finds it: fetch
//! `{issuer}/.well-known/openid-configuration`, read `jwks_uri`, fetch that. No new configuration,
//! and an identity provider that rotates its signing key needs no action here.
//!
//! Two properties match the attester cache, for the same reasons: **reads never fetch**, because
//! verification happens on the request path, and **a stale set beats a failed refresh**, because an
//! identity provider's outage must not turn every access token into a forgery. A successful refresh
//! with an empty JWKS is different: it is the provider saying no keys are currently valid, and it
//! replaces whatever had been cached before.
//!
//! What differs is the consequence of having no set at all. Here an exchange is **refused**: a
//! token whose signature was never checked is not something a realm may derive authority from.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

use pic_x_core::ExchangeProfileConfig;

use crate::attester_keys::{KeySetFetcher, parse_key_set};

/// How long a key set that cannot be refreshed keeps being served.
#[cfg(test)]
const SERVE_STALE_FOR: Duration = Duration::from_secs(3_600);

/// The identity-provider key sets one realm holds, keyed by Exchange Profile id.
pub(crate) struct IdpKeyCache {
    profiles: Vec<ExchangeProfileConfig>,
    serve_stale_for: Duration,
    entries: Mutex<BTreeMap<String, Entry>>,
}

struct Entry {
    keys: Vec<Value>,
    fetched_at: Instant,
    failed_since: Option<Instant>,
}

impl IdpKeyCache {
    #[cfg(test)]
    pub(crate) fn new(profiles: Vec<ExchangeProfileConfig>) -> Self {
        Self::with_stale_for(profiles, SERVE_STALE_FOR)
    }

    pub(crate) fn with_stale_for(
        profiles: Vec<ExchangeProfileConfig>,
        serve_stale_for: Duration,
    ) -> Self {
        Self {
            profiles,
            serve_stale_for,
            entries: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// `true` when every configured provider has a key set to serve.
    pub(crate) fn is_ready(&self) -> bool {
        match self.entries.lock() {
            Ok(entries) => self.profiles.iter().all(|p| entries.contains_key(&p.id)),
            Err(_) => false,
        }
    }

    /// The keys currently accepted for one Exchange Profile's identity provider.
    pub(crate) fn keys_for(&self, profile_id: &str) -> Result<Vec<Value>> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| anyhow!("the identity-provider key cache lock is poisoned"))?;
        let entry = entries.get(profile_id).ok_or_else(|| {
            anyhow!("no key set has been fetched yet for the exchange profile `{profile_id}`")
        })?;

        if let Some(failed_since) = entry.failed_since {
            let failure_age = failed_since.elapsed();
            if failure_age > self.serve_stale_for {
                let last_success_age = entry.fetched_at.elapsed();
                bail!(
                    "the cached key set for the exchange profile `{profile_id}` has been stale for \
                     {}s after refresh failures; the last successful fetch was {}s ago",
                    failure_age.as_secs(),
                    last_success_age.as_secs()
                );
            }
        }

        Ok(entry.keys.clone())
    }

    /// Fetches every configured provider's key set through OpenID Connect discovery.
    pub(crate) async fn refresh(&self, fetcher: &dyn KeySetFetcher) {
        for profile in &self.profiles {
            match fetch_provider_keys(
                fetcher,
                profile.source.discovery_base(),
                &profile.source.issuer,
            )
            .await
            {
                Ok(keys) => {
                    if let Ok(mut entries) = self.entries.lock() {
                        entries.insert(
                            profile.id.clone(),
                            Entry {
                                keys,
                                fetched_at: Instant::now(),
                                failed_since: None,
                            },
                        );
                    }
                }
                Err(error) => {
                    if let Ok(mut entries) = self.entries.lock()
                        && let Some(entry) = entries.get_mut(&profile.id)
                        && entry.failed_since.is_none()
                    {
                        entry.failed_since = Some(Instant::now());
                    }
                    tracing::warn!(
                        event.name = "idp.key_set_refresh_failed",
                        component = crate::COMPONENT,
                        exchange_profile = profile.id,
                        issuer = profile.source.issuer,
                        error = %error,
                        "the identity-provider key set could not be refreshed"
                    );
                }
            }
        }
    }
}

/// Discovery, then the key set: the two hops every OpenID Connect client makes.
async fn fetch_provider_keys(
    fetcher: &dyn KeySetFetcher,
    discovery_base: &str,
    issuer: &str,
) -> Result<Vec<Value>> {
    let discovery_uri = format!(
        "{}/.well-known/openid-configuration",
        discovery_base.trim_end_matches('/')
    );
    let document = fetcher
        .fetch(&discovery_uri)
        .await
        .with_context(|| format!("fetching {discovery_uri}"))?;
    let document: Value =
        serde_json::from_slice(&document).context("the discovery document is not JSON")?;

    // The document must agree about who it is: one naming another issuer is not the provider this
    // profile configured, whatever else it serves.
    let declared = document
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("the discovery document has no `issuer`"))?;
    if declared.trim_end_matches('/') != issuer.trim_end_matches('/') {
        bail!("the discovery document declares issuer `{declared}`, not `{issuer}`");
    }

    let jwks_uri = document
        .get("jwks_uri")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("the discovery document has no `jwks_uri`"))?;

    let body = fetcher
        .fetch(jwks_uri)
        .await
        .with_context(|| format!("fetching {jwks_uri}"))?;

    parse_key_set(&body)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a failing assertion is the point"
)]
mod tests {
    use super::*;
    use pic_x_core::BoxFuture;
    use std::sync::Arc;

    const KEY_SET: &str =
        r#"{"keys":[{"kid":"idp-1","kty":"RSA","alg":"RS256","use":"sig","n":"zzz","e":"AQAB"}]}"#;

    /// Answers discovery and key-set URLs, and records what was asked for.
    struct StubIdp {
        issuer: String,
        asked: Mutex<Vec<String>>,
        broken: Mutex<bool>,
        key_set: Mutex<String>,
    }

    impl StubIdp {
        fn new(issuer: &str) -> Arc<Self> {
            Arc::new(Self {
                issuer: issuer.to_owned(),
                asked: Mutex::new(Vec::new()),
                broken: Mutex::new(false),
                key_set: Mutex::new(KEY_SET.to_owned()),
            })
        }

        fn serve_key_set(&self, body: &str) {
            *self.key_set.lock().unwrap() = body.to_owned();
        }
    }

    impl KeySetFetcher for StubIdp {
        fn fetch<'a>(&'a self, uri: &'a str) -> BoxFuture<'a, Result<Vec<u8>>> {
            Box::pin(async move {
                self.asked.lock().unwrap().push(uri.to_owned());
                if *self.broken.lock().unwrap() {
                    bail!("connection refused");
                }
                if uri.ends_with("/.well-known/openid-configuration") {
                    return Ok(serde_json::json!({
                        "issuer": self.issuer,
                        "jwks_uri": format!("{}/keys", self.issuer),
                    })
                    .to_string()
                    .into_bytes());
                }

                Ok(self.key_set.lock().unwrap().as_bytes().to_vec())
            })
        }
    }

    fn profile(issuer: &str) -> ExchangeProfileConfig {
        ExchangeProfileConfig {
            id: "corporate-oauth-to-pic".to_owned(),
            source: pic_x_core::ExchangeProfileSource {
                issuer: issuer.to_owned(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn age_failed_refresh(cache: &IdpKeyCache, by: Duration) {
        let mut entries = cache.entries.lock().unwrap();
        let entry = entries.get_mut("corporate-oauth-to-pic").unwrap();
        entry.failed_since = Some(Instant::now() - by);
    }

    #[tokio::test]
    async fn discovery_leads_to_the_key_set() {
        let idp = StubIdp::new("https://idp.example.com");
        let cache = IdpKeyCache::new(vec![profile("https://idp.example.com")]);
        cache.refresh(idp.as_ref()).await;

        let keys = cache.keys_for("corporate-oauth-to-pic").expect("keys");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kid"], "idp-1");

        let asked = idp.asked.lock().unwrap().clone();
        assert_eq!(
            asked,
            vec![
                "https://idp.example.com/.well-known/openid-configuration",
                "https://idp.example.com/keys",
            ]
        );
    }

    #[tokio::test]
    async fn discovery_can_be_reached_at_an_address_that_is_not_the_issuer() {
        // The provider answers at an internal address but calls itself by its public identity —
        // a container network, a service mesh, a NAT. Both must be honoured: fetch there, match on
        // the identity the token will carry.
        let idp = StubIdp::new("https://idp.example.com");
        let mut configured = profile("https://idp.example.com");
        configured.source.discovery_url = Some("http://keycloak.internal:8080".to_owned());

        let cache = IdpKeyCache::new(vec![configured]);
        cache.refresh(idp.as_ref()).await;

        assert!(cache.keys_for("corporate-oauth-to-pic").is_ok());
        assert_eq!(
            idp.asked.lock().unwrap()[0],
            "http://keycloak.internal:8080/.well-known/openid-configuration"
        );
    }

    #[tokio::test]
    async fn a_discovery_document_naming_another_issuer_is_rejected() {
        // The profile trusts `issuer`; a document claiming to be someone else is not it.
        let idp = StubIdp::new("https://attacker.example.com");
        let cache = IdpKeyCache::new(vec![profile("https://idp.example.com")]);
        cache.refresh(idp.as_ref()).await;

        assert!(cache.keys_for("corporate-oauth-to-pic").is_err());
    }

    #[tokio::test]
    async fn an_unreachable_provider_leaves_the_realm_without_keys() {
        let idp = StubIdp::new("https://idp.example.com");
        *idp.broken.lock().unwrap() = true;
        let cache = IdpKeyCache::new(vec![profile("https://idp.example.com")]);
        cache.refresh(idp.as_ref()).await;

        // No keys means exchanges are refused, not that signatures are waved through.
        assert!(cache.keys_for("corporate-oauth-to-pic").is_err());
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_serving_the_last_known_key_set() {
        let idp = StubIdp::new("https://idp.example.com");
        let cache = IdpKeyCache::new(vec![profile("https://idp.example.com")]);
        cache.refresh(idp.as_ref()).await;
        let first = cache.keys_for("corporate-oauth-to-pic").expect("keys");

        *idp.broken.lock().unwrap() = true;
        cache.refresh(idp.as_ref()).await;

        assert_eq!(cache.keys_for("corporate-oauth-to-pic").unwrap(), first);
    }

    #[tokio::test]
    async fn a_key_set_stale_after_failed_refresh_stops_being_served() {
        let idp = StubIdp::new("https://idp.example.com");
        let cache = IdpKeyCache::new(vec![profile("https://idp.example.com")]);
        cache.refresh(idp.as_ref()).await;

        *idp.broken.lock().unwrap() = true;
        cache.refresh(idp.as_ref()).await;
        age_failed_refresh(&cache, SERVE_STALE_FOR + Duration::from_secs(1));

        assert!(cache.keys_for("corporate-oauth-to-pic").is_err());
    }

    #[tokio::test]
    async fn stale_window_can_fail_closed_after_a_refresh_failure() {
        let idp = StubIdp::new("https://idp.example.com");
        let cache =
            IdpKeyCache::with_stale_for(vec![profile("https://idp.example.com")], Duration::ZERO);
        cache.refresh(idp.as_ref()).await;
        assert!(cache.keys_for("corporate-oauth-to-pic").is_ok());

        *idp.broken.lock().unwrap() = true;
        cache.refresh(idp.as_ref()).await;

        assert!(cache.keys_for("corporate-oauth-to-pic").is_err());
    }

    #[tokio::test]
    async fn a_published_empty_key_set_clears_previously_accepted_keys() {
        let idp = StubIdp::new("https://idp.example.com");
        let cache = IdpKeyCache::new(vec![profile("https://idp.example.com")]);
        cache.refresh(idp.as_ref()).await;
        assert_eq!(cache.keys_for("corporate-oauth-to-pic").unwrap().len(), 1);

        idp.serve_key_set(r#"{"keys":[]}"#);
        cache.refresh(idp.as_ref()).await;

        assert!(cache.keys_for("corporate-oauth-to-pic").unwrap().is_empty());
    }
}
