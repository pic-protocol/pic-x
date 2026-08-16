//! Where a realm gets the verification keys of the attesters it trusts.
//!
//! Configuration names the attesters and their `jwks_uri`; this keeps their published key sets in
//! memory so an attester can rotate its signing key without a PIC-X restart.
//!
//! # Why reads never fetch
//!
//! Proof-of-Relationship validation happens inside the synchronous `PorValidator` boundary of the
//! protocol crate, on the request path. Fetching there would put a network round trip — and another
//! service's availability — in the middle of a token exchange. So [`AttesterKeyCache::keys_for`]
//! only reads memory, and [`AttesterKeyCache::refresh`] is what talks to the network, driven by a
//! background task.
//!
//! Two properties matter for correctness:
//!
//! * **a stale set beats no set** — when a refresh fails, the last fetched keys stay in use until
//!   they age out, because answering "no keys" would turn an attester's transient outage into every
//!   Proof of Relationship being rejected as a forgery;
//! * **an empty set is never an answer** — a realm that has never reached its attester rejects, and
//!   says why, rather than behaving as though the attester published nothing.

use std::collections::BTreeMap;
#[cfg(test)]
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

use pic_x_core::{BoxFuture, TrustedAttesterConfig};

/// How often the background task refreshes a key set.
pub(crate) const REFRESH_EVERY: Duration = Duration::from_secs(300);
/// How soon it retries while some configured source has never answered.
pub(crate) const RETRY_UNTIL_READY: Duration = Duration::from_secs(3);
/// How long a key set that cannot be refreshed keeps being served.
const SERVE_STALE_FOR: Duration = Duration::from_secs(3_600);

/// The verification keys currently accepted for an attester.
pub(crate) trait AttesterKeySource: Send + Sync {
    /// The keys accepted for the attester with this configured id.
    fn keys_for(&self, attester_id: &str) -> Result<Vec<Value>>;
}

/// Fetches one attester key set. Separated from the cache so the cache and the validator can be
/// tested without a network.
pub(crate) trait KeySetFetcher: Send + Sync {
    fn fetch<'a>(&'a self, jwks_uri: &'a str) -> BoxFuture<'a, Result<Vec<u8>>>;
}

/// The attester key sets this realm holds, and when each was last fetched.
pub(crate) struct AttesterKeyCache {
    attesters: Vec<TrustedAttesterConfig>,
    entries: Mutex<BTreeMap<String, CacheEntry>>,
}

struct CacheEntry {
    keys: Vec<Value>,
    fetched_at: Instant,
}

impl AttesterKeyCache {
    pub(crate) fn new(attesters: Vec<TrustedAttesterConfig>) -> Self {
        Self {
            attesters,
            entries: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn attesters(&self) -> &[TrustedAttesterConfig] {
        &self.attesters
    }

    /// `true` when every configured attester has a key set to serve.
    pub(crate) fn is_ready(&self) -> bool {
        match self.entries.lock() {
            Ok(entries) => self.attesters.iter().all(|a| entries.contains_key(&a.id)),
            Err(_) => false,
        }
    }

    /// Fetches every configured attester's key set, replacing what is held for the ones that
    /// answer. A failure is reported per attester and never clears what is already cached.
    pub(crate) async fn refresh(&self, fetcher: &dyn KeySetFetcher) {
        for attester in &self.attesters {
            match fetcher
                .fetch(&attester.jwks_uri)
                .await
                .and_then(|body| parse_key_set(&body))
            {
                Ok(keys) => {
                    if let Ok(mut entries) = self.entries.lock() {
                        entries.insert(
                            attester.id.clone(),
                            CacheEntry {
                                keys,
                                fetched_at: Instant::now(),
                            },
                        );
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        event.name = "attester.key_set_refresh_failed",
                        component = crate::COMPONENT,
                        attester = attester.id,
                        jwks_uri = attester.jwks_uri,
                        error = %error,
                        "the attester key set could not be refreshed"
                    );
                }
            }
        }
    }
}

impl AttesterKeySource for AttesterKeyCache {
    fn keys_for(&self, attester_id: &str) -> Result<Vec<Value>> {
        if !self
            .attesters
            .iter()
            .any(|attester| attester.id == attester_id)
        {
            bail!("the attester `{attester_id}` is not configured for this realm");
        }

        let entries = self
            .entries
            .lock()
            .map_err(|_| anyhow!("the attester key cache lock is poisoned"))?;
        let entry = entries.get(attester_id).ok_or_else(|| {
            anyhow!("no key set has been fetched yet for the attester `{attester_id}`")
        })?;

        let age = entry.fetched_at.elapsed();
        if age > SERVE_STALE_FOR {
            bail!(
                "the cached key set for the attester `{attester_id}` is {}s old and no refresh has \
                 succeeded",
                age.as_secs()
            );
        }

        Ok(entry.keys.clone())
    }
}

/// Reads a JWKS document, keeping only the keys usable for signature verification.
pub(crate) fn parse_key_set(body: &[u8]) -> Result<Vec<Value>> {
    let document: Value =
        serde_json::from_slice(body).context("the attester key set is not JSON")?;
    let keys = document
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("the attester key set has no `keys` array"))?;

    let usable: Vec<Value> = keys
        .iter()
        // A key published for encryption must never verify a signature.
        .filter(|jwk| {
            jwk.get("use")
                .and_then(Value::as_str)
                .is_none_or(|usage| usage == "sig")
        })
        // A published set has no business carrying private material; if it does, do not touch it.
        .filter(|jwk| jwk.get("d").is_none())
        .cloned()
        .collect();

    if usable.is_empty() {
        bail!("the attester key set contains no usable signature-verification key");
    }

    Ok(usable)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a failing assertion is the point"
)]
mod tests {
    use super::*;

    struct StubFetcher {
        body: Mutex<Result<Vec<u8>, String>>,
    }

    impl StubFetcher {
        fn serving(body: &str) -> Arc<Self> {
            Arc::new(Self {
                body: Mutex::new(Ok(body.as_bytes().to_vec())),
            })
        }

        fn breaks(&self) {
            *self.body.lock().unwrap() = Err("connection refused".to_owned());
        }
    }

    impl KeySetFetcher for StubFetcher {
        fn fetch<'a>(&'a self, _jwks_uri: &'a str) -> BoxFuture<'a, Result<Vec<u8>>> {
            Box::pin(async move {
                match &*self.body.lock().unwrap() {
                    Ok(body) => Ok(body.clone()),
                    Err(error) => bail!("{error}"),
                }
            })
        }
    }

    fn attester() -> TrustedAttesterConfig {
        TrustedAttesterConfig {
            id: "acme-por-attester".to_owned(),
            issuer: "https://attester.example.com".to_owned(),
            jwks_uri: "https://attester.example.com/jwks.json".to_owned(),
            proof_types: vec!["sd-jwt".to_owned()],
            formats: vec!["sd-jwt".to_owned()],
        }
    }

    const KEY_SET: &str = r#"{"keys":[
        {"kid":"a","kty":"OKP","crv":"Ed25519","use":"sig","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
        {"kid":"enc","kty":"OKP","crv":"X25519","use":"enc","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
    ]}"#;

    fn age_entry(cache: &AttesterKeyCache, by: Duration) {
        let mut entries = cache.entries.lock().unwrap();
        let entry = entries.get_mut("acme-por-attester").unwrap();
        entry.fetched_at = Instant::now() - by;
    }

    #[test]
    fn a_key_set_keeps_only_signature_keys() {
        let keys = parse_key_set(KEY_SET.as_bytes()).expect("the key set parses");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kid"], "a");
    }

    #[test]
    fn a_key_set_without_usable_keys_is_an_error() {
        assert!(parse_key_set(br#"{"keys":[]}"#).is_err());
        assert!(parse_key_set(br#"{}"#).is_err());
        assert!(parse_key_set(b"not json").is_err());
        // A set that only carries private material is not a set of verification keys.
        assert!(parse_key_set(br#"{"keys":[{"kty":"OKP","d":"secret","x":"a"}]}"#).is_err());
    }

    #[tokio::test]
    async fn an_unknown_attester_is_never_answered_for() {
        let cache = AttesterKeyCache::new(vec![attester()]);
        cache.refresh(StubFetcher::serving(KEY_SET).as_ref()).await;

        assert!(cache.keys_for("someone-else").is_err());
        assert!(cache.keys_for("acme-por-attester").is_ok());
    }

    #[test]
    fn a_realm_that_never_reached_its_attester_rejects_rather_than_serving_nothing() {
        let cache = AttesterKeyCache::new(vec![attester()]);
        // No refresh has succeeded: this must be an error, not an empty key set, or every
        // signature would look like a forgery.
        assert!(cache.keys_for("acme-por-attester").is_err());
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_serving_the_last_known_key_set() {
        let fetcher = StubFetcher::serving(KEY_SET);
        let cache = AttesterKeyCache::new(vec![attester()]);
        cache.refresh(fetcher.as_ref()).await;
        let first = cache.keys_for("acme-por-attester").expect("first fetch");

        fetcher.breaks();
        cache.refresh(fetcher.as_ref()).await;

        // Still answered: rejecting every PoR during an attester outage is worse than serving keys
        // that were valid minutes ago.
        assert_eq!(
            cache
                .keys_for("acme-por-attester")
                .expect("stale is served"),
            first
        );
    }

    #[tokio::test]
    async fn a_key_set_older_than_the_stale_window_stops_being_served() {
        let fetcher = StubFetcher::serving(KEY_SET);
        let cache = AttesterKeyCache::new(vec![attester()]);
        cache.refresh(fetcher.as_ref()).await;

        age_entry(&cache, SERVE_STALE_FOR + Duration::from_secs(1));
        assert!(cache.keys_for("acme-por-attester").is_err());
    }

    #[tokio::test]
    async fn a_rotated_key_replaces_the_previous_one() {
        let fetcher = StubFetcher::serving(KEY_SET);
        let cache = AttesterKeyCache::new(vec![attester()]);
        cache.refresh(fetcher.as_ref()).await;
        assert_eq!(cache.keys_for("acme-por-attester").unwrap()[0]["kid"], "a");

        *fetcher.body.lock().unwrap() = Ok(KEY_SET.replace("\"a\"", "\"b\"").into_bytes());
        cache.refresh(fetcher.as_ref()).await;
        assert_eq!(cache.keys_for("acme-por-attester").unwrap()[0]["kid"], "b");
    }
}
