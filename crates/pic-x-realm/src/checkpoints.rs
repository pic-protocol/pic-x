// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Which PCA checkpoints a realm accepts as the basis for advancement.
//!
//! Settlement asks one question — *are these exact signed PIC PCA COSE bytes a checkpoint I
//! issued?* — and a realm can answer it without remembering anything: **it signed them**. So the
//! answer is a signature check against this realm's own published keys, not a lookup in a store.
//!
//! # Why not a store
//!
//! Holding issued checkpoints in memory would make a restart destroy every lineage in flight — a
//! workload would be told its checkpoint is untrusted, with no way to obtain another short of
//! redoing the whole OAuth exchange — and would make replicas disagree depending on which one a
//! candidate reached. A signature check has neither problem: it is stateless, so restarts and
//! replicas are transparent.
//!
//! # What bounds a checkpoint's life
//!
//! A PIC PCA COSE payload carries no expiry: Profile 0.2 defines `profile`, `position`,
//! `context_of_authority` and `challenge`, and the articles state a PCA has no mandatory
//! independent expiration. What bounds it here is **key retention** — a checkpoint stays advanceable
//! for as long as the realm key that signed it is still published, which is the realm's `retain`
//! window. Ending one lineage sooner is a revocation decision, and revocation is a separate
//! mechanism.
//!
//! Sibling branches remain a property of the profile: nothing here retires a predecessor when its
//! successor is issued, so fan-out and worker pools work, and no branch can import authority from
//! another.

use std::sync::Arc;

use pic::continuity::artifacts::{PicPcaCose, PicPcaPayload};
use pic::continuity::cose::CoseError;
use pic::continuity::trust::{ArtifactVerifier, RevocationCheck, TrustedCheckpoint};

use pic_x_core::{Jwk, KeyManager};

use pic::continuity::jwk::public_key_from_jwk;

/// Accepts a checkpoint when this realm's own signature verifies over it.
pub(crate) struct RealmSignedCheckpoints {
    /// The realm's token ring. Its published keys are exactly the signatures this realm still
    /// stands behind, so key retention *is* the acceptance window.
    pub(crate) keys: Arc<dyn KeyManager>,
}

impl TrustedCheckpoint for RealmSignedCheckpoints {
    fn is_current_checkpoint(&self, exact_pca_bytes: &[u8]) -> bool {
        let Ok(cose) = PicPcaCose::from_bytes(exact_pca_bytes) else {
            return false;
        };
        let Ok(published) = self.keys.public_keys() else {
            // A ring that cannot be read must not become "everything is trusted".
            return false;
        };

        // The protected header names the key, so a signature from a rotated-away key is rejected
        // without trying the rest; with no `kid`, every published key is a candidate.
        let named = cose.kid();

        published
            .iter()
            .filter(|jwk| named.as_deref().is_none_or(|kid| jwk.kid == kid))
            .any(|jwk| verifies(&cose, jwk))
    }
}

fn verifies(cose: &PicPcaCose, jwk: &Jwk) -> bool {
    let Ok(key) = public_key_from_jwk(&serde_json::json!({
        "kty": jwk.kty,
        "crv": jwk.crv,
        "x": jwk.x,
        "y": jwk.y,
    })) else {
        return false;
    };

    cose.verify_with(|data, signature| {
        if ArtifactVerifier::verify(&key, data, signature) {
            Ok(())
        } else {
            Err(CoseError::VerificationFailed)
        }
    })
    .is_ok()
}

/// Revocation is not wired yet; this states that plainly instead of pretending to check.
///
/// With acceptance bounded by key retention rather than by a store, revocation is the only way to
/// end a single lineage early. A deployment that needs it replaces this with the mechanism of the
/// PIC Revocation Specification.
pub(crate) struct NoRevocationConfigured;

impl RevocationCheck for NoRevocationConfigured {
    fn is_revoked(&self, _checkpoint: &PicPcaPayload, _exact_pca_bytes: &[u8]) -> bool {
        false
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a failing assertion is the point"
)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use pic::continuity::authority::{
        AuthorityValue, IndexedAuthorityMap, Invariant, LogicalAuthority,
    };
    use pic::continuity::trust::{ArtifactSigner, Ed25519Signer};
    use pic_x_core::keys::{KeyId, Maintenance, Result as KeyResult, Signature};
    use std::collections::BTreeMap;

    /// A realm ring backed by one Ed25519 key, publishing it the way the product ring does.
    #[derive(Debug)]
    struct Ring {
        key: ed25519_dalek::SigningKey,
        kid: String,
        publishes: bool,
    }

    impl Ring {
        fn new(seed: u8, kid: &str) -> Self {
            Self {
                key: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
                kid: kid.to_owned(),
                publishes: true,
            }
        }

        fn signer(&self) -> Ed25519Signer {
            Ed25519Signer::new(self.key.clone(), &self.kid)
        }
    }

    impl KeyManager for Ring {
        fn name(&self) -> &'static str {
            "test-ring"
        }

        fn public_keys(&self) -> KeyResult<Vec<Jwk>> {
            if !self.publishes {
                return Ok(Vec::new());
            }
            Ok(vec![Jwk {
                kid: self.kid.clone(),
                kty: "OKP".to_owned(),
                crv: Some("Ed25519".to_owned()),
                x: URL_SAFE_NO_PAD.encode(self.key.verifying_key().as_bytes()),
                y: None,
                alg: "EdDSA".to_owned(),
                usage: "sig".to_owned(),
            }])
        }

        fn active_key_id(&self) -> KeyResult<KeyId> {
            Ok(KeyId::new(self.kid.clone()))
        }

        fn sign(&self, payload: &[u8]) -> KeyResult<Signature> {
            use ed25519_dalek::Signer;
            Ok(Signature::new(
                KeyId::new(self.kid.clone()),
                "EdDSA",
                self.key.sign(payload).to_bytes().to_vec(),
            ))
        }

        fn maintain(&self) -> KeyResult<Maintenance> {
            Ok(Maintenance::default())
        }
    }

    fn checkpoint_signed_by(signer: &dyn ArtifactSigner) -> Vec<u8> {
        let mut contract = BTreeMap::new();
        contract.insert("corporation".into(), AuthorityValue::One("ACME".into()));
        let authority = IndexedAuthorityMap::from_logical(&LogicalAuthority::new(
            None,
            vec![Invariant::new("storage:save", "save", "storage", "*")],
            contract,
        ))
        .unwrap();

        pic::continuity::verifier::issue_settled(
            PicPcaPayload::new(0, authority, vec![0x7b; 32]),
            signer,
            &pic::continuity::verifier::SettlementContext::default(),
        )
        .unwrap()
        .pca_bytes
    }

    #[test]
    fn a_checkpoint_this_realm_signed_is_accepted() {
        let ring = Ring::new(0x11, "realm-key-1");
        let pca = checkpoint_signed_by(&ring.signer());

        let trusted = RealmSignedCheckpoints {
            keys: Arc::new(Ring::new(0x11, "realm-key-1")),
        };
        assert!(trusted.is_current_checkpoint(&pca));
    }

    #[test]
    fn a_checkpoint_signed_by_another_realm_is_rejected() {
        // Same shape, different key: a checkpoint from elsewhere must not advance here.
        let elsewhere = Ring::new(0x22, "realm-key-1");
        let pca = checkpoint_signed_by(&elsewhere.signer());

        let trusted = RealmSignedCheckpoints {
            keys: Arc::new(Ring::new(0x11, "realm-key-1")),
        };
        assert!(!trusted.is_current_checkpoint(&pca));
    }

    #[test]
    fn a_checkpoint_whose_key_is_no_longer_published_is_rejected() {
        // Key retention is the acceptance window: once the ring stops publishing a key, the
        // checkpoints it signed stop being advanceable.
        let ring = Ring::new(0x11, "realm-key-1");
        let pca = checkpoint_signed_by(&ring.signer());

        let mut retired = Ring::new(0x11, "realm-key-1");
        retired.publishes = false;
        let trusted = RealmSignedCheckpoints {
            keys: Arc::new(retired),
        };
        assert!(!trusted.is_current_checkpoint(&pca));
    }

    #[test]
    fn tampered_or_malformed_checkpoint_bytes_are_rejected() {
        let ring = Ring::new(0x11, "realm-key-1");
        let pca = checkpoint_signed_by(&ring.signer());
        let trusted = RealmSignedCheckpoints {
            keys: Arc::new(Ring::new(0x11, "realm-key-1")),
        };

        let mut tampered = pca.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(!trusted.is_current_checkpoint(&tampered));

        assert!(!trusted.is_current_checkpoint(b"not a COSE artifact"));
        assert!(!trusted.is_current_checkpoint(&[]));
    }
}
