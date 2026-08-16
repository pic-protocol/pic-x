//! Which PCA checkpoints a realm currently accepts as the basis for advancement.
//!
//! Settlement asks one question — *are these exact signed PIC PCA COSE bytes a checkpoint I issued
//! and still accept?* — and this answers it.
//!
//! # Why a settled predecessor is not retired
//!
//! Profile 0.2 treats sibling branches as a property, not a gap: two workloads may each continue the
//! same checkpoint, which is what fan-out and worker pools need, and neither branch can import
//! authority from the other. So accepting a successor does **not** retire its predecessor here.
//! Terminating a lineage is a revocation decision, made through the revocation mechanism.
//!
//! # Why entries expire
//!
//! Keeping every checkpoint forever would make this grow without bound, and would keep a checkpoint
//! usable long after the token carrying it expired. Each entry therefore carries the expiry of the
//! token it was issued with, and the store is capped: when full, the entries closest to expiry go
//! first.

use std::collections::HashMap;
use std::sync::Mutex;

use pic::continuity::artifacts::{PicPcaPayload, artifact_sha256};
use pic::continuity::trust::{RevocationCheck, TrustedCheckpoint};

/// How many checkpoints one realm holds before the ones closest to expiry are dropped.
const MAX_CHECKPOINTS: usize = 100_000;

/// The checkpoints one realm currently accepts, keyed by the SHA-256 of their exact signed bytes.
///
/// The digest is the key, but acceptance still compares the **exact bytes**: a digest match with
/// different bytes would mean a hash collision, and this must not turn one into acceptance.
pub(crate) struct CheckpointStore {
    entries: Mutex<HashMap<Vec<u8>, Entry>>,
}

struct Entry {
    /// The exact signed PIC PCA COSE bytes, compared byte for byte on lookup.
    pca_bytes: Vec<u8>,
    /// When this checkpoint stops being accepted, in seconds since the Unix epoch.
    expires_at: i64,
}

impl CheckpointStore {
    pub(crate) fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Records a checkpoint this realm just issued, accepted until `expires_at`.
    pub(crate) fn insert(&self, pca_bytes: Vec<u8>, expires_at: i64, now: i64) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };

        entries.retain(|_, entry| entry.expires_at > now);
        if entries.len() >= MAX_CHECKPOINTS {
            // Drop what is closest to expiry: it is the entry whose loss costs the least.
            if let Some(soonest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| key.clone())
            {
                entries.remove(&soonest);
            }
        }

        entries.insert(
            artifact_sha256(&pca_bytes),
            Entry {
                pca_bytes,
                expires_at,
            },
        );
    }

    /// `true` when these exact bytes are an accepted, unexpired checkpoint.
    pub(crate) fn accepts(&self, pca_bytes: &[u8], now: i64) -> bool {
        let Ok(entries) = self.entries.lock() else {
            // A poisoned lock must not become "everything is trusted".
            return false;
        };

        entries
            .get(&artifact_sha256(pca_bytes))
            .is_some_and(|entry| entry.expires_at > now && entry.pca_bytes == pca_bytes)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries
            .lock()
            .map(|entries| entries.len())
            .unwrap_or(0)
    }
}

/// The [`TrustedCheckpoint`] view of the store at one instant.
pub(crate) struct CheckpointsAt<'a> {
    pub(crate) store: &'a CheckpointStore,
    pub(crate) now: i64,
}

impl TrustedCheckpoint for CheckpointsAt<'_> {
    fn is_current_checkpoint(&self, exact_pca_bytes: &[u8]) -> bool {
        self.store.accepts(exact_pca_bytes, self.now)
    }
}

/// Revocation is not wired yet; this states that plainly instead of pretending to check.
///
/// Terminating a lineage today means letting its checkpoint expire or restarting the realm. A
/// deployment that needs revocation replaces this with the PIC Revocation Specification mechanism.
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

    const NOW: i64 = 1_786_700_000;

    #[test]
    fn only_the_exact_bytes_of_a_recorded_checkpoint_are_accepted() {
        let store = CheckpointStore::new();
        store.insert(b"exact-signed-pca-0".to_vec(), NOW + 3_600, NOW);

        assert!(store.accepts(b"exact-signed-pca-0", NOW));
        assert!(!store.accepts(b"exact-signed-pca-1", NOW));
        assert!(!store.accepts(b"", NOW));
    }

    #[test]
    fn a_predecessor_stays_acceptable_after_a_successor_is_recorded() {
        // Profile 0.2 sibling branches: a second workload may continue the same checkpoint, so
        // recording PCA 1 must not retire PCA 0.
        let store = CheckpointStore::new();
        store.insert(b"pca-0".to_vec(), NOW + 3_600, NOW);
        store.insert(b"pca-1".to_vec(), NOW + 3_600, NOW);

        assert!(store.accepts(b"pca-0", NOW));
        assert!(store.accepts(b"pca-1", NOW));
    }

    #[test]
    fn an_expired_checkpoint_stops_being_accepted() {
        let store = CheckpointStore::new();
        store.insert(b"pca-0".to_vec(), NOW + 60, NOW);

        assert!(store.accepts(b"pca-0", NOW));
        assert!(!store.accepts(b"pca-0", NOW + 61));
    }

    #[test]
    fn expired_entries_are_dropped_rather_than_accumulated() {
        let store = CheckpointStore::new();
        store.insert(b"old".to_vec(), NOW + 10, NOW);
        assert_eq!(store.len(), 1);

        // A later insertion sweeps what has expired by then.
        store.insert(b"new".to_vec(), NOW + 3_600, NOW + 100);
        assert_eq!(store.len(), 1);
        assert!(store.accepts(b"new", NOW + 100));
        assert!(!store.accepts(b"old", NOW + 100));
    }

    #[test]
    fn the_trusted_checkpoint_view_answers_for_the_instant_it_was_built_with() {
        let store = CheckpointStore::new();
        store.insert(b"pca-0".to_vec(), NOW + 60, NOW);

        let inside = CheckpointsAt {
            store: &store,
            now: NOW,
        };
        assert!(inside.is_current_checkpoint(b"pca-0"));

        let after = CheckpointsAt {
            store: &store,
            now: NOW + 61,
        };
        assert!(!after.is_current_checkpoint(b"pca-0"));
    }
}
