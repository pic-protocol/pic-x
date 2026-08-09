//! The storage contract PIC-X runs against.

use crate::error::StorageError;
use crate::future::{BoxFuture, ready};

/// What a store answers with.
pub type Result<T> = std::result::Result<T, StorageError>;

/// The record store the server host and its services read and write.
///
/// Implementations are shared across tasks, so they are `Send + Sync` and take `&self`. The methods
/// are asynchronous because a real store is across a socket, and a synchronous contract would have
/// forced every backend to block a runtime thread.
///
/// The error is typed rather than opaque because a caller has to be able to tell a store that is
/// down from a store that answered: one is worth retrying and the other never will be.
///
/// This is records, not secrets: a value handed to [`Storage::put`] is expected to end up wherever
/// the backend puts records, in whatever form the backend keeps them. Anything that must not land
/// there goes through [`SecretStore`](crate::secrets::SecretStore) instead.
pub trait Storage: Send + Sync {
    /// Returns the name of this implementation, for banners and diagnostics.
    fn name(&self) -> &'static str;

    /// Stores `value` under `key`, replacing any previous value.
    fn put<'a>(&'a self, key: &'a str, value: &'a [u8]) -> BoxFuture<'a, Result<()>>;

    /// Returns the value stored under `key`, when there is one.
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>>>;

    /// Releases whatever this store is holding, before the process goes away.
    ///
    /// The host calls it during shutdown, within the configured budget. A store with buffered writes,
    /// an open connection pool, or a file to flush does that work here; one with nothing to release
    /// keeps the default.
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// The single record the stub keeps.
    type Record = Option<(String, Vec<u8>)>;

    /// A store written against the contract from outside any implementation crate.
    #[derive(Default)]
    struct StubStorage {
        last: Mutex<Record>,
        shut_down: AtomicBool,
    }

    impl Storage for StubStorage {
        fn name(&self) -> &'static str {
            "stub"
        }

        fn put<'a>(&'a self, key: &'a str, value: &'a [u8]) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                *self
                    .last
                    .lock()
                    .map_err(|error| StorageError::backend(error.to_string()))? =
                    Some((key.to_owned(), value.to_vec()));

                Ok(())
            })
        }

        fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>>> {
            Box::pin(async move {
                Ok(self
                    .last
                    .lock()
                    .map_err(|error| StorageError::backend(error.to_string()))?
                    .as_ref()
                    .filter(|(stored, _)| stored == key)
                    .map(|(_, value)| value.clone()))
            })
        }

        fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async move {
                self.shut_down.store(true, Ordering::SeqCst);

                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn test_the_contract_is_implementable_from_outside_and_usable_as_a_trait_object() {
        let storage: Box<dyn Storage> = Box::new(StubStorage::default());

        storage
            .put("a", b"one")
            .await
            .expect("the record is stored");

        assert_eq!(storage.name(), "stub");
        assert_eq!(
            storage.get("a").await.expect("the record is readable"),
            Some(b"one".to_vec())
        );
        assert_eq!(storage.get("b").await.expect("the read succeeds"), None);
    }

    #[tokio::test]
    async fn test_a_store_with_nothing_to_release_keeps_the_default_shutdown() {
        struct Minimal;

        impl Storage for Minimal {
            fn name(&self) -> &'static str {
                "minimal"
            }

            fn put<'a>(&'a self, _key: &'a str, _value: &'a [u8]) -> BoxFuture<'a, Result<()>> {
                ready(Ok(()))
            }

            fn get<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>>> {
                ready(Ok(None))
            }
        }

        Minimal
            .shutdown()
            .await
            .expect("the default releases nothing");
    }

    #[tokio::test]
    async fn test_a_store_with_something_to_release_is_told_to() {
        let storage = StubStorage::default();

        storage.shutdown().await.expect("the store releases");

        assert!(storage.shut_down.load(Ordering::SeqCst));
    }
}
