//! Bounding how many sockets one surface holds at once.
//!
//! # Why the permit rides on the stream
//!
//! A connection is not a request. It is a task, a TLS session and its buffers, and it lasts as long
//! as the client keeps it — which for an attacker is "forever". Limiting requests does nothing about
//! it: a client that opens ten thousand connections and sends nothing on any of them has spent none
//! of the request budget.
//!
//! So the permit is taken when the connection is accepted and released when the stream is dropped,
//! which happens exactly when the connection ends. There is nowhere to leak it, and no bookkeeping to
//! get wrong: the type system holds the count.
//!
//! # Refused, not queued
//!
//! A connection over the limit is closed immediately. Waiting for a slot would keep the socket open
//! for as long as the wait, which is the resource being defended — an attacker would get the same
//! outcome for the same effort, and legitimate clients would wait behind them.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::task::{Context, Poll};

use axum_server::accept::Accept;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use pic_x_core::Metrics;

use crate::measure::{ACCEPTED, CONNECTIONS, REFUSED};

/// The `component` every record of a refusal carries.
const COMPONENT: &str = "transport";

/// Accepts connections only while the surface is under its limit.
#[derive(Clone)]
pub struct LimitedAcceptor<A> {
    inner: A,
    permits: Arc<Semaphore>,
    /// Whether the limit is currently being hit, so saturation is reported once per episode rather
    /// than once per refused connection — which under an attack is the same as not reporting it.
    saturated: Arc<AtomicBool>,
    /// What the limit is, kept because the semaphore can only say how much of it is left — and at
    /// the moment worth reporting, that is zero.
    capacity: u32,
    /// How many are held right now. Kept beside the semaphore rather than derived from it: a permit
    /// is released when a stream is dropped, and a count read at that moment would be off by the one
    /// still being released.
    held: Arc<AtomicI64>,
    surface: &'static str,
    metrics: Metrics,
}

impl<A> LimitedAcceptor<A> {
    /// Wraps `inner`, admitting at most `connections` at a time.
    pub fn new(inner: A, connections: u32) -> Self {
        Self {
            inner,
            permits: Arc::new(Semaphore::new(connections as usize)),
            saturated: Arc::new(AtomicBool::new(false)),
            capacity: connections,
            held: Arc::new(AtomicI64::new(0)),
            surface: "surface",
            metrics: Metrics::none(),
        }
    }

    /// Records what this acceptor admits and refuses, under the name `surface`.
    pub fn measured(mut self, surface: &'static str, metrics: Metrics) -> Self {
        self.surface = surface;
        self.metrics = metrics;

        self
    }
}

impl<A: std::fmt::Debug> std::fmt::Debug for LimitedAcceptor<A> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LimitedAcceptor")
            .field("available", &self.permits.available_permits())
            .finish_non_exhaustive()
    }
}

impl<A, I, S> Accept<I, S> for LimitedAcceptor<A>
where
    A: Accept<I, S> + Send + 'static,
    A::Future: Send,
    A::Stream: Send,
    A::Service: Send,
    I: Send + 'static,
    S: Send + 'static,
{
    type Stream = Guarded<A::Stream>;
    type Service = A::Service;
    type Future = Pin<
        Box<dyn std::future::Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>,
    >;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        // Taken before the handshake, so a client that never finishes one still costs a slot rather
        // than an unbounded number of them.
        let permit = match Arc::clone(&self.permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                // Counted every time, unlike the log record: the whole point of the number is that a
                // refusal rate is visible, and one warning per episode cannot express a rate.
                self.metrics.count(&REFUSED, &[("surface", self.surface)]);

                if !self.saturated.swap(true, Ordering::SeqCst) {
                    tracing::warn!(
                        event.name = "transport.connections_saturated",
                        component = COMPONENT,
                        limit = self.capacity,
                        "refusing connections until one is released"
                    );
                }

                return Box::pin(async {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "the surface is holding as many connections as it is allowed to",
                    ))
                });
            }
        };

        self.saturated.store(false, Ordering::SeqCst);

        self.metrics.count(&ACCEPTED, &[("surface", self.surface)]);
        let held = self.held.fetch_add(1, Ordering::SeqCst) + 1;
        self.metrics
            .set(&CONNECTIONS, &[("surface", self.surface)], held as f64);

        let accepting = self.inner.accept(stream, service);
        let released = Released {
            held: Arc::clone(&self.held),
            surface: self.surface,
            metrics: self.metrics.clone(),
        };

        Box::pin(async move {
            // `?` here would drop `released` on a failed handshake, which is exactly right: a
            // connection that never became one must not be counted as held.
            let (stream, service) = accepting.await?;

            Ok((
                Guarded {
                    inner: stream,
                    _permit: permit,
                    _released: released,
                },
                service,
            ))
        })
    }
}

/// Takes one off the held count when it is dropped, whenever and wherever that happens.
///
/// A field rather than a `Drop` on [`Guarded`] itself, because a stream that failed its handshake is
/// dropped before it ever becomes one — and the count has to come down either way.
#[derive(Debug)]
struct Released {
    held: Arc<AtomicI64>,
    surface: &'static str,
    metrics: Metrics,
}

impl Drop for Released {
    fn drop(&mut self) {
        let held = self.held.fetch_sub(1, Ordering::SeqCst) - 1;
        self.metrics
            .set(&CONNECTIONS, &[("surface", self.surface)], held as f64);
    }
}

/// A stream that holds a connection permit for as long as it exists.
///
/// Neither field is ever read. They are here so that dropping the stream returns the permit and takes
/// the connection back off the count, which is the whole mechanism: there is no release path to
/// forget, because there is no release path.
pub struct Guarded<I> {
    inner: I,
    _permit: OwnedSemaphorePermit,
    _released: Released,
}

impl<I: AsyncRead + Unpin> AsyncRead for Guarded<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for Guarded<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        slices: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(context, slices)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// A guarded stream holding one of `permits`, counted into `held`.
    fn guarded(permits: &Arc<Semaphore>, held: &Arc<AtomicI64>) -> Guarded<tokio::io::Empty> {
        held.fetch_add(1, Ordering::SeqCst);

        Guarded {
            inner: tokio::io::empty(),
            _permit: Arc::clone(permits)
                .try_acquire_owned()
                .expect("a slot is free"),
            _released: Released {
                held: Arc::clone(held),
                surface: "test",
                metrics: Metrics::none(),
            },
        }
    }

    #[tokio::test]
    async fn test_a_permit_is_held_for_the_life_of_the_stream_and_no_longer() {
        let permits = Arc::new(Semaphore::new(2));
        let held = Arc::new(AtomicI64::new(0));

        let first = guarded(&permits, &held);
        let second = guarded(&permits, &held);

        assert_eq!(permits.available_permits(), 0);
        assert!(
            Arc::clone(&permits).try_acquire_owned().is_err(),
            "a third connection was admitted over the limit"
        );

        // Dropping is the release. There is no other path, which is the point.
        drop(first);
        assert_eq!(permits.available_permits(), 1);

        drop(second);
        assert_eq!(permits.available_permits(), 2);
    }

    #[tokio::test]
    async fn test_the_held_count_comes_back_down() {
        // A gauge that only goes up reads as a leak that is not there, and hides the saturation that
        // is. Whatever else happens to a stream, dropping it takes one off.
        let permits = Arc::new(Semaphore::new(4));
        let held = Arc::new(AtomicI64::new(0));

        let streams: Vec<_> = (0..3).map(|_| guarded(&permits, &held)).collect();
        assert_eq!(held.load(Ordering::SeqCst), 3);

        drop(streams);
        assert_eq!(held.load(Ordering::SeqCst), 0);
    }
}
