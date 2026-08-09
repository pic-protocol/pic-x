//! What a surface refuses to spend on any one client.
//!
//! A server with no limits is not neutral about abuse — it is on the attacker's side. Every one of
//! these bounds a resource that is otherwise unbounded, and each answers a different way of taking a
//! process down without a single valid request:
//!
//! | | what it bounds | what it stops |
//! | --- | --- | --- |
//! | `connections` | sockets held at once | opening thousands and leaving them |
//! | `handshake_timeout` | time spent before TLS finishes | starting a handshake and never finishing it |
//! | `header_timeout` | time spent sending a request head | sending a header a byte at a time |
//! | `request_timeout` | time spent serving one request | a handler, or a body, that never ends |
//! | `concurrent_requests` | requests in flight | arriving faster than they can be served |
//! | `body_bytes` | bytes read from one body | announcing a megabyte and sending a gigabyte |
//!
//! None of them is a rate limiter, and that is deliberate: rate limiting needs to know who a client
//! *is* over time, which is a decision about identity rather than about resources, and belongs in
//! front of this — in an ingress, or in a build that has a notion of tenant.
//!
//! # Why one set rather than one per surface
//!
//! The same reason the reload cadence is one setting: three copies of five numbers is three chances
//! to set two of them. The surfaces do have different profiles — the public one faces the world and
//! the administrative one faces a handful of named operators — but a single set of defensible
//! defaults beats a per-surface scheme nobody fills in.

use std::time::Duration;

/// How many sockets one surface will hold at once.
///
/// Each one costs a task, a TLS session and its buffers. A thousand is far above what this product
/// sees and far below what a machine notices.
const DEFAULT_CONNECTIONS: u32 = 1_024;

/// How many requests one surface will have in flight at once.
///
/// Beyond this a request is refused rather than queued: a queue under overload is a way of failing
/// slowly for everybody instead of quickly for the requests that could not be served anyway.
const DEFAULT_CONCURRENT_REQUESTS: u32 = 256;

/// How long one request may take before it is given up on.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a client has to finish a TLS handshake.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a client has to send a complete request head.
///
/// This is the one that answers slowloris: a client that sends `GET / HTTP/1.1` one byte a minute
/// never reaches a handler, so nothing a handler is wrapped in can time it out. Only the connection
/// limit would bound it, and a thousand sockets is nothing to spend.
const DEFAULT_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// How many bytes one request body may carry.
///
/// A megabyte, which is orders of magnitude more than anything here reads: the discovery documents
/// take no body at all, and an administrative RPC carries a few hundred bytes.
const DEFAULT_BODY_BYTES: usize = 1024 * 1024;

/// The bounds every surface serves within.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    connections: u32,
    concurrent_requests: u32,
    request_timeout: Duration,
    handshake_timeout: Duration,
    header_timeout: Duration,
    body_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connections: DEFAULT_CONNECTIONS,
            concurrent_requests: DEFAULT_CONCURRENT_REQUESTS,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            header_timeout: DEFAULT_HEADER_TIMEOUT,
            body_bytes: DEFAULT_BODY_BYTES,
        }
    }
}

impl Limits {
    /// Returns the defaults, which are what a deployment that says nothing gets.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bounds how many sockets one surface holds at once.
    pub fn with_connections(mut self, connections: u32) -> Self {
        self.connections = connections;

        self
    }

    /// Bounds how many requests one surface has in flight at once.
    pub fn with_concurrent_requests(mut self, requests: u32) -> Self {
        self.concurrent_requests = requests;

        self
    }

    /// Bounds how long one request may take.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;

        self
    }

    /// Bounds how long a client has to finish a TLS handshake.
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;

        self
    }

    /// Bounds how long a client has to send a complete request head.
    pub fn with_header_timeout(mut self, timeout: Duration) -> Self {
        self.header_timeout = timeout;

        self
    }

    /// Bounds how many bytes one request body may carry.
    pub fn with_body_bytes(mut self, bytes: usize) -> Self {
        self.body_bytes = bytes;

        self
    }

    /// Returns how many sockets one surface holds at once.
    pub fn connections(&self) -> u32 {
        self.connections
    }

    /// Returns how many requests one surface has in flight at once.
    pub fn concurrent_requests(&self) -> u32 {
        self.concurrent_requests
    }

    /// Returns how long one request may take.
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Returns how long a client has to finish a TLS handshake.
    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    /// Returns how long a client has to send a complete request head.
    pub fn header_timeout(&self) -> Duration {
        self.header_timeout
    }

    /// Returns how many bytes one request body may carry.
    pub fn body_bytes(&self) -> usize {
        self.body_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_deployment_that_says_nothing_is_still_bounded() {
        // The property that matters: every one of these has a number, so there is no way to end up
        // with a surface that will hold sockets, or wait, or read, without limit.
        let limits = Limits::new();

        assert!(limits.connections() > 0);
        assert!(limits.concurrent_requests() > 0);
        assert!(limits.body_bytes() > 0);
        assert!(limits.request_timeout() > Duration::ZERO);
        assert!(limits.handshake_timeout() > Duration::ZERO);
        assert!(limits.header_timeout() > Duration::ZERO);
    }

    #[test]
    fn test_the_handshake_is_given_less_time_than_the_request_it_precedes() {
        // A handshake that may take as long as a whole request is a handshake an attacker can hold
        // open for as long as a request, for a fraction of the effort.
        let limits = Limits::new();

        assert!(limits.handshake_timeout() < limits.request_timeout());
        assert!(limits.header_timeout() < limits.request_timeout());
    }

    #[test]
    fn test_every_bound_is_settable() {
        let limits = Limits::new()
            .with_connections(1)
            .with_concurrent_requests(2)
            .with_request_timeout(Duration::from_secs(3))
            .with_handshake_timeout(Duration::from_secs(4))
            .with_header_timeout(Duration::from_secs(6))
            .with_body_bytes(5);

        assert_eq!(limits.connections(), 1);
        assert_eq!(limits.concurrent_requests(), 2);
        assert_eq!(limits.request_timeout(), Duration::from_secs(3));
        assert_eq!(limits.handshake_timeout(), Duration::from_secs(4));
        assert_eq!(limits.header_timeout(), Duration::from_secs(6));
        assert_eq!(limits.body_bytes(), 5);
    }
}
