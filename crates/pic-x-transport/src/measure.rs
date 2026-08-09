//! What every surface counts about itself.
//!
//! Declared and recorded here rather than by each surface, for the same reason the limits are applied
//! here: a surface that has to remember to instrument itself is a surface that will be added one day
//! without it, and the gap will be found during the incident it would have explained.
//!
//! # The label that could have been the attack
//!
//! A request method is a token the client writes. HTTP allows extension methods, so `method` is a
//! label whose values come from outside — and a label like that turns every request into a series
//! that lives until the process exits. [`method_of`] maps anything outside the standard set to
//! `other`, which bounds it at nine values whatever a client sends.
//!
//! The path is deliberately **not** a label. It is the most useful label there is and the most
//! dangerous: a router with a wildcard turns every distinct URL into a series, and a client that can
//! ask for `/a`, `/b`, `/c`… controls how much memory the registry holds.

use std::task::{Context, Poll};
use std::time::Instant;

use http::{Request, Response};
use tower_service::Service;

use pic_x_core::Metrics;
use pic_x_core::metrics::{Metric, SECONDS};

/// How many requests each surface has answered, and how they ended.
pub const REQUESTS: Metric = Metric::counter(
    "picx_surface_requests_total",
    "Requests answered, by surface, method and status.",
);

/// How long they took.
///
/// The one number that answers "is it slow" — and the one an average cannot give, because the mean of
/// a hundred fast requests and one that took a minute is a fast request.
pub const LATENCY: Metric = Metric::histogram(
    "picx_surface_request_seconds",
    "How long requests took, by surface and method.",
    SECONDS,
);

/// How many connections a surface is holding right now.
///
/// Watch it against the configured ceiling: a surface sitting at its limit is refusing clients, and it
/// was doing so before anybody noticed.
pub const CONNECTIONS: Metric = Metric::gauge(
    "picx_surface_connections",
    "Connections currently held, by surface.",
);

/// How many connections have been accepted.
pub const ACCEPTED: Metric = Metric::counter(
    "picx_surface_connections_accepted_total",
    "Connections accepted, by surface.",
);

/// How many were turned away because the surface was already at its limit.
///
/// Any value above zero is worth an alert: it is the first thing that happens under a connection
/// flood, and it happens long before the process shows any other sign.
pub const REFUSED: Metric = Metric::counter(
    "picx_surface_connections_refused_total",
    "Connections refused because the surface was at its limit, by surface.",
);

/// Reduces a request method to one of a fixed set.
///
/// The set is the standard methods plus `other`. A client may send any token it likes; what it may not
/// do is decide how many series this process holds.
pub fn method_of<B>(request: &Request<B>) -> &'static str {
    match *request.method() {
        http::Method::GET => "GET",
        http::Method::POST => "POST",
        http::Method::PUT => "PUT",
        http::Method::DELETE => "DELETE",
        http::Method::HEAD => "HEAD",
        http::Method::OPTIONS => "OPTIONS",
        http::Method::PATCH => "PATCH",
        http::Method::TRACE => "TRACE",
        _ => "other",
    }
}

/// Times every request and records how it ended.
#[derive(Debug, Clone)]
pub struct MeasureLayer {
    surface: &'static str,
    metrics: Metrics,
}

impl MeasureLayer {
    /// Measures requests to the surface called `surface`, into `metrics`.
    pub fn new(surface: &'static str, metrics: Metrics) -> Self {
        Self { surface, metrics }
    }
}

impl<S> tower_layer::Layer<S> for MeasureLayer {
    type Service = Measured<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Measured {
            inner,
            surface: self.surface,
            metrics: self.metrics.clone(),
        }
    }
}

/// A service that records what each request cost and how it ended.
#[derive(Debug, Clone)]
pub struct Measured<S> {
    inner: S,
    surface: &'static str,
    metrics: Metrics,
}

impl<S, B, C> Service<Request<B>> for Measured<S>
where
    S: Service<Request<B>, Response = Response<C>>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let surface = self.surface;
        let metrics = self.metrics.clone();
        let method = method_of(&request);

        // Started before the inner service, so the measurement covers everything below this layer —
        // including the wait for a concurrency slot, which is exactly the time a client feels and the
        // time a handler-only measurement hides.
        let started = Instant::now();
        let called = self.inner.call(request);

        Box::pin(async move {
            let answered = called.await?;
            let elapsed = started.elapsed().as_secs_f64();

            metrics.observe(
                &LATENCY,
                &[("surface", surface), ("method", method)],
                elapsed,
            );
            metrics.count(
                &REQUESTS,
                &[
                    ("surface", surface),
                    ("method", method),
                    ("status", answered.status().as_str()),
                ],
            );

            Ok(answered)
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn test_a_method_a_client_invented_is_not_a_series_of_its_own() {
        // The attack: `FOO1 / HTTP/1.1`, `FOO2 / HTTP/1.1`, … every one a label value, every one a
        // series held until the process exits.
        let invented = Request::builder()
            .method(http::Method::from_bytes(b"WHATEVER").expect("a valid token"))
            .uri("/")
            .body(())
            .expect("the request builds");

        assert_eq!(method_of(&invented), "other");
    }

    #[test]
    fn test_the_methods_that_are_actually_used_keep_their_names() {
        for method in [http::Method::GET, http::Method::POST, http::Method::DELETE] {
            let request = Request::builder()
                .method(method.clone())
                .uri("/")
                .body(())
                .expect("the request builds");

            assert_eq!(method_of(&request), method.as_str());
        }
    }

    #[test]
    fn test_the_declarations_say_what_they_are() {
        // A counter named without `_total`, or a duration without `_seconds`, is one every dashboard
        // and every alerting rule has to special-case.
        assert!(REQUESTS.name().ends_with("_total"));
        assert!(ACCEPTED.name().ends_with("_total"));
        assert!(REFUSED.name().ends_with("_total"));
        assert!(LATENCY.name().ends_with("_seconds"));
        assert!(!CONNECTIONS.name().ends_with("_total"));
    }
}
