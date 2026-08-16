//! The public PIC-X surface: what a client is meant to find on its own.
//!
//! This is the only surface that faces the world, which is what makes it the one with the least on
//! it. Discovery documents belong here; anything that changes state belongs on the admin surface,
//! behind mTLS, on another port.
//!
//! # Extending it
//!
//! A build adds endpoints by **registering routes**, not by wrapping this crate. Wrapping would not
//! work anyway: the router is assembled here, so a wrapper would have nothing to add to. Registration
//! goes both ways —
//!
//! * a [`RouteProvider`] contributes an `axum::Router`, and its routes sit beside the ones PIC-X
//!   defines;
//! * a `tower` layer registered with [`WellKnownService::with_layer`] wraps **every** route,
//!   including the ones PIC-X defines — which is how an enterprise build puts its own authentication,
//!   rate limiting or request logging in front of endpoints it did not write.
//!
//! Adding is the easy half. Modifying what is already there is the half that wrapping never gives
//! you, and it is the reason the extension point is a layer rather than a merge.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]

mod attester_keys;
mod checkpoints;
mod exchange;
mod key_fetch;
mod por;
pub mod routes;
pub mod service;

pub use service::{RouteProvider, WellKnownService};

/// The `component` every record of this surface carries.
pub(crate) const COMPONENT: &str = "wellknown";
