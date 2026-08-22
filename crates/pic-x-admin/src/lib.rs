// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PIC-X administrative surface.
//!
//! It is gRPC, it is on a port of its own, and it is the one that must never be reachable from
//! outside without authentication. Everything that changes the state of a deployment belongs here,
//! which is exactly why the transport is separate from the public one: a mistake in a reverse proxy
//! should not be able to expose administration by accident.
//!
//! # Extending it
//!
//! A build adds RPCs by **registering services**, not by wrapping this crate — the same rule as the
//! public surface, for the same reason. A [`ServiceProvider`] contributes whatever `tonic` services
//! it defines from its own `.proto`, in its own package, compiled by its own build script. Nothing
//! about the protocol has to be centralised for that to work.
//!
//! # Who may call it
//!
//! Two questions, answered in two places. The handshake answers *who is this* — mutual TLS, so a
//! client with no certificate never reaches the application. The allowlist answers *may they* — see
//! [`authorization`], and the reason the second question exists at all.
//!
//! An administrative surface bound to an address outside this host, with no client certificate
//! demanded, is refused by `Config::validate` before anything binds. That has always been what the
//! documentation here promised; it is now also what the code does.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]

mod api;
pub mod authorization;
pub mod service;
pub mod v1;

pub use service::{AdminService, ServiceProvider};

/// The `component` every record of this surface carries.
pub(crate) const COMPONENT: &str = "admin";
