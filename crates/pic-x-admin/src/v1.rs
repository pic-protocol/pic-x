//! The protocol this surface speaks, compiled from `proto/picx/admin/v1/admin.proto`.
//!
//! A file of its own so the generated code — which nobody here writes and nobody here reviews —
//! carries its own `allow` attributes instead of relaxing the lints for everything around it.

#![allow(clippy::all, clippy::pedantic, missing_docs)]

tonic::include_proto!("picx.admin.v1");
