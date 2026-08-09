//! Compiles the administrative protocol into Rust at build time.
//!
//! The generated code is never committed: a checked-in copy is a copy that can drift from the `.proto`
//! it claims to describe, and the `.proto` is the artefact clients are given. `protoc` is therefore a
//! build requirement, which the CI workflow installs.
//!
//! A build that adds administrative RPCs of its own does exactly this in its own crate, over its own
//! `.proto`, in its own package. Nothing about this file has to be shared for that to work.

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let protos = ["proto/picx/admin/v1/admin.proto"];

    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    println!("cargo:rerun-if-changed=proto");

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&protos, &["proto"])?;

    Ok(())
}
