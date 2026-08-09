//! Validates the build-time banner metadata and re-exports it to the binary.

use std::env;
use std::error::Error;

/// Build-time variables the binary reads back through `env!`.
const BANNER_VARS: [&str; 2] = ["PIC_X_COPYRIGHT_YEAR", "PIC_X_COPYRIGHT_HOLDER"];

fn main() -> Result<(), Box<dyn Error>> {
    for name in BANNER_VARS {
        println!("cargo:rerun-if-env-changed={name}");
    }

    for name in BANNER_VARS {
        let value = env::var(name).map_err(|_| format!("{name} is not set"))?;

        if value.trim().is_empty() {
            return Err(format!("{name} is empty").into());
        }

        println!("cargo:rustc-env={name}={value}");
    }

    Ok(())
}
