// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Validates the build-time banner metadata and prepares the assets the binary compiles in.

use std::env;
use std::error::Error;
use std::path::Path;

/// Build-time variables the binary reads back through `env!`.
const BANNER_VARS: [&str; 2] = ["PIC_X_COPYRIGHT_YEAR", "PIC_X_COPYRIGHT_HOLDER"];

/// The logo the public landing renders, and the single source it is derived from.
///
/// The binary embeds it as a `data:` URI so the page is self-contained. Rather than commit that
/// derived blob and have it drift from the image, it is generated here on every build: change the
/// PNG and the next build re-encodes it. `rerun-if-changed` is what makes that automatic.
const LOGO_SOURCE: &str = "assets/pic-x-logo-mini.png";

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

    // The commit this binary was built from. A local build resolves it from the repository; an
    // image build has no `.git` in its context (.dockerignore) and passes PIC_X_BUILD_COMMIT as a
    // build argument instead; a build from a bare source archive has neither and says `unknown`
    // rather than inventing one. Truncated to twelve characters, which is what the banner prints.
    println!("cargo:rerun-if-env-changed=PIC_X_BUILD_COMMIT");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
    let commit = env::var("PIC_X_BUILD_COMMIT")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .or_else(git_head_commit)
        .unwrap_or_else(|| "unknown".to_owned());
    let commit: String = commit.chars().take(12).collect();
    println!("cargo:rustc-env=PIC_X_BUILD_COMMIT={commit}");

    println!("cargo:rerun-if-changed={LOGO_SOURCE}");
    let bytes =
        std::fs::read(LOGO_SOURCE).map_err(|error| format!("reading {LOGO_SOURCE}: {error}"))?;
    let data_uri = format!("data:image/png;base64,{}", base64(&bytes));
    let out = Path::new(&env::var("OUT_DIR")?).join("pic-x-logo.datauri");
    std::fs::write(&out, data_uri)
        .map_err(|error| format!("writing {}: {error}", out.display()))?;

    Ok(())
}

/// Returns the repository's short HEAD commit, or nothing when there is no repository to ask.
fn git_head_commit() -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let commit = String::from_utf8(output.stdout).ok()?;
    let commit = commit.trim();

    (!commit.is_empty()).then(|| commit.to_owned())
}

/// Encodes bytes as standard base64 with padding.
///
/// Hand-rolled so the build depends on nothing: it runs once per logo change and the alphabet is
/// fixed, so there is nothing here a crate would do better.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }

    out
}
