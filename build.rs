//! Records the engine version the server simulates with.
//!
//! The re-simulation (`--features resim`) replays matches with the
//! `rugen-sim` pinned in `Cargo.lock`. A match played on another engine
//! version may simulate differently, so the server only re-simulates
//! matches whose clients ran exactly this version
//! ([`crate::compat::SIM_ENGINE`]). Read from the lock file so that bumping
//! the engine tag updates it with no code change.

use std::path::Path;

fn main() {
    let lock = Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock.display());
    println!("cargo:rerun-if-changed=build.rs");
    let text = std::fs::read_to_string(&lock).unwrap_or_default();
    match sim_version(&text) {
        Some(v) => println!("cargo:rustc-env=RUGEN_SIM_ENGINE={v}"),
        // no lock file: never re-simulate rather than guess
        None => {
            println!("cargo:warning=no rugen-sim in Cargo.lock: matches are never re-simulated")
        }
    }
}

/// The `version` of the `[[package]]` named `rugen-sim`; `None` when there
/// is none or several different ones (which one the binary uses is unclear).
fn sim_version(lock: &str) -> Option<String> {
    let mut in_sim = false;
    let mut found: Option<String> = None;
    for line in lock.lines().map(str::trim) {
        if line == "[[package]]" {
            in_sim = false;
        } else if line == "name = \"rugen-sim\"" {
            in_sim = true;
        } else if in_sim && let Some(v) = line.strip_prefix("version = ") {
            let v = v.trim_matches('"').to_string();
            if found.as_ref().is_some_and(|f| *f != v) {
                return None;
            }
            found = Some(v);
            in_sim = false;
        }
    }
    found
}
