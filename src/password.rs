//! Password hashing: Argon2id with a per-hash random salt (PHC strings).
//! Verification is constant time (inside `argon2`) and reads the
//! parameters from the stored hash, so they can change later.
//!
//! * Room passwords: small parameters (8 MiB, 2 passes); they live as long
//!   as a room.
//! * Account passwords: 19 MiB, 2 passes, 1 lane (the OWASP baseline).
//!   Measured ≈ 22 ms per hash or verify on one core of a Ryzen 5 5500U
//!   (`argon2_timing` below; the official server runs in a 1 CPU / 768 MB
//!   container, budget < 100 ms per login). At most
//!   [`ACCOUNT_HASHERS`] account hashes run at once so a burst of logins
//!   can neither starve the lobby of its CPU nor take much memory.

use std::sync::{Condvar, Mutex, OnceLock};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

fn room_hasher() -> Argon2<'static> {
    let params = Params::new(8 * 1024, 2, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Account password parameters: memory (KiB), passes, lanes.
pub const ACCOUNT_PARAMS: (u32, u32, u32) = (19 * 1024, 2, 1);
/// Account hashes allowed to run at the same time.
pub const ACCOUNT_HASHERS: usize = 2;

fn account_hasher() -> Argon2<'static> {
    let (m, t, p) = ACCOUNT_PARAMS;
    let params = Params::new(m, t, p, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn hash_with(h: &Argon2<'_>, password: &str) -> Option<String> {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).ok()?;
    let salt = SaltString::encode_b64(&raw).ok()?;
    h.hash_password(password.as_bytes(), &salt)
        .ok()
        .map(|h| h.to_string())
}

fn verify_with(h: &Argon2<'_>, password: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    h.verify_password(password.as_bytes(), &parsed).is_ok()
}

/// Room password hash.
pub fn hash(password: &str) -> Option<String> {
    hash_with(&room_hasher(), password)
}

/// Room password check.
pub fn verify(password: &str, phc: &str) -> bool {
    verify_with(&room_hasher(), password, phc)
}

/// Counting gate around account hashing ([`ACCOUNT_HASHERS`] at a time).
struct Gate {
    busy: Mutex<usize>,
    free: Condvar,
}

static GATE: Gate = Gate {
    busy: Mutex::new(0),
    free: Condvar::new(),
};

fn gated<T>(f: impl FnOnce() -> T) -> T {
    {
        let mut busy = GATE.busy.lock().unwrap_or_else(|p| p.into_inner());
        while *busy >= ACCOUNT_HASHERS {
            busy = GATE.free.wait(busy).unwrap_or_else(|p| p.into_inner());
        }
        *busy += 1;
    }
    let out = f();
    let mut busy = GATE.busy.lock().unwrap_or_else(|p| p.into_inner());
    *busy -= 1;
    GATE.free.notify_one();
    out
}

/// Account password hash (PHC string, salt inside).
pub fn hash_account(password: &str) -> Option<String> {
    gated(|| hash_with(&account_hasher(), password))
}

/// Account password check. `None` (no such account) still spends the time
/// of a real check against a dummy hash, so response times do not tell
/// which usernames exist.
pub fn verify_account(password: &str, phc: Option<&str>) -> bool {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let dummy = DUMMY
        .get_or_init(|| hash_with(&account_hasher(), "rugen dummy password").unwrap_or_default());
    gated(|| match phc {
        Some(phc) => verify_with(&account_hasher(), password, phc),
        None => {
            let _ = verify_with(&account_hasher(), password, dummy);
            false
        }
    })
}

/// A random temporary password (operator resets): 12 characters without
/// look-alikes.
pub fn temporary() -> String {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut buf = [0u8; 12];
    let _ = getrandom::getrandom(&mut buf);
    buf.iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let h = hash("hunter2").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(!h.contains("hunter2"));
        assert!(verify("hunter2", &h));
        assert!(!verify("hunter3", &h));
        assert!(!verify("hunter2", "garbage"));
        // salted: the same password hashes differently
        assert_ne!(hash("hunter2").unwrap(), h);
    }

    #[test]
    fn account_hashes_use_the_account_parameters() {
        let h = hash_account("correct horse").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{h}");
        assert!(verify_account("correct horse", Some(&h)));
        assert!(!verify_account("correct horsE", Some(&h)));
        assert!(!verify_account("correct horse", None));
        assert!(!verify_account("correct horse", Some("garbage")));
        assert_ne!(hash_account("correct horse").unwrap(), h);
        let t = temporary();
        assert_eq!(t.len(), 12);
        assert!(rugen_proto::account::password_error(&t).is_none());
    }

    /// `cargo test --release -- --ignored --nocapture argon2_timing`
    /// (under `taskset -c 0` to mimic a 1 CPU container).
    #[test]
    #[ignore]
    fn argon2_timing() {
        let h = hash_account("timing password").unwrap();
        let n = 20;
        let t = std::time::Instant::now();
        for _ in 0..n {
            assert!(verify_account("timing password", Some(&h)));
        }
        let per = t.elapsed() / n;
        eprintln!("argon2id m=19MiB t=2 p=1 verify: {per:?}");
        let t = std::time::Instant::now();
        for _ in 0..n {
            assert!(!verify_account("timing password", None));
        }
        eprintln!("dummy verify: {:?}", t.elapsed() / n);
    }
}
