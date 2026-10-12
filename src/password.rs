//! Room passwords: Argon2id with a per-room random salt (PHC string), small
//! parameters (8 MiB, 2 passes) so a modest VPS stays responsive.
//! Verification is constant time (inside `argon2`).

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

fn hasher() -> Argon2<'static> {
    let params = Params::new(8 * 1024, 2, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash(password: &str) -> Option<String> {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).ok()?;
    let salt = SaltString::encode_b64(&raw).ok()?;
    hasher()
        .hash_password(password.as_bytes(), &salt)
        .ok()
        .map(|h| h.to_string())
}

pub fn verify(password: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    hasher()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
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
}
