use argon2::{
    self,
    password_hash::{PasswordHasher, SaltString},
    PasswordVerifier,
};
use base64::{self, engine::Engine};
use tracing::warn;

static SALT: &'static str = "GQ7u^e2&fmpWcpe62iTqaCmKkLU&3^";

// NOTE: Using a plain string is vulnerable to hacks that allow reading memory
// consider using a secure string in the future.
pub fn hash_password(cleartext_password: &str) -> Option<String> {
    let password_hasher = argon2::Argon2::default();
    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(SALT.as_bytes());
    let salt = match SaltString::from_b64(&salt_b64) {
        Ok(s) => s,
        Err(_) => {
            warn!("hash_password(..) - failed to load salt");
            return None;
        }
    };
    let encoded_password = match password_hasher.hash_password(cleartext_password.as_bytes(), &salt)
    {
        Ok(s) => s.to_string(),
        Err(_) => {
            warn!("hash_password(..) - failed to hash password");
            return None;
        }
    };
    return Some(encoded_password);
}

// NOTE: Using a plain string is vulnerable to hacks that allow reading memory
// consider using a secure string in the future.
pub fn check_password(hash: &str, cleartext_password: &str) -> bool {
    let parsed_hash = match argon2::password_hash::PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => {
            warn!("check_password(..) - failed to parse hash");
            return false;
        }
    };
    argon2::Argon2::default()
        .verify_password(cleartext_password.as_bytes(), &parsed_hash)
        .is_ok()
}
