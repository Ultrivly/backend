






use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha1::Sha1;
use sqlx::{Connection, PgConnection};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::identity::accounts::{method_name, record};
use crate::identity::sessions::{self, AuthMethod, ClientInfo, NewSession, Session};
use crate::platform::secrets::{Secrets, random_bytes, token_hash};

const STEP_SECS: u64 = 30;
const DIGITS: u32 = 6;

const SKEW_STEPS: i64 = 1;
const SECRET_BYTES: usize = 20;
const RECOVERY_CODES: usize = 10;
const MAX_CHALLENGE_ATTEMPTS: i32 = 5;

#[derive(Debug, thiserror::Error)]
pub enum MfaError {
    #[error("an authenticator app is already set up")]
    AlreadyEnrolled,
    #[error("no authenticator app is set up")]
    NotEnrolled,
    #[error("incorrect code")]
    InvalidCode,
    #[error("passkey name must be between 1 and 100 characters")]
    InvalidName,
    #[error("you have the maximum number of passkeys; remove one first")]
    TooManyFactors,
    
    #[error("this sign-in attempt has expired; please sign in again")]
    InvalidChallenge,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug)]
pub struct TotpEnrollment {
    pub factor_id: Uuid,
    
    pub secret: String,
    
    pub otpauth_uri: String,
}


pub async fn has_mfa(conn: &mut PgConnection, user_id: Uuid) -> sqlx::Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mfa_factors WHERE user_id = $1 AND confirmed_at IS NOT NULL)",
    )
    .bind(user_id)
    .fetch_one(conn)
    .await
}

pub async fn has_confirmed_totp(conn: &mut PgConnection, user_id: Uuid) -> sqlx::Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mfa_factors
                        WHERE user_id = $1 AND kind = 'totp' AND confirmed_at IS NOT NULL)",
    )
    .bind(user_id)
    .fetch_one(conn)
    .await
}



pub async fn start_totp_enrollment(
    conn: &mut PgConnection,
    secrets: &Secrets,
    user_id: Uuid,
    issuer: &str,
) -> Result<TotpEnrollment, MfaError> {
    let mut tx = conn.begin().await?;
    if has_confirmed_totp(&mut tx, user_id).await? {
        return Err(MfaError::AlreadyEnrolled);
    }
    sqlx::query(
        "DELETE FROM mfa_factors WHERE user_id = $1 AND kind = 'totp' AND confirmed_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    let factor_id = Uuid::now_v7();
    let seed = random_bytes::<SECRET_BYTES>();
    sqlx::query(
        "INSERT INTO mfa_factors (id, user_id, kind, label, secret_ciphertext)
         VALUES ($1, $2, 'totp', 'Authenticator app', $3)",
    )
    .bind(factor_id)
    .bind(user_id)
    .bind(secrets.encrypt(&factor_context(factor_id), &seed))
    .execute(&mut *tx)
    .await?;
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;

    let secret = base32(&seed);
    let mut uri = url::Url::parse("otpauth://totp/").expect("static URL");
    uri.set_path(&format!("{issuer}:{email}"));
    uri.query_pairs_mut()
        .append_pair("secret", &secret)
        .append_pair("issuer", issuer)
        .append_pair("algorithm", "SHA1")
        .append_pair("digits", &DIGITS.to_string())
        .append_pair("period", &STEP_SECS.to_string());
    Ok(TotpEnrollment {
        factor_id,
        secret,
        otpauth_uri: uri.to_string(),
    })
}




pub async fn confirm_totp_enrollment(
    conn: &mut PgConnection,
    secrets: &Secrets,
    user_id: Uuid,
    factor_id: Uuid,
    code: &str,
    session: Option<&Session>,
) -> Result<Vec<String>, MfaError> {
    let mut tx = conn.begin().await?;
    let ciphertext: Vec<u8> = sqlx::query_scalar(
        "SELECT secret_ciphertext FROM mfa_factors
         WHERE id = $1 AND user_id = $2 AND kind = 'totp' AND confirmed_at IS NULL FOR UPDATE",
    )
    .bind(factor_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(MfaError::NotEnrolled)?;
    let seed = secrets.decrypt(&factor_context(factor_id), &ciphertext)?;
    let step = matching_step(&seed, code, now_secs()).ok_or(MfaError::InvalidCode)?;

    let first_factor = !has_mfa(&mut tx, user_id).await?;
    sqlx::query("UPDATE mfa_factors SET confirmed_at = now(), last_used_step = $2 WHERE id = $1")
        .bind(factor_id)
        .bind(step)
        .execute(&mut *tx)
        .await?;
    let codes = if first_factor {
        replace_recovery_codes(&mut tx, user_id).await?
    } else {
        Vec::new()
    };
    if let Some(session) = session.filter(|s| s.user_id == user_id) {
        mark_session_verified(&mut tx, session.id).await?;
    }
    record(
        &mut tx,
        user_id,
        "user.mfa_enabled",
        json!({ "kind": "totp" }),
    )
    .await?;
    tx.commit().await?;
    Ok(codes)
}



pub async fn complete_challenge(
    conn: &mut PgConnection,
    secrets: &Secrets,
    challenge: &str,
    code: &str,
    client: &ClientInfo,
) -> Result<NewSession, MfaError> {
    let mut tx = conn.begin().await?;
    let pending = lock_challenge(&mut tx, challenge).await?;
    if !check_code(&mut tx, secrets, pending.user_id, code).await? {
        fail_challenge(&mut tx, &pending).await?;
        tx.commit().await?;
        return Err(MfaError::InvalidCode);
    }
    let session = finish_challenge(&mut tx, &pending, "code", client).await?;
    tx.commit().await?;
    Ok(session)
}


pub(crate) struct PendingChallenge {
    token_hash: Vec<u8>,
    pub(crate) user_id: Uuid,
    data: Value,
    attempts: i32,
}

pub(crate) async fn lock_challenge(
    conn: &mut PgConnection,
    challenge: &str,
) -> Result<PendingChallenge, MfaError> {
    let hash = token_hash(challenge);
    let (user_id, data, attempts): (Uuid, Value, i32) = sqlx::query_as(
        "SELECT user_id, data, attempts FROM auth_tokens
         WHERE token_hash = $1 AND purpose = 'mfa_challenge' AND expires_at > now() FOR UPDATE",
    )
    .bind(&hash)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(MfaError::InvalidChallenge)?;
    Ok(PendingChallenge {
        token_hash: hash,
        user_id,
        data,
        attempts,
    })
}


pub(crate) async fn fail_challenge(
    conn: &mut PgConnection,
    pending: &PendingChallenge,
) -> sqlx::Result<()> {
    let sql = if pending.attempts + 1 >= MAX_CHALLENGE_ATTEMPTS {
        "DELETE FROM auth_tokens WHERE token_hash = $1"
    } else {
        "UPDATE auth_tokens SET attempts = attempts + 1 WHERE token_hash = $1"
    };
    sqlx::query(sql)
        .bind(&pending.token_hash)
        .execute(conn)
        .await?;
    Ok(())
}


pub(crate) async fn finish_challenge(
    conn: &mut PgConnection,
    pending: &PendingChallenge,
    factor: &str,
    client: &ClientInfo,
) -> Result<NewSession, MfaError> {
    sqlx::query("DELETE FROM auth_tokens WHERE token_hash = $1")
        .bind(&pending.token_hash)
        .execute(&mut *conn)
        .await?;
    let method = if pending.data["social"] == json!(true) {
        AuthMethod::Social
    } else {
        AuthMethod::Password
    };
    let session = sessions::create(conn, pending.user_id, method, true, client).await?;
    record(
        conn,
        pending.user_id,
        "user.signed_in",
        json!({ "method": method_name(method), "mfa": factor }),
    )
    .await?;
    Ok(session)
}



pub async fn verify_session(
    conn: &mut PgConnection,
    secrets: &Secrets,
    session: &Session,
    code: &str,
) -> Result<(), MfaError> {
    let mut tx = conn.begin().await?;
    if !has_mfa(&mut tx, session.user_id).await? {
        return Err(MfaError::NotEnrolled);
    }
    if !check_code(&mut tx, secrets, session.user_id, code).await? {
        tx.commit().await?;
        return Err(MfaError::InvalidCode);
    }
    mark_session_verified(&mut tx, session.id).await?;
    tx.commit().await?;
    Ok(())
}


pub async fn regenerate_recovery_codes(
    conn: &mut PgConnection,
    user_id: Uuid,
) -> Result<Vec<String>, MfaError> {
    let mut tx = conn.begin().await?;
    if !has_mfa(&mut tx, user_id).await? {
        return Err(MfaError::NotEnrolled);
    }
    let codes = replace_recovery_codes(&mut tx, user_id).await?;
    record(
        &mut tx,
        user_id,
        "user.mfa_recovery_codes_regenerated",
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(codes)
}



pub async fn disable_totp(conn: &mut PgConnection, user_id: Uuid) -> Result<(), MfaError> {
    let mut tx = conn.begin().await?;
    sqlx::query("DELETE FROM mfa_factors WHERE user_id = $1 AND kind = 'totp'")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    remove_recovery_codes_if_unused(&mut tx, user_id).await?;
    record(
        &mut tx,
        user_id,
        "user.mfa_disabled",
        json!({ "kind": "totp" }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}


async fn check_code(
    conn: &mut PgConnection,
    secrets: &Secrets,
    user_id: Uuid,
    code: &str,
) -> Result<bool, MfaError> {
    let digits: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() == DIGITS as usize && digits.chars().all(|c| c.is_ascii_digit()) {
        let factor: Option<(Uuid, Vec<u8>, Option<i64>)> = sqlx::query_as(
            "SELECT id, secret_ciphertext, last_used_step FROM mfa_factors
             WHERE user_id = $1 AND kind = 'totp' AND confirmed_at IS NOT NULL FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await?;
        let Some((factor_id, ciphertext, last_step)) = factor else {
            return Ok(false);
        };
        let seed = secrets.decrypt(&factor_context(factor_id), &ciphertext)?;
        let Some(step) = matching_step(&seed, &digits, now_secs()) else {
            return Ok(false);
        };
        
        if last_step.is_some_and(|last| step <= last) {
            return Ok(false);
        }
        sqlx::query(
            "UPDATE mfa_factors SET last_used_step = $2, last_used_at = now() WHERE id = $1",
        )
        .bind(factor_id)
        .bind(step)
        .execute(conn)
        .await?;
        return Ok(true);
    }

    let used = sqlx::query(
        "UPDATE mfa_recovery_codes SET used_at = now()
         WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL",
    )
    .bind(user_id)
    .bind(token_hash(&normalize_recovery_code(code)))
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if used == 1 {
        record(conn, user_id, "user.mfa_recovery_code_used", json!({})).await?;
    }
    Ok(used == 1)
}

pub(crate) async fn remove_recovery_codes_if_unused(
    conn: &mut PgConnection,
    user_id: Uuid,
) -> sqlx::Result<()> {
    if !has_mfa(conn, user_id).await? {
        sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(conn)
            .await?;
    }
    Ok(())
}

pub(crate) async fn replace_recovery_codes(
    conn: &mut PgConnection,
    user_id: Uuid,
) -> sqlx::Result<Vec<String>> {
    sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
    let codes: Vec<String> = (0..RECOVERY_CODES).map(|_| recovery_code()).collect();
    for code in &codes {
        sqlx::query("INSERT INTO mfa_recovery_codes (id, user_id, code_hash) VALUES ($1, $2, $3)")
            .bind(Uuid::now_v7())
            .bind(user_id)
            .bind(token_hash(&normalize_recovery_code(code)))
            .execute(&mut *conn)
            .await?;
    }
    Ok(codes)
}

pub(crate) async fn mark_session_verified(
    conn: &mut PgConnection,
    session_id: Uuid,
) -> sqlx::Result<()> {
    sqlx::query("UPDATE sessions SET mfa_verified_at = now() WHERE id = $1")
        .bind(session_id)
        .execute(conn)
        .await?;
    Ok(())
}

fn factor_context(factor_id: Uuid) -> String {
    format!("mfa_factor:{factor_id}")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}


fn matching_step(seed: &[u8], code: &str, now: u64) -> Option<i64> {
    let current = (now / STEP_SECS) as i64;
    (current - SKEW_STEPS..=current + SKEW_STEPS)
        .filter(|step| *step >= 0)
        .find(|step| {
            let expected = format!(
                "{:0width$}",
                hotp(seed, *step as u64),
                width = DIGITS as usize
            );
            bool::from(expected.as_bytes().ct_eq(code.as_bytes()))
        })
}


fn hotp(seed: &[u8], counter: u64) -> u32 {
    let mut mac =
        <Hmac<Sha1> as KeyInit>::new_from_slice(seed).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let value = u32::from_be_bytes([
        hash[offset],
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]) & 0x7fff_ffff;
    value % 10u32.pow(DIGITS)
}


fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    for chunk in bytes.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let bits = u64::from_be_bytes([0, 0, 0, buf[0], buf[1], buf[2], buf[3], buf[4]]);
        let chars = (chunk.len() * 8).div_ceil(5);
        for i in 0..chars {
            out.push(ALPHABET[((bits >> (35 - i * 5)) & 0x1f) as usize] as char);
        }
    }
    out
}


fn recovery_code() -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghjkmnpqrstuvwxyz234567890";
    let bytes = random_bytes::<10>();
    let chars: String = bytes
        .iter()
        .map(|b| ALPHABET[(b & 0x1f) as usize] as char)
        .collect();
    format!("{}-{}", &chars[..5], &chars[5..])
}

fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    
    #[test]
    fn matches_rfc_6238_test_vectors() {
        let seed = b"12345678901234567890";
        for (time, code) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
        ] {
            assert_eq!(
                matching_step(seed, code, time),
                Some((time / STEP_SECS) as i64),
                "t={time}"
            );
        }
        assert_eq!(matching_step(seed, "000000", 59), None);
        
        assert!(matching_step(seed, "287082", 59 + 30).is_some());
        assert!(matching_step(seed, "287082", 59 + 90).is_none());
    }

    #[test]
    fn encodes_base32_like_rfc_4648() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(
            base32(b"12345678901234567890"),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
    }

    #[test]
    fn recovery_codes_normalize_for_lookup() {
        let code = recovery_code();
        assert_eq!(code.len(), 11);
        assert_eq!(
            normalize_recovery_code(&code.to_uppercase()),
            normalize_recovery_code(&code)
        );
        assert_eq!(normalize_recovery_code(" ab-cd "), "abcd");
    }
}
