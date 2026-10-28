






use std::sync::LazyLock;
use std::time::Duration;

use anyhow::anyhow;
use argon2::password_hash::Error as HashError;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::{self, Actor};
use crate::identity::mfa;
use crate::identity::sessions::{self, AuthMethod, ClientInfo, NewSession, Session};
use crate::platform::secrets::{random_token, token_hash};

pub const MIN_PASSWORD_CHARS: usize = 12;
pub const MAX_PASSWORD_BYTES: usize = 1024;

const EMAIL_VERIFICATION_TTL: Duration = Duration::from_secs(3 * 24 * 60 * 60);
const PASSWORD_RESET_TTL: Duration = Duration::from_secs(60 * 60);
pub(crate) const MFA_CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);



const FREE_FAILURES: i32 = 5;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("incorrect email or password")]
    InvalidCredentials,
    #[error("too many failed attempts; try again later")]
    TooManyAttempts,
    #[error("invalid email address")]
    InvalidEmail,
    #[error("display name must be between 1 and 200 characters")]
    InvalidDisplayName,
    #[error("{0}")]
    WeakPassword(&'static str),
    #[error("an account with this email already exists")]
    EmailTaken,
    #[error("this link is invalid or has expired")]
    InvalidToken,
    #[error("incorrect code")]
    InvalidCode,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}


#[derive(Debug)]
pub enum SignIn {
    Complete(NewSession),
    
    MfaRequired {
        challenge: String,
    },
}

#[derive(Debug)]
pub struct SignUp {
    pub user_id: Uuid,
    
    pub verification_token: String,
}

pub async fn sign_up(
    conn: &mut PgConnection,
    email: &str,
    display_name: &str,
    password: &str,
) -> Result<SignUp, AuthError> {
    let email = normalize_email(email)?;
    let display_name = display_name.trim();
    if display_name.is_empty() || display_name.chars().count() > 200 {
        return Err(AuthError::InvalidDisplayName);
    }
    check_password_strength(password, email)?;
    let hash = hash_password(password.to_string()).await?;

    let mut tx = conn.begin().await?;
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id, email, display_name, password_hash, password_changed_at)
         VALUES ($1, $2, $3, $4, now())",
    )
    .bind(user_id)
    .bind(email)
    .bind(display_name)
    .bind(hash)
    .execute(&mut *tx)
    .await
    .map_err(
        |err| match err.as_database_error().and_then(|e| e.constraint()) {
            Some("users_email_key") => AuthError::EmailTaken,
            _ => err.into(),
        },
    )?;

    let verification_token = issue_token(
        &mut tx,
        "email_verification",
        user_id,
        Some(email),
        json!({}),
        EMAIL_VERIFICATION_TTL,
    )
    .await?;
    record(&mut tx, user_id, "user.signed_up", json!({})).await?;
    tx.commit().await?;

    Ok(SignUp {
        user_id,
        verification_token,
    })
}

pub async fn sign_in_with_password(
    conn: &mut PgConnection,
    email: &str,
    password: &str,
    client: &ClientInfo,
) -> Result<SignIn, AuthError> {
    let email_key = email.trim().to_lowercase();
    if is_locked(conn, &email_key).await? {
        return Err(AuthError::TooManyAttempts);
    }

    let user: Option<(Uuid, Option<String>, bool)> = sqlx::query_as(
        "SELECT id, password_hash, disabled_at IS NOT NULL FROM users WHERE lower(email) = $1",
    )
    .bind(&email_key)
    .fetch_optional(&mut *conn)
    .await?;

    
    
    let stored_hash = user.as_ref().and_then(|(_, hash, _)| hash.clone());
    let password_ok = verify_password(password.to_string(), stored_hash).await?;

    let Some((user_id, _, disabled)) = user.filter(|_| password_ok) else {
        record_failure(conn, &email_key).await?;
        return Err(AuthError::InvalidCredentials);
    };
    if disabled {
        return Err(AuthError::InvalidCredentials);
    }

    clear_failures(conn, &email_key).await?;
    finish_sign_in(conn, user_id, AuthMethod::Password, client).await
}




pub(crate) async fn finish_sign_in(
    conn: &mut PgConnection,
    user_id: Uuid,
    method: AuthMethod,
    client: &ClientInfo,
) -> Result<SignIn, AuthError> {
    let sso = matches!(method, AuthMethod::Sso { .. });
    if !sso && mfa::has_mfa(conn, user_id).await? {
        let challenge = issue_token(
            conn,
            "mfa_challenge",
            user_id,
            None,
            json!({ "social": method == AuthMethod::Social }),
            MFA_CHALLENGE_TTL,
        )
        .await?;
        return Ok(SignIn::MfaRequired { challenge });
    }

    let session = sessions::create(conn, user_id, method, false, client).await?;
    record(
        conn,
        user_id,
        "user.signed_in",
        json!({ "method": method_name(method) }),
    )
    .await?;
    Ok(SignIn::Complete(session))
}

pub(crate) fn method_name(method: AuthMethod) -> &'static str {
    match method {
        AuthMethod::Password => "password",
        AuthMethod::Sso { .. } => "sso",
        AuthMethod::Social => "social",
    }
}



pub async fn verify_email(conn: &mut PgConnection, token: &str) -> Result<Uuid, AuthError> {
    let mut tx = conn.begin().await?;
    let (user_id, email, _) = take_token(&mut tx, "email_verification", token)
        .await?
        .ok_or(AuthError::InvalidToken)?;
    let updated = sqlx::query(
        "UPDATE users SET email_verified_at = coalesce(email_verified_at, now())
         WHERE id = $1 AND email = $2",
    )
    .bind(user_id)
    .bind(email)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if updated == 0 {
        return Err(AuthError::InvalidToken);
    }
    record(&mut tx, user_id, "user.email_verified", json!({})).await?;
    tx.commit().await?;
    Ok(user_id)
}


pub async fn resend_email_verification(
    conn: &mut PgConnection,
    user_id: Uuid,
) -> Result<String, AuthError> {
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;
    Ok(issue_token(
        conn,
        "email_verification",
        user_id,
        Some(&email),
        json!({}),
        EMAIL_VERIFICATION_TTL,
    )
    .await?)
}



pub async fn request_password_reset(
    conn: &mut PgConnection,
    email: &str,
) -> Result<Option<(Uuid, String)>, AuthError> {
    let user_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM users WHERE lower(email) = lower($1) AND disabled_at IS NULL",
    )
    .bind(email.trim())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(user_id) = user_id else {
        return Ok(None);
    };

    let mut tx = conn.begin().await?;
    
    sqlx::query("DELETE FROM auth_tokens WHERE user_id = $1 AND purpose = 'password_reset'")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    let token = issue_token(
        &mut tx,
        "password_reset",
        user_id,
        None,
        json!({}),
        PASSWORD_RESET_TTL,
    )
    .await?;
    tx.commit().await?;
    Ok(Some((user_id, token)))
}







pub async fn reset_password(
    conn: &mut PgConnection,
    token: &str,
    new_password: &str,
) -> Result<Uuid, AuthError> {
    let mut tx = conn.begin().await?;
    let (user_id, _, _) = take_token(&mut tx, "password_reset", token)
        .await?
        .ok_or(AuthError::InvalidToken)?;
    let (email, verified): (String, bool) = sqlx::query_as(
        "SELECT email, email_verified_at IS NOT NULL FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    check_password_strength(new_password, &email)?;

    if !verified {
        for sql in [
            "DELETE FROM auth_identities WHERE user_id = $1",
            "DELETE FROM mfa_factors WHERE user_id = $1",
            "DELETE FROM mfa_recovery_codes WHERE user_id = $1",
            "UPDATE users SET email_verified_at = now() WHERE id = $1",
        ] {
            sqlx::query(sql).bind(user_id).execute(&mut *tx).await?;
        }
    }
    set_password(&mut tx, user_id, new_password).await?;
    sessions::revoke_all(&mut tx, user_id, None).await?;
    clear_failures(&mut tx, &email.to_lowercase()).await?;
    record(&mut tx, user_id, "user.password_reset", json!({})).await?;
    tx.commit().await?;
    Ok(user_id)
}



pub async fn change_password(
    conn: &mut PgConnection,
    session: &Session,
    current: Option<&str>,
    new_password: &str,
) -> Result<(), AuthError> {
    let mut tx = conn.begin().await?;
    let (email, stored_hash): (String, Option<String>) =
        sqlx::query_as("SELECT email, password_hash FROM users WHERE id = $1 FOR UPDATE")
            .bind(session.user_id)
            .fetch_one(&mut *tx)
            .await?;
    if stored_hash.is_some() {
        let current = current.ok_or(AuthError::InvalidCredentials)?;
        if !verify_password(current.to_string(), stored_hash).await? {
            return Err(AuthError::InvalidCredentials);
        }
    }
    check_password_strength(new_password, &email)?;

    set_password(&mut tx, session.user_id, new_password).await?;
    sessions::revoke_all(&mut tx, session.user_id, Some(session.id)).await?;
    record(&mut tx, session.user_id, "user.password_changed", json!({})).await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Profile {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub display_name: String,
    pub has_password: bool,
    pub mfa_enabled: bool,
    pub organizations: Vec<OrganizationSummary>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct OrganizationSummary {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
}


pub async fn profile(conn: &mut PgConnection, user_id: Uuid) -> Result<Profile, AuthError> {
    let (email, email_verified, display_name, has_password): (String, bool, String, bool) =
        sqlx::query_as(
            "SELECT email, email_verified_at IS NOT NULL, display_name, password_hash IS NOT NULL
             FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;
    let organizations = sqlx::query_as(
        "SELECT o.id, o.slug, o.name FROM memberships m
         JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
         WHERE m.user_id = $1 AND m.status = 'active' ORDER BY o.name",
    )
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(Profile {
        id: user_id,
        email,
        email_verified,
        display_name,
        has_password,
        mfa_enabled: mfa::has_mfa(conn, user_id).await?,
        organizations,
    })
}



pub async fn confirm_password(
    conn: &mut PgConnection,
    user_id: Uuid,
    password: &str,
) -> Result<bool, AuthError> {
    let stored: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(conn)
            .await?;
    Ok(verify_password(password.to_string(), stored).await?)
}


pub async fn email_of(conn: &mut PgConnection, user_id: Uuid) -> sqlx::Result<String> {
    sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(conn)
        .await
}

async fn set_password(
    conn: &mut PgConnection,
    user_id: Uuid,
    password: &str,
) -> Result<(), AuthError> {
    let hash = hash_password(password.to_string()).await?;
    sqlx::query("UPDATE users SET password_hash = $2, password_changed_at = now() WHERE id = $1")
        .bind(user_id)
        .bind(hash)
        .execute(conn)
        .await?;
    Ok(())
}

pub(crate) fn normalize_email(email: &str) -> Result<&str, AuthError> {
    let email = email.trim();
    let valid = email.len() <= 254
        && !email.chars().any(char::is_whitespace)
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        });
    if valid {
        Ok(email)
    } else {
        Err(AuthError::InvalidEmail)
    }
}

fn check_password_strength(password: &str, email: &str) -> Result<(), AuthError> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(AuthError::WeakPassword(
            "password must be at least 12 characters",
        ));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(AuthError::WeakPassword("password is too long"));
    }
    if password.trim().eq_ignore_ascii_case(email.trim()) {
        return Err(AuthError::WeakPassword(
            "password must not be your email address",
        ));
    }
    Ok(())
}

async fn hash_password(password: String) -> anyhow::Result<String> {
    tokio::task::spawn_blocking(move || {
        let hash: PasswordHash = Argon2::default()
            .hash_password(password.as_bytes())
            .map_err(|e| anyhow!("password hashing failed: {e}"))?;
        Ok(hash.to_string())
    })
    .await?
}



static DUMMY_HASH: LazyLock<String> = LazyLock::new(|| {
    let hash: PasswordHash = Argon2::default()
        .hash_password(random_token().as_bytes())
        .expect("hashing a random password");
    hash.to_string()
});

async fn verify_password(password: String, stored_hash: Option<String>) -> anyhow::Result<bool> {
    tokio::task::spawn_blocking(move || {
        let real = stored_hash.is_some();
        let hash = stored_hash.unwrap_or_else(|| DUMMY_HASH.clone());
        match Argon2::default().verify_password(password.as_bytes(), hash.as_str()) {
            Ok(()) => Ok(real),
            Err(HashError::PasswordInvalid) => Ok(false),
            Err(e) => Err(anyhow!("password verification failed: {e}")),
        }
    })
    .await?
}

async fn is_locked(conn: &mut PgConnection, email_key: &str) -> sqlx::Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT coalesce(locked_until > now(), false) FROM login_throttles WHERE email_key = $1",
    )
    .bind(email_key)
    .fetch_optional(conn)
    .await?
    .unwrap_or(false))
}

async fn record_failure(conn: &mut PgConnection, email_key: &str) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO login_throttles AS t (email_key, failures) VALUES ($1, 1)
         ON CONFLICT (email_key) DO UPDATE SET
             failures = CASE WHEN t.updated_at < now() - interval '1 hour' THEN 1 ELSE t.failures + 1 END,
             updated_at = now()",
    )
    .bind(email_key)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE login_throttles
         SET locked_until = now() + least(interval '1 hour', interval '1 minute' * power(2, failures - $2))
         WHERE email_key = $1 AND failures >= $2",
    )
    .bind(email_key)
    .bind(FREE_FAILURES)
    .execute(conn)
    .await?;
    Ok(())
}

async fn clear_failures(conn: &mut PgConnection, email_key: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM login_throttles WHERE email_key = $1")
        .bind(email_key)
        .execute(conn)
        .await?;
    Ok(())
}

pub(crate) async fn issue_token(
    conn: &mut PgConnection,
    purpose: &str,
    user_id: Uuid,
    email: Option<&str>,
    data: Value,
    ttl: Duration,
) -> sqlx::Result<String> {
    let token = random_token();
    sqlx::query(
        "INSERT INTO auth_tokens (token_hash, purpose, user_id, email, data, expires_at)
         VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))",
    )
    .bind(token_hash(&token))
    .bind(purpose)
    .bind(user_id)
    .bind(email)
    .bind(data)
    .bind(ttl.as_secs_f64())
    .execute(conn)
    .await?;
    Ok(token)
}


async fn take_token(
    conn: &mut PgConnection,
    purpose: &str,
    token: &str,
) -> sqlx::Result<Option<(Uuid, Option<String>, Value)>> {
    sqlx::query_as(
        "DELETE FROM auth_tokens WHERE token_hash = $1 AND purpose = $2 AND expires_at > now()
         RETURNING user_id, email, data",
    )
    .bind(token_hash(token))
    .bind(purpose)
    .fetch_optional(conn)
    .await
}


pub(crate) async fn record(
    conn: &mut PgConnection,
    user_id: Uuid,
    action: &str,
    metadata: Value,
) -> sqlx::Result<()> {
    audit::record(
        conn,
        audit::Event {
            org_id: None,
            actor: Actor::User(user_id),
            action,
            target_type: "user",
            target_id: user_id,
            metadata,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_emails_and_passwords() {
        assert!(normalize_email("  sam@example.com ").is_ok());
        for bad in [
            "",
            "sam",
            "@example.com",
            "sam@example",
            "sam @example.com",
            "sam@.com",
        ] {
            assert!(normalize_email(bad).is_err(), "{bad}");
        }
        assert!(check_password_strength("correct horse battery", "a@b.co").is_ok());
        assert!(check_password_strength("short", "a@b.co").is_err());
        assert!(check_password_strength("sam@example.com", "SAM@example.com").is_err());
        assert!(check_password_strength(&"x".repeat(2000), "a@b.co").is_err());
    }
}
