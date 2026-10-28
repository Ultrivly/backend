


use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::PgPool;
use ultrivly::identity::accounts::{self, AuthError, SignIn};
use ultrivly::identity::mfa::{self, MfaError};
use ultrivly::identity::sessions::{self, AuthMethod, ClientInfo, NewSession, OrgAccessError};
use ultrivly::platform::secrets::Secrets;
use uuid::Uuid;

mod common;
use common::{create_org, grant, role_id, totp};

const PASSWORD: &str = "correct horse battery staple";

fn client() -> ClientInfo {
    ClientInfo {
        ip_address: Some("203.0.113.7".parse().unwrap()),
        user_agent: Some("tests".into()),
    }
}

fn secrets() -> Secrets {
    Secrets::from_base64_key(&Secrets::generate_key()).unwrap()
}

async fn sign_up(pool: &PgPool, email: &str) -> Uuid {
    let mut conn = pool.acquire().await.unwrap();
    accounts::sign_up(&mut conn, email, "Sam", PASSWORD)
        .await
        .unwrap()
        .user_id
}

async fn sign_in(pool: &PgPool, email: &str, password: &str) -> Result<SignIn, AuthError> {
    let mut conn = pool.acquire().await.unwrap();
    accounts::sign_in_with_password(&mut conn, email, password, &client()).await
}

fn complete(sign_in: SignIn) -> NewSession {
    match sign_in {
        SignIn::Complete(session) => session,
        SignIn::MfaRequired { .. } => panic!("unexpected MFA challenge"),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[sqlx::test]
async fn sign_up_verify_sign_in_and_sign_out(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let signed_up = accounts::sign_up(&mut conn, " Sam@Example.com ", "Sam", PASSWORD)
        .await
        .unwrap();

    let err = accounts::sign_up(&mut conn, "sam@example.com", "Other", PASSWORD)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::EmailTaken), "{err}");

    assert_eq!(
        accounts::verify_email(&mut conn, &signed_up.verification_token)
            .await
            .unwrap(),
        signed_up.user_id
    );
    let reused = accounts::verify_email(&mut conn, &signed_up.verification_token).await;
    assert!(matches!(reused, Err(AuthError::InvalidToken)));

    
    let new = complete(sign_in(&pool, "SAM@example.com", PASSWORD).await.unwrap());
    assert_eq!(new.session.user_id, signed_up.user_id);
    assert_eq!(new.session.method, AuthMethod::Password);

    let found = sessions::authenticate(&mut conn, &new.token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found, new.session);
    assert!(
        sessions::authenticate(&mut conn, "not-a-token")
            .await
            .unwrap()
            .is_none()
    );

    
    let stored: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sessions WHERE token_hash = $1::text::bytea")
            .bind(&new.token)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored, 0);

    sessions::revoke(&mut conn, new.session.id).await.unwrap();
    assert!(
        sessions::authenticate(&mut conn, &new.token)
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test]
async fn rejects_bad_input(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let weak = accounts::sign_up(&mut conn, "sam@example.com", "Sam", "short").await;
    assert!(matches!(weak, Err(AuthError::WeakPassword(_))));
    let bad_email = accounts::sign_up(&mut conn, "sam", "Sam", PASSWORD).await;
    assert!(matches!(bad_email, Err(AuthError::InvalidEmail)));
}

#[sqlx::test]
async fn failures_look_the_same_and_are_throttled(pool: PgPool) {
    sign_up(&pool, "sam@example.com").await;

    let wrong_password = sign_in(&pool, "sam@example.com", "wrong password!!").await;
    let unknown_email = sign_in(&pool, "nobody@example.com", PASSWORD).await;
    assert!(matches!(wrong_password, Err(AuthError::InvalidCredentials)));
    assert!(matches!(unknown_email, Err(AuthError::InvalidCredentials)));

    for _ in 0..4 {
        let _ = sign_in(&pool, "sam@example.com", "wrong password!!").await;
    }
    
    let locked = sign_in(&pool, "sam@example.com", PASSWORD).await;
    assert!(
        matches!(locked, Err(AuthError::TooManyAttempts)),
        "{locked:?}"
    );

    
    for _ in 0..4 {
        let _ = sign_in(&pool, "nobody@example.com", PASSWORD).await;
    }
    let locked = sign_in(&pool, "nobody@example.com", PASSWORD).await;
    assert!(
        matches!(locked, Err(AuthError::TooManyAttempts)),
        "{locked:?}"
    );

    
    let disabled = sign_up(&pool, "gone@example.com").await;
    sqlx::query("UPDATE users SET disabled_at = now() WHERE id = $1")
        .bind(disabled)
        .execute(&pool)
        .await
        .unwrap();
    let result = sign_in(&pool, "gone@example.com", PASSWORD).await;
    assert!(matches!(result, Err(AuthError::InvalidCredentials)));
}

#[sqlx::test]
async fn password_reset_signs_out_everywhere(pool: PgPool) {
    let user = sign_up(&pool, "sam@example.com").await;
    let old = complete(sign_in(&pool, "sam@example.com", PASSWORD).await.unwrap());
    let mut conn = pool.acquire().await.unwrap();

    assert!(
        accounts::request_password_reset(&mut conn, "nobody@example.com")
            .await
            .unwrap()
            .is_none()
    );
    let (_, first) = accounts::request_password_reset(&mut conn, "sam@example.com")
        .await
        .unwrap()
        .unwrap();
    let (reset_user, token) = accounts::request_password_reset(&mut conn, "sam@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reset_user, user);

    
    let stale = accounts::reset_password(&mut conn, &first, "a brand new password").await;
    assert!(matches!(stale, Err(AuthError::InvalidToken)));
    accounts::reset_password(&mut conn, &token, "a brand new password")
        .await
        .unwrap();
    let reused = accounts::reset_password(&mut conn, &token, "another new password").await;
    assert!(matches!(reused, Err(AuthError::InvalidToken)));

    assert!(
        sessions::authenticate(&mut conn, &old.token)
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        sign_in(&pool, "sam@example.com", PASSWORD).await,
        Err(AuthError::InvalidCredentials)
    ));
    complete(
        sign_in(&pool, "sam@example.com", "a brand new password")
            .await
            .unwrap(),
    );
}

#[sqlx::test]
async fn changing_password_keeps_only_the_current_session(pool: PgPool) {
    sign_up(&pool, "sam@example.com").await;
    let here = complete(sign_in(&pool, "sam@example.com", PASSWORD).await.unwrap());
    let elsewhere = complete(sign_in(&pool, "sam@example.com", PASSWORD).await.unwrap());
    let mut conn = pool.acquire().await.unwrap();

    let wrong = accounts::change_password(
        &mut conn,
        &here.session,
        Some("nope nope nope"),
        "a brand new password",
    )
    .await;
    assert!(matches!(wrong, Err(AuthError::InvalidCredentials)));
    let missing =
        accounts::change_password(&mut conn, &here.session, None, "a brand new password").await;
    assert!(matches!(missing, Err(AuthError::InvalidCredentials)));

    accounts::change_password(
        &mut conn,
        &here.session,
        Some(PASSWORD),
        "a brand new password",
    )
    .await
    .unwrap();
    assert!(
        sessions::authenticate(&mut conn, &here.token)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        sessions::authenticate(&mut conn, &elsewhere.token)
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test]
async fn idle_and_expired_sessions_stop_working(pool: PgPool) {
    sign_up(&pool, "sam@example.com").await;
    let idle = complete(sign_in(&pool, "sam@example.com", PASSWORD).await.unwrap());
    let expired = complete(sign_in(&pool, "sam@example.com", PASSWORD).await.unwrap());
    sqlx::query("UPDATE sessions SET last_seen_at = now() - interval '8 days' WHERE id = $1")
        .bind(idle.session.id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE sessions SET expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(expired.session.id)
        .execute(&pool)
        .await
        .unwrap();
    let mut conn = pool.acquire().await.unwrap();
    assert!(
        sessions::authenticate(&mut conn, &idle.token)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        sessions::authenticate(&mut conn, &expired.token)
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test]
async fn totp_and_recovery_codes(pool: PgPool) {
    let secrets = secrets();
    let user = sign_up(&pool, "sam@example.com").await;
    let mut conn = pool.acquire().await.unwrap();

    let enrollment = mfa::start_totp_enrollment(&mut conn, &secrets, user, "Ultrivly")
        .await
        .unwrap();
    assert!(
        enrollment
            .otpauth_uri
            .starts_with("otpauth://totp/Ultrivly:sam@example.com?secret=")
    );
    
    complete(sign_in(&pool, "sam@example.com", PASSWORD).await.unwrap());

    let wrong = mfa::confirm_totp_enrollment(
        &mut conn,
        &secrets,
        user,
        enrollment.factor_id,
        "000000",
        None,
    )
    .await;
    assert!(matches!(wrong, Err(MfaError::InvalidCode)));
    
    
    let recovery = mfa::confirm_totp_enrollment(
        &mut conn,
        &secrets,
        user,
        enrollment.factor_id,
        &totp(&enrollment.secret, now() - 30),
        None,
    )
    .await
    .unwrap();
    assert_eq!(recovery.len(), 10);

    
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT secret_ciphertext FROM mfa_factors WHERE user_id = $1")
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!String::from_utf8_lossy(&stored).contains(&enrollment.secret));

    
    let SignIn::MfaRequired { challenge } =
        sign_in(&pool, "sam@example.com", PASSWORD).await.unwrap()
    else {
        panic!("expected an MFA challenge");
    };
    let code = totp(&enrollment.secret, now());
    let session = mfa::complete_challenge(&mut conn, &secrets, &challenge, &code, &client())
        .await
        .unwrap();
    assert!(session.session.mfa_verified);

    
    let SignIn::MfaRequired { challenge } =
        sign_in(&pool, "sam@example.com", PASSWORD).await.unwrap()
    else {
        panic!("expected an MFA challenge");
    };
    let replay = mfa::complete_challenge(&mut conn, &secrets, &challenge, &code, &client()).await;
    assert!(matches!(replay, Err(MfaError::InvalidCode)), "{replay:?}");

    
    let first = recovery[0].to_uppercase();
    mfa::complete_challenge(&mut conn, &secrets, &challenge, &first, &client())
        .await
        .unwrap();
    let SignIn::MfaRequired { challenge } =
        sign_in(&pool, "sam@example.com", PASSWORD).await.unwrap()
    else {
        panic!("expected an MFA challenge");
    };
    let reused =
        mfa::complete_challenge(&mut conn, &secrets, &challenge, &recovery[0], &client()).await;
    assert!(matches!(reused, Err(MfaError::InvalidCode)));
}

#[sqlx::test]
async fn mfa_challenges_allow_five_attempts(pool: PgPool) {
    let secrets = secrets();
    let user = sign_up(&pool, "sam@example.com").await;
    let mut conn = pool.acquire().await.unwrap();
    let enrollment = mfa::start_totp_enrollment(&mut conn, &secrets, user, "Ultrivly")
        .await
        .unwrap();
    mfa::confirm_totp_enrollment(
        &mut conn,
        &secrets,
        user,
        enrollment.factor_id,
        &totp(&enrollment.secret, now() - 30),
        None,
    )
    .await
    .unwrap();

    let SignIn::MfaRequired { challenge } =
        sign_in(&pool, "sam@example.com", PASSWORD).await.unwrap()
    else {
        panic!("expected an MFA challenge");
    };
    for _ in 0..5 {
        let err =
            mfa::complete_challenge(&mut conn, &secrets, &challenge, "000000", &client()).await;
        assert!(matches!(err, Err(MfaError::InvalidCode)));
    }
    
    let code = totp(&enrollment.secret, now());
    let err = mfa::complete_challenge(&mut conn, &secrets, &challenge, &code, &client()).await;
    assert!(matches!(err, Err(MfaError::InvalidChallenge)), "{err:?}");
}

#[sqlx::test]
async fn organization_policies_require_mfa_and_sso(pool: PgPool) {
    let secrets = secrets();
    let (org, owner) = create_org(&pool, "acme").await;
    let agent_role = role_id(&pool, org.org_id, "agent").await;
    let agent = sign_up(&pool, "agent@acme.test").await;
    let membership = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO memberships (id, org_id, user_id, status) VALUES ($1, $2, $3, 'active')",
    )
    .bind(membership)
    .bind(org.org_id)
    .bind(agent)
    .execute(&pool)
    .await
    .unwrap();
    grant(&pool, org.org_id, membership, agent_role, None).await;
    let signed_in = complete(sign_in(&pool, "agent@acme.test", PASSWORD).await.unwrap());
    let session = signed_in.session.clone();
    let mut conn = pool.acquire().await.unwrap();

    let access = sessions::check_org_access(&mut conn, &session, org.org_id)
        .await
        .unwrap();
    assert_eq!(access, Ok(()));

    
    sqlx::query("UPDATE organizations SET require_mfa = true WHERE id = $1")
        .bind(org.org_id)
        .execute(&pool)
        .await
        .unwrap();
    let access = sessions::check_org_access(&mut conn, &session, org.org_id)
        .await
        .unwrap();
    assert_eq!(access, Err(OrgAccessError::MfaRequired));

    let enrollment = mfa::start_totp_enrollment(&mut conn, &secrets, agent, "Ultrivly")
        .await
        .unwrap();
    mfa::confirm_totp_enrollment(
        &mut conn,
        &secrets,
        agent,
        enrollment.factor_id,
        &totp(&enrollment.secret, now()),
        Some(&session),
    )
    .await
    .unwrap();
    
    let session = sessions::authenticate(&mut conn, &signed_in.token)
        .await
        .unwrap()
        .unwrap();
    assert!(session.mfa_verified);
    let access = sessions::check_org_access(&mut conn, &session, org.org_id)
        .await
        .unwrap();
    assert_eq!(access, Ok(()));

    
    sqlx::query(
        "INSERT INTO sso_connections (id, org_id, name, issuer_url, client_id, client_secret_ciphertext, enforced)
         VALUES ($1, $2, 'Okta', 'https://acme.okta.example', 'client', '\\x00', true)",
    )
    .bind(Uuid::now_v7())
    .bind(org.org_id)
    .execute(&pool)
    .await
    .unwrap();
    let access = sessions::check_org_access(&mut conn, &session, org.org_id)
        .await
        .unwrap();
    assert_eq!(access, Err(OrgAccessError::SsoRequired));

    
    
    sqlx::query("UPDATE organizations SET require_mfa = false WHERE id = $1")
        .bind(org.org_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET password_hash = (SELECT password_hash FROM users WHERE id = $2) WHERE id = $1")
        .bind(owner)
        .bind(agent)
        .execute(&pool)
        .await
        .unwrap();
    let owner_email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(owner)
        .fetch_one(&pool)
        .await
        .unwrap();
    let admin_session = complete(sign_in(&pool, &owner_email, PASSWORD).await.unwrap()).session;
    let access = sessions::check_org_access(&mut conn, &admin_session, org.org_id)
        .await
        .unwrap();
    assert_eq!(access, Ok(()));
}

#[sqlx::test]
async fn password_reset_on_an_unverified_account_removes_pre_attached_access(pool: PgPool) {
    
    
    let secrets = secrets();
    let user = sign_up(&pool, "victim@example.com").await;
    let mut conn = pool.acquire().await.unwrap();
    sqlx::query(
        "INSERT INTO auth_identities (id, user_id, issuer, subject) VALUES ($1, $2, 'https://idp.example', 'attacker')",
    )
    .bind(Uuid::now_v7())
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    let enrollment = mfa::start_totp_enrollment(&mut conn, &secrets, user, "Ultrivly")
        .await
        .unwrap();
    mfa::confirm_totp_enrollment(
        &mut conn,
        &secrets,
        user,
        enrollment.factor_id,
        &totp(&enrollment.secret, now()),
        None,
    )
    .await
    .unwrap();

    
    let (_, token) = accounts::request_password_reset(&mut conn, "victim@example.com")
        .await
        .unwrap()
        .unwrap();
    accounts::reset_password(&mut conn, &token, "the owner's new password")
        .await
        .unwrap();

    let (identities, factors, verified): (i64, i64, bool) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM auth_identities WHERE user_id = $1),
                (SELECT count(*) FROM mfa_factors WHERE user_id = $1),
                (SELECT email_verified_at IS NOT NULL FROM users WHERE id = $1)",
    )
    .bind(user)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((identities, factors, verified), (0, 0, true));
    complete(
        sign_in(&pool, "victim@example.com", "the owner's new password")
            .await
            .unwrap(),
    );
}
