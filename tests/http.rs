


use axum::http::{Method, StatusCode, header};
use serde_json::{Value, json};
use sqlx::PgPool;
use ultrivly::identity::{self, NewOrganization};
use uuid::Uuid;

mod common;
use common::app::{App, ORIGIN, PASSWORD, Reply, SESSION, now, token_in};
use common::totp;

#[sqlx::test]
async fn sign_up_verify_sign_in_and_out(pool: PgPool) {
    let app = App::new(pool).await;
    app.sign_up_and_verify("sam@example.com").await;

    let reply = app
        .call(
            Method::POST,
            "/api/v1/auth/sign-in",
            Some(json!({ "email": "sam@example.com", "password": PASSWORD })),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    let cookie = reply.cookie(SESSION).unwrap();
    for attribute in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
        assert!(cookie.contains(attribute), "{cookie} lacks {attribute}");
    }
    let token = reply.cookie_value(SESSION).unwrap();

    let me = app
        .call(Method::GET, "/api/v1/me", None, Some(&token))
        .await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.body["user"]["email"], "sam@example.com");
    assert_eq!(me.body["user"]["email_verified"], true);

    let out = app
        .call(Method::POST, "/api/v1/auth/sign-out", None, Some(&token))
        .await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    let me = app
        .call(Method::GET, "/api/v1/me", None, Some(&token))
        .await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
    assert_eq!(me.body["error"]["code"], "unauthenticated");
}

#[sqlx::test]
async fn responses_never_reveal_whether_an_account_exists(pool: PgPool) {
    let app = App::new(pool).await;
    app.sign_up_and_verify("sam@example.com").await;

    
    let reply = app
        .call(
            Method::POST,
            "/api/v1/auth/sign-up",
            Some(json!({ "email": "sam@example.com", "display_name": "X", "password": PASSWORD })),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::ACCEPTED);
    assert_eq!(reply.body, json!({ "status": "check_your_email" }));
    
    let emails = app.deliver().await;
    assert_eq!(emails.len(), 1);
    assert!(emails[0].subject.contains("tried to sign up"));

    
    
    for email in ["sam@example.com", "nobody@example.com"] {
        let reply = app
            .call(
                Method::POST,
                "/api/v1/auth/forgot-password",
                Some(json!({ "email": email })),
                None,
            )
            .await;
        assert_eq!(reply.status, StatusCode::ACCEPTED);
        assert_eq!(reply.body, json!({ "status": "check_your_email" }));
    }
    let emails = app.deliver().await;
    assert_eq!(emails.len(), 1);
    assert_eq!(emails[0].to, "sam@example.com");

    
    let token = token_in(&emails, "sam@example.com");
    let reset = |token: String| {
        app.call(
            Method::POST,
            "/api/v1/auth/reset-password",
            Some(json!({ "token": token, "password": "a whole new password" })),
            None,
        )
    };
    assert_eq!(reset(token.clone()).await.status, StatusCode::OK);
    assert_eq!(reset(token).await.status, StatusCode::BAD_REQUEST);
    assert!(
        app.deliver().await[0]
            .subject
            .contains("password was changed")
    );

    
    app.call(
        Method::POST,
        "/api/v1/auth/forgot-password",
        Some(json!({ "email": "sam@example.com" })),
        None,
    )
    .await;
    let payload: Value = sqlx::query_scalar("SELECT payload FROM jobs WHERE state = 'queued'")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert!(
        !payload.to_string().contains("sam@example.com"),
        "{payload}"
    );
}

#[sqlx::test]
async fn cross_site_requests_are_refused(pool: PgPool) {
    let app = App::new(pool).await;
    app.sign_up_and_verify("sam@example.com").await;
    let token = app.sign_in("sam@example.com").await;

    
    let reply = app
        .raw(
            Method::POST,
            "/api/v1/me/sessions/sign-out-others",
            None,
            Some(&token),
            Some("https://evil.example"),
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.body["error"]["code"], "cross_site_request");

    
    let reply = app
        .raw(
            Method::POST,
            "/api/v1/me/sessions/sign-out-others",
            None,
            Some(&token),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    
    let reply = app
        .raw(
            Method::POST,
            "/api/v1/auth/sign-in",
            Some(json!({ "email": "sam@example.com", "password": PASSWORD })),
            None,
            Some("https://evil.example"),
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    
    let reply = app
        .call(
            Method::POST,
            "/api/v1/me/sessions/sign-out-others",
            None,
            Some(&token),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK);
}

#[sqlx::test]
async fn every_response_carries_security_headers(pool: PgPool) {
    let app = App::new(pool).await;
    for path in ["/healthz", "/api/v1/me", "/no-such-page"] {
        let reply = app.call(Method::GET, path, None, None).await;
        let h = &reply.headers;
        assert_eq!(h["x-content-type-options"], "nosniff", "{path}");
        assert_eq!(h["x-frame-options"], "DENY");
        assert_eq!(h["referrer-policy"], "no-referrer");
        assert_eq!(h["cache-control"], "no-store");
        assert!(
            h["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
        assert!(
            h["strict-transport-security"]
                .to_str()
                .unwrap()
                .starts_with("max-age=")
        );
        assert!(h.contains_key("x-request-id"));
    }
    let missing = app.call(Method::GET, "/no-such-page", None, None).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.body["error"]["code"], "not_found");
    assert_eq!(
        app.call(Method::GET, "/readyz", None, None).await.status,
        StatusCode::OK
    );
}

#[sqlx::test]
async fn sign_in_is_rate_limited_per_ip(pool: PgPool) {
    let app = App::new(pool.clone()).await;
    async fn attempt(app: &App) -> Reply {
        let email = format!("{}@example.com", Uuid::now_v7());
        app.call(
            Method::POST,
            "/api/v1/auth/sign-in",
            Some(json!({ "email": email, "password": "wrong password!" })),
            None,
        )
        .await
    }
    for _ in 0..30 {
        assert_eq!(attempt(&app).await.status, StatusCode::UNAUTHORIZED);
    }
    let limited = attempt(&app).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers.contains_key(header::RETRY_AFTER));

    
    let other = App::with_ip(pool, [198, 51, 100, 20]).await;
    assert_eq!(attempt(&other).await.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn mfa_sign_in_and_reauthentication(pool: PgPool) {
    let app = App::new(pool).await;
    app.sign_up_and_verify("sam@example.com").await;
    let token = app.sign_in("sam@example.com").await;

    let started = app
        .call(
            Method::POST,
            "/api/v1/me/mfa/totp",
            Some(json!({})),
            Some(&token),
        )
        .await;
    let secret = started.body["secret"].as_str().unwrap().to_string();
    let confirmed = app
        .call(
            Method::POST,
            "/api/v1/me/mfa/totp/confirm",
            Some(json!({ "factor_id": started.body["factor_id"], "code": totp(&secret, now() - 30) })),
            Some(&token),
        )
        .await;
    assert_eq!(confirmed.status, StatusCode::OK, "{}", confirmed.body);
    assert_eq!(
        confirmed.body["recovery_codes"].as_array().unwrap().len(),
        10
    );

    
    let reply = app
        .call(
            Method::POST,
            "/api/v1/auth/sign-in",
            Some(json!({ "email": "sam@example.com", "password": PASSWORD })),
            None,
        )
        .await;
    assert_eq!(reply.body["status"], "mfa_required");
    assert!(reply.cookie_value(SESSION).is_none());
    let challenge = reply.body["challenge"].as_str().unwrap();
    let reply = app
        .call(
            Method::POST,
            "/api/v1/auth/mfa",
            Some(json!({ "challenge": challenge, "code": totp(&secret, now()) })),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let mfa_token = reply.cookie_value(SESSION).unwrap();

    
    let reply = app
        .call(
            Method::POST,
            "/api/v1/me/mfa/totp/disable",
            Some(json!({})),
            Some(&mfa_token),
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.body["error"]["code"], "reauthentication_required");
    let reply = app
        .call(
            Method::POST,
            "/api/v1/me/mfa/totp/disable",
            Some(json!({ "password": PASSWORD })),
            Some(&mfa_token),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert!(
        app.deliver()
            .await
            .iter()
            .any(|e| e.subject.contains("turned off"))
    );
}

#[sqlx::test]
async fn invitations_flow(pool: PgPool) {
    let app = App::new(pool.clone()).await;
    let owner = app.sign_up_and_verify("owner@acme.test").await;
    let mut conn = pool.acquire().await.unwrap();
    let org = identity::create_organization(
        &mut conn,
        NewOrganization {
            name: "Acme",
            slug: "acme",
            workspace_name: "Support",
            workspace_slug: "support",
            owner_user_id: owner,
        },
    )
    .await
    .unwrap();
    let agent_role: Uuid =
        sqlx::query_scalar("SELECT id FROM roles WHERE org_id = $1 AND key = 'agent'")
            .bind(org.org_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let owner_token = app.sign_in("owner@acme.test").await;
    let path = format!("/api/v1/orgs/{}/invitations", org.org_id);

    let reply = app
        .call(
            Method::POST,
            &path,
            Some(json!({ "email": "new@acme.test", "role_id": agent_role })),
            Some(&owner_token),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    let invite = token_in(&app.deliver().await, "new@acme.test");

    let listed = app.call(Method::GET, &path, None, Some(&owner_token)).await;
    assert_eq!(listed.body["invitations"].as_array().unwrap().len(), 1);

    
    app.sign_up_and_verify("other@acme.test").await;
    let other = app.sign_in("other@acme.test").await;
    let reply = app
        .call(
            Method::POST,
            "/api/v1/invitations/accept",
            Some(json!({ "token": invite })),
            Some(&other),
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.body["error"]["code"], "invitation_wrong_account");

    
    app.sign_up_and_verify("new@acme.test").await;
    let newcomer = app.sign_in("new@acme.test").await;
    let reply = app
        .call(
            Method::POST,
            "/api/v1/invitations/accept",
            Some(json!({ "token": invite })),
            Some(&newcomer),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let me = app
        .call(Method::GET, "/api/v1/me", None, Some(&newcomer))
        .await;
    assert_eq!(me.body["user"]["organizations"][0]["slug"], "acme");

    
    let reply = app
        .call(
            Method::POST,
            &path,
            Some(json!({ "email": "x@acme.test", "role_id": agent_role })),
            Some(&newcomer),
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    
    sqlx::query("UPDATE organizations SET require_mfa = true WHERE id = $1")
        .bind(org.org_id)
        .execute(&pool)
        .await
        .unwrap();
    let reply = app.call(Method::GET, &path, None, Some(&owner_token)).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.body["error"]["code"], "mfa_required");
}

#[sqlx::test]
async fn sso_callback_requires_the_browser_that_started_it(pool: PgPool) {
    let app = App::new(pool).await;
    
    let reply = app
        .call(
            Method::GET,
            "/auth/oidc/callback?state=abc&code=xyz",
            None,
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(
        reply.headers[header::LOCATION],
        "/sign-in?error=sso_state_invalid"
    );
    assert!(reply.cookie_value(SESSION).is_none());
}

#[sqlx::test]
async fn passkeys_as_a_second_factor(pool: PgPool) {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

    let app = App::new(pool).await;
    app.sign_up_and_verify("sam@example.com").await;
    let token = app.sign_in("sam@example.com").await;
    let origin: url::Url = ORIGIN.parse().unwrap();
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    
    let start = app
        .call(
            Method::POST,
            "/api/v1/me/mfa/passkeys/start",
            Some(json!({ "label": "Laptop" })),
            Some(&token),
        )
        .await;
    assert_eq!(start.status, StatusCode::OK, "{}", start.body);
    let options: CreationChallengeResponse =
        serde_json::from_value(start.body["options"].clone()).unwrap();
    let credential = authenticator
        .do_registration(origin.clone(), options)
        .unwrap();
    let finish = app
        .call(
            Method::POST,
            "/api/v1/me/mfa/passkeys/finish",
            Some(json!({ "ceremony_id": start.body["ceremony_id"], "credential": credential })),
            Some(&token),
        )
        .await;
    assert_eq!(finish.status, StatusCode::OK, "{}", finish.body);
    assert_eq!(finish.body["recovery_codes"].as_array().unwrap().len(), 10);

    
    let reply = app
        .call(
            Method::POST,
            "/api/v1/me/mfa/totp",
            Some(json!({})),
            Some(&token),
        )
        .await;
    assert_eq!(reply.body["error"]["code"], "reauthentication_required");

    
    let signed = app
        .call(
            Method::POST,
            "/api/v1/auth/sign-in",
            Some(json!({ "email": "sam@example.com", "password": PASSWORD })),
            None,
        )
        .await;
    assert_eq!(signed.body["status"], "mfa_required");
    let challenge = signed.body["challenge"].clone();

    let begin = |challenge: Value| {
        let body = json!({ "challenge": challenge });
        let app = &app;
        async move {
            let start = app
                .call(
                    Method::POST,
                    "/api/v1/auth/mfa/passkey/start",
                    Some(body),
                    None,
                )
                .await;
            assert_eq!(start.status, StatusCode::OK, "{}", start.body);
            let options: RequestChallengeResponse =
                serde_json::from_value(start.body["options"].clone()).unwrap();
            (start.body["ceremony_id"].clone(), options)
        }
    };

    
    let (_, options) = begin(challenge.clone()).await;
    assert!(
        authenticator
            .do_authentication("https://evil.example".parse().unwrap(), options)
            .is_err()
    );

    
    
    let (first_ceremony, options) = begin(challenge.clone()).await;
    let assertion = authenticator.do_authentication(origin, options).unwrap();
    let (other_ceremony, _) = begin(challenge.clone()).await;
    let reply = app
        .call(
            Method::POST,
            "/api/v1/auth/mfa/passkey/finish",
            Some(json!({ "challenge": challenge, "ceremony_id": other_ceremony, "credential": assertion })),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
    assert_eq!(reply.body["error"]["code"], "invalid_code");

    
    let answer =
        json!({ "challenge": challenge, "ceremony_id": first_ceremony, "credential": assertion });
    let reply = app
        .call(
            Method::POST,
            "/api/v1/auth/mfa/passkey/finish",
            Some(answer.clone()),
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(reply.cookie_value(SESSION).is_some());

    
    let replay = app
        .call(
            Method::POST,
            "/api/v1/auth/mfa/passkey/finish",
            Some(answer),
            None,
        )
        .await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
    assert_eq!(replay.body["error"]["code"], "mfa_challenge_expired");

    let listed = app
        .call(Method::GET, "/api/v1/me/mfa/passkeys", None, Some(&token))
        .await;
    assert_eq!(listed.body["passkeys"][0]["label"], "Laptop");
    assert!(!listed.body["passkeys"][0]["last_used_at"].is_null());
}
