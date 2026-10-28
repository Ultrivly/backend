




use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use chrono::{Duration, Utc};
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
    CoreRsaPrivateSigningKey,
};
use openidconnect::{
    Audience, EmptyAdditionalClaims, EndUserEmail, IssuerUrl, JsonWebKeyId, Nonce,
    PrivateSigningKey, StandardClaims, SubjectIdentifier,
};
use serde_json::{Value, json};
use sqlx::PgPool;
use ultrivly::audit::Actor;
use ultrivly::config::Deployment;
use ultrivly::identity::accounts::{self, SignIn};
use ultrivly::identity::sessions::{self, AuthMethod, ClientInfo};
use ultrivly::identity::sso::{
    ConnectionChanges, NewConnection, Provider, SocialProvider, Sso, SsoError, SsoOutcome,
};
use ultrivly::platform::net::{HttpClient, NetPolicy};
use ultrivly::platform::secrets::Secrets;
use uuid::Uuid;

mod common;
use common::{create_org, member_with_role, role_id};

const CLIENT_SECRET: &str = "connection-client-secret";


struct PendingLogin {
    client_id: String,
    subject: String,
    email: String,
    email_verified: bool,
    nonce: String,
}

struct IdpState {
    issuer: String,
    key: CoreRsaPrivateSigningKey,
    pending: Mutex<HashMap<String, PendingLogin>>,
}

struct FakeIdp {
    state: Arc<IdpState>,
}

impl FakeIdp {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let key = CoreRsaPrivateSigningKey::from_pem(
            include_str!("fixtures/test-idp-key.pem"),
            Some(JsonWebKeyId::new("test-key".into())),
        )
        .unwrap();
        let state = Arc::new(IdpState {
            issuer,
            key,
            pending: Mutex::new(HashMap::new()),
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .with_state(state.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { state }
    }

    fn issuer(&self) -> &str {
        &self.state.issuer
    }
}

async fn discovery(State(idp): State<Arc<IdpState>>) -> Json<Value> {
    let base = &idp.issuer;
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }))
}

async fn jwks(State(idp): State<Arc<IdpState>>) -> Json<Value> {
    let set = CoreJsonWebKeySet::new(vec![idp.key.as_verification_key()]);
    Json(serde_json::to_value(set).unwrap())
}

async fn token(
    State(idp): State<Arc<IdpState>>,
    Form(form): Form<HashMap<String, String>>,
) -> Json<Value> {
    let login = idp
        .pending
        .lock()
        .unwrap()
        .remove(&form["code"])
        .expect("unknown authorization code");
    let claims = CoreIdTokenClaims::new(
        IssuerUrl::new(idp.issuer.clone()).unwrap(),
        vec![Audience::new(login.client_id)],
        Utc::now() + Duration::hours(1),
        Utc::now(),
        StandardClaims::new(SubjectIdentifier::new(login.subject))
            .set_email(Some(EndUserEmail::new(login.email)))
            .set_email_verified(Some(login.email_verified)),
        EmptyAdditionalClaims {},
    )
    .set_nonce(Some(Nonce::new(login.nonce)));
    let id_token = CoreIdToken::new(
        claims,
        &idp.key,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .unwrap();
    Json(json!({
        "access_token": "access-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": serde_json::to_value(id_token).unwrap(),
    }))
}

fn sso_for(social: Vec<SocialProvider>) -> Sso {
    
    
    let http = HttpClient::new(NetPolicy::new(
        Deployment::SelfHosted,
        &["127.0.0.1".into()],
    ))
    .unwrap();
    Sso::new(
        Secrets::from_base64_key(&Secrets::generate_key()).unwrap(),
        http,
        "https://ultrivly.test",
        social,
    )
    .unwrap()
}


struct Person<'a> {
    subject: &'a str,
    email: &'a str,
    email_verified: bool,
}


async fn round_trip(
    pool: &PgPool,
    sso: &Sso,
    idp: &FakeIdp,
    provider: Provider<'_>,
    person: Person<'_>,
    link_user_id: Option<Uuid>,
) -> Result<SsoOutcome, SsoError> {
    let mut conn = pool.acquire().await.unwrap();
    let url = sso
        .begin(&mut conn, provider, Some("/cases"), link_user_id)
        .await?;
    let url = url::Url::parse(&url).unwrap();
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(
        query["redirect_uri"],
        "https://ultrivly.test/auth/oidc/callback"
    );
    assert_eq!(query["code_challenge_method"], "S256");

    let code = Uuid::now_v7().to_string();
    idp.state.pending.lock().unwrap().insert(
        code.clone(),
        PendingLogin {
            client_id: query["client_id"].clone(),
            subject: person.subject.into(),
            email: person.email.into(),
            email_verified: person.email_verified,
            nonce: query["nonce"].clone(),
        },
    );
    sso.complete(&mut conn, &query["state"], &code, &ClientInfo::default())
        .await
}

fn signed_in_user(outcome: SsoOutcome) -> (Uuid, AuthMethod, String) {
    match outcome {
        SsoOutcome::SignedIn {
            sign_in: SignIn::Complete(new),
            redirect_to,
        } => {
            assert_eq!(redirect_to.as_deref(), Some("/cases"));
            (new.session.user_id, new.session.method, new.token)
        }
        other => panic!("expected a completed sign-in, got {other:?}"),
    }
}

async fn create_connection(
    pool: &PgPool,
    sso: &Sso,
    idp: &FakeIdp,
    org_id: Uuid,
    owner: Uuid,
    jit: bool,
    default_role_id: Option<Uuid>,
) -> Uuid {
    let mut conn = pool.acquire().await.unwrap();
    sso.create_connection(
        &mut conn,
        org_id,
        Actor::User(owner),
        NewConnection {
            name: "Acme IdP",
            issuer_url: idp.issuer(),
            client_id: "acme-client",
            client_secret: CLIENT_SECRET,
            email_domains: &["acme.test"],
            jit_provisioning: jit,
            default_role_id,
            enforced: false,
        },
    )
    .await
    .unwrap()
}

#[sqlx::test]
async fn first_sign_in_provisions_a_member_with_the_default_role(pool: PgPool) {
    let idp = FakeIdp::start().await;
    let sso = sso_for(vec![]);
    let (org, owner) = create_org(&pool, "acme").await;
    let agent_role = role_id(&pool, org.org_id, "agent").await;
    let connection =
        create_connection(&pool, &sso, &idp, org.org_id, owner, true, Some(agent_role)).await;

    
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT client_secret_ciphertext FROM sso_connections WHERE id = $1")
            .bind(connection)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!String::from_utf8_lossy(&stored).contains(CLIENT_SECRET));

    let alice = Person {
        subject: "alice-123",
        email: "alice@acme.test",
        email_verified: true,
    };
    let outcome = round_trip(
        &pool,
        &sso,
        &idp,
        Provider::Connection(connection),
        alice,
        None,
    )
    .await
    .unwrap();
    let (user, method, token) = signed_in_user(outcome);
    assert_eq!(
        method,
        AuthMethod::Sso {
            connection_id: connection
        }
    );

    
    let mut conn = pool.acquire().await.unwrap();
    let held = ultrivly::platform::authz::effective_permissions(&mut conn, org.org_id, user, None)
        .await
        .unwrap();
    assert!(held.contains(&ultrivly::platform::authz::Permission::CasesRead));
    let session = sessions::authenticate(&mut conn, &token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        sessions::check_org_access(&mut conn, &session, org.org_id)
            .await
            .unwrap(),
        Ok(())
    );

    
    let again = Person {
        subject: "alice-123",
        email: "alice@acme.test",
        email_verified: true,
    };
    let outcome = round_trip(
        &pool,
        &sso,
        &idp,
        Provider::Connection(connection),
        again,
        None,
    )
    .await
    .unwrap();
    assert_eq!(signed_in_user(outcome).0, user);
}

#[sqlx::test]
async fn sign_in_states_are_single_use_and_bound_to_the_nonce(pool: PgPool) {
    let idp = FakeIdp::start().await;
    let sso = sso_for(vec![]);
    let (org, owner) = create_org(&pool, "acme").await;
    let connection = create_connection(&pool, &sso, &idp, org.org_id, owner, true, None).await;
    let mut conn = pool.acquire().await.unwrap();

    let url = sso
        .begin(&mut conn, Provider::Connection(connection), None, None)
        .await
        .unwrap();
    let query: HashMap<String, String> = url::Url::parse(&url)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect();

    
    idp.state.pending.lock().unwrap().insert(
        "code-1".into(),
        PendingLogin {
            client_id: query["client_id"].clone(),
            subject: "mallory".into(),
            email: "mallory@acme.test".into(),
            email_verified: true,
            nonce: "some-other-nonce".into(),
        },
    );
    let err = sso
        .complete(&mut conn, &query["state"], "code-1", &ClientInfo::default())
        .await
        .unwrap_err();
    assert!(matches!(err, SsoError::Provider(_)), "{err}");

    
    let err = sso
        .complete(&mut conn, &query["state"], "code-2", &ClientInfo::default())
        .await
        .unwrap_err();
    assert!(matches!(err, SsoError::InvalidState), "{err}");

    
    let err = sso
        .begin(
            &mut conn,
            Provider::Connection(connection),
            Some("https://evil.example"),
            None,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            SsoError::Invalid {
                field: "redirect_to",
                ..
            }
        ),
        "{err}"
    );
}

#[sqlx::test]
async fn domains_and_provisioning_settings_are_enforced(pool: PgPool) {
    let idp = FakeIdp::start().await;
    let sso = sso_for(vec![]);
    let (org, owner) = create_org(&pool, "acme").await;
    let connection = create_connection(&pool, &sso, &idp, org.org_id, owner, false, None).await;

    let outsider = Person {
        subject: "eve",
        email: "eve@evil.test",
        email_verified: true,
    };
    let err = round_trip(
        &pool,
        &sso,
        &idp,
        Provider::Connection(connection),
        outsider,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, SsoError::EmailDomainNotAllowed), "{err}");

    
    let newcomer = Person {
        subject: "dave",
        email: "dave@acme.test",
        email_verified: true,
    };
    let err = round_trip(
        &pool,
        &sso,
        &idp,
        Provider::Connection(connection),
        newcomer,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, SsoError::NotProvisioned), "{err}");
    let users: i64 =
        sqlx::query_scalar("SELECT count(*) FROM users WHERE email = 'dave@acme.test'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(users, 0);

    
    let mut conn = pool.acquire().await.unwrap();
    sso.update_connection(
        &mut conn,
        org.org_id,
        connection,
        Actor::User(owner),
        ConnectionChanges {
            enabled: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let err = sso
        .begin(&mut conn, Provider::Connection(connection), None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, SsoError::Unavailable), "{err}");
}

#[sqlx::test]
async fn existing_accounts_are_linked_only_by_their_owner(pool: PgPool) {
    let idp = FakeIdp::start().await;
    let sso = sso_for(vec![]);
    let (org, owner) = create_org(&pool, "acme").await;
    let connection = create_connection(&pool, &sso, &idp, org.org_id, owner, true, None).await;
    let mut conn = pool.acquire().await.unwrap();
    let carol = {
        let signup = accounts::sign_up(
            &mut conn,
            "carol@acme.test",
            "Carol",
            "carol's long password",
        )
        .await
        .unwrap();
        
        accounts::verify_email(&mut conn, &signup.verification_token)
            .await
            .unwrap();
        signup.user_id
    };

    
    let claimed = Person {
        subject: "carol-idp",
        email: "carol@acme.test",
        email_verified: true,
    };
    let err = round_trip(
        &pool,
        &sso,
        &idp,
        Provider::Connection(connection),
        claimed,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, SsoError::AccountExists), "{err}");

    
    let link = Person {
        subject: "carol-idp",
        email: "carol@acme.test",
        email_verified: true,
    };
    let outcome = round_trip(
        &pool,
        &sso,
        &idp,
        Provider::Connection(connection),
        link,
        Some(carol),
    )
    .await
    .unwrap();
    assert!(matches!(outcome, SsoOutcome::Linked { user_id, .. } if user_id == carol));

    
    let again = Person {
        subject: "carol-idp",
        email: "carol@acme.test",
        email_verified: true,
    };
    let outcome = round_trip(
        &pool,
        &sso,
        &idp,
        Provider::Connection(connection),
        again,
        None,
    )
    .await
    .unwrap();
    assert_eq!(signed_in_user(outcome).0, carol);

    
    let someone = {
        let signup =
            accounts::sign_up(&mut conn, "else@acme.test", "Else", "another long password")
                .await
                .unwrap();
        
        accounts::verify_email(&mut conn, &signup.verification_token)
            .await
            .unwrap();
        signup.user_id
    };
    let steal = Person {
        subject: "carol-idp",
        email: "carol@acme.test",
        email_verified: true,
    };
    let err = round_trip(
        &pool,
        &sso,
        &idp,
        Provider::Connection(connection),
        steal,
        Some(someone),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, SsoError::IdentityInUse), "{err}");
}

#[sqlx::test]
async fn social_sign_in_trusts_only_verified_emails(pool: PgPool) {
    let idp = FakeIdp::start().await;
    let google = SocialProvider {
        key: "google".into(),
        issuer_url: idp.issuer().into(),
        client_id: "social-client".into(),
        client_secret: "social-secret".into(),
        trust_verified_email: true,
    };
    let sso = sso_for(vec![google]);
    let mut conn = pool.acquire().await.unwrap();

    
    let pat = Person {
        subject: "g-pat",
        email: "pat@gmail.test",
        email_verified: true,
    };
    let (pat_id, method, _) = signed_in_user(
        round_trip(&pool, &sso, &idp, Provider::Social("google"), pat, None)
            .await
            .unwrap(),
    );
    assert_eq!(method, AuthMethod::Social);
    let verified: bool =
        sqlx::query_scalar("SELECT email_verified_at IS NOT NULL FROM users WHERE id = $1")
            .bind(pat_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(verified);

    
    let signup = accounts::sign_up(&mut conn, "lee@gmail.test", "Lee", "lee's long password")
        .await
        .unwrap();
    accounts::verify_email(&mut conn, &signup.verification_token)
        .await
        .unwrap();
    let lee = Person {
        subject: "g-lee",
        email: "lee@gmail.test",
        email_verified: true,
    };
    let (lee_id, _, _) = signed_in_user(
        round_trip(&pool, &sso, &idp, Provider::Social("google"), lee, None)
            .await
            .unwrap(),
    );
    assert_eq!(lee_id, signup.user_id);

    
    accounts::sign_up(&mut conn, "kim@gmail.test", "Kim", "kim's long password")
        .await
        .unwrap();
    let kim = Person {
        subject: "g-kim",
        email: "kim@gmail.test",
        email_verified: false,
    };
    let err = round_trip(&pool, &sso, &idp, Provider::Social("google"), kim, None)
        .await
        .unwrap_err();
    assert!(matches!(err, SsoError::AccountExists), "{err}");

    let err = sso
        .begin(&mut conn, Provider::Social("myspace"), None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, SsoError::Unavailable), "{err}");
}

#[sqlx::test]
async fn managing_connections_needs_security_manage_and_a_safe_issuer(pool: PgPool) {
    let idp = FakeIdp::start().await;
    let sso = sso_for(vec![]);
    let (org, owner) = create_org(&pool, "acme").await;
    let agent_role = role_id(&pool, org.org_id, "agent").await;
    let agent = member_with_role(&pool, org.org_id, agent_role, None).await;
    let mut conn = pool.acquire().await.unwrap();
    let new = |issuer_url| NewConnection {
        name: "IdP",
        issuer_url,
        client_id: "client",
        client_secret: "secret",
        email_domains: &[],
        jit_provisioning: false,
        default_role_id: None,
        enforced: false,
    };

    let err = sso
        .create_connection(&mut conn, org.org_id, Actor::User(agent), new(idp.issuer()))
        .await
        .unwrap_err();
    assert!(matches!(err, SsoError::Forbidden), "{err}");

    
    for issuer in [
        "https://",
        "http://",
        "https://[::1]/",
    ] {
        let err = sso
            .create_connection(&mut conn, org.org_id, Actor::User(owner), new(issuer))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                SsoError::Invalid {
                    field: "issuer_url",
                    ..
                }
            ),
            "{issuer}: {err}"
        );
    }
}
