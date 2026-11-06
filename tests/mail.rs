use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use ultrivly::channels::mail_domains;
use ultrivly::integrations::webhooks::sign;

mod common;
use common::app::{MAIL_EVENTS_SECRET, Reply, now};
use common::org::{Org, org};

async fn post_events(o: &Org, body: Value, secret: Option<&str>) -> Reply {
    let bytes = body.to_string().into_bytes();
    let signature = secret.map(|s| {
        let t = now() as i64;
        format!("t={t},v1={}", sign(s, t, &bytes))
    });
    let mut headers = vec![("content-type", "application/json")];
    if let Some(signature) = signature.as_deref() {
        headers.push(("ultrivly-signature", signature));
    }
    o.app
        .send(Method::POST, "/api/v1/mail/events", bytes, &headers, None)
        .await
}

async fn email_case(o: &Org, address: &str, from: &str) -> String {
    let channel = o
        .post(
            "/channels",
            json!({ "workspace_id": o.workspace, "kind": "email", "name": "Acme Support", "address": address }),
            &o.owner,
        )
        .await;
    assert_eq!(channel.status, StatusCode::CREATED, "{}", channel.body);
    let id = channel.body["channel"]["id"].as_str().unwrap().to_string();
    let secret = channel.body["secret"].as_str().unwrap().to_string();
    let body = json!({ "from": { "email": from }, "subject": "Help", "text": "Hi", "message_id": format!("<{}@x>", uuid::Uuid::now_v7()) })
        .to_string()
        .into_bytes();
    let t = now() as i64;
    let signature = format!("t={t},v1={}", sign(&secret, t, &body));
    let reply = o
        .app
        .send(
            Method::POST,
            &format!("/api/v1/inbound/{id}/email"),
            body,
            &[
                ("content-type", "application/json"),
                ("ultrivly-signature", &signature),
            ],
            None,
        )
        .await;
    assert_eq!(reply.status, StatusCode::ACCEPTED, "{}", reply.body);
    reply.body["case_id"].as_str().unwrap().to_string()
}

#[sqlx::test]
async fn bounces_and_complaints_suppress_helpdesk_mail_only(pool: PgPool) {
    let o = org(pool).await;
    let events = json!({ "events": [
        { "type": "bounce", "email": "Gone@Customer.test", "permanent": true, "detail": "550 no such user" },
        { "type": "bounce", "email": "full@customer.test", "permanent": false },
        { "type": "complaint", "email": "angry@customer.test" },
        { "type": "delivery", "email": "fine@customer.test" },
    ] });
    assert_eq!(
        post_events(&o, events.clone(), None).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post_events(&o, events.clone(), Some("whsec_wrong"))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let accepted = post_events(&o, events, Some(MAIL_EVENTS_SECRET)).await;
    assert_eq!(accepted.status, StatusCode::ACCEPTED, "{}", accepted.body);
    assert_eq!(accepted.body["suppressed"], 2);
    let suppressed: Vec<String> =
        sqlx::query_scalar("SELECT email FROM email_suppressions ORDER BY email")
            .fetch_all(&o.app.pool)
            .await
            .unwrap();
    assert_eq!(suppressed, ["angry@customer.test", "gone@customer.test"]);

    let case_id = email_case(&o, "help@acme.test", "gone@customer.test").await;
    o.post(
        &format!("/cases/{case_id}/messages"),
        json!({ "visibility": "public", "body": "Reply" }),
        &o.owner,
    )
    .await;
    let outbox = o.app.deliver().await;
    assert!(
        outbox.iter().all(|e| e.to != "gone@customer.test"),
        "{outbox:?}"
    );
    let dead: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs WHERE state = 'dead'")
        .fetch_one(&o.app.pool)
        .await
        .unwrap();
    assert_eq!(dead, 0, "a suppressed recipient is not a failure");

    ultrivly::platform::mail::suppress(&o.app.pool, "new@acme.test", "manual", None)
        .await
        .unwrap();
    o.app
        .call(
            Method::POST,
            "/api/v1/auth/sign-up",
            Some(json!({ "email": "new@acme.test", "display_name": "New", "password": common::app::PASSWORD })),
            None,
        )
        .await;
    let outbox = o.app.deliver().await;
    assert!(
        outbox.iter().any(|e| e.to == "new@acme.test"),
        "account verification is sent even to suppressed addresses"
    );
}

#[sqlx::test]
async fn verified_domains_sign_channel_replies(pool: PgPool) {
    let o = org(pool).await;
    let agent = o.member("agent@acme.test", "agent").await;
    assert_ne!(
        o.post("/mail-domains", json!({ "domain": "acme.test" }), &agent)
            .await
            .status,
        StatusCode::CREATED
    );
    assert_eq!(
        o.post(
            "/mail-domains",
            json!({ "domain": "not a domain" }),
            &o.owner
        )
        .await
        .status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let added = o
        .post("/mail-domains", json!({ "domain": "Acme.TEST" }), &o.owner)
        .await;
    assert_eq!(added.status, StatusCode::CREATED, "{}", added.body);
    let domain = added.body["mail_domain"].clone();
    assert_eq!(domain["domain"], "acme.test");
    assert_eq!(domain["verified"], false);
    assert!(
        domain["dns_record"]["name"]
            .as_str()
            .unwrap()
            .ends_with("._domainkey.acme.test")
    );
    let value = domain["dns_record"]["value"].as_str().unwrap().to_string();
    assert!(value.starts_with("v=DKIM1; k=rsa; p="));
    assert!(!added.body.to_string().contains("PRIVATE KEY"));
    let id: uuid::Uuid = domain["id"].as_str().unwrap().parse().unwrap();

    let (other_org, other_owner) = o.other_org("globex", "owner@globex.test").await;
    let foreign = o
        .app
        .call(
            Method::POST,
            &format!("/api/v1/orgs/{other_org}/mail-domains/{id}/verify"),
            Some(json!({})),
            Some(&other_owner),
        )
        .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);

    let case_id = email_case(&o, "help@acme.test", "pat@customer.test").await;
    o.post(
        &format!("/cases/{case_id}/messages"),
        json!({ "visibility": "public", "body": "Unsigned" }),
        &o.owner,
    )
    .await;
    let unsigned = o.app.deliver().await;
    let reply = unsigned
        .iter()
        .find(|e| e.to == "pat@customer.test")
        .unwrap();
    assert!(
        reply.dkim.is_none() && reply.from.is_none(),
        "unverified domains are not used"
    );

    let mut conn = o.app.pool.acquire().await.unwrap();
    let wrong = mail_domains::verify(
        &mut conn,
        o.id,
        o.actor(),
        id,
        &["v=DKIM1; k=rsa; p=OTHER".into()],
    )
    .await
    .unwrap();
    assert!(!wrong.verified);
    let verified = mail_domains::verify(&mut conn, o.id, o.actor(), id, &[value])
        .await
        .unwrap();
    assert!(verified.verified);
    drop(conn);

    o.post(
        &format!("/cases/{case_id}/messages"),
        json!({ "visibility": "public", "body": "Signed" }),
        &o.owner,
    )
    .await;
    let signed = o.app.deliver().await;
    let reply = signed.iter().find(|e| e.to == "pat@customer.test").unwrap();
    assert_eq!(
        reply.from.as_deref(),
        Some("\"Acme Support\" <help@acme.test>")
    );
    let key = reply.dkim.as_ref().expect("reply is signed");
    assert_eq!(key.domain, "acme.test");

    let other_channel = o
        .app
        .call(
            Method::POST,
            &format!("/api/v1/orgs/{other_org}/channels"),
            Some(json!({ "workspace_id": workspace_of(&o, other_org).await, "kind": "email", "name": "Spoof", "address": "help@acme.test" })),
            Some(&other_owner),
        )
        .await;
    assert_eq!(
        other_channel.status,
        StatusCode::CREATED,
        "{}",
        other_channel.body
    );
    let mut conn = o.app.pool.acquire().await.unwrap();
    assert!(
        mail_domains::signing_key(
            &mut conn,
            &o.app.worker.secrets,
            other_org,
            "help@acme.test"
        )
        .await
        .unwrap()
        .is_none(),
        "another organization cannot sign with this domain"
    );
}

async fn workspace_of(o: &Org, org_id: uuid::Uuid) -> uuid::Uuid {
    sqlx::query_scalar("SELECT id FROM workspaces WHERE org_id = $1 LIMIT 1")
        .bind(org_id)
        .fetch_one(&o.app.pool)
        .await
        .unwrap()
}
