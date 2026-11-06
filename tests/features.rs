use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::routing::{get, post};
use serde_json::{Value, json};
use sqlx::PgPool;
use ultrivly::ai::{self, SettingsInput, Task};
use ultrivly::audit::Actor;
use ultrivly::cases::settings;
use ultrivly::integrations::webhooks::sign;
use ultrivly::plugins;
use uuid::Uuid;

mod common;
use common::app::{Reply, now};
use common::org::{Org, org};

fn signed(secret: &str, body: &[u8]) -> String {
    let t = now() as i64;
    format!("t={t},v1={}", sign(secret, t, body))
}

#[sqlx::test]
async fn idempotency_keys_replay_and_reject_mismatches(pool: PgPool) {
    let o = org(pool).await;
    let body = json!({ "workspace_id": o.workspace, "subject": "Once", "requester": { "email": "pat@customer.test" } }).to_string();
    let send = |body: String, key: &'static str| {
        let path = o.path("/cases");
        let owner = o.owner.clone();
        let app = &o.app;
        async move {
            app.send(
                Method::POST,
                &path,
                body.into_bytes(),
                &[
                    ("content-type", "application/json"),
                    ("idempotency-key", key),
                ],
                Some(&owner),
            )
            .await
        }
    };
    let first = send(body.clone(), "abc").await;
    assert_eq!(first.status, StatusCode::CREATED, "{}", first.body);
    assert!(first.headers.get("idempotent-replayed").is_none());
    let again = send(body.clone(), "abc").await;
    assert_eq!(again.status, StatusCode::CREATED);
    assert_eq!(again.headers.get("idempotent-replayed").unwrap(), "true");
    assert_eq!(again.body["case"]["id"], first.body["case"]["id"]);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cases WHERE org_id = $1")
        .bind(o.id)
        .fetch_one(&o.app.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);

    let different = send(body.replace("Once", "Twice"), "abc").await;
    assert_eq!(different.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        different.body["error"]["code"], "idempotency_key_reused",
        "{}",
        different.body
    );

    let fresh = send(body, "other").await;
    assert_eq!(fresh.status, StatusCode::CREATED);
    assert_ne!(fresh.body["case"]["id"], first.body["case"]["id"]);
}

#[sqlx::test]
async fn idempotent_responses_with_secrets_are_encrypted_at_rest(pool: PgPool) {
    let o = org(pool).await;
    let body = json!({ "name": "CI", "permissions": ["cases.read"] }).to_string();
    let path = o.path("/api-credentials");
    let send = || {
        o.app.send(
            Method::POST,
            &path,
            body.clone().into_bytes(),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "cred-1"),
            ],
            Some(&o.owner),
        )
    };
    let first = send().await;
    assert_eq!(first.status, StatusCode::CREATED, "{}", first.body);
    let token = first.body["token"].as_str().unwrap().to_string();
    let replay = send().await;
    assert_eq!(replay.headers.get("idempotent-replayed").unwrap(), "true");
    assert_eq!(replay.body["token"], token.as_str());
    let stored: Vec<u8> = sqlx::query_scalar("SELECT response_ciphertext FROM idempotency_keys")
        .fetch_one(&o.app.pool)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&stored).contains(&token));
    assert!(!String::from_utf8_lossy(&stored).contains("token"));
}

#[sqlx::test]
async fn statuses_priorities_and_custom_fields_are_configurable(pool: PgPool) {
    let o = org(pool).await;
    let agent = o.member("agent@acme.test", "agent").await;

    let status = o
        .post("/statuses", json!({ "key": "waiting_on_vendor", "label": "Waiting on vendor", "category": "pending" }), &o.owner)
        .await;
    assert_eq!(status.status, StatusCode::CREATED, "{}", status.body);
    assert_ne!(
        o.post(
            "/statuses",
            json!({ "key": "x", "label": "X", "category": "pending" }),
            &agent
        )
        .await
        .status,
        StatusCode::CREATED
    );
    let case = o.new_case(json!({ "status": "waiting_on_vendor" })).await;
    assert_eq!(case.status, StatusCode::CREATED, "{}", case.body);
    let status_id = status.body["status"]["id"].as_str().unwrap();
    let in_use = o
        .app
        .call(
            Method::DELETE,
            &o.path(&format!("/statuses/{status_id}")),
            None,
            Some(&o.owner),
        )
        .await;
    assert_eq!(in_use.status, StatusCode::CONFLICT, "{}", in_use.body);

    let field = o
        .post(
            "/custom-fields",
            json!({ "key": "plan", "label": "Plan", "field_type": "select", "options": ["free", "pro"], "required": true }),
            &o.owner,
        )
        .await;
    assert_eq!(field.status, StatusCode::CREATED, "{}", field.body);
    assert_eq!(
        o.new_case(json!({})).await.status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        o.new_case(json!({ "custom_fields": { "plan": "enterprise" } }))
            .await
            .status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        o.new_case(json!({ "custom_fields": { "plan": "pro", "unknown": 1 } }))
            .await
            .status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let ok = o
        .new_case(json!({ "custom_fields": { "plan": "pro" } }))
        .await;
    assert_eq!(ok.status, StatusCode::CREATED, "{}", ok.body);
    assert_eq!(ok.body["case"]["custom_fields"]["plan"], "pro");
}

#[sqlx::test]
async fn sla_breaches_are_detected_once(pool: PgPool) {
    let o = org(pool).await;
    let priority: Uuid =
        sqlx::query_scalar("SELECT id FROM case_priorities WHERE org_id = $1 AND key = 'high'")
            .bind(o.id)
            .fetch_one(&o.app.pool)
            .await
            .unwrap();
    let policy = o
        .put("/sla-policies", json!({ "priority_id": priority, "first_response_minutes": 30, "resolution_minutes": 480 }), &o.owner)
        .await;
    assert!(policy.status.is_success(), "{}", policy.body);

    let high = o.new_case(json!({ "priority": "high" })).await.body["case"].clone();
    let normal = o.new_case(json!({ "priority": "normal" })).await.body["case"].clone();
    assert!(high["first_response_due_at"].is_string(), "{high}");
    assert!(normal["first_response_due_at"].is_null());

    sqlx::query(
        "UPDATE cases SET first_response_due_at = now() - interval '1 minute' WHERE id = $1",
    )
    .bind(high["id"].as_str().unwrap().parse::<Uuid>().unwrap())
    .execute(&o.app.pool)
    .await
    .unwrap();
    assert_eq!(settings::mark_breaches(&o.app.pool).await.unwrap(), 1);
    assert_eq!(settings::mark_breaches(&o.app.pool).await.unwrap(), 0);
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM domain_events WHERE org_id = $1 AND kind = 'case.sla_breached'",
    )
    .bind(o.id)
    .fetch_one(&o.app.pool)
    .await
    .unwrap();
    assert_eq!(events, 1);
    let breached = o.get("/cases?sla_breached=true", &o.owner).await;
    assert_eq!(
        breached.body["data"].as_array().map(Vec::len),
        Some(1),
        "{}",
        breached.body
    );
}

#[sqlx::test]
async fn saved_views_filter_cases_and_stay_private(pool: PgPool) {
    let o = org(pool).await;
    let agent = o.member("agent@acme.test", "agent").await;
    o.new_case(json!({ "priority": "urgent", "subject": "Down" }))
        .await;
    o.new_case(json!({ "priority": "low", "subject": "Question" }))
        .await;

    assert_eq!(
        o.post(
            "/views",
            json!({ "name": "Bad", "filter": { "sql": "1=1" } }),
            &o.owner
        )
        .await
        .status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let view = o
        .post(
            "/views",
            json!({ "name": "Urgent", "filter": { "priority": "urgent" } }),
            &o.owner,
        )
        .await;
    assert_eq!(view.status, StatusCode::CREATED, "{}", view.body);
    let id = view.body["view"]["id"].as_str().unwrap();
    let cases = o.get(&format!("/views/{id}/cases"), &o.owner).await;
    let subjects: Vec<&str> = cases.body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["subject"].as_str().unwrap())
        .collect();
    assert_eq!(subjects, ["Down"]);

    let theirs = o.get("/views", &agent).await;
    assert!(
        theirs.body["views"].as_array().unwrap().is_empty(),
        "{}",
        theirs.body
    );
    assert_eq!(
        o.get(&format!("/views/{id}/cases"), &agent).await.status,
        StatusCode::NOT_FOUND
    );
}

async fn channel(o: &Org, body: Value) -> (String, String) {
    let mut request = json!({ "workspace_id": o.workspace });
    for (key, value) in body.as_object().unwrap() {
        request[key] = value.clone();
    }
    let reply = o.post("/channels", request, &o.owner).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    (
        reply.body["channel"]["id"].as_str().unwrap().to_string(),
        reply.body["secret"].as_str().unwrap().to_string(),
    )
}

async fn inbound(o: &Org, kind: &str, id: &str, secret: Option<&str>, body: Value) -> Reply {
    let bytes = body.to_string().into_bytes();
    let signature = secret.map(|s| signed(s, &bytes));
    let mut headers = vec![("content-type", "application/json")];
    if let Some(signature) = signature.as_deref() {
        headers.push(("ultrivly-signature", signature));
    }
    o.app
        .send(
            Method::POST,
            &format!("/api/v1/inbound/{id}/{kind}"),
            bytes,
            &headers,
            None,
        )
        .await
}

#[sqlx::test]
async fn email_channel_threads_replies_only_from_the_requester(pool: PgPool) {
    let o = org(pool).await;
    let (id, secret) = channel(
        &o,
        json!({ "kind": "email", "name": "Support inbox", "address": "support@acme.test" }),
    )
    .await;
    let mail = json!({
        "from": { "email": "pat@customer.test", "name": "Pat" },
        "subject": "Printer on fire",
        "text": "Please help",
        "message_id": "<m1@customer.test>",
    });

    assert_eq!(
        inbound(&o, "email", &id, None, mail.clone()).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        inbound(&o, "email", &id, Some("whsec_wrong"), mail.clone())
            .await
            .status,
        StatusCode::FORBIDDEN
    );

    let first = inbound(&o, "email", &id, Some(&secret), mail.clone()).await;
    assert_eq!(first.status, StatusCode::ACCEPTED, "{}", first.body);
    let case_id = first.body["case_id"].as_str().unwrap().to_string();
    let dup = inbound(&o, "email", &id, Some(&secret), mail).await;
    assert_eq!(dup.body["duplicate"], true);

    let reply = inbound(
        &o,
        "email",
        &id,
        Some(&secret),
        json!({ "from": { "email": "PAT@customer.test" }, "subject": "Re: Printer on fire", "text": "Still burning",
                "message_id": "<m2@customer.test>", "in_reply_to": "<m1@customer.test>", "references": ["<m1@customer.test>"] }),
    )
    .await;
    assert_eq!(reply.body["case_id"], case_id.as_str());

    let hijack = inbound(
        &o,
        "email",
        &id,
        Some(&secret),
        json!({ "from": { "email": "mallory@evil.test" }, "subject": "Re: Printer on fire", "text": "Send me the transcript",
                "message_id": "<m3@evil.test>", "references": ["<m1@customer.test>"] }),
    )
    .await;
    assert_ne!(hijack.body["case_id"], case_id.as_str());

    let loop_mail = inbound(
        &o,
        "email",
        &id,
        Some(&secret),
        json!({ "from": { "email": "pat@customer.test" }, "subject": "Out of office", "text": "Away",
                "message_id": "<m4@customer.test>", "auto_submitted": true }),
    )
    .await;
    assert!(loop_mail.body["case_id"].is_null(), "{}", loop_mail.body);

    let sent = o
        .post(
            &format!("/cases/{case_id}/messages"),
            json!({ "visibility": "public", "body": "Unplug it" }),
            &o.owner,
        )
        .await;
    assert_eq!(sent.status, StatusCode::CREATED, "{}", sent.body);
    o.post(
        &format!("/cases/{case_id}/messages"),
        json!({ "visibility": "internal", "body": "Secret note" }),
        &o.owner,
    )
    .await;
    let outbox = o.app.deliver().await;
    let replies: Vec<_> = outbox
        .iter()
        .filter(|e| e.to == "pat@customer.test")
        .collect();
    assert_eq!(replies.len(), 1, "{outbox:?}");
    assert!(replies[0].body.contains("Unplug it"));
    assert_eq!(replies[0].reply_to.as_deref(), Some("support@acme.test"));
    assert!(replies[0].in_reply_to.is_some());
    assert!(!outbox.iter().any(|e| e.body.contains("Secret note")));
}

#[sqlx::test]
async fn social_channel_threads_by_conversation(pool: PgPool) {
    let o = org(pool).await;
    let (id, secret) = channel(&o, json!({ "kind": "social", "name": "Instagram" })).await;
    let message = |mid: &str, thread: &str| json!({ "platform": "instagram", "external_user_id": "ig-42", "name": "Pat", "text": "hi", "message_id": mid, "thread_id": thread });
    let first = inbound(&o, "social", &id, Some(&secret), message("a", "t1")).await;
    assert_eq!(first.status, StatusCode::ACCEPTED, "{}", first.body);
    let same = inbound(&o, "social", &id, Some(&secret), message("b", "t1")).await;
    assert_eq!(same.body["case_id"], first.body["case_id"]);
    let other = inbound(&o, "social", &id, Some(&secret), message("c", "t2")).await;
    assert_ne!(other.body["case_id"], first.body["case_id"]);
    assert_eq!(
        inbound(&o, "social", &id, None, message("d", "t1"))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
}

#[sqlx::test]
async fn chat_requires_an_allowed_origin_and_the_conversation_token(pool: PgPool) {
    let o = org(pool).await;
    let (id, _) = channel(
        &o,
        json!({ "kind": "chat", "name": "Website", "allowed_origins": ["https://shop.example"] }),
    )
    .await;
    let start = |origin: &'static str| {
        let path = format!("/api/v1/chat/{id}/conversations");
        let app = &o.app;
        async move {
            app.send(
                Method::POST,
                &path,
                json!({ "name": "Pat", "email": "pat@customer.test", "message": "Where is my order?" }).to_string().into_bytes(),
                &[("content-type", "application/json"), ("origin", origin)],
                None,
            )
            .await
        }
    };
    assert_eq!(
        start("https://evil.example").await.status,
        StatusCode::FORBIDDEN
    );
    let started = start("https://shop.example").await;
    assert_eq!(started.status, StatusCode::CREATED, "{}", started.body);
    assert_eq!(
        started.headers.get("access-control-allow-origin").unwrap(),
        "https://shop.example"
    );
    let case_id = started.body["conversation_id"]
        .as_str()
        .unwrap()
        .to_string();
    let token = started.body["token"].as_str().unwrap().to_string();

    o.post(
        &format!("/cases/{case_id}/messages"),
        json!({ "visibility": "public", "body": "It ships today" }),
        &o.owner,
    )
    .await;
    o.post(
        &format!("/cases/{case_id}/messages"),
        json!({ "visibility": "internal", "body": "VIP customer" }),
        &o.owner,
    )
    .await;

    let messages_path = format!("/api/v1/chat/{id}/conversations/{case_id}/messages");
    let read = |token: String| {
        let path = messages_path.clone();
        let app = &o.app;
        async move {
            let auth = format!("Bearer {token}");
            app.send(
                Method::GET,
                &path,
                Vec::new(),
                &[("origin", "https://shop.example"), ("authorization", &auth)],
                None,
            )
            .await
        }
    };
    let wrong = read("not-the-token".into()).await;
    assert!(
        matches!(
            wrong.status,
            StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND
        ),
        "{}",
        wrong.status
    );
    let thread = read(token.clone()).await;
    assert_eq!(thread.status, StatusCode::OK, "{}", thread.body);
    let bodies: Vec<&str> = thread.body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["body"].as_str().unwrap())
        .collect();
    assert_eq!(bodies, ["Where is my order?", "It ships today"]);

    let auth = format!("Bearer {token}");
    let sent = o
        .app
        .send(
            Method::POST,
            &messages_path,
            json!({ "body": "Thanks!" }).to_string().into_bytes(),
            &[
                ("content-type", "application/json"),
                ("origin", "https://shop.example"),
                ("authorization", &auth),
            ],
            None,
        )
        .await;
    assert_eq!(sent.status, StatusCode::CREATED, "{}", sent.body);
    let case = o.get(&format!("/cases/{case_id}"), &o.owner).await;
    assert_eq!(
        case.body["case"]["requester_unverified"], true,
        "{}",
        case.body
    );
}

type Calls = Arc<Mutex<Vec<(String, HeaderMap, String)>>>;

async fn fake_service(manifest: Value, reply: Value) -> (String, Calls) {
    let calls: Calls = Arc::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let record = |calls: Calls, reply: Value| {
        move |uri: axum::http::Uri, headers: HeaderMap, body: String| {
            let calls = calls.clone();
            let reply = reply.clone();
            async move {
                calls
                    .lock()
                    .unwrap()
                    .push((uri.path().to_string(), headers, body));
                axum::Json(reply)
            }
        }
    };
    let app = Router::new()
        .route(
            "/manifest",
            get(move || async move { axum::Json(manifest) }),
        )
        .route("/events", post(record(calls.clone(), json!({}))))
        .route("/actions/{action}", post(record(calls.clone(), json!({}))))
        .route("/v1/responses", post(record(calls.clone(), reply.clone())))
        .route("/v1/chat/completions", post(record(calls.clone(), reply)));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, calls)
}

#[sqlx::test]
async fn builtin_plugins_validate_their_config(pool: PgPool) {
    let o = org(pool).await;
    let catalogue = o
        .app
        .call(Method::GET, "/api/v1/plugins", None, Some(&o.owner))
        .await;
    assert_eq!(catalogue.body["plugins"][0]["key"], "slack_notify");
    let bad = o
        .post("/plugins", json!({ "kind": "builtin", "plugin_key": "slack_notify", "config": { "webhook_url": "https://169.254.169.254/" } }), &o.owner)
        .await;
    assert_eq!(bad.status, StatusCode::UNPROCESSABLE_ENTITY);
    let good = o
        .post("/plugins", json!({ "kind": "builtin", "plugin_key": "slack_notify", "config": { "webhook_url": "https://hooks.slack.com/services/T/B/x" } }), &o.owner)
        .await;
    assert_eq!(good.status, StatusCode::CREATED, "{}", good.body);
    assert!(
        good.body.to_string().find("hooks.slack.com").is_none(),
        "config must not be echoed back"
    );
    let again = o
        .post("/plugins", json!({ "kind": "builtin", "plugin_key": "slack_notify", "config": { "webhook_url": "https://hooks.slack.com/services/T/B/x" } }), &o.owner)
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    let agent = o.member("agent@acme.test", "agent").await;
    assert_ne!(o.get("/plugins", &agent).await.status, StatusCode::OK);
}

#[sqlx::test]
async fn webhook_plugins_receive_signed_actions_and_lose_access_on_uninstall(pool: PgPool) {
    let o = org(pool).await;
    let manifest = json!({
        "key": "crm_sync",
        "name": "CRM sync",
        "version": "1.0.0",
        "permissions": ["cases.read"],
        "events": ["case.created"],
        "actions": [{ "key": "notify", "name": "Notify CRM", "inputs": [{ "key": "text", "label": "Text", "type": "text", "required": true }] }],
    });
    let (base, calls) = fake_service(manifest, json!({})).await;

    let blocked = o
        .post(
            "/plugins",
            json!({ "kind": "webhook", "base_url": base }),
            &o.owner,
        )
        .await;
    assert_eq!(
        blocked.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "cloud deployments must not reach loopback"
    );

    let mut conn = o.app.pool.acquire().await.unwrap();
    let installed = plugins::install_webhook(
        &mut conn,
        &o.app.worker.http,
        &o.app.worker.secrets,
        o.id,
        o.actor(),
        &base,
    )
    .await
    .unwrap();
    drop(conn);
    let token = installed.api_token.clone().unwrap();
    assert_eq!(
        o.app
            .bearer(Method::GET, &o.path("/cases"), None, &token)
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        o.app
            .bearer(Method::GET, &o.path("/webhooks"), None, &token)
            .await
            .status,
        StatusCode::FORBIDDEN
    );

    let workflow = o
        .post(
            "/workflows",
            json!({ "name": "Tell CRM", "definition": { "trigger": "case_created", "actions": [
                { "type": "plugin", "install_id": installed.install.id, "action": "notify", "input": { "text": "new case" } }
            ] } }),
            &o.owner,
        )
        .await;
    assert_eq!(workflow.status, StatusCode::CREATED, "{}", workflow.body);
    let bad_input = o
        .post(
            "/workflows",
            json!({ "name": "Bad", "definition": { "trigger": "case_created", "actions": [
                { "type": "plugin", "install_id": installed.install.id, "action": "notify", "input": { "text": 5 } }
            ] } }),
            &o.owner,
        )
        .await;
    assert_eq!(bad_input.status, StatusCode::UNPROCESSABLE_ENTITY);
    let id = workflow.body["workflow"]["id"].as_str().unwrap();
    o.post(&format!("/workflows/{id}/publish"), json!({}), &o.owner)
        .await;

    o.new_case(json!({ "subject": "Sync me" })).await;
    o.run_worker().await;
    let calls = calls.lock().unwrap().clone();
    let action = calls
        .iter()
        .find(|(path, _, _)| path == "/actions/notify")
        .expect("plugin action was called");
    let header = action
        .1
        .get("ultrivly-signature")
        .unwrap()
        .to_str()
        .unwrap();
    let (t, v1) = header
        .strip_prefix("t=")
        .unwrap()
        .split_once(",v1=")
        .unwrap();
    assert_eq!(
        sign(
            &installed.signing_secret,
            t.parse().unwrap(),
            action.2.as_bytes()
        ),
        v1
    );
    let payload: Value = serde_json::from_str(&action.2).unwrap();
    assert_eq!(payload["input"]["text"], "new case");
    assert_eq!(payload["case"]["subject"], "Sync me");
    assert!(
        calls.iter().any(|(path, _, _)| path == "/events"),
        "plugin receives subscribed events"
    );

    let plugin = o.path(&format!("/plugins/{}", installed.install.id));
    let paused = o
        .app
        .call(
            Method::PATCH,
            &plugin,
            Some(json!({ "enabled": false })),
            Some(&o.owner),
        )
        .await;
    assert_eq!(paused.status, StatusCode::OK, "{}", paused.body);
    assert_eq!(
        o.app
            .bearer(Method::GET, &o.path("/cases"), None, &token)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    o.app
        .call(
            Method::PATCH,
            &plugin,
            Some(json!({ "enabled": true })),
            Some(&o.owner),
        )
        .await;
    assert_eq!(
        o.app
            .bearer(Method::GET, &o.path("/cases"), None, &token)
            .await
            .status,
        StatusCode::OK
    );

    let removed = o
        .app
        .call(
            Method::DELETE,
            &o.path(&format!("/plugins/{}", installed.install.id)),
            None,
            Some(&o.owner),
        )
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    assert_eq!(
        o.app
            .bearer(Method::GET, &o.path("/cases"), None, &token)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

fn ai_input(provider: &str, base_url: &str, include_internal_notes: bool) -> SettingsInput {
    serde_json::from_value(json!({
        "enabled": true,
        "provider": provider,
        "model": "test-model",
        "base_url": base_url,
        "api_key": "sk-test",
        "features": ["summary", "reply_draft"],
        "include_internal_notes": include_internal_notes,
    }))
    .unwrap()
}

#[sqlx::test]
async fn ai_assist_is_off_by_default_and_respects_note_visibility(pool: PgPool) {
    let o = org(pool).await;
    let agent = o.member("agent@acme.test", "agent").await;
    let case = o
        .new_case(json!({ "subject": "Refund please", "description": "I was charged twice" }))
        .await
        .body["case"]
        .clone();
    let case_id = case["id"].as_str().unwrap().to_string();
    o.post(
        &format!("/cases/{case_id}/messages"),
        json!({ "visibility": "internal", "body": "Card ends 4242" }),
        &o.owner,
    )
    .await;

    let off = o
        .post(
            &format!("/cases/{case_id}/assist"),
            json!({ "task": "summary" }),
            &o.owner,
        )
        .await;
    assert_eq!(off.status, StatusCode::CONFLICT, "{}", off.body);
    assert_eq!(o.get("/ai", &o.owner).await.body["ai"]["enabled"], false);
    assert_ne!(
        o.put("/ai", json!({ "enabled": true, "provider": "openai", "model": "m", "api_key": "k", "features": ["summary"] }), &agent)
            .await
            .status,
        StatusCode::OK
    );
    let private = o
        .put(
            "/ai",
            json!({ "enabled": true, "provider": "openai_compatible", "model": "m", "base_url": "http://10.0.0.5/v1", "features": ["summary"] }),
            &o.owner,
        )
        .await;
    assert_eq!(private.status, StatusCode::UNPROCESSABLE_ENTITY);

    let (base, calls) = fake_service(
        json!({}),
        json!({ "choices": [{ "finish_reason": "stop", "message": { "role": "assistant", "content": "Customer wants a refund." } }] }),
    )
    .await;
    let mut conn = o.app.pool.acquire().await.unwrap();
    let saved = ai::save_settings(
        &mut conn,
        o.app.worker.http.policy(),
        &o.app.worker.secrets,
        o.id,
        o.actor(),
        ai_input("openai_compatible", &format!("{base}/v1"), false),
    )
    .await
    .unwrap();
    drop(conn);
    assert!(saved.has_api_key);
    let shown = o.get("/ai", &o.owner).await;
    assert!(!shown.body.to_string().contains("sk-test"));

    let case_uuid: Uuid = case_id.parse().unwrap();
    let suggestion = ai::assist(
        &o.app.pool,
        &o.app.worker.http,
        &o.app.worker.secrets,
        o.id,
        o.actor(),
        case_uuid,
        Task::Summary,
    )
    .await
    .unwrap();
    assert_eq!(suggestion.text, "Customer wants a refund.");
    let request = calls.lock().unwrap().last().cloned().unwrap();
    assert_eq!(request.0, "/v1/chat/completions");
    assert_eq!(request.1.get("authorization").unwrap(), "Bearer sk-test");
    assert!(request.2.contains("I was charged twice"));
    assert!(
        !request.2.contains("4242"),
        "internal notes are excluded unless enabled"
    );

    let audited: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE org_id = $1 AND action = 'ai.suggestion_generated'")
        .bind(o.id)
        .fetch_one(&o.app.pool)
        .await
        .unwrap();
    assert_eq!(audited, 1);

    let outsider = ai::assist(
        &o.app.pool,
        &o.app.worker.http,
        &o.app.worker.secrets,
        o.id,
        Actor::User(Uuid::now_v7()),
        case_uuid,
        Task::Summary,
    )
    .await;
    assert!(outsider.is_err());
}

#[sqlx::test]
async fn ai_openai_provider_uses_the_responses_api_without_storage(pool: PgPool) {
    let o = org(pool).await;
    let case = o.new_case(json!({ "subject": "Login broken" })).await.body["case"].clone();
    let (base, calls) = fake_service(
        json!({}),
        json!({ "status": "completed", "output": [
            { "type": "message", "role": "assistant", "content": [{ "type": "output_text", "text": "Hi Pat, try resetting your password." }] }
        ] }),
    )
    .await;
    let mut conn = o.app.pool.acquire().await.unwrap();
    ai::save_settings(
        &mut conn,
        o.app.worker.http.policy(),
        &o.app.worker.secrets,
        o.id,
        o.actor(),
        ai_input("openai", &format!("{base}/v1"), true),
    )
    .await
    .unwrap();
    drop(conn);
    let suggestion = ai::assist(
        &o.app.pool,
        &o.app.worker.http,
        &o.app.worker.secrets,
        o.id,
        o.actor(),
        case["id"].as_str().unwrap().parse().unwrap(),
        Task::ReplyDraft,
    )
    .await
    .unwrap();
    assert_eq!(suggestion.text, "Hi Pat, try resetting your password.");
    let request = calls.lock().unwrap().last().cloned().unwrap();
    assert_eq!(request.0, "/v1/responses");
    let body: Value = serde_json::from_str(&request.2).unwrap();
    assert_eq!(body["store"], false);
    assert_eq!(body["model"], "test-model");
    assert!(body["input"].as_str().unwrap().contains("Login broken"));
}

#[sqlx::test]
async fn concurrent_cases_for_a_new_requester_share_one_contact(pool: PgPool) {
    let o = org(pool).await;
    let requests = (0..10).map(|i| {
        o.new_case(json!({ "subject": format!("Burst {i}"), "requester": { "email": "Burst@Customer.test" } }))
    });
    let replies = futures::future::join_all(requests).await;
    for reply in &replies {
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    }
    let contacts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM contacts WHERE org_id = $1 AND lower(email) = 'burst@customer.test'",
    )
    .bind(o.id)
    .fetch_one(&o.app.pool)
    .await
    .unwrap();
    assert_eq!(contacts, 1);
    let created: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM domain_events WHERE org_id = $1 AND kind = 'contact.created'",
    )
    .bind(o.id)
    .fetch_one(&o.app.pool)
    .await
    .unwrap();
    assert_eq!(created, 1);
}
