use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::routing::post;
use serde_json::{Value, json};
use sqlx::PgPool;
use ultrivly::audit::Actor;
use ultrivly::config::Deployment;
use ultrivly::integrations::webhooks;
use ultrivly::platform::net::NetPolicy;
use uuid::Uuid;

mod common;
use common::app::{App, Reply};
use common::{grant, role_id};

struct Org {
    app: App,
    id: Uuid,
    workspace: Uuid,
    owner: String,
    owner_id: Uuid,
}

async fn org(pool: PgPool) -> Org {
    let app = App::new(pool).await;
    let owner_id = app.sign_up_and_verify("owner@acme.test").await;
    let owner = app.sign_in("owner@acme.test").await;
    let reply = app
        .call(
            Method::POST,
            "/api/v1/orgs",
            Some(json!({ "name": "Acme", "slug": "acme", "workspace_name": "Support", "workspace_slug": "support" })),
            Some(&owner),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    Org {
        id: reply.body["organization"]["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
        workspace: reply.body["workspace_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
        app,
        owner,
        owner_id,
    }
}

impl Org {
    fn path(&self, rest: &str) -> String {
        format!("/api/v1/orgs/{}{rest}", self.id)
    }

    async fn post(&self, rest: &str, body: Value, session: &str) -> Reply {
        self.app
            .call(Method::POST, &self.path(rest), Some(body), Some(session))
            .await
    }

    async fn get(&self, rest: &str, session: &str) -> Reply {
        self.app
            .call(Method::GET, &self.path(rest), None, Some(session))
            .await
    }

    async fn member(&self, email: &str, role_key: &str) -> String {
        let user = self.app.sign_up_and_verify(email).await;
        let membership = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO memberships (id, org_id, user_id, status) VALUES ($1, $2, $3, 'active')",
        )
        .bind(membership)
        .bind(self.id)
        .bind(user)
        .execute(&self.app.pool)
        .await
        .unwrap();
        grant(
            &self.app.pool,
            self.id,
            membership,
            role_id(&self.app.pool, self.id, role_key).await,
            None,
        )
        .await;
        self.app.sign_in(email).await
    }

    async fn new_case(&self, subject: &str) -> Value {
        let reply = self
            .post(
                "/cases",
                json!({ "workspace_id": self.workspace, "subject": subject, "requester": { "email": "pat@customer.test" } }),
                &self.owner,
            )
            .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        reply.body["case"].clone()
    }

    async fn run_worker(&self) {
        while self.app.worker.run_once().await.unwrap() {}
    }
}

#[sqlx::test]
async fn knowledge_visibility_and_help_center(pool: PgPool) {
    let o = org(pool).await;
    let agent = o.member("agent@acme.test", "agent").await;
    let category = o
        .post("/kb/categories", json!({ "name": "Accounts" }), &o.owner)
        .await;
    assert_eq!(category.status, StatusCode::CREATED);

    let public = o
        .post(
            "/kb/articles",
            json!({ "title": "Reset your password", "body": "Click forgot password.", "visibility": "public",
                    "category_id": category.body["category"]["id"] }),
            &o.owner,
        )
        .await;
    assert_eq!(public.status, StatusCode::CREATED, "{}", public.body);
    assert_eq!(public.body["article"]["slug"], "reset-your-password");
    assert_eq!(public.body["article"]["state"], "draft");
    let internal = o
        .post("/kb/articles", json!({ "title": "VPN admin password rotation", "body": "Secret runbook password", "visibility": "internal" }), &o.owner)
        .await;
    let public_id = public.body["article"]["id"].as_str().unwrap();
    let internal_id = internal.body["article"]["id"].as_str().unwrap();

    let help = o
        .app
        .call(Method::GET, "/api/v1/help/acme/articles", None, None)
        .await;
    assert_eq!(help.body["data"].as_array().unwrap().len(), 0);
    assert_eq!(
        o.post(
            &format!("/kb/articles/{public_id}/state"),
            json!({ "state": "published" }),
            &agent
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    for id in [public_id, internal_id] {
        let reply = o
            .post(
                &format!("/kb/articles/{id}/state"),
                json!({ "state": "published" }),
                &o.owner,
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK);
    }

    let help = o
        .app
        .call(
            Method::GET,
            "/api/v1/help/acme/articles?q=password",
            None,
            None,
        )
        .await;
    let titles: Vec<&str> = help.body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, ["Reset your password"]);
    let article = o
        .app
        .call(
            Method::GET,
            "/api/v1/help/acme/articles/reset-your-password",
            None,
            None,
        )
        .await;
    assert_eq!(article.status, StatusCode::OK);
    let hidden = o
        .app
        .call(
            Method::GET,
            "/api/v1/help/acme/articles/vpn-admin-password-rotation",
            None,
            None,
        )
        .await;
    assert_eq!(hidden.status, StatusCode::NOT_FOUND);

    let for_agent = o.get("/kb/articles?q=password", &agent).await;
    assert_eq!(for_agent.body["data"].as_array().unwrap().len(), 2);

    o.app.sign_up_and_verify("viewer@acme.test").await;
    let membership = Uuid::now_v7();
    let viewer_user: Uuid =
        sqlx::query_scalar("SELECT id FROM users WHERE email = 'viewer@acme.test'")
            .fetch_one(&o.app.pool)
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO memberships (id, org_id, user_id, status) VALUES ($1, $2, $3, 'active')",
    )
    .bind(membership)
    .bind(o.id)
    .bind(viewer_user)
    .execute(&o.app.pool)
    .await
    .unwrap();
    let viewer = o.app.sign_in("viewer@acme.test").await;
    let for_viewer = o.get("/kb/articles?q=password", &viewer).await;
    assert_eq!(for_viewer.body["data"].as_array().unwrap().len(), 1);
    assert_eq!(
        o.get(&format!("/kb/articles/{internal_id}"), &viewer)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[derive(Clone, Default)]
struct Received(Arc<Mutex<Vec<(HeaderMap, String)>>>);

async fn receiver(received: Received) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://127.0.0.1:{}/hook",
        listener.local_addr().unwrap().port()
    );
    let app = Router::new().route(
        "/hook",
        post(move |headers: HeaderMap, body: String| {
            let received = received.clone();
            async move {
                received.0.lock().unwrap().push((headers, body));
                StatusCode::OK
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

#[sqlx::test]
async fn webhooks_are_signed_and_never_reach_private_networks(pool: PgPool) {
    let o = org(pool).await;
    for url in [
        "http://127.0.0.1:9/hook",
        "https://169.254.169.254/latest",
        "https://10.0.0.1/x",
        "ftp://example.com",
    ] {
        let reply = o
            .post(
                "/webhooks",
                json!({ "url": url, "events": ["case.created"] }),
                &o.owner,
            )
            .await;
        assert_eq!(
            reply.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{url}: {}",
            reply.body
        );
    }
    let reply = o
        .post(
            "/webhooks",
            json!({ "url": "https://hooks.example.com/x", "events": ["case.exploded"] }),
            &o.owner,
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);

    let received = Received::default();
    let url = receiver(received.clone()).await;
    let mut conn = o.app.pool.acquire().await.unwrap();
    let trusting = NetPolicy::new(Deployment::SelfHosted, &["127.0.0.1".into()]);
    let (endpoint, secret) = webhooks::create(
        &mut conn,
        &trusting,
        &o.app.worker.secrets,
        o.id,
        Actor::User(o.owner_id),
        webhooks::NewEndpoint {
            url: &url,
            description: "test",
            events: &["case.created".into()],
        },
    )
    .await
    .unwrap();
    assert!(secret.starts_with("whsec_"));

    let case = o.new_case("Webhook me").await;
    o.run_worker().await;
    let deliveries = received.0.lock().unwrap().clone();
    assert_eq!(deliveries.len(), 1);
    let (headers, body) = &deliveries[0];
    assert_eq!(headers["ultrivly-event"], "case.created");
    let signature = headers["ultrivly-signature"].to_str().unwrap();
    let (t, v1) = signature
        .trim_start_matches("t=")
        .split_once(",v1=")
        .unwrap();
    assert_eq!(
        webhooks::sign(&secret, t.parse().unwrap(), body.as_bytes()),
        v1
    );
    let payload: Value = serde_json::from_str(body).unwrap();
    assert_eq!(payload["data"]["case_id"], case["id"]);

    let log = o
        .get(&format!("/webhooks/{}/deliveries", endpoint.id), &o.owner)
        .await;
    assert_eq!(log.body["data"][0]["status"], "succeeded");
    let listed = o.get("/webhooks", &o.owner).await;
    assert!(listed.body.to_string().find("whsec_").is_none());
}

#[sqlx::test]
async fn workflows_run_on_events_with_permissions_and_limits(pool: PgPool) {
    let o = org(pool).await;
    let agent = o.member("agent@acme.test", "agent").await;
    let definition = json!({
        "trigger": "case_created",
        "conditions": [{ "field": "subject", "op": "contains", "value": "urgent" }],
        "actions": [
            { "type": "set_priority", "priority": "urgent" },
            { "type": "add_tags", "tags": ["escalated"] },
            { "type": "add_note", "body": "Auto-escalated." }
        ]
    });
    assert_eq!(
        o.post(
            "/workflows",
            json!({ "name": "Escalate", "definition": definition }),
            &agent
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    let bad = o
        .post("/workflows", json!({ "name": "Bad", "definition": { "trigger": "case_created", "actions": [{ "type": "run_shell", "cmd": "rm" }] } }), &o.owner)
        .await;
    assert_eq!(bad.status, StatusCode::UNPROCESSABLE_ENTITY);
    let unknown_status = o
        .post("/workflows", json!({ "name": "Bad", "definition": { "trigger": "case_created", "actions": [{ "type": "set_status", "status": "nope" }] } }), &o.owner)
        .await;
    assert_eq!(unknown_status.status, StatusCode::UNPROCESSABLE_ENTITY);

    let created = o
        .post(
            "/workflows",
            json!({ "name": "Escalate", "definition": definition }),
            &o.owner,
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let id = created.body["workflow"]["id"].as_str().unwrap().to_string();

    let draft_case = o.new_case("urgent: before publishing").await;
    o.run_worker().await;
    let unchanged = o
        .get(
            &format!("/cases/{}", draft_case["id"].as_str().unwrap()),
            &o.owner,
        )
        .await;
    assert_eq!(unchanged.body["case"]["priority"], "normal");

    assert_eq!(
        o.post(&format!("/workflows/{id}/publish"), json!({}), &o.owner)
            .await
            .status,
        StatusCode::OK
    );
    let hit = o.new_case("URGENT printer").await;
    let miss = o.new_case("Routine question").await;
    o.run_worker().await;

    let hit = o
        .get(&format!("/cases/{}", hit["id"].as_str().unwrap()), &o.owner)
        .await
        .body["case"]
        .clone();
    assert_eq!(hit["priority"], "urgent");
    assert_eq!(hit["tags"], json!(["escalated"]));
    let notes = o
        .get(
            &format!("/cases/{}/messages", hit["id"].as_str().unwrap()),
            &o.owner,
        )
        .await;
    assert_eq!(notes.body["messages"][0]["author_kind"], "workflow");
    assert_eq!(notes.body["messages"][0]["visibility"], "internal");
    let miss = o
        .get(
            &format!("/cases/{}", miss["id"].as_str().unwrap()),
            &o.owner,
        )
        .await
        .body["case"]
        .clone();
    assert_eq!(miss["priority"], "normal");

    let runs = o.get(&format!("/workflows/{id}/runs"), &o.owner).await;
    let statuses: Vec<&str> = runs.body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["status"].as_str().unwrap())
        .collect();
    assert!(statuses.contains(&"succeeded"), "{statuses:?}");

    let event: Uuid = sqlx::query_scalar(
        "SELECT id FROM domain_events WHERE kind = 'case.created' AND subject_id = $1",
    )
    .bind(hit["id"].as_str().unwrap().parse::<Uuid>().unwrap())
    .fetch_one(&o.app.pool)
    .await
    .unwrap();
    ultrivly::workflows::evaluate(&o.app.pool, &o.app.worker.secrets, event)
        .await
        .unwrap();
    let notes = o
        .get(
            &format!("/cases/{}/messages", hit["id"].as_str().unwrap()),
            &o.owner,
        )
        .await;
    assert_eq!(notes.body["messages"].as_array().unwrap().len(), 1);

    let report = o.get("/reports/summary", &o.owner).await;
    assert_eq!(report.status, StatusCode::OK, "{}", report.body);
    assert_eq!(report.body["created"], 3);
    assert!(report.body["definitions"]["resolution_hours"].is_string());
    assert_eq!(
        o.get("/reports/summary", &agent).await.status,
        StatusCode::FORBIDDEN
    );
    let bad_range = o
        .get(
            "/reports/summary?from=2020-01-01T00:00:00Z&to=2026-01-01T00:00:00Z",
            &o.owner,
        )
        .await;
    assert_eq!(bad_range.status, StatusCode::UNPROCESSABLE_ENTITY);
}
