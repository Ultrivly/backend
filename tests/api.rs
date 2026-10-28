use axum::http::{Method, StatusCode, header};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::app::App;
use common::{grant, role_id};

struct Org {
    app: App,
    id: Uuid,
    workspace: Uuid,
    owner: String,
}

async fn org(pool: PgPool) -> Org {
    let app = App::new(pool).await;
    app.sign_up_and_verify("owner@acme.test").await;
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
    let id = reply.body["organization"]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let workspace = reply.body["workspace_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    Org {
        app,
        id,
        workspace,
        owner,
    }
}

impl Org {
    fn path(&self, rest: &str) -> String {
        format!("/api/v1/orgs/{}{rest}", self.id)
    }

    async fn member(&self, email: &str, role_key: &str, workspace: Option<Uuid>) -> String {
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
        let role = role_id(&self.app.pool, self.id, role_key).await;
        grant(&self.app.pool, self.id, membership, role, workspace).await;
        self.app.sign_in(email).await
    }

    async fn post(&self, rest: &str, body: Value, session: &str) -> common::app::Reply {
        self.app
            .call(Method::POST, &self.path(rest), Some(body), Some(session))
            .await
    }

    async fn get(&self, rest: &str, session: &str) -> common::app::Reply {
        self.app
            .call(Method::GET, &self.path(rest), None, Some(session))
            .await
    }

    async fn patch(&self, rest: &str, body: Value, session: &str) -> common::app::Reply {
        self.app
            .call(Method::PATCH, &self.path(rest), Some(body), Some(session))
            .await
    }

    async fn new_case(&self, session: &str, workspace: Uuid, email: &str) -> Value {
        let reply = self
            .post(
                "/cases",
                json!({
                    "workspace_id": workspace,
                    "subject": "Printer is on fire",
                    "description": "Smoke everywhere",
                    "requester": { "email": email, "name": "Pat" },
                    "tags": ["Hardware", "urgent"],
                }),
                session,
            )
            .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        reply.body["case"].clone()
    }
}

#[sqlx::test]
async fn organization_administration(pool: PgPool) {
    let o = org(pool).await;

    let reply = o
        .patch(
            "",
            json!({ "name": "Acme Inc", "require_mfa": false }),
            &o.owner,
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.body["organization"]["name"], "Acme Inc");

    let reply = o
        .post(
            "/workspaces",
            json!({ "name": "Internal IT", "slug": "it" }),
            &o.owner,
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED);
    let reply = o
        .post(
            "/workspaces",
            json!({ "name": "Dup", "slug": "it" }),
            &o.owner,
        )
        .await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(
        o.get("/workspaces", &o.owner).await.body["workspaces"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let roles = o.get("/roles", &o.owner).await;
    assert_eq!(roles.body["roles"].as_array().unwrap().len(), 6);
    let reply = o
        .post(
            "/roles",
            json!({ "name": "Billing", "permissions": ["reports.view", "cases.read"] }),
            &o.owner,
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    let reply = o
        .post(
            "/roles",
            json!({ "name": "Bad", "permissions": ["cases.fly"] }),
            &o.owner,
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);

    let agent = o.member("agent@acme.test", "agent", None).await;
    let members = o.get("/members", &agent).await;
    assert_eq!(members.body["members"].as_array().unwrap().len(), 2);
    assert_eq!(
        o.patch("", json!({ "name": "Hijacked" }), &agent)
            .await
            .status,
        StatusCode::FORBIDDEN
    );

    let owner_membership = members.body["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["email"] == "owner@acme.test")
        .unwrap()["membership_id"]
        .clone();
    let reply = o
        .patch(
            &format!("/members/{}", owner_membership.as_str().unwrap()),
            json!({ "status": "suspended" }),
            &o.owner,
        )
        .await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(reply.body["error"]["code"], "last_administrator");

    let audit = o.get("/audit-events?action=workspace.", &o.owner).await;
    assert_eq!(audit.status, StatusCode::OK);
    assert_eq!(audit.body["data"][0]["action"], "workspace.created");
    assert_eq!(
        o.get("/audit-events", &agent).await.status,
        StatusCode::FORBIDDEN
    );

    let outsider_app = &o.app;
    outsider_app.sign_up_and_verify("stranger@else.test").await;
    let stranger = outsider_app.sign_in("stranger@else.test").await;
    assert_eq!(o.get("", &stranger).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        o.get("/cases", &stranger).await.status,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test]
async fn cases_messages_and_history(pool: PgPool) {
    let o = org(pool).await;
    let agent = o.member("agent@acme.test", "agent", None).await;
    let case = o.new_case(&agent, o.workspace, "pat@customer.test").await;
    let id = case["id"].as_str().unwrap();
    assert_eq!(case["number"], 1);
    assert_eq!(case["status"], "new");
    assert_eq!(case["tags"], json!(["hardware", "urgent"]));
    let second = o.new_case(&agent, o.workspace, "pat@customer.test").await;
    assert_eq!(second["number"], 2);
    assert_eq!(second["requester_contact_id"], case["requester_contact_id"]);

    let reply = o
        .post(
            &format!("/cases/{id}/messages"),
            json!({ "visibility": "public", "body": "On it!" }),
            &agent,
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    o.post(
        &format!("/cases/{id}/messages"),
        json!({ "visibility": "internal", "body": "Call facilities" }),
        &agent,
    )
    .await;
    let messages = o.get(&format!("/cases/{id}/messages"), &agent).await;
    assert_eq!(messages.body["messages"].as_array().unwrap().len(), 2);
    let html = o
        .post(
            &format!("/cases/{id}/messages"),
            json!({ "visibility": "public", "body": "x", "body_format": "html" }),
            &agent,
        )
        .await;
    assert_eq!(html.status, StatusCode::UNPROCESSABLE_ENTITY);

    let me: Value = o
        .app
        .call(Method::GET, "/api/v1/me", None, Some(&agent))
        .await
        .body;
    let reply = o
        .patch(
            &format!("/cases/{id}"),
            json!({ "status": "resolved", "priority": "high", "assignee_user_id": me["user"]["id"] }),
            &agent,
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.body["case"]["status"], "resolved");
    assert!(!reply.body["case"]["resolved_at"].is_null());
    assert!(!reply.body["case"]["first_response_at"].is_null());

    let reply = o
        .patch(
            &format!("/cases/{id}"),
            json!({ "status": "nonsense" }),
            &agent,
        )
        .await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);

    let listed = o.get("/cases?status=resolved&tags=hardware", &agent).await;
    assert_eq!(listed.body["data"].as_array().unwrap().len(), 1);
    let searched = o.get("/cases?q=printer", &agent).await;
    assert_eq!(searched.body["data"].as_array().unwrap().len(), 2);
    let paged = o.get("/cases?limit=1", &agent).await;
    assert!(!paged.body["next_cursor"].is_null());

    let history = o.get(&format!("/cases/{id}/history"), &agent).await;
    let kinds: Vec<&str> = history.body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert!(
        kinds.contains(&"created")
            && kinds.contains(&"updated")
            && kinds.contains(&"message_added")
    );

    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM domain_events WHERE org_id = $1 AND kind LIKE 'case.%'",
    )
    .bind(o.id)
    .fetch_one(&o.app.pool)
    .await
    .unwrap();
    assert!(events >= 6, "{events}");
}

#[sqlx::test]
async fn workspace_and_organization_isolation(pool: PgPool) {
    let o = org(pool).await;
    let it = o
        .post(
            "/workspaces",
            json!({ "name": "IT", "slug": "it" }),
            &o.owner,
        )
        .await
        .body["workspace"]["id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();
    let support_agent = o
        .member("support@acme.test", "agent", Some(o.workspace))
        .await;
    let it_case = o.new_case(&o.owner, it, "emp@acme.test").await;
    let support_case = o.new_case(&o.owner, o.workspace, "cust@else.test").await;

    let reply = o
        .get(
            &format!("/cases/{}", it_case["id"].as_str().unwrap()),
            &support_agent,
        )
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    let listed = o.get("/cases", &support_agent).await;
    let ids: Vec<&str> = listed.body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [support_case["id"].as_str().unwrap()]);
    let reply = o
        .post(
            "/cases",
            json!({ "workspace_id": it, "subject": "x", "requester": { "email": "a@b.co" } }),
            &support_agent,
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    let other = org_two(&o).await;
    let reply = o
        .app
        .call(
            Method::GET,
            &format!(
                "/api/v1/orgs/{}/cases/{}",
                o.id,
                support_case["id"].as_str().unwrap()
            ),
            None,
            Some(&other),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

async fn org_two(o: &Org) -> String {
    o.app.sign_up_and_verify("boss@globex.test").await;
    let boss = o.app.sign_in("boss@globex.test").await;
    let reply = o
        .app
        .call(
            Method::POST,
            "/api/v1/orgs",
            Some(json!({ "name": "Globex", "slug": "globex", "workspace_name": "Support", "workspace_slug": "support" })),
            Some(&boss),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED);
    boss
}

#[sqlx::test]
async fn attachments_are_stored_and_downloaded_safely(pool: PgPool) {
    let o = org(pool).await;
    let case = o.new_case(&o.owner, o.workspace, "pat@customer.test").await;
    let id = case["id"].as_str().unwrap();
    let reply = o
        .app
        .upload(
            &o.path(&format!(
                "/cases/{id}/attachments?file_name=..%2F..%2Fevil.html"
            )),
            "text/html",
            b"<script>alert(1)</script>".to_vec(),
            &o.owner,
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    assert_eq!(reply.body["attachment"]["file_name"], "evil.html");
    let attachment = reply.body["attachment"]["id"].as_str().unwrap().to_string();

    let download = o.get(&format!("/attachments/{attachment}"), &o.owner).await;
    assert_eq!(download.status, StatusCode::OK);
    assert!(
        download.headers[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .starts_with("attachment;")
    );
    assert!(
        download.headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("sandbox")
    );
    assert_eq!(download.headers["x-content-type-options"], "nosniff");

    let listed = o.get(&format!("/cases/{id}/attachments"), &o.owner).await;
    assert_eq!(listed.body["attachments"].as_array().unwrap().len(), 1);
    assert!(listed.body["attachments"][0].get("storage_key").is_none());
}

#[sqlx::test]
async fn requester_portal(pool: PgPool) {
    let o = org(pool).await;
    o.patch(
        &format!("/workspaces/{}", o.workspace),
        json!({ "portal_enabled": true }),
        &o.owner,
    )
    .await;
    o.app.sign_up_and_verify("pat@customer.test").await;
    let pat = o.app.sign_in("pat@customer.test").await;

    let reply = o
        .app
        .call(
            Method::POST,
            &format!("/api/v1/portal/workspaces/{}/cases", o.workspace),
            Some(json!({ "subject": "Need help", "description": "Please" })),
            Some(&pat),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    let id = reply.body["case"]["id"].as_str().unwrap().to_string();

    o.post(
        &format!("/cases/{id}/messages"),
        json!({ "visibility": "internal", "body": "VIP, be nice" }),
        &o.owner,
    )
    .await;
    o.post(
        &format!("/cases/{id}/messages"),
        json!({ "visibility": "public", "body": "Fixed!" }),
        &o.owner,
    )
    .await;
    o.patch(
        &format!("/cases/{id}"),
        json!({ "status": "resolved" }),
        &o.owner,
    )
    .await;

    let view = o
        .app
        .call(
            Method::GET,
            &format!("/api/v1/portal/cases/{id}"),
            None,
            Some(&pat),
        )
        .await;
    let bodies: Vec<&str> = view.body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["body"].as_str().unwrap())
        .collect();
    assert_eq!(bodies, ["Fixed!"]);
    assert!(view.body["case"].get("assignee_user_id").is_none());

    let reply = o
        .app
        .call(
            Method::POST,
            &format!("/api/v1/portal/cases/{id}/messages"),
            Some(json!({ "body": "Still broken" })),
            Some(&pat),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED);
    let case = o.get(&format!("/cases/{id}"), &o.owner).await;
    assert_eq!(case.body["case"]["status"], "open");

    o.app.sign_up_and_verify("eve@else.test").await;
    let eve = o.app.sign_in("eve@else.test").await;
    let reply = o
        .app
        .call(
            Method::GET,
            &format!("/api/v1/portal/cases/{id}"),
            None,
            Some(&eve),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    o.patch(
        &format!("/workspaces/{}", o.workspace),
        json!({ "portal_enabled": false }),
        &o.owner,
    )
    .await;
    let reply = o
        .app
        .call(
            Method::POST,
            &format!("/api/v1/portal/workspaces/{}/cases", o.workspace),
            Some(json!({ "subject": "Again" })),
            Some(&pat),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn api_credentials(pool: PgPool) {
    let o = org(pool).await;
    o.new_case(&o.owner, o.workspace, "pat@customer.test").await;
    let reply = o
        .post(
            "/api-credentials",
            json!({ "name": "Reporting", "permissions": ["cases.read"], "expires_in_days": 30 }),
            &o.owner,
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    let token = reply.body["token"].as_str().unwrap().to_string();
    let key_id = reply.body["api_credential"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(token.starts_with("ult_"));

    let listed = o
        .app
        .bearer(Method::GET, &o.path("/cases"), None, &token)
        .await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    assert_eq!(listed.body["data"].as_array().unwrap().len(), 1);
    let create = o
        .app
        .bearer(
            Method::POST,
            &o.path("/cases"),
            Some(json!({ "workspace_id": o.workspace, "subject": "x", "requester": { "email": "a@b.co" } })),
            &token,
        )
        .await;
    assert_eq!(create.status, StatusCode::FORBIDDEN);
    let mint = o
        .app
        .bearer(
            Method::POST,
            &o.path("/api-credentials"),
            Some(json!({ "name": "x", "permissions": ["cases.read"] })),
            &token,
        )
        .await;
    assert_eq!(mint.status, StatusCode::FORBIDDEN);

    let boss = org_two(&o).await;
    let other: Value = o
        .app
        .call(Method::GET, "/api/v1/orgs", None, Some(&boss))
        .await
        .body;
    let other_id = other["organizations"][0]["id"].as_str().unwrap();
    let cross = o
        .app
        .bearer(
            Method::GET,
            &format!("/api/v1/orgs/{other_id}/cases"),
            None,
            &token,
        )
        .await;
    assert_eq!(cross.status, StatusCode::NOT_FOUND);

    let agent = o.member("agent@acme.test", "agent", None).await;
    let escalate = o
        .post(
            "/api-credentials",
            json!({ "name": "x", "permissions": ["cases.read"] }),
            &agent,
        )
        .await;
    assert_eq!(escalate.status, StatusCode::FORBIDDEN);

    o.post(
        &format!("/api-credentials/{key_id}/revoke"),
        json!({}),
        &o.owner,
    )
    .await;
    let revoked = o
        .app
        .bearer(Method::GET, &o.path("/cases"), None, &token)
        .await;
    assert_eq!(revoked.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn teams_and_queues(pool: PgPool) {
    let o = org(pool).await;
    let agent = o.member("agent@acme.test", "agent", None).await;
    let me: Value = o
        .app
        .call(Method::GET, "/api/v1/me", None, Some(&agent))
        .await
        .body;
    let agent_id = me["user"]["id"].as_str().unwrap();

    let team = o
        .post(
            "/teams",
            json!({ "workspace_id": o.workspace, "name": "Tier 1" }),
            &o.owner,
        )
        .await;
    assert_eq!(team.status, StatusCode::CREATED, "{}", team.body);
    let team_id = team.body["team"]["id"].as_str().unwrap().to_string();
    let added = o
        .app
        .call(
            Method::PUT,
            &o.path(&format!("/teams/{team_id}/members/{agent_id}")),
            None,
            Some(&o.owner),
        )
        .await;
    assert_eq!(added.body["team"]["member_user_ids"], json!([agent_id]));
    assert_eq!(
        o.post(
            "/teams",
            json!({ "workspace_id": o.workspace, "name": "X" }),
            &agent
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );

    let queue = o
        .post(
            "/queues",
            json!({ "workspace_id": o.workspace, "name": "Unassigned urgent",
                    "criteria": { "tags": ["urgent"], "unassigned": true } }),
            &o.owner,
        )
        .await;
    assert_eq!(queue.status, StatusCode::CREATED, "{}", queue.body);
    let bad = o
        .post(
            "/queues",
            json!({ "workspace_id": o.workspace, "name": "Bad", "criteria": { "sql": "drop" } }),
            &o.owner,
        )
        .await;
    assert_eq!(bad.status, StatusCode::UNPROCESSABLE_ENTITY);

    let case = o.new_case(&o.owner, o.workspace, "pat@customer.test").await;
    let queue_id = queue.body["queue"]["id"].as_str().unwrap();
    let in_queue = o.get(&format!("/queues/{queue_id}/cases"), &agent).await;
    assert_eq!(in_queue.body["data"].as_array().unwrap().len(), 1);
    o.patch(
        &format!("/cases/{}", case["id"].as_str().unwrap()),
        json!({ "assignee_user_id": agent_id, "team_id": team_id }),
        &agent,
    )
    .await;
    let in_queue = o.get(&format!("/queues/{queue_id}/cases"), &agent).await;
    assert_eq!(in_queue.body["data"].as_array().unwrap().len(), 0);
}
