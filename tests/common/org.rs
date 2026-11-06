use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use ultrivly::audit::Actor;
use uuid::Uuid;

use super::app::{App, Reply};
use super::{grant, role_id};

pub struct Org {
    pub app: App,
    pub id: Uuid,
    pub workspace: Uuid,
    pub owner: String,
    pub owner_id: Uuid,
}

pub async fn org(pool: PgPool) -> Org {
    org_with(pool, "acme", "owner@acme.test").await
}

pub async fn org_with(pool: PgPool, slug: &str, owner_email: &str) -> Org {
    let app = App::new(pool).await;
    from_app(app, slug, owner_email).await
}

pub async fn from_app(app: App, slug: &str, owner_email: &str) -> Org {
    let owner_id = app.sign_up_and_verify(owner_email).await;
    let owner = app.sign_in(owner_email).await;
    let reply = app
        .call(
            Method::POST,
            "/api/v1/orgs",
            Some(json!({ "name": slug, "slug": slug, "workspace_name": "Support", "workspace_slug": "support" })),
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
    pub async fn other_org(&self, slug: &str, email: &str) -> (Uuid, String) {
        self.app.sign_up_and_verify(email).await;
        let session = self.app.sign_in(email).await;
        let reply = self
            .app
            .call(
                Method::POST,
                "/api/v1/orgs",
                Some(json!({ "name": slug, "slug": slug, "workspace_name": "Support", "workspace_slug": "support" })),
                Some(&session),
            )
            .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        (
            reply.body["organization"]["id"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            session,
        )
    }

    pub fn path(&self, rest: &str) -> String {
        format!("/api/v1/orgs/{}{rest}", self.id)
    }

    pub async fn post(&self, rest: &str, body: Value, session: &str) -> Reply {
        self.app
            .call(Method::POST, &self.path(rest), Some(body), Some(session))
            .await
    }

    pub async fn put(&self, rest: &str, body: Value, session: &str) -> Reply {
        self.app
            .call(Method::PUT, &self.path(rest), Some(body), Some(session))
            .await
    }

    pub async fn get(&self, rest: &str, session: &str) -> Reply {
        self.app
            .call(Method::GET, &self.path(rest), None, Some(session))
            .await
    }

    pub async fn member(&self, email: &str, role_key: &str) -> String {
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

    pub async fn new_case(&self, body: Value) -> Reply {
        let mut request = json!({ "workspace_id": self.workspace, "subject": "Help", "requester": { "email": "pat@customer.test" } });
        for (key, value) in body.as_object().unwrap() {
            request[key] = value.clone();
        }
        self.post("/cases", request, &self.owner).await
    }

    pub async fn run_worker(&self) {
        while self.app.worker.run_once().await.unwrap() {}
    }

    pub fn actor(&self) -> Actor {
        Actor::User(self.owner_id)
    }
}
