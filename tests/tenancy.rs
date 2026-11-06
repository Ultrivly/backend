use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::app::Reply;
use common::org::{Org, org};

struct Other {
    id: Uuid,
    session: String,
    workspace: Uuid,
    case: String,
    contact: String,
    team: String,
    attachment: String,
    priority: Uuid,
    article: String,
}

async fn as_other(
    o: &Org,
    other: &Other,
    method: Method,
    rest: &str,
    body: Option<Value>,
) -> Reply {
    o.app
        .call(
            method,
            &format!("/api/v1/orgs/{}{rest}", other.id),
            body,
            Some(&other.session),
        )
        .await
}

async fn other(o: &Org) -> Other {
    let (id, session) = o.other_org("globex", "owner@globex.test").await;
    let workspace: Uuid = sqlx::query_scalar("SELECT id FROM workspaces WHERE org_id = $1")
        .bind(id)
        .fetch_one(&o.app.pool)
        .await
        .unwrap();
    let mut b = Other {
        id,
        session,
        workspace,
        case: String::new(),
        contact: String::new(),
        team: String::new(),
        attachment: String::new(),
        priority: Uuid::nil(),
        article: String::new(),
    };
    let case = as_other(
        o,
        &b,
        Method::POST,
        "/cases",
        Some(json!({ "workspace_id": workspace, "subject": "Zanzibar merger secrets", "requester": { "email": "ceo@globex.test" } })),
    )
    .await;
    assert_eq!(case.status, StatusCode::CREATED, "{}", case.body);
    b.case = case.body["case"]["id"].as_str().unwrap().into();
    b.contact = case.body["case"]["requester_contact_id"]
        .as_str()
        .unwrap()
        .into();
    let team = as_other(
        o,
        &b,
        Method::POST,
        "/teams",
        Some(json!({ "workspace_id": workspace, "name": "Legal" })),
    )
    .await;
    assert_eq!(team.status, StatusCode::CREATED, "{}", team.body);
    b.team = team.body["team"]["id"].as_str().unwrap().into();
    let upload = o
        .app
        .upload(
            &format!(
                "/api/v1/orgs/{id}/cases/{}/attachments?file_name=plan.txt",
                b.case
            ),
            "text/plain",
            b"Zanzibar term sheet".to_vec(),
            &b.session,
        )
        .await;
    assert_eq!(upload.status, StatusCode::CREATED, "{}", upload.body);
    b.attachment = upload.body["attachment"]["id"].as_str().unwrap().into();
    b.priority =
        sqlx::query_scalar("SELECT id FROM case_priorities WHERE org_id = $1 AND key = 'high'")
            .bind(id)
            .fetch_one(&o.app.pool)
            .await
            .unwrap();
    let article = as_other(
        o,
        &b,
        Method::POST,
        "/kb/articles",
        Some(json!({ "title": "Zanzibar playbook", "body": "Zanzibar internal", "visibility": "public" })),
    )
    .await;
    assert_eq!(article.status, StatusCode::CREATED, "{}", article.body);
    b.article = article.body["article"]["id"].as_str().unwrap().into();
    as_other(
        o,
        &b,
        Method::POST,
        &format!("/kb/articles/{}/state", b.article),
        Some(json!({ "state": "published" })),
    )
    .await;
    b
}

fn rejected(reply: &Reply) -> bool {
    matches!(
        reply.status,
        StatusCode::NOT_FOUND | StatusCode::FORBIDDEN | StatusCode::UNPROCESSABLE_ENTITY
    )
}

#[sqlx::test]
async fn another_organizations_ids_cannot_be_read_or_referenced(pool: PgPool) {
    let o = org(pool).await;
    let b = other(&o).await;
    let mine = o.new_case(json!({ "subject": "Own case" })).await.body["case"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    for path in [
        format!("/cases/{}", b.case),
        format!("/cases/{}/messages", b.case),
        format!("/cases/{}/history", b.case),
        format!("/cases/{}/attachments", b.case),
        format!("/attachments/{}", b.attachment),
        format!("/contacts/{}", b.contact),
        format!("/kb/articles/{}", b.article),
    ] {
        let reply = o.get(&path, &o.owner).await;
        assert_eq!(
            reply.status,
            StatusCode::NOT_FOUND,
            "{path}: {}",
            reply.body
        );
        assert!(!reply.body.to_string().contains("Zanzibar"), "{path}");
    }
    let foreign = o
        .app
        .call(
            Method::GET,
            &format!("/api/v1/orgs/{}/attachments/{}", b.id, b.attachment),
            None,
            Some(&o.owner),
        )
        .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);

    for (path, body) in [
        (
            "/cases".to_string(),
            json!({ "workspace_id": b.workspace, "subject": "x", "requester": { "email": "a@b.test" } }),
        ),
        (
            "/cases".to_string(),
            json!({ "workspace_id": o.workspace, "subject": "x", "team_id": b.team, "requester": { "email": "a@b.test" } }),
        ),
        (
            format!("/cases/{mine}/links"),
            json!({ "linked_case_id": b.case, "kind": "related" }),
        ),
        (
            "/teams".to_string(),
            json!({ "workspace_id": b.workspace, "name": "Spy" }),
        ),
        (
            "/channels".to_string(),
            json!({ "workspace_id": b.workspace, "kind": "chat", "name": "Spy", "allowed_origins": ["https://spy.example"] }),
        ),
        ("/exports".to_string(), json!({ "contact_id": b.contact })),
        (
            "/workflows".to_string(),
            json!({ "name": "Spy", "definition": { "trigger": "case_created", "actions": [{ "type": "assign_team", "team_id": b.team }] } }),
        ),
        (
            "/workflows".to_string(),
            json!({ "name": "Spy", "definition": { "trigger": "case_created", "actions": [{ "type": "plugin", "install_id": Uuid::now_v7(), "action": "x" }] } }),
        ),
    ] {
        let reply = o.post(&path, body.clone(), &o.owner).await;
        assert!(
            rejected(&reply),
            "{path} {body}: {} {}",
            reply.status,
            reply.body
        );
    }
    let renamed = o
        .app
        .call(
            Method::PATCH,
            &o.path(&format!("/teams/{}", b.team)),
            Some(json!({ "name": "Owned" })),
            Some(&o.owner),
        )
        .await;
    assert_eq!(renamed.status, StatusCode::NOT_FOUND, "{}", renamed.body);
    let patched = o
        .app
        .call(
            Method::PATCH,
            &o.path(&format!("/cases/{mine}")),
            Some(json!({ "team_id": b.team })),
            Some(&o.owner),
        )
        .await;
    assert!(rejected(&patched), "{}", patched.body);
    let other_owner: Uuid = sqlx::query_scalar("SELECT user_id FROM memberships WHERE org_id = $1")
        .bind(b.id)
        .fetch_one(&o.app.pool)
        .await
        .unwrap();
    let assigned = o
        .app
        .call(
            Method::PATCH,
            &o.path(&format!("/cases/{mine}")),
            Some(json!({ "assignee_user_id": other_owner })),
            Some(&o.owner),
        )
        .await;
    assert!(rejected(&assigned), "{}", assigned.body);
    let sla = o
        .put(
            "/sla-policies",
            json!({ "priority_id": b.priority, "first_response_minutes": 5 }),
            &o.owner,
        )
        .await;
    assert!(rejected(&sla), "{}", sla.body);

    let view = o
        .post(
            "/views",
            json!({ "name": "Spy", "filter": { "workspace_id": b.workspace } }),
            &o.owner,
        )
        .await;
    if view.status == StatusCode::CREATED {
        let id = view.body["view"]["id"].as_str().unwrap();
        let cases = o.get(&format!("/views/{id}/cases"), &o.owner).await;
        assert_eq!(
            cases.body["data"].as_array().map(Vec::len),
            Some(0),
            "{}",
            cases.body
        );
    } else {
        assert!(rejected(&view));
    }

    let linked: i64 = sqlx::query_scalar("SELECT count(*) FROM case_links WHERE org_id = $1")
        .bind(o.id)
        .fetch_one(&o.app.pool)
        .await
        .unwrap();
    assert_eq!(linked, 0);
}

#[sqlx::test]
async fn search_never_returns_another_organizations_content(pool: PgPool) {
    let o = org(pool).await;
    let b = other(&o).await;
    o.new_case(json!({ "subject": "Printer jam" })).await;

    for path in [
        "/cases?q=zanzibar",
        "/kb/articles?q=zanzibar",
        "/contacts?q=globex",
    ] {
        let reply = o.get(path, &o.owner).await;
        assert_eq!(reply.status, StatusCode::OK, "{path}: {}", reply.body);
        assert!(
            !reply.body.to_string().to_lowercase().contains("zanzibar"),
            "{path}: {}",
            reply.body
        );
        assert!(
            !reply.body.to_string().contains("globex.test"),
            "{path}: {}",
            reply.body
        );
    }
    let help = o
        .app
        .call(
            Method::GET,
            "/api/v1/help/acme/articles?q=zanzibar",
            None,
            None,
        )
        .await;
    assert!(!help.body.to_string().contains("Zanzibar"), "{}", help.body);
    let theirs = o
        .app
        .call(
            Method::GET,
            "/api/v1/help/globex/articles?q=zanzibar",
            None,
            None,
        )
        .await;
    assert!(
        theirs.body.to_string().contains("Zanzibar"),
        "the other help center still works: {}",
        theirs.body
    );
    let _ = b;
}

#[sqlx::test]
async fn api_keys_only_work_for_their_own_organization(pool: PgPool) {
    let o = org(pool).await;
    let b = other(&o).await;
    let created = o
        .post(
            "/api-credentials",
            json!({ "name": "CI", "permissions": ["cases.read"] }),
            &o.owner,
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let token = created.body["token"].as_str().unwrap();
    assert_eq!(
        o.app
            .bearer(Method::GET, &o.path("/cases"), None, token)
            .await
            .status,
        StatusCode::OK
    );
    for path in [
        format!("/api/v1/orgs/{}/cases", b.id),
        format!("/api/v1/orgs/{}/cases/{}", b.id, b.case),
        format!("/api/v1/orgs/{}/attachments/{}", b.id, b.attachment),
    ] {
        let reply = o.app.bearer(Method::GET, &path, None, token).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
    }
}
