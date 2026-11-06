use std::io::{Cursor, Read};

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::org::{Org, org};

async fn dead_job(o: &Org, org_id: Uuid, kind: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO jobs (id, org_id, kind, state, attempts, max_attempts, last_error, finished_at)
         VALUES ($1, $2, $3, 'dead', 5, 5, 'endpoint answered 500', now())",
    )
    .bind(id)
    .bind(org_id)
    .bind(kind)
    .execute(&o.app.pool)
    .await
    .unwrap();
    id
}

#[sqlx::test]
async fn admins_can_inspect_and_retry_their_dead_jobs(pool: PgPool) {
    let o = org(pool).await;
    let agent = o.member("agent@acme.test", "agent").await;
    let (other_org, other_owner) = o.other_org("globex", "owner@globex.test").await;
    let mine = dead_job(&o, o.id, "webhook.deliver").await;
    let theirs = dead_job(&o, other_org, "webhook.deliver").await;

    let listed = o.get("/jobs?state=dead", &o.owner).await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    let ids: Vec<&str> = listed.body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|j| j["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [mine.to_string()]);
    assert_eq!(
        listed.body["data"][0]["last_error"],
        "endpoint answered 500"
    );
    assert!(listed.body["data"][0].get("payload").is_none());

    assert_ne!(o.get("/jobs", &agent).await.status, StatusCode::OK);
    assert_eq!(
        o.get("/jobs?state=exploded", &o.owner).await.status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        o.post(&format!("/jobs/{theirs}/retry"), json!({}), &o.owner)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let other = o
        .app
        .call(
            Method::POST,
            &format!("/api/v1/orgs/{other_org}/jobs/{mine}/retry"),
            Some(json!({})),
            Some(&other_owner),
        )
        .await;
    assert_eq!(other.status, StatusCode::NOT_FOUND);

    let retried = o
        .post(&format!("/jobs/{mine}/retry"), json!({}), &o.owner)
        .await;
    assert_eq!(retried.status, StatusCode::ACCEPTED, "{}", retried.body);
    let (state, attempts): (String, i32) =
        sqlx::query_as("SELECT state, attempts FROM jobs WHERE id = $1")
            .bind(mine)
            .fetch_one(&o.app.pool)
            .await
            .unwrap();
    assert_eq!((state.as_str(), attempts), ("queued", 0));
    assert_eq!(
        o.post(&format!("/jobs/{mine}/retry"), json!({}), &o.owner)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE org_id = $1 AND action = 'job.retried'",
    )
    .bind(o.id)
    .fetch_one(&o.app.pool)
    .await
    .unwrap();
    assert_eq!(audited, 1);
}

#[sqlx::test]
async fn retrying_does_not_duplicate_a_queued_job(pool: PgPool) {
    let o = org(pool).await;
    let dead = dead_job(&o, o.id, "auth.password_reset").await;
    sqlx::query("UPDATE jobs SET dedupe_key = 'same' WHERE id = $1")
        .bind(dead)
        .execute(&o.app.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO jobs (id, org_id, kind, dedupe_key) VALUES ($1, $2, 'auth.password_reset', 'same')",
    )
    .bind(Uuid::now_v7())
    .bind(o.id)
    .execute(&o.app.pool)
    .await
    .unwrap();
    let reply = o
        .post(&format!("/jobs/{dead}/retry"), json!({}), &o.owner)
        .await;
    assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);
}

fn unzip(bytes: &[u8]) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    (0..archive.len())
        .map(|i| {
            let mut file = archive.by_index(i).unwrap();
            let mut content = Vec::new();
            file.read_to_end(&mut content).unwrap();
            (file.name().unwrap().to_string(), content)
        })
        .collect()
}

fn rows(files: &std::collections::BTreeMap<String, Vec<u8>>, table: &str) -> Vec<Value> {
    String::from_utf8(files[&format!("data/{table}.jsonl")].clone())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

async fn download(o: &Org, id: &str, session: &str) -> (StatusCode, Vec<u8>) {
    o.app
        .raw_bytes(
            Method::GET,
            &o.path(&format!("/exports/{id}/download")),
            session,
        )
        .await
}

#[sqlx::test]
async fn organization_export_contains_data_and_files_but_no_secrets(pool: PgPool) {
    let o = org(pool).await;
    let agent = o.member("agent@acme.test", "agent").await;
    let case = o.new_case(json!({ "subject": "Export me" })).await.body["case"].clone();
    let case_id = case["id"].as_str().unwrap();
    let upload = o
        .app
        .upload(
            &o.path(&format!(
                "/cases/{case_id}/attachments?file_name=..%2Fnotes.txt"
            )),
            "text/plain",
            b"hello export".to_vec(),
            &o.owner,
        )
        .await;
    assert_eq!(upload.status, StatusCode::CREATED, "{}", upload.body);
    let channel = o
        .post(
            "/channels",
            json!({ "workspace_id": o.workspace, "kind": "email", "name": "Inbox", "address": "help@acme.test" }),
            &o.owner,
        )
        .await;
    let channel_secret = channel.body["secret"].as_str().unwrap().to_string();

    assert_ne!(
        o.post("/exports", json!({}), &agent).await.status,
        StatusCode::ACCEPTED
    );
    let requested = o.post("/exports", json!({}), &o.owner).await;
    assert_eq!(requested.status, StatusCode::ACCEPTED, "{}", requested.body);
    let id = requested.body["export"]["id"].as_str().unwrap().to_string();
    assert_eq!(requested.body["export"]["status"], "pending");
    let early = download(&o, &id, &o.owner).await;
    assert_eq!(early.0, StatusCode::CONFLICT);

    o.run_worker().await;
    let ready = o.get(&format!("/exports/{id}"), &o.owner).await;
    assert_eq!(ready.body["export"]["status"], "ready", "{}", ready.body);

    let (status, bytes) = download(&o, &id, &o.owner).await;
    assert_eq!(status, StatusCode::OK);
    let files = unzip(&bytes);
    let manifest: Value = serde_json::from_slice(&files["manifest.json"]).unwrap();
    assert_eq!(manifest["kind"], "organization");
    assert_eq!(manifest["format_version"], 1);
    let cases = rows(&files, "cases");
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0]["subject"], "Export me");
    assert!(cases[0].get("search_vector").is_none());
    let attachment_id = upload.body["attachment"]["id"].as_str().unwrap();
    let stored = files
        .iter()
        .find(|(name, _)| name.starts_with(&format!("attachments/{attachment_id}/")))
        .expect("attachment file is included");
    assert_eq!(stored.1, b"hello export");
    assert!(!stored.0.contains(".."));
    let everything = String::from_utf8_lossy(&bytes).to_string()
        + &files
            .values()
            .map(|v| String::from_utf8_lossy(v).to_string())
            .collect::<String>();
    assert!(!everything.contains(&channel_secret));
    assert!(!everything.contains("_ciphertext"));
    assert!(!everything.contains("password_hash"));
    assert!(!everything.contains("token_hash"));

    let (other_org, other_owner) = o.other_org("globex", "owner@globex.test").await;
    let cross = o
        .app
        .raw_bytes(
            Method::GET,
            &format!("/api/v1/orgs/{other_org}/exports/{id}/download"),
            &other_owner,
        )
        .await;
    assert_eq!(cross.0, StatusCode::NOT_FOUND);
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE org_id = $1 AND action IN ('export.requested', 'export.downloaded')",
    )
    .bind(o.id)
    .fetch_one(&o.app.pool)
    .await
    .unwrap();
    assert_eq!(audited, 2);

    sqlx::query("UPDATE data_exports SET expires_at = now() - interval '1 minute'")
        .execute(&o.app.pool)
        .await
        .unwrap();
    assert_eq!(ultrivly::exports::expire(&o.app.pool).await.unwrap(), 1);
    assert_eq!(
        o.get(&format!("/exports/{id}"), &o.owner).await.status,
        StatusCode::NOT_FOUND
    );
    let queued: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM blob_deletions WHERE storage_key LIKE '%/exports/%'",
    )
    .fetch_one(&o.app.pool)
    .await
    .unwrap();
    assert_eq!(queued, 1);
}

#[sqlx::test]
async fn contact_export_covers_only_that_contact(pool: PgPool) {
    let o = org(pool).await;
    let pat = o
        .new_case(json!({ "subject": "Pat's case", "requester": { "email": "pat@customer.test" } }))
        .await
        .body["case"]
        .clone();
    o.new_case(json!({ "subject": "Sam's case", "requester": { "email": "sam@customer.test" } }))
        .await;
    let contact_id = pat["requester_contact_id"].as_str().unwrap().to_string();

    assert_eq!(
        o.post(
            "/exports",
            json!({ "contact_id": Uuid::now_v7() }),
            &o.owner
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    let requested = o
        .post("/exports", json!({ "contact_id": contact_id }), &o.owner)
        .await;
    assert_eq!(requested.status, StatusCode::ACCEPTED, "{}", requested.body);
    let id = requested.body["export"]["id"].as_str().unwrap().to_string();
    o.run_worker().await;
    let (status, bytes) = download(&o, &id, &o.owner).await;
    assert_eq!(status, StatusCode::OK);
    let files = unzip(&bytes);
    let subjects: Vec<String> = rows(&files, "cases")
        .iter()
        .map(|c| c["subject"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(subjects, ["Pat's case"]);
    assert_eq!(rows(&files, "contact")[0]["email"], "pat@customer.test");
    assert!(!files.contains_key("data/users.jsonl"));
}

#[sqlx::test]
async fn housekeeping_expires_old_operational_records(pool: PgPool) {
    let o = org(pool).await;
    o.new_case(json!({ "subject": "Recent" })).await;
    o.run_worker().await;
    sqlx::query(
        "INSERT INTO domain_events (id, org_id, kind, subject_type, subject_id, data, occurred_at, dispatched_at)
         SELECT gen_random_uuid(), org_id, kind, subject_type, subject_id, data, now() - interval '40 days', now() - interval '40 days'
         FROM domain_events WHERE org_id = $1 LIMIT 1",
    )
    .bind(o.id)
    .execute(&o.app.pool)
    .await
    .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM domain_events WHERE org_id = $1")
        .bind(o.id)
        .fetch_one(&o.app.pool)
        .await
        .unwrap();
    o.app.worker.housekeeping().await;
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM domain_events WHERE org_id = $1")
        .bind(o.id)
        .fetch_one(&o.app.pool)
        .await
        .unwrap();
    assert_eq!(
        after,
        before - 1,
        "only the 40-day-old dispatched event is removed"
    );
}
