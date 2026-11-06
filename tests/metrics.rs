use axum::http::{Method, StatusCode};
use sqlx::PgPool;
use ultrivly::platform::telemetry;

mod common;
use common::org::org;

#[sqlx::test]
async fn metrics_cover_requests_and_queues(pool: PgPool) {
    let handle = telemetry::install().unwrap();
    let o = org(pool).await;
    let reply = o.get("/cases", &o.owner).await;
    assert_eq!(reply.status, StatusCode::OK);
    o.app
        .call(
            Method::GET,
            &format!("/api/v1/orgs/{}/cases/{}", o.id, uuid::Uuid::now_v7()),
            None,
            Some(&o.owner),
        )
        .await;
    sqlx::query(
        "INSERT INTO jobs (id, kind, state, finished_at) VALUES ($1, 'email.send', 'dead', now())",
    )
    .bind(uuid::Uuid::now_v7())
    .execute(&o.app.pool)
    .await
    .unwrap();
    telemetry::record_queue(&o.app.pool).await.unwrap();

    let text = handle.render();
    assert!(
        text.contains(r#"ultrivly_http_requests_total{method="GET",route="/api/v1/orgs/{org_id}/cases",status="200"}"#),
        "{text}"
    );
    assert!(
        text.contains(r#"route="/api/v1/orgs/{org_id}/cases/{id}",status="404""#),
        "{text}"
    );
    assert!(
        text.contains(r#"ultrivly_jobs{kind="email.send",state="dead"} 1"#),
        "{text}"
    );
    assert!(text.contains("ultrivly_outbox_lag_seconds"), "{text}");
    assert!(
        !text.contains(&o.id.to_string()),
        "metrics must not carry tenant IDs"
    );
}
