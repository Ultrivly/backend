use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use serde_json::json;
use sha2::Sha256;
use sqlx::{Connection, PgConnection, PgPool};
use uuid::Uuid;

use crate::audit::Actor;
use crate::identity::orgs::record;
use crate::platform::authz::{self, Permission};
use crate::platform::error::{ServiceError, ServiceResult, invalid};
use crate::platform::events::{self, KINDS};
use crate::platform::jobs::{self, NewJob};
use crate::platform::net::{HttpClient, NetPolicy};
use crate::platform::page::Page;
use crate::platform::secrets::{Secrets, random_token};

pub const DELIVER: &str = "webhook.deliver";
pub const EVALUATE_WORKFLOWS: &str = "workflow.evaluate";
const SECRET_PREFIX: &str = "whsec_";
const MAX_ENDPOINTS: i64 = 25;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Endpoint {
    pub id: Uuid,
    pub url: String,
    pub description: String,
    pub events: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Delivery {
    pub id: Uuid,
    pub event_id: Uuid,
    pub event_kind: String,
    pub status: String,
    pub attempts: i32,
    pub response_status: Option<i32>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
}

macro_rules! endpoint_columns {
    () => {
        "id, url, description, events, enabled, created_at, updated_at"
    };
}

fn check_url(policy: &NetPolicy, url: &str) -> ServiceResult<String> {
    let parsed = url::Url::parse(url.trim()).map_err(|_| invalid("url", "is not a valid URL"))?;
    if url.len() > 2000 || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid("url", "must not contain credentials and must be under 2000 characters"));
    }
    policy
        .check_url(&parsed)
        .map_err(|_| invalid("url", "must be a public https URL"))?;
    Ok(parsed.to_string())
}

fn check_events(events: &[String]) -> ServiceResult<Vec<String>> {
    if events.is_empty() || events.len() > 20 {
        return Err(invalid("events", "must list between 1 and 20 event types"));
    }
    let mut out: Vec<String> = Vec::new();
    for event in events {
        if event != "*" && !KINDS.contains(&event.as_str()) {
            return Err(invalid("events", "contains an unknown event type"));
        }
        if !out.contains(event) {
            out.push(event.clone());
        }
    }
    Ok(out)
}

fn secret_context(id: Uuid) -> String {
    format!("webhook:{id}")
}

pub async fn list(conn: &mut PgConnection, org_id: Uuid, actor: Actor) -> ServiceResult<Vec<Endpoint>> {
    authz::require(conn, org_id, actor, Permission::WebhooksManage).await?;
    Ok(sqlx::query_as(concat!(
        "SELECT ",
        endpoint_columns!(),
        " FROM webhook_endpoints WHERE org_id = $1 ORDER BY created_at"
    ))
    .bind(org_id)
    .fetch_all(conn)
    .await?)
}

pub async fn create(
    conn: &mut PgConnection,
    policy: &NetPolicy,
    secrets: &Secrets,
    org_id: Uuid,
    actor: Actor,
    url: &str,
    description: &str,
    events: &[String],
) -> ServiceResult<(Endpoint, String)> {
    let url = check_url(policy, url)?;
    let events = check_events(events)?;
    if description.chars().count() > 500 {
        return Err(invalid("description", "is too long"));
    }
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::WebhooksManage).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM webhook_endpoints WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(&mut *tx)
        .await?;
    if count >= MAX_ENDPOINTS {
        return Err(invalid("url", "the organization has the maximum number of webhooks"));
    }
    let id = Uuid::now_v7();
    let secret = format!("{SECRET_PREFIX}{}", random_token());
    let endpoint: Endpoint = sqlx::query_as(concat!(
        "INSERT INTO webhook_endpoints (id, org_id, url, description, events, secret_ciphertext)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING ",
        endpoint_columns!()
    ))
    .bind(id)
    .bind(org_id)
    .bind(&url)
    .bind(description.trim())
    .bind(&events)
    .bind(secrets.encrypt(&secret_context(id), secret.as_bytes()))
    .fetch_one(&mut *tx)
    .await?;
    record(&mut tx, org_id, actor, "webhook.created", "webhook", id, json!({ "url": url, "events": events })).await?;
    tx.commit().await?;
    Ok((endpoint, secret))
}

#[derive(Default)]
pub struct EndpointChanges<'a> {
    pub url: Option<&'a str>,
    pub description: Option<&'a str>,
    pub events: Option<&'a [String]>,
    pub enabled: Option<bool>,
}

pub async fn update(
    conn: &mut PgConnection,
    policy: &NetPolicy,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
    changes: EndpointChanges<'_>,
) -> ServiceResult<Endpoint> {
    let url = changes.url.map(|u| check_url(policy, u)).transpose()?;
    let events = changes.events.map(check_events).transpose()?;
    if changes.description.is_some_and(|d| d.chars().count() > 500) {
        return Err(invalid("description", "is too long"));
    }
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::WebhooksManage).await?;
    let endpoint: Endpoint = sqlx::query_as(concat!(
        "UPDATE webhook_endpoints SET url = coalesce($3, url), description = coalesce($4, description),
             events = coalesce($5, events), enabled = coalesce($6, enabled)
         WHERE org_id = $1 AND id = $2 RETURNING ",
        endpoint_columns!()
    ))
    .bind(org_id)
    .bind(id)
    .bind(&url)
    .bind(changes.description.map(str::trim))
    .bind(&events)
    .bind(changes.enabled)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ServiceError::NotFound)?;
    record(
        &mut tx,
        org_id,
        actor,
        "webhook.updated",
        "webhook",
        id,
        json!({ "url": url, "events": events, "enabled": changes.enabled }),
    )
    .await?;
    tx.commit().await?;
    Ok(endpoint)
}

pub async fn rotate_secret(
    conn: &mut PgConnection,
    secrets: &Secrets,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> ServiceResult<String> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::WebhooksManage).await?;
    let secret = format!("{SECRET_PREFIX}{}", random_token());
    let updated = sqlx::query("UPDATE webhook_endpoints SET secret_ciphertext = $3 WHERE org_id = $1 AND id = $2")
        .bind(org_id)
        .bind(id)
        .bind(secrets.encrypt(&secret_context(id), secret.as_bytes()))
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if updated == 0 {
        return Err(ServiceError::NotFound);
    }
    record(&mut tx, org_id, actor, "webhook.secret_rotated", "webhook", id, json!({})).await?;
    tx.commit().await?;
    Ok(secret)
}

pub async fn delete(conn: &mut PgConnection, org_id: Uuid, actor: Actor, id: Uuid) -> ServiceResult<()> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::WebhooksManage).await?;
    let deleted = sqlx::query("DELETE FROM webhook_endpoints WHERE org_id = $1 AND id = $2")
        .bind(org_id)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Err(ServiceError::NotFound);
    }
    record(&mut tx, org_id, actor, "webhook.deleted", "webhook", id, json!({})).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn deliveries(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    endpoint_id: Uuid,
    page: Page,
) -> ServiceResult<Vec<Delivery>> {
    authz::require(conn, org_id, actor, Permission::WebhooksManage).await?;
    Ok(sqlx::query_as(
        "SELECT id, event_id, event_kind, status, attempts, response_status, last_error, created_at, delivered_at
         FROM webhook_deliveries
         WHERE org_id = $1 AND endpoint_id = $2 AND ($3::uuid IS NULL OR id < $3)
         ORDER BY id DESC LIMIT $4",
    )
    .bind(org_id)
    .bind(endpoint_id)
    .bind(page.cursor)
    .bind(page.limit + 1)
    .fetch_all(conn)
    .await?)
}

pub async fn redeliver(conn: &mut PgConnection, org_id: Uuid, actor: Actor, delivery_id: Uuid) -> ServiceResult<()> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::WebhooksManage).await?;
    let updated = sqlx::query("UPDATE webhook_deliveries SET status = 'pending' WHERE org_id = $1 AND id = $2")
        .bind(org_id)
        .bind(delivery_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if updated == 0 {
        return Err(ServiceError::NotFound);
    }
    enqueue_delivery(&mut tx, org_id, delivery_id).await?;
    tx.commit().await?;
    Ok(())
}

async fn enqueue_delivery(conn: &mut PgConnection, org_id: Uuid, delivery_id: Uuid) -> sqlx::Result<()> {
    let key = delivery_id.to_string();
    jobs::enqueue(
        conn,
        NewJob {
            org_id: Some(org_id),
            dedupe_key: Some(&key),
            max_attempts: 8,
            ..NewJob::new(DELIVER, json!({ "delivery_id": delivery_id }))
        },
    )
    .await?;
    Ok(())
}

pub async fn dispatch_events(pool: &PgPool) -> sqlx::Result<usize> {
    let mut tx = pool.begin().await?;
    let pending: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT id, org_id, kind FROM domain_events WHERE dispatched_at IS NULL
         ORDER BY occurred_at LIMIT 200 FOR UPDATE SKIP LOCKED",
    )
    .fetch_all(&mut *tx)
    .await?;
    for (event_id, org_id, kind) in &pending {
        let endpoints: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM webhook_endpoints
             WHERE org_id = $1 AND enabled AND ($2 = ANY(events) OR '*' = ANY(events))",
        )
        .bind(org_id)
        .bind(kind)
        .fetch_all(&mut *tx)
        .await?;
        for endpoint_id in endpoints {
            let delivery_id = Uuid::now_v7();
            let inserted = sqlx::query(
                "INSERT INTO webhook_deliveries (id, org_id, endpoint_id, event_id, event_kind)
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
            )
            .bind(delivery_id)
            .bind(org_id)
            .bind(endpoint_id)
            .bind(event_id)
            .bind(kind)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if inserted == 1 {
                enqueue_delivery(&mut tx, *org_id, delivery_id).await?;
            }
        }
        if kind.starts_with("case.") {
            let key = event_id.to_string();
            jobs::enqueue(
                &mut tx,
                NewJob {
                    org_id: Some(*org_id),
                    dedupe_key: Some(&key),
                    max_attempts: 3,
                    ..NewJob::new(EVALUATE_WORKFLOWS, json!({ "event_id": event_id }))
                },
            )
            .await?;
        }
        sqlx::query("UPDATE domain_events SET dispatched_at = now() WHERE id = $1")
            .bind(event_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(pending.len())
}

pub fn sign(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).expect("any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub async fn deliver(pool: &PgPool, http: &HttpClient, secrets: &Secrets, delivery_id: Uuid) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    type Row = (Uuid, Uuid, Uuid, String, Vec<u8>, bool, String);
    let row: Option<Row> = sqlx::query_as(
        "SELECT d.org_id, d.endpoint_id, d.event_id, e.url, e.secret_ciphertext, e.enabled, d.event_kind
         FROM webhook_deliveries d JOIN webhook_endpoints e ON e.id = d.endpoint_id
         WHERE d.id = $1",
    )
    .bind(delivery_id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((org_id, endpoint_id, event_id, url, ciphertext, enabled, kind)) = row else {
        return Ok(());
    };
    if !enabled {
        sqlx::query("UPDATE webhook_deliveries SET status = 'failed', last_error = 'endpoint disabled' WHERE id = $1")
            .bind(delivery_id)
            .execute(&mut *conn)
            .await?;
        return Ok(());
    }
    let event = events::load(&mut conn, event_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("event {event_id} no longer exists"))?;
    let secret = String::from_utf8(secrets.decrypt(&secret_context(endpoint_id), &ciphertext)?)?;
    let body = serde_json::to_vec(&json!({
        "id": event.id,
        "type": kind,
        "created_at": event.occurred_at,
        "org_id": org_id,
        "data": event.data,
    }))?;
    let timestamp = Utc::now().timestamp();
    let signature = sign(&secret, timestamp, &body);
    let result = http
        .post(
            &url,
            &[
                ("content-type", "application/json".into()),
                ("ultrivly-event", kind.clone()),
                ("ultrivly-delivery", delivery_id.to_string()),
                ("ultrivly-signature", format!("t={timestamp},v1={signature}")),
            ],
            body,
        )
        .await;
    let (status, error) = match &result {
        Ok(code) if (200..300).contains(code) => (Some(*code as i32), None),
        Ok(code) => (Some(*code as i32), Some(format!("receiver answered {code}"))),
        Err(err) => (None, Some(err.to_string())),
    };
    sqlx::query(
        "UPDATE webhook_deliveries SET attempts = attempts + 1, response_status = $2, last_error = left($3, 500),
             status = CASE WHEN $3 IS NULL THEN 'succeeded' ELSE 'failed' END,
             delivered_at = CASE WHEN $3 IS NULL THEN now() ELSE delivered_at END
         WHERE id = $1",
    )
    .bind(delivery_id)
    .bind(status)
    .bind(&error)
    .execute(&mut *conn)
    .await?;
    match error {
        None => Ok(()),
        Some(error) => anyhow::bail!(error),
    }
}

#[cfg(test)]
mod tests {
    use super::sign;

    #[test]
    fn signature_covers_timestamp_and_body() {
        let a = sign("whsec_x", 1, b"{}");
        assert_eq!(a.len(), 64);
        assert_ne!(a, sign("whsec_x", 2, b"{}"));
        assert_ne!(a, sign("whsec_x", 1, b"{ }"));
        assert_ne!(a, sign("whsec_y", 1, b"{}"));
    }
}
