









use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::platform::secrets::Secrets;


pub const LEASE: Duration = Duration::from_secs(5 * 60);

pub struct NewJob<'a> {
    pub kind: &'a str,
    pub org_id: Option<Uuid>,
    pub payload: Value,
    
    pub dedupe_key: Option<&'a str>,
    pub max_attempts: i32,
}

impl<'a> NewJob<'a> {
    pub fn new(kind: &'a str, payload: Value) -> Self {
        Self {
            kind,
            org_id: None,
            payload,
            dedupe_key: None,
            max_attempts: 10,
        }
    }
}



pub async fn enqueue(conn: &mut PgConnection, job: NewJob<'_>) -> sqlx::Result<Option<Uuid>> {
    let id = Uuid::now_v7();
    sqlx::query_scalar(
        "INSERT INTO jobs (id, org_id, kind, payload, dedupe_key, max_attempts)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (kind, dedupe_key) WHERE dedupe_key IS NOT NULL AND state IN ('queued', 'running')
         DO NOTHING
         RETURNING id",
    )
    .bind(id)
    .bind(job.org_id)
    .bind(job.kind)
    .bind(job.payload)
    .bind(job.dedupe_key)
    .bind(job.max_attempts)
    .fetch_optional(conn)
    .await
}

#[derive(Debug)]
pub struct ClaimedJob {
    pub id: Uuid,
    pub kind: String,
    pub org_id: Option<Uuid>,
    pub payload: Value,
    
    pub attempt: i32,
    pub max_attempts: i32,
}

pub async fn claim(pool: &PgPool, worker: &str) -> sqlx::Result<Option<ClaimedJob>> {
    let row: Option<(Uuid, String, Option<Uuid>, Value, i32, i32)> = sqlx::query_as(
        "UPDATE jobs SET state = 'running', attempts = attempts + 1, locked_by = $1,
                         locked_until = now() + make_interval(secs => $2)
         WHERE id = (SELECT id FROM jobs WHERE state = 'queued' AND run_at <= now()
                     ORDER BY run_at LIMIT 1 FOR UPDATE SKIP LOCKED)
         RETURNING id, kind, org_id, payload, attempts, max_attempts",
    )
    .bind(worker)
    .bind(LEASE.as_secs_f64())
    .fetch_optional(pool)
    .await?;
    Ok(row.map(
        |(id, kind, org_id, payload, attempt, max_attempts)| ClaimedJob {
            id,
            kind,
            org_id,
            payload,
            attempt,
            max_attempts,
        },
    ))
}


pub async fn succeed(pool: &PgPool, id: Uuid) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE jobs SET state = 'succeeded', payload = '{}', finished_at = now(),
                         locked_by = NULL, locked_until = NULL, last_error = NULL
         WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}



pub async fn fail(pool: &PgPool, job: &ClaimedJob, error: &str) -> sqlx::Result<()> {
    let dead = job.attempt >= job.max_attempts;
    sqlx::query(
        "UPDATE jobs SET
             state = CASE WHEN $2 THEN 'dead' ELSE 'queued' END,
             run_at = now() + least(interval '1 hour', interval '30 seconds' * power(2, attempts - 1)),
             finished_at = CASE WHEN $2 THEN now() END,
             locked_by = NULL, locked_until = NULL, last_error = left($3, 2000)
         WHERE id = $1",
    )
    .bind(job.id)
    .bind(dead)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}


pub async fn release_expired_leases(pool: &PgPool) -> sqlx::Result<u64> {
    Ok(sqlx::query(
        "UPDATE jobs SET state = 'queued', locked_by = NULL, locked_until = NULL
         WHERE state = 'running' AND locked_until < now()",
    )
    .execute(pool)
    .await?
    .rows_affected())
}


pub fn seal(secrets: &Secrets, kind: &str, value: &Value) -> Value {
    let ciphertext = secrets.encrypt(&format!("job:{kind}"), value.to_string().as_bytes());
    json!({ "sealed": STANDARD.encode(ciphertext) })
}

pub fn unseal(secrets: &Secrets, kind: &str, payload: &Value) -> anyhow::Result<Value> {
    let sealed = payload["sealed"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("job payload is not sealed"))?;
    let plaintext = secrets.decrypt(&format!("job:{kind}"), &STANDARD.decode(sealed)?)?;
    Ok(serde_json::from_slice(&plaintext)?)
}
