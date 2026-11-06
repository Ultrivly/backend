use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::platform::error::unique_violation;
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

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct JobInfo {
    pub id: Uuid,
    pub org_id: Option<Uuid>,
    pub kind: String,
    pub state: String,
    pub attempts: i32,
    pub max_attempts: i32,
    pub last_error: Option<String>,
    pub run_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Default)]
pub struct JobFilter<'a> {
    pub org_id: Option<Uuid>,
    pub state: Option<&'a str>,
    pub kind: Option<&'a str>,
}

pub const STATES: &[&str] = &["queued", "running", "succeeded", "dead"];

pub async fn list(
    conn: &mut PgConnection,
    filter: JobFilter<'_>,
    cursor: Option<Uuid>,
    limit: i64,
) -> sqlx::Result<Vec<JobInfo>> {
    sqlx::query_as(
        "SELECT id, org_id, kind, state, attempts, max_attempts, last_error, run_at, created_at, finished_at
         FROM jobs
         WHERE ($1::uuid IS NULL OR org_id = $1) AND ($2::text IS NULL OR state = $2)
           AND ($3::text IS NULL OR kind = $3) AND ($4::uuid IS NULL OR id < $4)
         ORDER BY id DESC LIMIT $5",
    )
    .bind(filter.org_id)
    .bind(filter.state)
    .bind(filter.kind)
    .bind(cursor)
    .bind(limit)
    .fetch_all(conn)
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    Queued,
    NotFound,
    AlreadyQueued,
}

pub async fn retry(conn: &mut PgConnection, id: Uuid, org_id: Option<Uuid>) -> sqlx::Result<Retry> {
    let updated = sqlx::query(
        "UPDATE jobs SET state = 'queued', attempts = 0, run_at = now(), finished_at = NULL, last_error = NULL
         WHERE id = $1 AND state = 'dead' AND ($2::uuid IS NULL OR org_id = $2)",
    )
    .bind(id)
    .bind(org_id)
    .execute(conn)
    .await;
    match updated {
        Ok(result) if result.rows_affected() == 1 => Ok(Retry::Queued),
        Ok(_) => Ok(Retry::NotFound),
        Err(err) if unique_violation(&err, "jobs_dedupe_key") => Ok(Retry::AlreadyQueued),
        Err(err) => Err(err),
    }
}

pub async fn retry_dead(conn: &mut PgConnection, kind: Option<&str>) -> sqlx::Result<(u64, u64)> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM jobs WHERE state = 'dead' AND ($1::text IS NULL OR kind = $1) ORDER BY id",
    )
    .bind(kind)
    .fetch_all(&mut *conn)
    .await?;
    let (mut retried, mut skipped) = (0, 0);
    for id in ids {
        match retry(conn, id, None).await? {
            Retry::Queued => retried += 1,
            Retry::AlreadyQueued => skipped += 1,
            Retry::NotFound => {}
        }
    }
    Ok((retried, skipped))
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct QueueCount {
    pub kind: String,
    pub state: String,
    pub count: i64,
}

pub async fn counts(pool: &PgPool) -> sqlx::Result<Vec<QueueCount>> {
    sqlx::query_as(
        "SELECT kind, state, count(*) AS count FROM jobs
         WHERE state IN ('queued', 'running', 'dead') GROUP BY kind, state ORDER BY kind, state",
    )
    .fetch_all(pool)
    .await
}
