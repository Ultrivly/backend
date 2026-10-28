use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;

pub const MAX_DEPTH: i32 = 3;

pub const KINDS: &[&str] = &[
    "case.created",
    "case.updated",
    "case.status_changed",
    "case.assigned",
    "case.message_added",
    "case.deleted",
    "contact.created",
    "article.published",
];

#[derive(Debug, Clone, Copy, Default)]
pub struct Cause {
    pub event_id: Option<Uuid>,
    pub depth: i32,
}

impl Cause {
    pub fn next(event_id: Uuid, depth: i32) -> Self {
        Self {
            event_id: Some(event_id),
            depth: depth + 1,
        }
    }
}

pub async fn emit(
    conn: &mut PgConnection,
    org_id: Uuid,
    kind: &str,
    subject_type: &str,
    subject_id: Uuid,
    data: Value,
    cause: Cause,
) -> sqlx::Result<Uuid> {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO domain_events (id, org_id, kind, subject_type, subject_id, data, causation_id, depth)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(id)
    .bind(org_id)
    .bind(kind)
    .bind(subject_type)
    .bind(subject_id)
    .bind(data)
    .bind(cause.event_id)
    .bind(cause.depth)
    .execute(conn)
    .await?;
    Ok(id)
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DomainEvent {
    pub id: Uuid,
    pub org_id: Uuid,
    pub kind: String,
    pub subject_type: String,
    pub subject_id: Uuid,
    pub data: Value,
    pub depth: i32,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
}

pub async fn load(conn: &mut PgConnection, id: Uuid) -> sqlx::Result<Option<DomainEvent>> {
    sqlx::query_as(
        "SELECT id, org_id, kind, subject_type, subject_id, data, depth, occurred_at
         FROM domain_events WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(conn)
    .await
}
