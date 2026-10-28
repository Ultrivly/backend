pub mod attachments;
pub mod contacts;
pub mod messages;
pub mod portal;
pub mod records;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::audit::Actor;
use crate::identity::orgs::require_member;
use crate::platform::error::ServiceResult;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Status {
    pub id: Uuid,
    pub key: String,
    pub label: String,
    pub category: String,
    pub position: i32,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Priority {
    pub id: Uuid,
    pub key: String,
    pub label: String,
    pub rank: i32,
    pub is_default: bool,
}

pub async fn statuses(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
) -> ServiceResult<Vec<Status>> {
    require_member(conn, org_id, actor).await?;
    Ok(sqlx::query_as(
        "SELECT id, key, label, category, position, is_default FROM case_statuses
         WHERE org_id = $1 ORDER BY position",
    )
    .bind(org_id)
    .fetch_all(conn)
    .await?)
}

pub async fn priorities(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
) -> ServiceResult<Vec<Priority>> {
    require_member(conn, org_id, actor).await?;
    Ok(sqlx::query_as(
        "SELECT id, key, label, rank, is_default FROM case_priorities WHERE org_id = $1 ORDER BY rank",
    )
    .bind(org_id)
    .fetch_all(conn)
    .await?)
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct HistoryEntry {
    pub id: Uuid,
    pub kind: String,
    pub actor_kind: String,
    pub actor_id: Option<Uuid>,
    pub data: serde_json::Value,
    pub occurred_at: DateTime<Utc>,
}

const DEFAULT_STATUSES: &[(&str, &str, &str)] = &[
    ("new", "New", "new"),
    ("open", "Open", "open"),
    ("pending", "Pending", "pending"),
    ("resolved", "Resolved", "resolved"),
    ("closed", "Closed", "closed"),
];

const DEFAULT_PRIORITIES: &[(&str, &str, i32)] = &[
    ("low", "Low", 1),
    ("normal", "Normal", 2),
    ("high", "High", 3),
    ("urgent", "Urgent", 4),
];
const DEFAULT_PRIORITY_KEY: &str = "normal";

pub async fn seed_org_defaults(conn: &mut PgConnection, org_id: Uuid) -> sqlx::Result<()> {
    for (position, (key, label, category)) in DEFAULT_STATUSES.iter().enumerate() {
        sqlx::query(
            "INSERT INTO case_statuses (id, org_id, key, label, category, position, is_default)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(Uuid::now_v7())
        .bind(org_id)
        .bind(key)
        .bind(label)
        .bind(category)
        .bind(position as i32)
        .bind(position == 0)
        .execute(&mut *conn)
        .await?;
    }

    for (key, label, rank) in DEFAULT_PRIORITIES {
        sqlx::query(
            "INSERT INTO case_priorities (id, org_id, key, label, rank, is_default)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::now_v7())
        .bind(org_id)
        .bind(key)
        .bind(label)
        .bind(rank)
        .bind(*key == DEFAULT_PRIORITY_KEY)
        .execute(&mut *conn)
        .await?;
    }

    sqlx::query("INSERT INTO case_number_counters (org_id) VALUES ($1)")
        .bind(org_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}
