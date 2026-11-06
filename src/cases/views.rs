use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::Actor;
use crate::cases::records::{self, Case, CaseFilter};
use crate::identity::orgs::require_member;
use crate::platform::error::{ServiceError, ServiceResult, invalid, text};
use crate::platform::page::Page;

const FILTER_KEYS: &[&str] = &[
    "workspace_id",
    "status",
    "status_category",
    "priority",
    "team_id",
    "assignee_user_id",
    "unassigned",
    "tags",
    "requester_contact_id",
    "created_after",
    "created_before",
    "q",
    "sla_breached",
    "channel_id",
];

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SavedView {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub filter: Value,
    pub shared: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn user_of(actor: Actor) -> ServiceResult<Uuid> {
    match actor {
        Actor::User(id) => Ok(id),
        _ => Err(ServiceError::Forbidden),
    }
}

fn check_filter(filter: &Value) -> ServiceResult<CaseFilter> {
    let object = filter
        .as_object()
        .ok_or(invalid("filter", "must be an object"))?;
    if object.keys().any(|k| !FILTER_KEYS.contains(&k.as_str())) {
        return Err(invalid("filter", "contains an unknown key"));
    }
    serde_json::from_value(filter.clone()).map_err(|_| invalid("filter", "has an invalid value"))
}

pub async fn list(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
) -> ServiceResult<Vec<SavedView>> {
    require_member(conn, org_id, actor).await?;
    let user = user_of(actor)?;
    Ok(sqlx::query_as(
        "SELECT id, user_id, name, filter, shared, created_at, updated_at FROM saved_views
         WHERE org_id = $1 AND (user_id = $2 OR shared) ORDER BY name",
    )
    .bind(org_id)
    .bind(user)
    .fetch_all(conn)
    .await?)
}

pub async fn save(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    existing: Option<Uuid>,
    name: &str,
    filter: Value,
    shared: bool,
) -> ServiceResult<SavedView> {
    let name = text("name", name, 100)?;
    check_filter(&filter)?;
    let mut tx = conn.begin().await?;
    require_member(&mut tx, org_id, actor).await?;
    let user = user_of(actor)?;
    let view = match existing {
        Some(id) => sqlx::query_as(
            "UPDATE saved_views SET name = $4, filter = $5, shared = $6
             WHERE org_id = $1 AND id = $2 AND user_id = $3
             RETURNING id, user_id, name, filter, shared, created_at, updated_at",
        )
        .bind(org_id)
        .bind(id)
        .bind(user)
        .bind(&name)
        .bind(&filter)
        .bind(shared)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ServiceError::NotFound)?,
        None => sqlx::query_as(
            "INSERT INTO saved_views (id, org_id, user_id, name, filter, shared) VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, user_id, name, filter, shared, created_at, updated_at",
        )
        .bind(Uuid::now_v7())
        .bind(org_id)
        .bind(user)
        .bind(&name)
        .bind(&filter)
        .bind(shared)
        .fetch_one(&mut *tx)
        .await?,
    };
    tx.commit().await?;
    Ok(view)
}

pub async fn delete(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> ServiceResult<()> {
    let user = user_of(actor)?;
    let deleted =
        sqlx::query("DELETE FROM saved_views WHERE org_id = $1 AND id = $2 AND user_id = $3")
            .bind(org_id)
            .bind(id)
            .bind(user)
            .execute(conn)
            .await?
            .rows_affected();
    if deleted == 0 {
        return Err(ServiceError::NotFound);
    }
    Ok(())
}

pub async fn cases(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
    page: Page,
) -> ServiceResult<Vec<Case>> {
    require_member(conn, org_id, actor).await?;
    let user = user_of(actor)?;
    let filter: Value = sqlx::query_scalar(
        "SELECT filter FROM saved_views WHERE org_id = $1 AND id = $2 AND (user_id = $3 OR shared)",
    )
    .bind(org_id)
    .bind(id)
    .bind(user)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(ServiceError::NotFound)?;
    let filter = check_filter(&filter)?;
    records::list(conn, org_id, actor, &filter, page).await
}
