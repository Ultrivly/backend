use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::Actor;
use crate::cases::records::{self, history};
use crate::platform::authz::{self, Permission};
use crate::platform::error::{ServiceResult, invalid};
use crate::platform::events::{self, Cause};

pub const MAX_BODY_CHARS: usize = 100_000;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Message {
    pub id: Uuid,
    pub visibility: String,
    pub author_kind: String,
    pub author_user_id: Option<Uuid>,
    pub author_contact_id: Option<Uuid>,
    pub author_name: Option<String>,
    pub body: String,
    pub body_format: String,
    pub source_channel: String,
    pub created_at: DateTime<Utc>,
    pub attachment_ids: Vec<Uuid>,
}

macro_rules! message_select {
    () => {
        "SELECT m.id, m.visibility, m.author_kind, m.author_user_id, m.author_contact_id,
                coalesce(u.display_name, ct.display_name) AS author_name,
                m.body, m.body_format, m.source_channel, m.created_at,
                coalesce((SELECT array_agg(a.id ORDER BY a.created_at) FROM attachments a
                          WHERE a.message_id = m.id AND a.deleted_at IS NULL), '{}') AS attachment_ids
         FROM case_messages m
         LEFT JOIN users u ON u.id = m.author_user_id
         LEFT JOIN contacts ct ON ct.id = m.author_contact_id"
    };
}
pub(crate) use message_select;

pub(crate) async fn can_see_internal(
    conn: &mut PgConnection,
    org_id: Uuid,
    workspace_id: Uuid,
    actor: Actor,
) -> sqlx::Result<bool> {
    Ok(authz::missing_permissions(
        conn,
        org_id,
        Some(workspace_id),
        actor,
        [Permission::CasesViewInternalNotes],
    )
    .await?
    .is_empty())
}

pub async fn list(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    case_id: Uuid,
) -> ServiceResult<Vec<Message>> {
    let case = records::get(conn, org_id, actor, case_id).await?;
    let internal = can_see_internal(conn, org_id, case.workspace_id, actor).await?;
    Ok(sqlx::query_as(concat!(
        message_select!(),
        " WHERE m.org_id = $1 AND m.case_id = $2 AND (m.visibility = 'public' OR $3)
          ORDER BY m.created_at, m.id"
    ))
    .bind(org_id)
    .bind(case_id)
    .bind(internal)
    .fetch_all(conn)
    .await?)
}

pub async fn add(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    case_id: Uuid,
    visibility: &str,
    body: &str,
    body_format: Option<&str>,
    cause: Cause,
) -> ServiceResult<Message> {
    if !matches!(visibility, "public" | "internal") {
        return Err(invalid("visibility", "must be public or internal"));
    }
    let format = body_format.unwrap_or("markdown");
    if !matches!(format, "text" | "markdown") {
        return Err(invalid("body_format", "must be text or markdown"));
    }
    let body = body.trim();
    if body.is_empty() || body.chars().count() > MAX_BODY_CHARS {
        return Err(invalid("body", "must be between 1 and 100000 characters"));
    }

    let mut tx = conn.begin().await?;
    let case = records::load(&mut tx, org_id, case_id, true).await?;
    records::readable(&mut tx, org_id, actor, &case).await?;
    let ws = Some(case.workspace_id);
    if visibility == "internal" {
        authz::require_in(
            &mut tx,
            org_id,
            ws,
            actor,
            Permission::CasesViewInternalNotes,
        )
        .await?;
    } else {
        authz::require_in(&mut tx, org_id, ws, actor, Permission::CasesEdit).await?;
    }
    let (author_kind, author_user_id) = match actor {
        Actor::User(id) => ("user", Some(id)),
        Actor::Workflow { .. } => ("workflow", None),
        Actor::ApiCredential { .. } | Actor::System => ("system", None),
    };
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO case_messages (id, org_id, case_id, visibility, author_kind, author_user_id, body, body_format, source_channel)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'api')",
    )
    .bind(id)
    .bind(org_id)
    .bind(case_id)
    .bind(visibility)
    .bind(author_kind)
    .bind(author_user_id)
    .bind(body)
    .bind(format)
    .execute(&mut *tx)
    .await?;
    if visibility == "public" && author_kind == "user" {
        sqlx::query(
            "UPDATE cases SET first_response_at = coalesce(first_response_at, now()) WHERE id = $1",
        )
        .bind(case_id)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("UPDATE cases SET updated_at = now() WHERE id = $1")
        .bind(case_id)
        .execute(&mut *tx)
        .await?;
    history(
        &mut tx,
        org_id,
        case_id,
        actor,
        "message_added",
        json!({ "message_id": id, "visibility": visibility }),
    )
    .await?;
    events::emit(
        &mut tx,
        org_id,
        "case.message_added",
        "case",
        case_id,
        json!({ "case_id": case_id, "message_id": id, "visibility": visibility, "author_kind": author_kind }),
        cause,
    )
    .await?;
    let message = sqlx::query_as(concat!(message_select!(), " WHERE m.id = $1"))
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(message)
}
