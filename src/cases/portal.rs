use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::Actor;
use crate::cases::contacts;
use crate::cases::messages::{MAX_BODY_CHARS, Message, message_select};
use crate::cases::records::{history, priority_id, status_id};
use crate::platform::error::{ServiceError, ServiceResult, conflict, invalid, text};
use crate::platform::events::{self, Cause};
use crate::platform::page::Page;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct PortalCase {
    pub id: Uuid,
    pub org_id: Uuid,
    pub organization: String,
    pub number: i64,
    pub subject: String,
    pub description: String,
    pub status: String,
    pub status_category: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

macro_rules! portal_select {
    () => {
        "SELECT c.id, c.org_id, o.name AS organization, c.number, c.subject, c.description,
                s.label AS status, s.category AS status_category, c.created_at, c.updated_at
         FROM cases c
         JOIN contacts ct ON ct.id = c.requester_contact_id
         JOIN case_statuses s ON s.id = c.status_id
         JOIN organizations o ON o.id = c.org_id AND o.deleted_at IS NULL
         JOIN workspaces w ON w.id = c.workspace_id AND w.deleted_at IS NULL"
    };
}

pub async fn list(
    conn: &mut PgConnection,
    user_id: Uuid,
    page: Page,
) -> ServiceResult<Vec<PortalCase>> {
    Ok(sqlx::query_as(concat!(
        portal_select!(),
        " WHERE ct.user_id = $1 AND c.deleted_at IS NULL AND ($2::uuid IS NULL OR c.id < $2)
          ORDER BY c.id DESC LIMIT $3"
    ))
    .bind(user_id)
    .bind(page.cursor)
    .bind(page.limit + 1)
    .fetch_all(conn)
    .await?)
}

async fn own_case(
    conn: &mut PgConnection,
    user_id: Uuid,
    case_id: Uuid,
    lock: bool,
) -> ServiceResult<PortalCase> {
    let sql = if lock {
        concat!(
            portal_select!(),
            " WHERE ct.user_id = $1 AND c.id = $2 AND c.deleted_at IS NULL FOR UPDATE OF c"
        )
    } else {
        concat!(
            portal_select!(),
            " WHERE ct.user_id = $1 AND c.id = $2 AND c.deleted_at IS NULL"
        )
    };
    sqlx::query_as(sql)
        .bind(user_id)
        .bind(case_id)
        .fetch_optional(conn)
        .await?
        .ok_or(ServiceError::NotFound)
}

pub async fn get(
    conn: &mut PgConnection,
    user_id: Uuid,
    case_id: Uuid,
) -> ServiceResult<(PortalCase, Vec<Message>)> {
    let case = own_case(conn, user_id, case_id, false).await?;
    let messages = sqlx::query_as(concat!(
        message_select!(),
        " WHERE m.case_id = $1 AND m.visibility = 'public' ORDER BY m.created_at, m.id"
    ))
    .bind(case_id)
    .fetch_all(conn)
    .await?;
    Ok((case, messages))
}

pub async fn reply(
    conn: &mut PgConnection,
    user_id: Uuid,
    case_id: Uuid,
    body: &str,
) -> ServiceResult<Message> {
    let body = body.trim();
    if body.is_empty() || body.chars().count() > MAX_BODY_CHARS {
        return Err(invalid("body", "must be between 1 and 100000 characters"));
    }
    let mut tx = conn.begin().await?;
    let case = own_case(&mut tx, user_id, case_id, true).await?;
    if case.status_category == "closed" {
        return Err(conflict(
            "case_closed",
            "this case is closed; please open a new one",
        ));
    }
    let contact_id: Uuid =
        sqlx::query_scalar("SELECT requester_contact_id FROM cases WHERE id = $1")
            .bind(case_id)
            .fetch_one(&mut *tx)
            .await?;
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO case_messages (id, org_id, case_id, visibility, author_kind, author_contact_id, body, body_format, source_channel)
         VALUES ($1, $2, $3, 'public', 'contact', $4, $5, 'text', 'web')",
    )
    .bind(id)
    .bind(case.org_id)
    .bind(case_id)
    .bind(contact_id)
    .bind(body)
    .execute(&mut *tx)
    .await?;
    let actor = Actor::User(user_id);
    if case.status_category == "resolved" {
        let open: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM case_statuses WHERE org_id = $1 AND category = 'open' ORDER BY position LIMIT 1",
        )
        .bind(case.org_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(open) = open {
            sqlx::query("UPDATE cases SET status_id = $2, resolved_at = NULL WHERE id = $1")
                .bind(case_id)
                .bind(open)
                .execute(&mut *tx)
                .await?;
            history(
                &mut tx,
                case.org_id,
                case_id,
                actor,
                "reopened_by_requester",
                json!({}),
            )
            .await?;
            events::emit(
                &mut tx,
                case.org_id,
                "case.status_changed",
                "case",
                case_id,
                json!({ "case_id": case_id, "from": "resolved", "to": "open" }),
                Cause::default(),
            )
            .await?;
        }
    }
    sqlx::query("UPDATE cases SET updated_at = now() WHERE id = $1")
        .bind(case_id)
        .execute(&mut *tx)
        .await?;
    history(
        &mut tx,
        case.org_id,
        case_id,
        actor,
        "message_added",
        json!({ "message_id": id, "visibility": "public" }),
    )
    .await?;
    events::emit(
        &mut tx,
        case.org_id,
        "case.message_added",
        "case",
        case_id,
        json!({ "case_id": case_id, "message_id": id, "visibility": "public", "author_kind": "contact" }),
        Cause::default(),
    )
    .await?;
    let message = sqlx::query_as(concat!(message_select!(), " WHERE m.id = $1"))
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(message)
}

pub async fn submit(
    conn: &mut PgConnection,
    user_id: Uuid,
    workspace_id: Uuid,
    subject: &str,
    description: &str,
) -> ServiceResult<PortalCase> {
    let subject = text("subject", subject, 500)?;
    if description.chars().count() > MAX_BODY_CHARS {
        return Err(invalid("description", "is too long"));
    }
    let mut tx = conn.begin().await?;
    let org_id: Uuid = sqlx::query_scalar(
        "SELECT w.org_id FROM workspaces w JOIN organizations o ON o.id = w.org_id AND o.deleted_at IS NULL
         WHERE w.id = $1 AND w.portal_enabled AND w.deleted_at IS NULL",
    )
    .bind(workspace_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ServiceError::NotFound)?;
    let (email, name, verified): (String, String, bool) = sqlx::query_as(
        "SELECT email, display_name, email_verified_at IS NOT NULL FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    if !verified {
        return Err(conflict(
            "email_not_verified",
            "verify your email address before submitting a request",
        ));
    }
    let contact_id = match sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM contacts WHERE org_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?
    {
        Some(id) => id,
        None => {
            contacts::find_or_create(
                &mut tx,
                org_id,
                &email,
                Some(&name),
                Some(user_id),
                Cause::default(),
            )
            .await?
        }
    };
    let number: i64 = sqlx::query_scalar(
        "UPDATE case_number_counters SET last_value = last_value + 1 WHERE org_id = $1 RETURNING last_value",
    )
    .bind(org_id)
    .fetch_one(&mut *tx)
    .await?;
    let status = status_id(&mut tx, org_id, None).await?;
    let priority = priority_id(&mut tx, org_id, None).await?;
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cases (id, org_id, workspace_id, number, subject, description, status_id, priority_id,
                            requester_contact_id, source_channel)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'web')",
    )
    .bind(id)
    .bind(org_id)
    .bind(workspace_id)
    .bind(number)
    .bind(&subject)
    .bind(description.trim())
    .bind(status)
    .bind(priority)
    .bind(contact_id)
    .execute(&mut *tx)
    .await?;
    history(
        &mut tx,
        org_id,
        id,
        Actor::User(user_id),
        "created",
        json!({ "number": number, "source_channel": "web" }),
    )
    .await?;
    events::emit(
        &mut tx,
        org_id,
        "case.created",
        "case",
        id,
        json!({ "case_id": id, "number": number, "workspace_id": workspace_id }),
        Cause::default(),
    )
    .await?;
    let case = own_case(&mut tx, user_id, id, false).await?;
    tx.commit().await?;
    Ok(case)
}
