use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::Actor;
use crate::identity::accounts::normalize_email;
use crate::identity::orgs::require_member;
use crate::platform::authz::{self, Permission, WorkspaceScope};
use crate::platform::error::{
    ServiceError, ServiceResult, conflict, invalid, text, unique_violation,
};
use crate::platform::events::{self, Cause};
use crate::platform::page::Page;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Contact {
    pub id: Uuid,
    pub email: Option<String>,
    pub display_name: String,
    pub user_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

async fn require_any(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    permission: Permission,
) -> ServiceResult<()> {
    require_member(conn, org_id, actor).await?;
    if authz::workspaces_with(conn, org_id, actor, permission).await?
        == WorkspaceScope::Only(Vec::new())
    {
        return Err(ServiceError::Forbidden);
    }
    Ok(())
}

pub async fn list(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    q: Option<&str>,
    page: Page,
) -> ServiceResult<Vec<Contact>> {
    require_any(conn, org_id, actor, Permission::CasesRead).await?;
    let q = q.map(str::trim).filter(|q| !q.is_empty());
    Ok(sqlx::query_as(
        "SELECT id, email, display_name, user_id, created_at, updated_at FROM contacts
         WHERE org_id = $1
           AND ($2::text IS NULL OR email ILIKE '%' || $2 || '%' OR display_name ILIKE '%' || $2 || '%')
           AND ($3::uuid IS NULL OR id < $3)
         ORDER BY id DESC LIMIT $4",
    )
    .bind(org_id)
    .bind(q.map(|q| q.replace(['%', '_', '\\'], "")))
    .bind(page.cursor)
    .bind(page.limit + 1)
    .fetch_all(conn)
    .await?)
}

pub async fn get(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> ServiceResult<Contact> {
    require_any(conn, org_id, actor, Permission::CasesRead).await?;
    load(conn, org_id, id).await
}

pub(crate) async fn load(
    conn: &mut PgConnection,
    org_id: Uuid,
    id: Uuid,
) -> ServiceResult<Contact> {
    sqlx::query_as(
        "SELECT id, email, display_name, user_id, created_at, updated_at FROM contacts WHERE org_id = $1 AND id = $2",
    )
    .bind(org_id)
    .bind(id)
    .fetch_optional(conn)
    .await?
    .ok_or(ServiceError::NotFound)
}

pub async fn create(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    email: Option<&str>,
    display_name: &str,
) -> ServiceResult<Contact> {
    let name = text("display_name", display_name, 200)?;
    let email = email
        .map(|e| normalize_email(e).map_err(|_| invalid("email", "is not a valid email address")))
        .transpose()?;
    let mut tx = conn.begin().await?;
    require_any(&mut tx, org_id, actor, Permission::CasesCreate).await?;
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO contacts (id, org_id, email, display_name) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(org_id)
        .bind(email)
        .bind(&name)
        .execute(&mut *tx)
        .await
        .map_err(|err| {
            if unique_violation(&err, "contacts_email_key") {
                conflict("email_taken", "a contact with this email already exists")
            } else {
                err.into()
            }
        })?;
    events::emit(
        &mut tx,
        org_id,
        "contact.created",
        "contact",
        id,
        json!({ "contact_id": id }),
        Cause::default(),
    )
    .await?;
    let contact = load(&mut tx, org_id, id).await?;
    tx.commit().await?;
    Ok(contact)
}

pub async fn update(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
    email: Option<&str>,
    display_name: Option<&str>,
) -> ServiceResult<Contact> {
    let name = display_name
        .map(|n| text("display_name", n, 200))
        .transpose()?;
    let email = email
        .map(|e| normalize_email(e).map_err(|_| invalid("email", "is not a valid email address")))
        .transpose()?;
    let mut tx = conn.begin().await?;
    require_any(&mut tx, org_id, actor, Permission::CasesEdit).await?;
    let linked: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT user_id FROM contacts WHERE org_id = $1 AND id = $2 FOR UPDATE")
            .bind(org_id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    if linked.ok_or(ServiceError::NotFound)?.is_some() && email.is_some() {
        return Err(invalid(
            "email",
            "cannot change for a contact linked to a user account",
        ));
    }
    sqlx::query(
        "UPDATE contacts SET email = coalesce($3, email), display_name = coalesce($4, display_name)
         WHERE org_id = $1 AND id = $2",
    )
    .bind(org_id)
    .bind(id)
    .bind(email)
    .bind(&name)
    .execute(&mut *tx)
    .await
    .map_err(|err| {
        if unique_violation(&err, "contacts_email_key") {
            conflict("email_taken", "a contact with this email already exists")
        } else {
            err.into()
        }
    })?;
    let contact = load(&mut tx, org_id, id).await?;
    tx.commit().await?;
    Ok(contact)
}

pub(crate) async fn find_or_create(
    conn: &mut PgConnection,
    org_id: Uuid,
    email: &str,
    name: Option<&str>,
    user_id: Option<Uuid>,
    cause: Cause,
) -> ServiceResult<Uuid> {
    let email =
        normalize_email(email).map_err(|_| invalid("requester", "has an invalid email address"))?;
    if let Some(id) = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM contacts WHERE org_id = $1 AND lower(email) = lower($2)",
    )
    .bind(org_id)
    .bind(email)
    .fetch_optional(&mut *conn)
    .await?
    {
        if let Some(user_id) = user_id {
            sqlx::query("UPDATE contacts SET user_id = $3 WHERE org_id = $1 AND id = $2 AND user_id IS NULL")
                .bind(org_id)
                .bind(id)
                .bind(user_id)
                .execute(&mut *conn)
                .await?;
        }
        return Ok(id);
    }
    let display_name = name
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .unwrap_or(email)
        .chars()
        .take(200)
        .collect::<String>();
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO contacts (id, org_id, email, display_name, user_id) VALUES ($1, $2, $3, $4, $5)")
        .bind(id)
        .bind(org_id)
        .bind(email)
        .bind(display_name)
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
    events::emit(
        conn,
        org_id,
        "contact.created",
        "contact",
        id,
        json!({ "contact_id": id }),
        cause,
    )
    .await?;
    Ok(id)
}
