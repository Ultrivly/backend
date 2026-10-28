use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::{self, Actor};
use crate::identity::validate_slug_value;
use crate::platform::authz::{self, Permission};
use crate::platform::error::{ServiceError, ServiceResult, conflict, text, unique_violation};

pub async fn is_member(conn: &mut PgConnection, org_id: Uuid, actor: Actor) -> sqlx::Result<bool> {
    match actor {
        Actor::System => Ok(true),
        Actor::ApiCredential { org_id: own, .. } | Actor::Workflow { org_id: own, .. } => {
            Ok(own == org_id)
        }
        Actor::User(user_id) => {
            sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM memberships m
                            JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
                            WHERE m.org_id = $1 AND m.user_id = $2 AND m.status = 'active')",
            )
            .bind(org_id)
            .bind(user_id)
            .fetch_one(conn)
            .await
        }
    }
}

pub async fn require_member(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
) -> ServiceResult<()> {
    if is_member(conn, org_id, actor).await? {
        Ok(())
    } else {
        Err(ServiceError::NotFound)
    }
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub require_mfa: bool,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub purge_after: Option<DateTime<Utc>>,
}

macro_rules! org_columns {
    () => {
        "id, name, slug, require_mfa, created_at, deleted_at, purge_after"
    };
}

pub async fn get(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
) -> ServiceResult<Organization> {
    require_member(conn, org_id, actor).await?;
    fetch(conn, org_id).await
}

async fn fetch(conn: &mut PgConnection, org_id: Uuid) -> ServiceResult<Organization> {
    sqlx::query_as(concat!(
        "SELECT ",
        org_columns!(),
        " FROM organizations WHERE id = $1"
    ))
    .bind(org_id)
    .fetch_optional(conn)
    .await?
    .ok_or(ServiceError::NotFound)
}

#[derive(Default)]
pub struct OrgChanges<'a> {
    pub name: Option<&'a str>,
    pub require_mfa: Option<bool>,
}

pub async fn update(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    changes: OrgChanges<'_>,
) -> ServiceResult<Organization> {
    let mut tx = conn.begin().await?;
    if let Some(name) = changes.name {
        authz::require(&mut tx, org_id, actor, Permission::OrganizationManage).await?;
        let name = text("name", name, 200)?;
        sqlx::query("UPDATE organizations SET name = $2 WHERE id = $1")
            .bind(org_id)
            .bind(name)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(require_mfa) = changes.require_mfa {
        authz::require(&mut tx, org_id, actor, Permission::SecurityManage).await?;
        sqlx::query("UPDATE organizations SET require_mfa = $2 WHERE id = $1")
            .bind(org_id)
            .bind(require_mfa)
            .execute(&mut *tx)
            .await?;
    }
    record(
        &mut tx,
        org_id,
        actor,
        "organization.updated",
        "organization",
        org_id,
        json!({ "name": changes.name, "require_mfa": changes.require_mfa }),
    )
    .await?;
    let org = fetch(&mut tx, org_id).await?;
    tx.commit().await?;
    Ok(org)
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct Workspace {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub portal_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub purge_after: Option<DateTime<Utc>>,
}

macro_rules! workspace_columns {
    () => {
        "id, name, slug, portal_enabled, created_at, deleted_at, purge_after"
    };
}

pub async fn list_workspaces(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
) -> ServiceResult<Vec<Workspace>> {
    require_member(conn, org_id, actor).await?;
    let include_deleted =
        authz::missing_permissions(conn, org_id, None, actor, [Permission::WorkspacesManage])
            .await?
            .is_empty();
    Ok(sqlx::query_as(concat!(
        "SELECT ",
        workspace_columns!(),
        " FROM workspaces
         WHERE org_id = $1 AND (deleted_at IS NULL OR $2) ORDER BY name"
    ))
    .bind(org_id)
    .bind(include_deleted)
    .fetch_all(conn)
    .await?)
}

pub async fn get_workspace(
    conn: &mut PgConnection,
    org_id: Uuid,
    workspace_id: Uuid,
) -> ServiceResult<Workspace> {
    sqlx::query_as(concat!(
        "SELECT ",
        workspace_columns!(),
        " FROM workspaces WHERE org_id = $1 AND id = $2"
    ))
    .bind(org_id)
    .bind(workspace_id)
    .fetch_optional(conn)
    .await?
    .ok_or(ServiceError::NotFound)
}

pub async fn create_workspace(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    name: &str,
    slug: &str,
) -> ServiceResult<Workspace> {
    let name = text("name", name, 200)?;
    validate_slug_value("slug", slug)?;
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::WorkspacesManage).await?;
    let id = Uuid::now_v7();
    let workspace: Workspace = sqlx::query_as(concat!(
        "INSERT INTO workspaces (id, org_id, name, slug) VALUES ($1, $2, $3, $4)
         RETURNING ",
        workspace_columns!()
    ))
    .bind(id)
    .bind(org_id)
    .bind(&name)
    .bind(slug)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| {
        if unique_violation(&err, "workspaces_org_id_slug_key") {
            conflict("slug_taken", "a workspace with this slug already exists")
        } else {
            err.into()
        }
    })?;
    record(
        &mut tx,
        org_id,
        actor,
        "workspace.created",
        "workspace",
        id,
        json!({ "name": name, "slug": slug }),
    )
    .await?;
    tx.commit().await?;
    Ok(workspace)
}

#[derive(Default)]
pub struct WorkspaceChanges<'a> {
    pub name: Option<&'a str>,
    pub portal_enabled: Option<bool>,
}

pub async fn update_workspace(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    workspace_id: Uuid,
    changes: WorkspaceChanges<'_>,
) -> ServiceResult<Workspace> {
    let name = changes.name.map(|n| text("name", n, 200)).transpose()?;
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::WorkspacesManage).await?;
    let workspace: Workspace = sqlx::query_as(concat!("UPDATE workspaces SET name = coalesce($3, name), portal_enabled = coalesce($4, portal_enabled)
         WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL
         RETURNING ", workspace_columns!()))
    .bind(org_id)
    .bind(workspace_id)
    .bind(&name)
    .bind(changes.portal_enabled)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ServiceError::NotFound)?;
    record(
        &mut tx,
        org_id,
        actor,
        "workspace.updated",
        "workspace",
        workspace_id,
        json!({ "name": name, "portal_enabled": changes.portal_enabled }),
    )
    .await?;
    tx.commit().await?;
    Ok(workspace)
}

pub(crate) async fn record(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    action: &str,
    target_type: &str,
    target_id: Uuid,
    metadata: serde_json::Value,
) -> sqlx::Result<()> {
    audit::record(
        conn,
        audit::Event {
            org_id: Some(org_id),
            actor,
            action,
            target_type,
            target_id,
            metadata,
        },
    )
    .await
}
