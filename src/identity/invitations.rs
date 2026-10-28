







use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::{self, Actor};
use crate::identity::accounts::normalize_email;
use crate::identity::sessions::Session;
use crate::platform::authz::{self, AuthzError, Permission};
use crate::platform::secrets::{random_token, token_hash};

pub const INVITATION_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Debug, thiserror::Error)]
pub enum InvitationError {
    #[error("permission denied")]
    Forbidden,
    #[error("you cannot invite someone with permissions you do not have: {}",
        .0.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(", "))]
    CannotGrant(Vec<Permission>),
    #[error("invalid email address")]
    InvalidEmail,
    #[error("role not found")]
    RoleNotFound,
    #[error("workspace not found")]
    WorkspaceNotFound,
    #[error("this person is already a member")]
    AlreadyMember,
    #[error("invitation not found")]
    NotFound,
    
    #[error("this invitation is invalid or has expired")]
    InvalidToken,
    #[error("this invitation is for a different email address; sign in with that address")]
    WrongAccount,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

impl From<AuthzError> for InvitationError {
    fn from(err: AuthzError) -> Self {
        match err {
            AuthzError::Forbidden => InvitationError::Forbidden,
            AuthzError::Database(err) => InvitationError::Database(err),
        }
    }
}

pub struct NewInvitation<'a> {
    pub email: &'a str,
    pub role_id: Uuid,
    pub workspace_id: Option<Uuid>,
}

#[derive(Debug)]
pub struct CreatedInvitation {
    pub id: Uuid,
    
    pub token: String,
    pub email: String,
    pub org_name: String,
    pub inviter_name: String,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct InvitationSummary {
    pub id: Uuid,
    pub email: String,
    pub role_id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}


pub async fn create(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    new: NewInvitation<'_>,
) -> Result<CreatedInvitation, InvitationError> {
    let email = normalize_email(new.email).map_err(|_| InvitationError::InvalidEmail)?;
    let mut tx = conn.begin().await?;
    authz::require_in(
        &mut tx,
        org_id,
        new.workspace_id,
        actor,
        Permission::UsersManage,
    )
    .await?;

    let permissions: Vec<String> = sqlx::query_scalar(
        "SELECT coalesce((SELECT array_agg(permission) FROM role_permissions WHERE role_id = r.id), '{}')
         FROM roles r WHERE r.org_id = $1 AND r.id = $2",
    )
    .bind(org_id)
    .bind(new.role_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(InvitationError::RoleNotFound)?;
    if let Some(workspace_id) = new.workspace_id {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM workspaces WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL)",
        )
        .bind(org_id)
        .bind(workspace_id)
        .fetch_one(&mut *tx)
        .await?;
        if !exists {
            return Err(InvitationError::WorkspaceNotFound);
        }
    }
    let missing = authz::missing_permissions(
        &mut tx,
        org_id,
        new.workspace_id,
        actor,
        permissions.iter().filter_map(|p| p.parse().ok()),
    )
    .await?;
    if !missing.is_empty() {
        return Err(InvitationError::CannotGrant(missing));
    }

    let already_member: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
                        WHERE m.org_id = $1 AND lower(u.email) = lower($2))",
    )
    .bind(org_id)
    .bind(email)
    .fetch_one(&mut *tx)
    .await?;
    if already_member {
        return Err(InvitationError::AlreadyMember);
    }

    sqlx::query(
        "UPDATE invitations SET revoked_at = now()
         WHERE org_id = $1 AND lower(email) = lower($2) AND accepted_at IS NULL AND revoked_at IS NULL",
    )
    .bind(org_id)
    .bind(email)
    .execute(&mut *tx)
    .await?;

    let id = Uuid::now_v7();
    let token = random_token();
    let invited_by = match actor {
        Actor::User(user_id) => Some(user_id),
        _ => None,
    };
    sqlx::query(
        "INSERT INTO invitations (id, org_id, email, role_id, workspace_id, token_hash, invited_by, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8))",
    )
    .bind(id)
    .bind(org_id)
    .bind(email)
    .bind(new.role_id)
    .bind(new.workspace_id)
    .bind(token_hash(&token))
    .bind(invited_by)
    .bind(INVITATION_TTL.as_secs_f64())
    .execute(&mut *tx)
    .await?;

    let (org_name, inviter_name): (String, Option<String>) = sqlx::query_as(
        "SELECT o.name, (SELECT display_name FROM users WHERE id = $2)
         FROM organizations o WHERE o.id = $1",
    )
    .bind(org_id)
    .bind(invited_by)
    .fetch_one(&mut *tx)
    .await?;

    record(
        &mut tx,
        org_id,
        actor,
        "invitation.created",
        id,
        json!({ "email": email, "role_id": new.role_id, "workspace_id": new.workspace_id }),
    )
    .await?;
    tx.commit().await?;
    Ok(CreatedInvitation {
        id,
        token,
        email: email.to_string(),
        org_name,
        inviter_name: inviter_name.unwrap_or_else(|| "An administrator".into()),
    })
}

pub async fn list_open(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
) -> Result<Vec<InvitationSummary>, InvitationError> {
    authz::require(conn, org_id, actor, Permission::UsersManage).await?;
    Ok(sqlx::query_as(
        "SELECT id, email, role_id, workspace_id, created_at, expires_at FROM invitations
         WHERE org_id = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()
         ORDER BY created_at DESC",
    )
    .bind(org_id)
    .fetch_all(conn)
    .await?)
}

pub async fn revoke(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    invitation_id: Uuid,
) -> Result<(), InvitationError> {
    let mut tx = conn.begin().await?;
    let workspace_id: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT workspace_id FROM invitations
         WHERE org_id = $1 AND id = $2 AND accepted_at IS NULL AND revoked_at IS NULL FOR UPDATE",
    )
    .bind(org_id)
    .bind(invitation_id)
    .fetch_optional(&mut *tx)
    .await?;
    let workspace_id = workspace_id.ok_or(InvitationError::NotFound)?;
    authz::require_in(
        &mut tx,
        org_id,
        workspace_id,
        actor,
        Permission::UsersManage,
    )
    .await?;

    sqlx::query("UPDATE invitations SET revoked_at = now() WHERE id = $1")
        .bind(invitation_id)
        .execute(&mut *tx)
        .await?;
    record(
        &mut tx,
        org_id,
        actor,
        "invitation.revoked",
        invitation_id,
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn accept(
    conn: &mut PgConnection,
    session: &Session,
    token: &str,
) -> Result<Uuid, InvitationError> {
    let mut tx = conn.begin().await?;
    let invitation: Option<(Uuid, Uuid, String, Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT i.id, i.org_id, i.email, i.role_id, i.workspace_id FROM invitations i
         JOIN organizations o ON o.id = i.org_id AND o.deleted_at IS NULL
         WHERE i.token_hash = $1 AND i.accepted_at IS NULL AND i.revoked_at IS NULL
           AND i.expires_at > now()
         FOR UPDATE OF i",
    )
    .bind(token_hash(token))
    .fetch_optional(&mut *tx)
    .await?;
    let (invitation_id, org_id, invited_email, role_id, workspace_id) =
        invitation.ok_or(InvitationError::InvalidToken)?;

    let user_email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(session.user_id)
        .fetch_one(&mut *tx)
        .await?;
    if !user_email.eq_ignore_ascii_case(&invited_email) {
        return Err(InvitationError::WrongAccount);
    }
    sqlx::query(
        "UPDATE users SET email_verified_at = coalesce(email_verified_at, now()) WHERE id = $1",
    )
    .bind(session.user_id)
    .execute(&mut *tx)
    .await?;

    let membership_id: Uuid = sqlx::query_scalar(
        "INSERT INTO memberships (id, org_id, user_id, status) VALUES ($1, $2, $3, 'active')
         ON CONFLICT (org_id, user_id) DO UPDATE SET updated_at = now()
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(org_id)
    .bind(session.user_id)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO membership_roles (org_id, membership_id, role_id, workspace_id)
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(org_id)
    .bind(membership_id)
    .bind(role_id)
    .bind(workspace_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE invitations SET accepted_at = now(), accepted_by = $2 WHERE id = $1")
        .bind(invitation_id)
        .bind(session.user_id)
        .execute(&mut *tx)
        .await?;

    record(
        &mut tx,
        org_id,
        Actor::User(session.user_id),
        "invitation.accepted",
        invitation_id,
        json!({ "membership_id": membership_id }),
    )
    .await?;
    tx.commit().await?;
    Ok(org_id)
}

async fn record(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    action: &str,
    invitation_id: Uuid,
    metadata: serde_json::Value,
) -> sqlx::Result<()> {
    audit::record(
        conn,
        audit::Event {
            org_id: Some(org_id),
            actor,
            action,
            target_type: "invitation",
            target_id: invitation_id,
            metadata,
        },
    )
    .await
}
