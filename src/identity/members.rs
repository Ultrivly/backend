






use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::{self, Actor};
use crate::platform::authz::{self, ADMIN_ROLE_KEY, AuthzError, Permission};


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleAssignment {
    pub membership_id: Uuid,
    pub role_id: Uuid,
    pub workspace_id: Option<Uuid>,
}

#[derive(Debug, thiserror::Error)]
pub enum MemberError {
    #[error("permission denied")]
    Forbidden,
    
    #[error("you cannot assign or remove a role with permissions you do not have: {}",
        .0.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(", "))]
    CannotGrant(Vec<Permission>),
    #[error("member not found")]
    MemberNotFound,
    #[error("role not found")]
    RoleNotFound,
    #[error("workspace not found")]
    WorkspaceNotFound,
    #[error("the member already has this role")]
    AlreadyAssigned,
    #[error("the member does not have this role")]
    NotAssigned,
    #[error("the organization must keep at least one active Administrator")]
    LastAdministrator,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

impl From<AuthzError> for MemberError {
    fn from(err: AuthzError) -> Self {
        match err {
            AuthzError::Forbidden => MemberError::Forbidden,
            AuthzError::Database(err) => MemberError::Database(err),
        }
    }
}

pub async fn assign_role(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    assignment: RoleAssignment,
) -> Result<(), MemberError> {
    let mut tx = conn.begin().await?;
    let role = authorize(&mut tx, org_id, actor, assignment).await?;

    sqlx::query(
        "INSERT INTO membership_roles (org_id, membership_id, role_id, workspace_id)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(org_id)
    .bind(assignment.membership_id)
    .bind(assignment.role_id)
    .bind(assignment.workspace_id)
    .execute(&mut *tx)
    .await
    .map_err(
        |err| match err.as_database_error().and_then(|e| e.constraint()) {
            Some("membership_roles_membership_id_role_id_workspace_id_key") => {
                MemberError::AlreadyAssigned
            }
            _ => err.into(),
        },
    )?;

    record(
        &mut tx,
        org_id,
        actor,
        "membership.role_assigned",
        assignment,
        &role,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn remove_role(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    assignment: RoleAssignment,
) -> Result<(), MemberError> {
    let mut tx = conn.begin().await?;
    let role = authorize(&mut tx, org_id, actor, assignment).await?;

    if role.key == ADMIN_ROLE_KEY && assignment.workspace_id.is_none() {
        
        
        sqlx::query(
            "SELECT 1 FROM membership_roles
             WHERE org_id = $1 AND role_id = $2 AND workspace_id IS NULL FOR UPDATE",
        )
        .bind(org_id)
        .bind(assignment.role_id)
        .execute(&mut *tx)
        .await?;
        let other_admins: i64 = sqlx::query_scalar(
            "SELECT count(*)
             FROM membership_roles mr
             JOIN memberships m ON m.id = mr.membership_id AND m.status = 'active'
             JOIN users u ON u.id = m.user_id AND u.disabled_at IS NULL
             WHERE mr.org_id = $1 AND mr.role_id = $2 AND mr.workspace_id IS NULL
               AND mr.membership_id <> $3",
        )
        .bind(org_id)
        .bind(assignment.role_id)
        .bind(assignment.membership_id)
        .fetch_one(&mut *tx)
        .await?;
        if other_admins == 0 {
            return Err(MemberError::LastAdministrator);
        }
    }

    let removed = sqlx::query(
        "DELETE FROM membership_roles
         WHERE org_id = $1 AND membership_id = $2 AND role_id = $3
           AND workspace_id IS NOT DISTINCT FROM $4",
    )
    .bind(org_id)
    .bind(assignment.membership_id)
    .bind(assignment.role_id)
    .bind(assignment.workspace_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if removed == 0 {
        return Err(MemberError::NotAssigned);
    }

    record(
        &mut tx,
        org_id,
        actor,
        "membership.role_removed",
        assignment,
        &role,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

struct RoleInfo {
    key: String,
    name: String,
}




async fn authorize(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    assignment: RoleAssignment,
) -> Result<RoleInfo, MemberError> {
    authz::require_in(
        conn,
        org_id,
        assignment.workspace_id,
        actor,
        Permission::UsersManage,
    )
    .await?;

    let member_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM memberships WHERE org_id = $1 AND id = $2)",
    )
    .bind(org_id)
    .bind(assignment.membership_id)
    .fetch_one(&mut *conn)
    .await?;
    if !member_exists {
        return Err(MemberError::MemberNotFound);
    }

    if let Some(workspace_id) = assignment.workspace_id {
        let workspace_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM workspaces
                            WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL)",
        )
        .bind(org_id)
        .bind(workspace_id)
        .fetch_one(&mut *conn)
        .await?;
        if !workspace_exists {
            return Err(MemberError::WorkspaceNotFound);
        }
    }

    let (key, name, permissions): (String, String, Vec<String>) = sqlx::query_as(
        "SELECT r.key, r.name,
                coalesce((SELECT array_agg(permission) FROM role_permissions WHERE role_id = r.id), '{}')
         FROM roles r WHERE r.org_id = $1 AND r.id = $2",
    )
    .bind(org_id)
    .bind(assignment.role_id)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(MemberError::RoleNotFound)?;

    let permissions = permissions.iter().filter_map(|p| p.parse().ok());
    let missing =
        authz::missing_permissions(conn, org_id, assignment.workspace_id, actor, permissions)
            .await?;
    if !missing.is_empty() {
        return Err(MemberError::CannotGrant(missing));
    }

    Ok(RoleInfo { key, name })
}

async fn record(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    action: &str,
    assignment: RoleAssignment,
    role: &RoleInfo,
) -> sqlx::Result<()> {
    audit::record(
        conn,
        audit::Event {
            org_id: Some(org_id),
            actor,
            action,
            target_type: "membership",
            target_id: assignment.membership_id,
            metadata: json!({
                "role_id": assignment.role_id,
                "role_name": role.name,
                "workspace_id": assignment.workspace_id,
            }),
        },
    )
    .await
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Member {
    pub membership_id: Uuid,
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub roles: Vec<MemberRole>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemberRole {
    pub role_id: Uuid,
    pub role_name: String,
    pub workspace_id: Option<Uuid>,
}

pub async fn list(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
) -> crate::platform::error::ServiceResult<Vec<Member>> {
    crate::identity::orgs::require_member(conn, org_id, actor).await?;
    type Row = (
        Uuid,
        Uuid,
        String,
        String,
        String,
        chrono::DateTime<chrono::Utc>,
        serde_json::Value,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT m.id, u.id, u.email, u.display_name, m.status, m.created_at,
                coalesce(jsonb_agg(jsonb_build_object('role_id', r.id, 'role_name', r.name,
                                                      'workspace_id', mr.workspace_id))
                         FILTER (WHERE r.id IS NOT NULL), '[]')
         FROM memberships m
         JOIN users u ON u.id = m.user_id
         LEFT JOIN membership_roles mr ON mr.membership_id = m.id
         LEFT JOIN roles r ON r.id = mr.role_id
         WHERE m.org_id = $1
         GROUP BY m.id, u.id
         ORDER BY u.display_name",
    )
    .bind(org_id)
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(membership_id, user_id, email, display_name, status, created_at, roles)| Member {
                membership_id,
                user_id,
                email,
                display_name,
                status,
                created_at,
                roles: serde_json::from_value(roles).unwrap_or_default(),
            },
        )
        .collect())
}

pub async fn set_status(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    membership_id: Uuid,
    status: &str,
) -> crate::platform::error::ServiceResult<()> {
    use crate::platform::error::invalid;
    if !matches!(status, "active" | "suspended") {
        return Err(invalid("status", "must be active or suspended"));
    }
    let mut tx = conn.begin().await?;
    authorize_over(&mut tx, org_id, actor, membership_id).await?;
    if status == "suspended" && is_last_admin(&mut tx, org_id, membership_id).await? {
        return Err(MemberError::LastAdministrator.into_service());
    }
    sqlx::query("UPDATE memberships SET status = $3 WHERE org_id = $1 AND id = $2")
        .bind(org_id)
        .bind(membership_id)
        .bind(status)
        .execute(&mut *tx)
        .await?;
    crate::identity::orgs::record(
        &mut tx,
        org_id,
        actor,
        "membership.status_changed",
        "membership",
        membership_id,
        json!({ "status": status }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn remove(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    membership_id: Uuid,
) -> crate::platform::error::ServiceResult<()> {
    let mut tx = conn.begin().await?;
    authorize_over(&mut tx, org_id, actor, membership_id).await?;
    if is_last_admin(&mut tx, org_id, membership_id).await? {
        return Err(MemberError::LastAdministrator.into_service());
    }
    sqlx::query("DELETE FROM memberships WHERE org_id = $1 AND id = $2")
        .bind(org_id)
        .bind(membership_id)
        .execute(&mut *tx)
        .await?;
    crate::identity::orgs::record(
        &mut tx,
        org_id,
        actor,
        "membership.removed",
        "membership",
        membership_id,
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn authorize_over(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    membership_id: Uuid,
) -> crate::platform::error::ServiceResult<()> {
    use crate::platform::error::ServiceError;
    authz::require(conn, org_id, actor, Permission::UsersManage).await?;
    let held: Option<Vec<String>> = sqlx::query_scalar(
        "SELECT coalesce(array_agg(DISTINCT rp.permission) FILTER (WHERE rp.permission IS NOT NULL), '{}')
         FROM memberships m
         LEFT JOIN membership_roles mr ON mr.membership_id = m.id
         LEFT JOIN role_permissions rp ON rp.role_id = mr.role_id
         WHERE m.org_id = $1 AND m.id = $2
         GROUP BY m.id",
    )
    .bind(org_id)
    .bind(membership_id)
    .fetch_optional(&mut *conn)
    .await?;
    let held = held.ok_or(ServiceError::NotFound)?;
    let missing = authz::missing_permissions(
        conn,
        org_id,
        None,
        actor,
        held.iter().filter_map(|p| p.parse().ok()),
    )
    .await?;
    if missing.is_empty() {
        Ok(())
    } else {
        Err(ServiceError::CannotGrant(missing))
    }
}

async fn is_last_admin(
    conn: &mut PgConnection,
    org_id: Uuid,
    membership_id: Uuid,
) -> sqlx::Result<bool> {
    sqlx::query(
        "SELECT 1 FROM membership_roles mr JOIN roles r ON r.id = mr.role_id
         WHERE mr.org_id = $1 AND r.key = $2 AND r.is_builtin AND mr.workspace_id IS NULL FOR UPDATE OF mr",
    )
    .bind(org_id)
    .bind(ADMIN_ROLE_KEY)
    .execute(&mut *conn)
    .await?;
    let (is_admin, others): (bool, i64) = sqlx::query_as(
        "SELECT
            EXISTS (SELECT 1 FROM membership_roles mr JOIN roles r ON r.id = mr.role_id
                    WHERE mr.membership_id = $2 AND r.key = $3 AND r.is_builtin AND mr.workspace_id IS NULL),
            (SELECT count(*) FROM membership_roles mr
             JOIN roles r ON r.id = mr.role_id AND r.key = $3 AND r.is_builtin
             JOIN memberships m ON m.id = mr.membership_id AND m.status = 'active'
             JOIN users u ON u.id = m.user_id AND u.disabled_at IS NULL
             WHERE mr.org_id = $1 AND mr.workspace_id IS NULL AND mr.membership_id <> $2)",
    )
    .bind(org_id)
    .bind(membership_id)
    .bind(ADMIN_ROLE_KEY)
    .fetch_one(conn)
    .await?;
    Ok(is_admin && others == 0)
}

impl MemberError {
    fn into_service(self) -> crate::platform::error::ServiceError {
        crate::platform::error::conflict(
            "last_administrator",
            "the organization must keep at least one active Administrator",
        )
    }
}
