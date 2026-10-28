





use std::collections::BTreeSet;

use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::{self, Actor};
use crate::platform::authz::{self, AuthzError, Permission};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub id: Uuid,
    
    pub key: String,
    pub name: String,
    pub is_builtin: bool,
    
    pub permissions: Vec<Permission>,
}

pub struct NewRole<'a> {
    pub name: &'a str,
    pub permissions: &'a [Permission],
}


#[derive(Default)]
pub struct RoleChanges<'a> {
    pub name: Option<&'a str>,
    pub permissions: Option<&'a [Permission]>,
}

#[derive(Debug, thiserror::Error)]
pub enum RoleError {
    #[error("permission denied")]
    Forbidden,
    
    #[error("you cannot grant permissions you do not have: {}", stored(.0).join(", "))]
    CannotGrant(Vec<Permission>),
    #[error("{field} {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    #[error("a role with this name already exists")]
    NameTaken,
    #[error("role not found")]
    NotFound,
    #[error("built-in roles cannot be changed or deleted")]
    BuiltIn,
    
    #[error("role is assigned to {members} member(s)")]
    InUse { members: i64 },
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

impl From<AuthzError> for RoleError {
    fn from(err: AuthzError) -> Self {
        match err {
            AuthzError::Forbidden => RoleError::Forbidden,
            AuthzError::Database(err) => RoleError::Database(err),
        }
    }
}



pub async fn list_roles(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
) -> Result<Vec<Role>, RoleError> {
    match authz::require(conn, org_id, actor, Permission::RolesManage).await {
        Err(AuthzError::Forbidden) => {
            authz::require(conn, org_id, actor, Permission::UsersManage).await?
        }
        result => result?,
    }

    let rows: Vec<(Uuid, String, String, bool, Vec<String>)> = sqlx::query_as(
        "SELECT r.id, r.key, r.name, r.is_builtin,
                coalesce(array_agg(rp.permission ORDER BY rp.permission)
                         FILTER (WHERE rp.permission IS NOT NULL), '{}')
         FROM roles r
         LEFT JOIN role_permissions rp ON rp.role_id = r.id
         WHERE r.org_id = $1
         GROUP BY r.id
         ORDER BY r.is_builtin DESC, r.name",
    )
    .bind(org_id)
    .fetch_all(&mut *conn)
    .await?;

    Ok(rows.into_iter().map(Role::from_row).collect())
}

pub async fn create_role(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    new: NewRole<'_>,
) -> Result<Role, RoleError> {
    let name = validate_name(new.name)?;
    let permissions = validate_permissions(new.permissions)?;

    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::RolesManage).await?;
    check_can_grant(&mut tx, org_id, actor, &permissions).await?;

    let id = Uuid::now_v7();
    let key = free_key(&mut tx, org_id, name, id).await?;
    insert_role(&mut tx, org_id, id, &key, name, false, &permissions)
        .await
        .map_err(map_name_conflict)?;

    audit::record(
        &mut tx,
        audit::Event {
            org_id: Some(org_id),
            actor,
            action: "role.created",
            target_type: "role",
            target_id: id,
            metadata: json!({ "name": name, "permissions": stored(&permissions) }),
        },
    )
    .await?;

    tx.commit().await?;
    Ok(Role {
        id,
        key,
        name: name.to_string(),
        is_builtin: false,
        permissions: permissions.into_iter().collect(),
    })
}

pub async fn update_role(
    conn: &mut PgConnection,
    org_id: Uuid,
    role_id: Uuid,
    actor: Actor,
    changes: RoleChanges<'_>,
) -> Result<Role, RoleError> {
    let new_name = changes.name.map(validate_name).transpose()?;
    let new_permissions = changes.permissions.map(validate_permissions).transpose()?;

    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::RolesManage).await?;
    let mut role = lock_custom_role(&mut tx, org_id, role_id).await?;

    if let Some(name) = new_name {
        sqlx::query("UPDATE roles SET name = $3 WHERE org_id = $1 AND id = $2")
            .bind(org_id)
            .bind(role_id)
            .bind(name)
            .execute(&mut *tx)
            .await
            .map_err(map_name_conflict)?;
        role.name = name.to_string();
    }

    let (mut added, mut removed) = (Vec::new(), Vec::new());
    if let Some(permissions) = new_permissions {
        let current: BTreeSet<Permission> = role.permissions.iter().copied().collect();
        added = permissions.difference(&current).copied().collect();
        removed = current.difference(&permissions).copied().collect();
        
        
        check_can_grant(&mut tx, org_id, actor, &added.iter().copied().collect()).await?;

        sqlx::query("DELETE FROM role_permissions WHERE org_id = $1 AND role_id = $2")
            .bind(org_id)
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
        insert_permissions(&mut tx, org_id, role_id, &permissions).await?;
        role.permissions = permissions.into_iter().collect();
    }

    audit::record(
        &mut tx,
        audit::Event {
            org_id: Some(org_id),
            actor,
            action: "role.updated",
            target_type: "role",
            target_id: role_id,
            metadata: json!({
                "name": new_name,
                "permissions_added": stored(&added),
                "permissions_removed": stored(&removed),
            }),
        },
    )
    .await?;

    tx.commit().await?;
    Ok(role)
}


pub async fn delete_role(
    conn: &mut PgConnection,
    org_id: Uuid,
    role_id: Uuid,
    actor: Actor,
) -> Result<(), RoleError> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::RolesManage).await?;
    let role = lock_custom_role(&mut tx, org_id, role_id).await?;

    let members: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT membership_id) FROM membership_roles WHERE org_id = $1 AND role_id = $2",
    )
    .bind(org_id)
    .bind(role_id)
    .fetch_one(&mut *tx)
    .await?;
    if members > 0 {
        return Err(RoleError::InUse { members });
    }

    sqlx::query("DELETE FROM roles WHERE org_id = $1 AND id = $2")
        .bind(org_id)
        .bind(role_id)
        .execute(&mut *tx)
        .await?;

    audit::record(
        &mut tx,
        audit::Event {
            org_id: Some(org_id),
            actor,
            action: "role.deleted",
            target_type: "role",
            target_id: role_id,
            metadata: json!({ "name": role.name, "permissions": stored(&role.permissions) }),
        },
    )
    .await?;

    tx.commit().await?;
    Ok(())
}



pub(crate) async fn insert_role(
    conn: &mut PgConnection,
    org_id: Uuid,
    id: Uuid,
    key: &str,
    name: &str,
    is_builtin: bool,
    permissions: &BTreeSet<Permission>,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO roles (id, org_id, key, name, is_builtin) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(org_id)
    .bind(key)
    .bind(name)
    .bind(is_builtin)
    .execute(&mut *conn)
    .await?;
    insert_permissions(conn, org_id, id, permissions).await
}

async fn insert_permissions(
    conn: &mut PgConnection,
    org_id: Uuid,
    role_id: Uuid,
    permissions: &BTreeSet<Permission>,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO role_permissions (org_id, role_id, permission)
         SELECT $1, $2, unnest($3::text[])",
    )
    .bind(org_id)
    .bind(role_id)
    .bind(stored(permissions))
    .execute(conn)
    .await?;
    Ok(())
}

async fn lock_custom_role(
    conn: &mut PgConnection,
    org_id: Uuid,
    role_id: Uuid,
) -> Result<Role, RoleError> {
    let row: Option<(Uuid, String, String, bool, Vec<String>)> = sqlx::query_as(
        "SELECT r.id, r.key, r.name, r.is_builtin,
                coalesce((SELECT array_agg(permission ORDER BY permission)
                          FROM role_permissions WHERE role_id = r.id), '{}')
         FROM roles r WHERE r.org_id = $1 AND r.id = $2 FOR UPDATE",
    )
    .bind(org_id)
    .bind(role_id)
    .fetch_optional(&mut *conn)
    .await?;
    let role = Role::from_row(row.ok_or(RoleError::NotFound)?);
    if role.is_builtin {
        return Err(RoleError::BuiltIn);
    }
    Ok(role)
}

async fn check_can_grant(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    permissions: &BTreeSet<Permission>,
) -> Result<(), RoleError> {
    let missing =
        authz::missing_permissions(conn, org_id, None, actor, permissions.iter().copied()).await?;
    if missing.is_empty() {
        Ok(())
    } else {
        Err(RoleError::CannotGrant(missing))
    }
}



async fn free_key(
    conn: &mut PgConnection,
    org_id: Uuid,
    name: &str,
    id: Uuid,
) -> sqlx::Result<String> {
    let base = key_from_name(name);
    let taken: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM roles WHERE org_id = $1 AND key = $2)")
            .bind(org_id)
            .bind(&base)
            .fetch_one(conn)
            .await?;
    if !taken {
        return Ok(base);
    }
    let suffix = id.simple().to_string();
    Ok(format!("{base}_{}", &suffix[suffix.len() - 8..]))
}



fn key_from_name(name: &str) -> String {
    let mut key = String::new();
    for c in name.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            key.push(c);
        } else if !key.is_empty() && !key.ends_with('_') {
            key.push('_');
        }
    }
    let key = key.trim_end_matches('_');
    match key.chars().next() {
        Some(c) if c.is_ascii_lowercase() => key.chars().take(60).collect(),
        Some(_) => format!("role_{}", key.chars().take(55).collect::<String>()),
        None => "role".to_string(),
    }
}

fn validate_name(name: &str) -> Result<&str, RoleError> {
    let name = name.trim();
    let len = name.chars().count();
    if len == 0 || len > 100 {
        return Err(RoleError::Invalid {
            field: "name",
            reason: "must be between 1 and 100 characters",
        });
    }
    Ok(name)
}

fn validate_permissions(permissions: &[Permission]) -> Result<BTreeSet<Permission>, RoleError> {
    if permissions.is_empty() {
        return Err(RoleError::Invalid {
            field: "permissions",
            reason: "must include at least one permission",
        });
    }
    Ok(permissions.iter().copied().collect())
}

fn map_name_conflict(err: sqlx::Error) -> RoleError {
    match err.as_database_error().and_then(|e| e.constraint()) {
        Some("roles_name_key") => RoleError::NameTaken,
        _ => err.into(),
    }
}

fn stored<'a>(permissions: impl IntoIterator<Item = &'a Permission>) -> Vec<&'static str> {
    permissions.into_iter().map(|p| p.as_str()).collect()
}

impl Role {
    fn from_row(
        (id, key, name, is_builtin, permissions): (Uuid, String, String, bool, Vec<String>),
    ) -> Self {
        Role {
            id,
            key,
            name,
            is_builtin,
            permissions: permissions
                .iter()
                .filter_map(|p| p.parse().ok())
                .collect::<BTreeSet<Permission>>()
                .into_iter()
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::key_from_name;

    #[test]
    fn keys_derived_from_names_satisfy_the_database_rule() {
        assert_eq!(key_from_name("Billing Admins"), "billing_admins");
        assert_eq!(
            key_from_name("  Tier-2 / Escalations "),
            "tier_2_escalations"
        );
        assert_eq!(key_from_name("2nd line"), "role_2nd_line");
        assert_eq!(key_from_name("Équipe"), "quipe");
        assert_eq!(key_from_name("日本"), "role");
        assert!(key_from_name(&"x".repeat(500)).len() <= 63);
    }
}
