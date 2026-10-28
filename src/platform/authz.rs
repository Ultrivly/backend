






use std::collections::HashSet;
use std::str::FromStr;

use sqlx::PgConnection;
use uuid::Uuid;

use crate::audit::Actor;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Permission {
    CasesRead,
    CasesCreate,
    CasesEdit,
    CasesAssign,
    CasesMerge,
    CasesResolve,
    CasesDelete,
    CasesViewInternalNotes,
    UsersManage,
    TeamsManage,
    WorkspacesManage,
    RolesManage,
    KnowledgeReadPrivate,
    KnowledgeEdit,
    KnowledgePublish,
    KnowledgeDelete,
    WorkflowsManage,
    WorkflowsPublish,
    IntegrationsManage,
    ApiCredentialsManage,
    WebhooksManage,
    PluginsManage,
    ReportsView,
    DataExport,
    AuditView,
    SecurityManage,
    OrganizationDelete,
    OrganizationManage,
}

impl Permission {
    pub const ALL: &[Permission] = &[
        Permission::CasesRead,
        Permission::CasesCreate,
        Permission::CasesEdit,
        Permission::CasesAssign,
        Permission::CasesMerge,
        Permission::CasesResolve,
        Permission::CasesDelete,
        Permission::CasesViewInternalNotes,
        Permission::UsersManage,
        Permission::TeamsManage,
        Permission::WorkspacesManage,
        Permission::RolesManage,
        Permission::KnowledgeReadPrivate,
        Permission::KnowledgeEdit,
        Permission::KnowledgePublish,
        Permission::KnowledgeDelete,
        Permission::WorkflowsManage,
        Permission::WorkflowsPublish,
        Permission::IntegrationsManage,
        Permission::ApiCredentialsManage,
        Permission::WebhooksManage,
        Permission::PluginsManage,
        Permission::ReportsView,
        Permission::DataExport,
        Permission::AuditView,
        Permission::SecurityManage,
        Permission::OrganizationDelete,
        Permission::OrganizationManage,
    ];

    
    pub fn as_str(self) -> &'static str {
        match self {
            Permission::CasesRead => "cases.read",
            Permission::CasesCreate => "cases.create",
            Permission::CasesEdit => "cases.edit",
            Permission::CasesAssign => "cases.assign",
            Permission::CasesMerge => "cases.merge",
            Permission::CasesResolve => "cases.resolve",
            Permission::CasesDelete => "cases.delete",
            Permission::CasesViewInternalNotes => "cases.view_internal_notes",
            Permission::UsersManage => "users.manage",
            Permission::TeamsManage => "teams.manage",
            Permission::WorkspacesManage => "workspaces.manage",
            Permission::RolesManage => "roles.manage",
            Permission::KnowledgeReadPrivate => "knowledge.read_private",
            Permission::KnowledgeEdit => "knowledge.edit",
            Permission::KnowledgePublish => "knowledge.publish",
            Permission::KnowledgeDelete => "knowledge.delete",
            Permission::WorkflowsManage => "workflows.manage",
            Permission::WorkflowsPublish => "workflows.publish",
            Permission::IntegrationsManage => "integrations.manage",
            Permission::ApiCredentialsManage => "api_credentials.manage",
            Permission::WebhooksManage => "webhooks.manage",
            Permission::PluginsManage => "plugins.manage",
            Permission::ReportsView => "reports.view",
            Permission::DataExport => "data.export",
            Permission::AuditView => "audit.view",
            Permission::SecurityManage => "security.manage",
            Permission::OrganizationDelete => "organization.delete",
            Permission::OrganizationManage => "organization.manage",
        }
    }
}

impl FromStr for Permission {
    type Err = UnknownPermission;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Permission::ALL
            .iter()
            .copied()
            .find(|p| p.as_str() == s)
            .ok_or_else(|| UnknownPermission(s.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown permission {0:?}")]
pub struct UnknownPermission(pub String);



pub struct BuiltinRole {
    pub key: &'static str,
    pub name: &'static str,
    pub permissions: &'static [Permission],
}

pub const ADMIN_ROLE_KEY: &str = "admin";



pub const BUILTIN_ROLES: &[BuiltinRole] = &[
    BuiltinRole {
        key: ADMIN_ROLE_KEY,
        name: "Administrator",
        permissions: Permission::ALL,
    },
    BuiltinRole {
        key: "team_lead",
        name: "Team lead",
        permissions: &[
            Permission::CasesRead,
            Permission::CasesCreate,
            Permission::CasesEdit,
            Permission::CasesAssign,
            Permission::CasesMerge,
            Permission::CasesResolve,
            Permission::CasesViewInternalNotes,
            Permission::KnowledgeReadPrivate,
            Permission::ReportsView,
        ],
    },
    BuiltinRole {
        key: "agent",
        name: "Agent",
        permissions: &[
            Permission::CasesRead,
            Permission::CasesCreate,
            Permission::CasesEdit,
            Permission::CasesAssign,
            Permission::CasesResolve,
            Permission::CasesViewInternalNotes,
            Permission::KnowledgeReadPrivate,
        ],
    },
    BuiltinRole {
        key: "knowledge_editor",
        name: "Knowledge editor",
        permissions: &[
            Permission::KnowledgeReadPrivate,
            Permission::KnowledgeEdit,
            Permission::KnowledgePublish,
            Permission::KnowledgeDelete,
        ],
    },
    BuiltinRole {
        key: "developer",
        name: "Developer",
        permissions: &[
            Permission::IntegrationsManage,
            Permission::ApiCredentialsManage,
            Permission::WebhooksManage,
            Permission::PluginsManage,
        ],
    },
    BuiltinRole {
        key: "auditor",
        name: "Auditor",
        permissions: &[Permission::AuditView, Permission::ReportsView],
    },
];




pub async fn effective_permissions(
    conn: &mut PgConnection,
    org_id: Uuid,
    user_id: Uuid,
    workspace_id: Option<Uuid>,
) -> sqlx::Result<HashSet<Permission>> {
    permissions(conn, org_id, user_id, workspace_id, false).await
}

async fn permissions(
    conn: &mut PgConnection,
    org_id: Uuid,
    user_id: Uuid,
    workspace_id: Option<Uuid>,
    include_deleted_org: bool,
) -> sqlx::Result<HashSet<Permission>> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT rp.permission
         FROM memberships m
         JOIN users u ON u.id = m.user_id AND u.disabled_at IS NULL
         JOIN organizations o ON o.id = m.org_id AND (o.deleted_at IS NULL OR $4)
         JOIN membership_roles mr ON mr.membership_id = m.id
             AND (mr.workspace_id IS NULL OR mr.workspace_id = $3)
         JOIN role_permissions rp ON rp.role_id = mr.role_id
         WHERE m.org_id = $1 AND m.user_id = $2 AND m.status = 'active'",
    )
    .bind(org_id)
    .bind(user_id)
    .bind(workspace_id)
    .bind(include_deleted_org)
    .fetch_all(conn)
    .await?;
    
    Ok(names.iter().filter_map(|n| n.parse().ok()).collect())
}

#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    #[error("permission denied")]
    Forbidden,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}



pub async fn require(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    permission: Permission,
) -> Result<(), AuthzError> {
    require_in(conn, org_id, None, actor, permission).await
}



pub async fn require_in(
    conn: &mut PgConnection,
    org_id: Uuid,
    workspace_id: Option<Uuid>,
    actor: Actor,
    permission: Permission,
) -> Result<(), AuthzError> {
    if missing_permissions(conn, org_id, workspace_id, actor, [permission])
        .await?
        .is_empty()
    {
        Ok(())
    } else {
        Err(AuthzError::Forbidden)
    }
}




pub async fn require_ignoring_org_deletion(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    permission: Permission,
) -> Result<(), AuthzError> {
    let user_id = match actor {
        Actor::System => return Ok(()),
        Actor::User(user_id) => user_id,
        _ => return Err(AuthzError::Forbidden),
    };
    if permissions(conn, org_id, user_id, None, true)
        .await?
        .contains(&permission)
    {
        Ok(())
    } else {
        Err(AuthzError::Forbidden)
    }
}



pub async fn missing_permissions(
    conn: &mut PgConnection,
    org_id: Uuid,
    workspace_id: Option<Uuid>,
    actor: Actor,
    wanted: impl IntoIterator<Item = Permission>,
) -> sqlx::Result<Vec<Permission>> {
    let Some(held) = actor_permissions(conn, org_id, workspace_id, actor).await? else {
        return Ok(Vec::new());
    };
    let mut missing: Vec<Permission> = wanted.into_iter().filter(|p| !held.contains(p)).collect();
    missing.sort();
    missing.dedup();
    Ok(missing)
}



pub async fn actor_permissions(
    conn: &mut PgConnection,
    org_id: Uuid,
    workspace_id: Option<Uuid>,
    actor: Actor,
) -> sqlx::Result<Option<HashSet<Permission>>> {
    match actor {
        Actor::System => Ok(None),
        Actor::Workflow { org_id: own, .. } if own == org_id => Ok(None),
        Actor::Workflow { .. } => Ok(Some(HashSet::new())),
        Actor::User(user_id) => effective_permissions(conn, org_id, user_id, workspace_id)
            .await
            .map(Some),
        Actor::ApiCredential { id, org_id: own } => {
            if own != org_id {
                return Ok(Some(HashSet::new()));
            }
            let names: Option<Vec<String>> = sqlx::query_scalar(
                "SELECT c.permissions FROM api_credentials c
                 JOIN organizations o ON o.id = c.org_id AND o.deleted_at IS NULL
                 WHERE c.id = $1 AND c.org_id = $2 AND c.revoked_at IS NULL
                   AND (c.expires_at IS NULL OR c.expires_at > now())",
            )
            .bind(id)
            .bind(org_id)
            .fetch_optional(conn)
            .await?;
            Ok(Some(
                names
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|n| n.parse().ok())
                    .collect(),
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceScope {
    All,
    Only(Vec<Uuid>),
}

impl WorkspaceScope {
    pub fn allows(&self, workspace_id: Uuid) -> bool {
        match self {
            WorkspaceScope::All => true,
            WorkspaceScope::Only(ids) => ids.contains(&workspace_id),
        }
    }

    pub fn ids(&self) -> Option<&[Uuid]> {
        match self {
            WorkspaceScope::All => None,
            WorkspaceScope::Only(ids) => Some(ids),
        }
    }
}



pub async fn workspaces_with(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    permission: Permission,
) -> sqlx::Result<WorkspaceScope> {
    match actor_permissions(conn, org_id, None, actor).await? {
        None => return Ok(WorkspaceScope::All),
        Some(held) if held.contains(&permission) => return Ok(WorkspaceScope::All),
        Some(_) => {}
    }
    let Actor::User(user_id) = actor else {
        return Ok(WorkspaceScope::Only(Vec::new()));
    };
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT mr.workspace_id
         FROM memberships m
         JOIN users u ON u.id = m.user_id AND u.disabled_at IS NULL
         JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
         JOIN membership_roles mr ON mr.membership_id = m.id AND mr.workspace_id IS NOT NULL
         JOIN role_permissions rp ON rp.role_id = mr.role_id AND rp.permission = $3
         WHERE m.org_id = $1 AND m.user_id = $2 AND m.status = 'active'",
    )
    .bind(org_id)
    .bind(user_id)
    .bind(permission.as_str())
    .fetch_all(conn)
    .await?;
    Ok(WorkspaceScope::Only(ids))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn permission_names_are_unique_and_match_the_database_check() {
        let mut seen = HashSet::new();
        for p in Permission::ALL {
            let name = p.as_str();
            assert!(seen.insert(name), "duplicate permission {name}");
            
            let (area, action) = name.split_once('.').expect("missing '.'");
            let valid =
                |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c == '_');
            assert!(valid(area) && valid(action), "invalid permission {name}");
        }
    }

    #[test]
    fn permissions_round_trip_through_their_stored_names() {
        for p in Permission::ALL {
            assert_eq!(p.as_str().parse::<Permission>(), Ok(*p));
        }
        assert!("cases.fly".parse::<Permission>().is_err());
    }

    #[test]
    fn builtin_roles_have_unique_keys_and_no_duplicate_permissions() {
        let mut keys = HashSet::new();
        for role in BUILTIN_ROLES {
            assert!(keys.insert(role.key), "duplicate role {}", role.key);
            let unique: HashSet<_> = role.permissions.iter().collect();
            assert_eq!(
                unique.len(),
                role.permissions.len(),
                "{} repeats a permission",
                role.key
            );
        }
        assert!(keys.contains(ADMIN_ROLE_KEY));
    }
}
