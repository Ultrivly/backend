

use sqlx::PgPool;
use ultrivly::audit::Actor;
use ultrivly::identity::roles::{self, NewRole, RoleChanges, RoleError};
use ultrivly::platform::authz::{self, Permission};

mod common;
use common::{create_org, create_workspace, member_with_role, role_id};

#[sqlx::test]
async fn admin_creates_lists_updates_and_deletes_a_custom_role(pool: PgPool) {
    let (org, owner) = create_org(&pool, "acme").await;
    let admin = Actor::User(owner);
    let mut conn = pool.acquire().await.unwrap();

    let role = roles::create_role(
        &mut conn,
        org.org_id,
        admin,
        NewRole {
            name: "  Billing Admins ",
            permissions: &[
                Permission::ReportsView,
                Permission::CasesRead,
                Permission::ReportsView,
            ],
        },
    )
    .await
    .unwrap();
    assert_eq!(role.name, "Billing Admins");
    assert_eq!(role.key, "billing_admins");
    assert!(!role.is_builtin);
    assert_eq!(
        role.permissions,
        [Permission::CasesRead, Permission::ReportsView]
    );

    let listed = roles::list_roles(&mut conn, org.org_id, admin)
        .await
        .unwrap();
    assert_eq!(listed.len(), 7);
    assert!(
        listed[..6].iter().all(|r| r.is_builtin),
        "built-in roles come first"
    );
    assert_eq!(listed[6], role);

    let updated = roles::update_role(
        &mut conn,
        org.org_id,
        role.id,
        admin,
        RoleChanges {
            name: Some("Finance"),
            permissions: Some(&[Permission::ReportsView, Permission::DataExport]),
        },
    )
    .await
    .unwrap();
    assert_eq!(updated.name, "Finance");
    assert_eq!(
        updated.key, "billing_admins",
        "keys stay stable across renames"
    );
    assert_eq!(
        updated.permissions,
        [Permission::ReportsView, Permission::DataExport]
    );

    
    let member = member_with_role(&pool, org.org_id, role.id, None).await;
    let held = authz::effective_permissions(&mut conn, org.org_id, member, None)
        .await
        .unwrap();
    assert_eq!(
        held,
        [Permission::ReportsView, Permission::DataExport].into()
    );

    let err = roles::delete_role(&mut conn, org.org_id, role.id, admin)
        .await
        .unwrap_err();
    assert!(matches!(err, RoleError::InUse { members: 1 }), "{err}");

    sqlx::query("DELETE FROM membership_roles WHERE role_id = $1")
        .bind(role.id)
        .execute(&pool)
        .await
        .unwrap();
    roles::delete_role(&mut conn, org.org_id, role.id, admin)
        .await
        .unwrap();

    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE target_id = $1 ORDER BY occurred_at, id",
    )
    .bind(role.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(actions, ["role.created", "role.updated", "role.deleted"]);
}

#[sqlx::test]
async fn managing_roles_requires_roles_manage(pool: PgPool) {
    let (org, _) = create_org(&pool, "acme").await;
    let agent_role = role_id(&pool, org.org_id, "agent").await;
    let agent = Actor::User(member_with_role(&pool, org.org_id, agent_role, None).await);
    let mut conn = pool.acquire().await.unwrap();

    let new = NewRole {
        name: "Sneaky",
        permissions: &[Permission::CasesRead],
    };
    let err = roles::create_role(&mut conn, org.org_id, agent, new)
        .await
        .unwrap_err();
    assert!(matches!(err, RoleError::Forbidden), "{err}");

    let err = roles::list_roles(&mut conn, org.org_id, agent)
        .await
        .unwrap_err();
    assert!(matches!(err, RoleError::Forbidden), "{err}");
}

#[sqlx::test]
async fn nobody_can_grant_permissions_they_do_not_hold(pool: PgPool) {
    let (org, owner) = create_org(&pool, "acme").await;
    let mut conn = pool.acquire().await.unwrap();

    
    let manager_role = roles::create_role(
        &mut conn,
        org.org_id,
        Actor::User(owner),
        NewRole {
            name: "Role manager",
            permissions: &[Permission::RolesManage, Permission::ReportsView],
        },
    )
    .await
    .unwrap();
    let manager = Actor::User(member_with_role(&pool, org.org_id, manager_role.id, None).await);

    let err = roles::create_role(
        &mut conn,
        org.org_id,
        manager,
        NewRole {
            name: "Exporters",
            permissions: &[
                Permission::ReportsView,
                Permission::DataExport,
                Permission::AuditView,
            ],
        },
    )
    .await
    .unwrap_err();
    match err {
        RoleError::CannotGrant(missing) => {
            assert_eq!(missing, [Permission::DataExport, Permission::AuditView])
        }
        other => panic!("unexpected error: {other}"),
    }

    
    let viewers = roles::create_role(
        &mut conn,
        org.org_id,
        manager,
        NewRole {
            name: "Viewers",
            permissions: &[Permission::ReportsView],
        },
    )
    .await
    .unwrap();
    let err = roles::update_role(
        &mut conn,
        org.org_id,
        viewers.id,
        manager,
        RoleChanges {
            permissions: Some(&[Permission::ReportsView, Permission::DataExport]),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, RoleError::CannotGrant(_)), "{err}");
}

#[sqlx::test]
async fn built_in_roles_cannot_be_changed_or_deleted(pool: PgPool) {
    let (org, owner) = create_org(&pool, "acme").await;
    let admin_role = role_id(&pool, org.org_id, "admin").await;
    let mut conn = pool.acquire().await.unwrap();

    let err = roles::update_role(
        &mut conn,
        org.org_id,
        admin_role,
        Actor::User(owner),
        RoleChanges {
            name: Some("Superuser"),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, RoleError::BuiltIn), "{err}");

    let err = roles::delete_role(&mut conn, org.org_id, admin_role, Actor::User(owner))
        .await
        .unwrap_err();
    assert!(matches!(err, RoleError::BuiltIn), "{err}");
}

#[sqlx::test]
async fn names_are_unique_per_org_ignoring_case(pool: PgPool) {
    let (acme, acme_owner) = create_org(&pool, "acme").await;
    let (globex, globex_owner) = create_org(&pool, "globex").await;
    let mut conn = pool.acquire().await.unwrap();
    let new = || NewRole {
        name: "Escalations",
        permissions: &[Permission::CasesRead],
    };

    
    let err = roles::create_role(
        &mut conn,
        acme.org_id,
        Actor::User(acme_owner),
        NewRole {
            name: "AGENT",
            permissions: &[Permission::CasesRead],
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, RoleError::NameTaken), "{err}");

    let first = roles::create_role(&mut conn, acme.org_id, Actor::User(acme_owner), new())
        .await
        .unwrap();
    
    roles::create_role(&mut conn, globex.org_id, Actor::User(globex_owner), new())
        .await
        .unwrap();

    
    roles::update_role(
        &mut conn,
        acme.org_id,
        first.id,
        Actor::User(acme_owner),
        RoleChanges {
            name: Some("Tier 3"),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let second = roles::create_role(&mut conn, acme.org_id, Actor::User(acme_owner), new())
        .await
        .unwrap();
    assert_ne!(second.key, first.key);
    assert!(second.key.starts_with("escalations_"), "{}", second.key);
}

#[sqlx::test]
async fn roles_of_another_org_are_not_found(pool: PgPool) {
    let (acme, acme_owner) = create_org(&pool, "acme").await;
    let (globex, globex_owner) = create_org(&pool, "globex").await;
    let mut conn = pool.acquire().await.unwrap();

    let globex_role = roles::create_role(
        &mut conn,
        globex.org_id,
        Actor::User(globex_owner),
        NewRole {
            name: "Globex team",
            permissions: &[Permission::CasesRead],
        },
    )
    .await
    .unwrap();

    let err = roles::delete_role(
        &mut conn,
        acme.org_id,
        globex_role.id,
        Actor::User(acme_owner),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, RoleError::NotFound), "{err}");

    
    let held = authz::effective_permissions(&mut conn, globex.org_id, acme_owner, None)
        .await
        .unwrap();
    assert!(held.is_empty());
}

#[sqlx::test]
async fn workspace_roles_apply_only_in_their_workspace(pool: PgPool) {
    let (org, owner) = create_org(&pool, "acme").await;
    let other_workspace = create_workspace(&pool, org.org_id, "it").await;
    let agent_role = role_id(&pool, org.org_id, "agent").await;
    let agent = member_with_role(&pool, org.org_id, agent_role, Some(org.workspace_id)).await;
    let mut conn = pool.acquire().await.unwrap();

    let in_workspace =
        authz::effective_permissions(&mut conn, org.org_id, agent, Some(org.workspace_id))
            .await
            .unwrap();
    assert!(in_workspace.contains(&Permission::CasesRead));

    for scope in [Some(other_workspace), None] {
        let held = authz::effective_permissions(&mut conn, org.org_id, agent, scope)
            .await
            .unwrap();
        assert!(held.is_empty(), "{scope:?}");
    }

    
    sqlx::query("UPDATE memberships SET status = 'suspended' WHERE user_id = $1")
        .bind(owner)
        .execute(&pool)
        .await
        .unwrap();
    let err = authz::require(
        &mut conn,
        org.org_id,
        Actor::User(owner),
        Permission::CasesRead,
    )
    .await;
    assert!(matches!(err, Err(authz::AuthzError::Forbidden)));
}
