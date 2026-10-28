

use sqlx::PgPool;
use ultrivly::audit::Actor;
use ultrivly::identity::members::{self, MemberError, RoleAssignment};
use ultrivly::identity::roles::{self, NewRole};
use ultrivly::platform::authz::{self, Permission};
use uuid::Uuid;

mod common;
use common::{add_member, create_org, create_workspace, member_with_role, membership_id, role_id};

#[sqlx::test]
async fn admin_assigns_and_removes_a_role(pool: PgPool) {
    let (org, owner) = create_org(&pool, "acme").await;
    let admin = Actor::User(owner);
    let (user, membership) = add_member(&pool, org.org_id).await;
    let agent_role = role_id(&pool, org.org_id, "agent").await;
    let mut conn = pool.acquire().await.unwrap();
    let assignment = RoleAssignment {
        membership_id: membership,
        role_id: agent_role,
        workspace_id: None,
    };

    members::assign_role(&mut conn, org.org_id, admin, assignment)
        .await
        .unwrap();
    let held = authz::effective_permissions(&mut conn, org.org_id, user, None)
        .await
        .unwrap();
    assert!(held.contains(&Permission::CasesRead));

    let err = members::assign_role(&mut conn, org.org_id, admin, assignment)
        .await
        .unwrap_err();
    assert!(matches!(err, MemberError::AlreadyAssigned), "{err}");

    members::remove_role(&mut conn, org.org_id, admin, assignment)
        .await
        .unwrap();
    let held = authz::effective_permissions(&mut conn, org.org_id, user, None)
        .await
        .unwrap();
    assert!(held.is_empty());

    let err = members::remove_role(&mut conn, org.org_id, admin, assignment)
        .await
        .unwrap_err();
    assert!(matches!(err, MemberError::NotAssigned), "{err}");

    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE target_id = $1 ORDER BY occurred_at, id",
    )
    .bind(membership)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        actions,
        ["membership.role_assigned", "membership.role_removed"]
    );
}

#[sqlx::test]
async fn assigning_requires_users_manage(pool: PgPool) {
    let (org, _) = create_org(&pool, "acme").await;
    let agent_role = role_id(&pool, org.org_id, "agent").await;
    let agent = Actor::User(member_with_role(&pool, org.org_id, agent_role, None).await);
    let (_, newcomer) = add_member(&pool, org.org_id).await;
    let mut conn = pool.acquire().await.unwrap();

    let err = members::assign_role(
        &mut conn,
        org.org_id,
        agent,
        RoleAssignment {
            membership_id: newcomer,
            role_id: agent_role,
            workspace_id: None,
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, MemberError::Forbidden), "{err}");
}

#[sqlx::test]
async fn managers_cannot_hand_out_or_take_away_more_than_they_have(pool: PgPool) {
    let (org, owner) = create_org(&pool, "acme").await;
    let admin_role = role_id(&pool, org.org_id, "admin").await;
    let agent_role = role_id(&pool, org.org_id, "agent").await;
    let mut conn = pool.acquire().await.unwrap();

    
    let managers = roles::create_role(
        &mut conn,
        org.org_id,
        Actor::User(owner),
        NewRole {
            name: "People managers",
            permissions: &[Permission::UsersManage],
        },
    )
    .await
    .unwrap();
    let manager_user = member_with_role(&pool, org.org_id, managers.id, None).await;
    common::grant(
        &pool,
        org.org_id,
        membership_id(&pool, org.org_id, manager_user).await,
        agent_role,
        None,
    )
    .await;
    let manager = Actor::User(manager_user);
    let (_, newcomer) = add_member(&pool, org.org_id).await;

    
    members::assign_role(
        &mut conn,
        org.org_id,
        manager,
        RoleAssignment {
            membership_id: newcomer,
            role_id: agent_role,
            workspace_id: None,
        },
    )
    .await
    .unwrap();

    
    let err = members::assign_role(
        &mut conn,
        org.org_id,
        manager,
        RoleAssignment {
            membership_id: newcomer,
            role_id: admin_role,
            workspace_id: None,
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, MemberError::CannotGrant(missing) if missing.contains(&Permission::OrganizationDelete)),
        "{err}"
    );

    
    let err = members::remove_role(
        &mut conn,
        org.org_id,
        manager,
        RoleAssignment {
            membership_id: org.owner_membership_id,
            role_id: admin_role,
            workspace_id: None,
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err, MemberError::CannotGrant(_)), "{err}");
}

#[sqlx::test]
async fn the_last_administrator_keeps_the_role(pool: PgPool) {
    let (org, owner) = create_org(&pool, "acme").await;
    let admin_role = role_id(&pool, org.org_id, "admin").await;
    let mut conn = pool.acquire().await.unwrap();
    let owner_admin = RoleAssignment {
        membership_id: org.owner_membership_id,
        role_id: admin_role,
        workspace_id: None,
    };

    let err = members::remove_role(&mut conn, org.org_id, Actor::User(owner), owner_admin)
        .await
        .unwrap_err();
    assert!(matches!(err, MemberError::LastAdministrator), "{err}");

    
    let (second, second_membership) = add_member(&pool, org.org_id).await;
    members::assign_role(
        &mut conn,
        org.org_id,
        Actor::User(owner),
        RoleAssignment {
            membership_id: second_membership,
            role_id: admin_role,
            workspace_id: None,
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE memberships SET status = 'suspended' WHERE id = $1")
        .bind(second_membership)
        .execute(&pool)
        .await
        .unwrap();
    let err = members::remove_role(&mut conn, org.org_id, Actor::User(owner), owner_admin)
        .await
        .unwrap_err();
    assert!(matches!(err, MemberError::LastAdministrator), "{err}");

    
    sqlx::query("UPDATE memberships SET status = 'active' WHERE id = $1")
        .bind(second_membership)
        .execute(&pool)
        .await
        .unwrap();
    members::remove_role(&mut conn, org.org_id, Actor::User(second), owner_admin)
        .await
        .unwrap();
}

#[sqlx::test]
async fn workspace_managers_assign_only_in_their_workspace(pool: PgPool) {
    let (org, owner) = create_org(&pool, "acme").await;
    let agent_role = role_id(&pool, org.org_id, "agent").await;
    let it = create_workspace(&pool, org.org_id, "it").await;
    let mut conn = pool.acquire().await.unwrap();

    let leads = roles::create_role(
        &mut conn,
        org.org_id,
        Actor::User(owner),
        NewRole {
            name: "Workspace leads",
            permissions: &[
                Permission::UsersManage,
                Permission::CasesRead,
                Permission::CasesCreate,
                Permission::CasesEdit,
                Permission::CasesAssign,
                Permission::CasesResolve,
                Permission::CasesViewInternalNotes,
                Permission::KnowledgeReadPrivate,
            ],
        },
    )
    .await
    .unwrap();
    let lead =
        Actor::User(member_with_role(&pool, org.org_id, leads.id, Some(org.workspace_id)).await);
    let (newcomer_user, newcomer) = add_member(&pool, org.org_id).await;
    let assign = |workspace_id| RoleAssignment {
        membership_id: newcomer,
        role_id: agent_role,
        workspace_id,
    };

    members::assign_role(&mut conn, org.org_id, lead, assign(Some(org.workspace_id)))
        .await
        .unwrap();
    let held =
        authz::effective_permissions(&mut conn, org.org_id, newcomer_user, Some(org.workspace_id))
            .await
            .unwrap();
    assert!(held.contains(&Permission::CasesRead));

    for scope in [Some(it), None] {
        let err = members::assign_role(&mut conn, org.org_id, lead, assign(scope))
            .await
            .unwrap_err();
        assert!(matches!(err, MemberError::Forbidden), "{scope:?}: {err}");
    }
}

type IsExpected = fn(&MemberError) -> bool;

#[sqlx::test]
async fn members_roles_and_workspaces_of_other_orgs_are_not_found(pool: PgPool) {
    let (acme, acme_owner) = create_org(&pool, "acme").await;
    let (globex, _) = create_org(&pool, "globex").await;
    let admin = Actor::User(acme_owner);
    let acme_agent = role_id(&pool, acme.org_id, "agent").await;
    let globex_agent = role_id(&pool, globex.org_id, "agent").await;
    let (_, acme_member) = add_member(&pool, acme.org_id).await;
    let (_, globex_member) = add_member(&pool, globex.org_id).await;
    let mut conn = pool.acquire().await.unwrap();

    let cases: [(RoleAssignment, IsExpected); 3] = [
        (
            RoleAssignment {
                membership_id: globex_member,
                role_id: acme_agent,
                workspace_id: None,
            },
            |e| matches!(e, MemberError::MemberNotFound),
        ),
        (
            RoleAssignment {
                membership_id: acme_member,
                role_id: globex_agent,
                workspace_id: None,
            },
            |e| matches!(e, MemberError::RoleNotFound),
        ),
        (
            RoleAssignment {
                membership_id: acme_member,
                role_id: acme_agent,
                workspace_id: Some(globex.workspace_id),
            },
            |e| matches!(e, MemberError::WorkspaceNotFound),
        ),
    ];
    for (assignment, expected) in cases {
        let err = members::assign_role(&mut conn, acme.org_id, admin, assignment)
            .await
            .unwrap_err();
        assert!(expected(&err), "{assignment:?}: {err}");
    }

    let unknown = RoleAssignment {
        membership_id: Uuid::now_v7(),
        role_id: acme_agent,
        workspace_id: None,
    };
    let err = members::assign_role(&mut conn, acme.org_id, admin, unknown)
        .await
        .unwrap_err();
    assert!(matches!(err, MemberError::MemberNotFound), "{err}");
}
