

use sqlx::PgPool;
use ultrivly::identity::{self, CreateOrganizationError, NewOrganization};
use ultrivly::platform::authz::Permission;
use uuid::Uuid;

async fn create_user(pool: &PgPool, email: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO users (id, email, display_name) VALUES ($1, $2, 'Sam')")
        .bind(id)
        .bind(email)
        .execute(pool)
        .await
        .unwrap();
    id
}

fn acme(owner_user_id: Uuid) -> NewOrganization<'static> {
    NewOrganization {
        name: "Acme",
        slug: "acme",
        workspace_name: "Customer Support",
        workspace_slug: "support",
        owner_user_id,
    }
}

async fn count(pool: &PgPool, sql: &'static str, id: Uuid) -> i64 {
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn creates_a_ready_to_use_organization(pool: PgPool) {
    let owner = create_user(&pool, "sam@acme.test").await;
    let mut conn = pool.acquire().await.unwrap();
    let org = identity::create_organization(&mut conn, acme(owner))
        .await
        .unwrap();

    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM workspaces WHERE org_id = $1",
            org.org_id
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM roles WHERE org_id = $1 AND is_builtin",
            org.org_id
        )
        .await,
        6
    );

    
    let owner_permissions: Vec<String> = sqlx::query_scalar(
        "SELECT rp.permission
         FROM memberships m
         JOIN membership_roles mr ON mr.membership_id = m.id AND mr.workspace_id IS NULL
         JOIN role_permissions rp ON rp.role_id = mr.role_id
         WHERE m.id = $1 AND m.status = 'active'
         ORDER BY 1",
    )
    .bind(org.owner_membership_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    let mut expected: Vec<&str> = Permission::ALL.iter().map(|p| p.as_str()).collect();
    expected.sort();
    assert_eq!(owner_permissions, expected);

    
    let default_status: (i64, String) = sqlx::query_as(
        "SELECT count(*) OVER (), key FROM case_statuses WHERE org_id = $1 ORDER BY is_default DESC LIMIT 1",
    )
    .bind(org.org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(default_status, (5, "new".to_string()));
    let default_priority: (i64, String) = sqlx::query_as(
        "SELECT count(*) OVER (), key FROM case_priorities WHERE org_id = $1 ORDER BY is_default DESC LIMIT 1",
    )
    .bind(org.org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(default_priority, (4, "normal".to_string()));
    assert_eq!(
        count(
            &pool,
            "SELECT last_value FROM case_number_counters WHERE org_id = $1",
            org.org_id
        )
        .await,
        0
    );

    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM audit_events WHERE org_id = $1 AND action = 'organization.created'",
            org.org_id
        )
        .await,
        1
    );
}

#[sqlx::test]
async fn taken_slug_is_rejected_and_nothing_is_left_behind(pool: PgPool) {
    let owner = create_user(&pool, "sam@acme.test").await;
    let mut conn = pool.acquire().await.unwrap();
    identity::create_organization(&mut conn, acme(owner))
        .await
        .unwrap();

    let err = identity::create_organization(&mut conn, acme(owner))
        .await
        .unwrap_err();
    assert!(matches!(err, CreateOrganizationError::SlugTaken), "{err}");

    
    let (orgs, roles, memberships): (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM organizations), (SELECT count(*) FROM roles),
                (SELECT count(*) FROM memberships)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((orgs, roles, memberships), (1, 6, 1));
}

#[sqlx::test]
async fn invalid_input_is_reported_by_field(pool: PgPool) {
    let owner = create_user(&pool, "sam@acme.test").await;
    let mut conn = pool.acquire().await.unwrap();

    let bad_slug = NewOrganization {
        slug: "Acme Inc",
        ..acme(owner)
    };
    let err = identity::create_organization(&mut conn, bad_slug)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CreateOrganizationError::Invalid { field: "slug", .. }
    ));

    let blank_workspace = NewOrganization {
        workspace_name: "   ",
        ..acme(owner)
    };
    let err = identity::create_organization(&mut conn, blank_workspace)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CreateOrganizationError::Invalid {
            field: "workspace_name",
            ..
        }
    ));
}

#[sqlx::test]
async fn owner_must_exist_and_be_enabled(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let err = identity::create_organization(&mut conn, acme(Uuid::now_v7()))
        .await
        .unwrap_err();
    assert!(matches!(err, CreateOrganizationError::OwnerNotFound));

    let disabled = create_user(&pool, "gone@acme.test").await;
    sqlx::query("UPDATE users SET disabled_at = now() WHERE id = $1")
        .bind(disabled)
        .execute(&pool)
        .await
        .unwrap();
    let err = identity::create_organization(&mut conn, acme(disabled))
        .await
        .unwrap_err();
    assert!(matches!(err, CreateOrganizationError::OwnerNotFound));
}
