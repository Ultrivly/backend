


use sqlx::PgPool;
use uuid::Uuid;

async fn create_org(pool: &PgPool, slug: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $2)")
        .bind(id)
        .bind(slug)
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn create_workspace(pool: &PgPool, org_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO workspaces (id, org_id, name, slug) VALUES ($1, $2, 'Support', 'support')",
    )
    .bind(id)
    .bind(org_id)
    .execute(pool)
    .await
    .unwrap();
    id
}

fn is_foreign_key_violation(err: &sqlx::Error) -> bool {
    err.as_database_error().and_then(|e| e.code()).as_deref() == Some("23503")
}

#[sqlx::test]
async fn team_cannot_reference_another_orgs_workspace(pool: PgPool) {
    let org_a = create_org(&pool, "acme").await;
    let org_b = create_org(&pool, "globex").await;
    let workspace_b = create_workspace(&pool, org_b).await;

    let err = sqlx::query(
        "INSERT INTO teams (id, org_id, workspace_id, name) VALUES ($1, $2, $3, 'Tier 1')",
    )
    .bind(Uuid::now_v7())
    .bind(org_a)
    .bind(workspace_b)
    .execute(&pool)
    .await
    .unwrap_err();

    assert!(is_foreign_key_violation(&err), "unexpected error: {err}");
}

#[sqlx::test]
async fn team_member_must_belong_to_the_teams_org(pool: PgPool) {
    let org_a = create_org(&pool, "acme").await;
    let org_b = create_org(&pool, "globex").await;
    let workspace_a = create_workspace(&pool, org_a).await;

    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id, email, display_name) VALUES ($1, 'sam@globex.test', 'Sam')",
    )
    .bind(user_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO memberships (id, org_id, user_id, status) VALUES ($1, $2, $3, 'active')",
    )
    .bind(Uuid::now_v7())
    .bind(org_b)
    .bind(user_id)
    .execute(&pool)
    .await
    .unwrap();

    let team_id = Uuid::now_v7();
    sqlx::query("INSERT INTO teams (id, org_id, workspace_id, name) VALUES ($1, $2, $3, 'Tier 1')")
        .bind(team_id)
        .bind(org_a)
        .bind(workspace_a)
        .execute(&pool)
        .await
        .unwrap();

    
    let err =
        sqlx::query("INSERT INTO team_members (org_id, team_id, user_id) VALUES ($1, $2, $3)")
            .bind(org_a)
            .bind(team_id)
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap_err();

    assert!(is_foreign_key_violation(&err), "unexpected error: {err}");
}

#[sqlx::test]
async fn attachment_storage_key_must_be_under_its_org(pool: PgPool) {
    let org_a = create_org(&pool, "acme").await;
    let org_b = create_org(&pool, "globex").await;

    
    let err = sqlx::query(
        "INSERT INTO attachments (id, org_id, case_id, file_name, content_type, size_bytes, sha256, storage_key)
         VALUES ($1, $2, $3, 'a.txt', 'text/plain', 1, decode(repeat('00', 32), 'hex'), $4)",
    )
    .bind(Uuid::now_v7())
    .bind(org_a)
    .bind(Uuid::now_v7())
    .bind(format!("org/{org_b}/a.txt"))
    .execute(&pool)
    .await
    .unwrap_err();

    let code = err.as_database_error().and_then(|e| e.code());
    assert_eq!(code.as_deref(), Some("23514"), "unexpected error: {err}");
}
