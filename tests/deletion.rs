

use std::time::Duration;

use sqlx::PgPool;
use ultrivly::audit::Actor;
use ultrivly::identity::roles::{self, NewRole};
use ultrivly::platform::authz::Permission;
use ultrivly::platform::blob::BlobStore;
use ultrivly::platform::deletion::{self, DEFAULT_RETENTION, DeletionError, PurgeReport, Target};
use uuid::Uuid;

mod common;
use common::{create_org, create_workspace, member_with_role, role_id};


struct Fixture {
    org_id: Uuid,
    workspace_id: Uuid,
    
    owner: Actor,
    case_id: Uuid,
    attachment_id: Uuid,
    attachment_key: String,
}

async fn seed(pool: &PgPool, blobs: &BlobStore, slug: &'static str) -> Fixture {
    let (org, owner) = create_org(pool, slug).await;
    let org_id = org.org_id;
    let contact_id = Uuid::now_v7();
    let case_id = Uuid::now_v7();
    let message_id = Uuid::now_v7();
    let attachment_id = Uuid::now_v7();
    let attachment_key = format!("org/{org_id}/attachments/{attachment_id}");

    let statements: [(&str, Vec<Uuid>); 4] = [
        (
            "INSERT INTO contacts (id, org_id, email, display_name) VALUES ($1, $2, 'pat@example.test', 'Pat')",
            vec![contact_id, org_id],
        ),
        (
            "INSERT INTO cases (id, org_id, workspace_id, number, subject, status_id, priority_id, requester_contact_id, source_channel)
             VALUES ($1, $2, $3, 1042, 'Printer on fire',
                     (SELECT id FROM case_statuses WHERE org_id = $2 AND is_default),
                     (SELECT id FROM case_priorities WHERE org_id = $2 AND is_default),
                     $4, 'web')",
            vec![case_id, org_id, org.workspace_id, contact_id],
        ),
        (
            "INSERT INTO case_messages (id, org_id, case_id, visibility, author_kind, author_contact_id, body, source_channel)
             VALUES ($1, $2, $3, 'public', 'contact', $4, 'Help', 'web')",
            vec![message_id, org_id, case_id, contact_id],
        ),
        (
            "INSERT INTO attachments (id, org_id, case_id, message_id, file_name, content_type, size_bytes, sha256, storage_key)
             VALUES ($1, $2, $3, $4, 'fire.jpg', 'image/jpeg', 4, decode(repeat('00', 32), 'hex'), 'org/' || $2 || '/attachments/' || $1)",
            vec![attachment_id, org_id, case_id, message_id],
        ),
    ];
    for (sql, ids) in statements {
        let mut query = sqlx::query(sql);
        for id in ids {
            query = query.bind(id);
        }
        query.execute(pool).await.unwrap();
    }

    blobs.put(&attachment_key, b"jpeg".to_vec()).await.unwrap();
    Fixture {
        org_id,
        workspace_id: org.workspace_id,
        owner: Actor::User(owner),
        case_id,
        attachment_id,
        attachment_key,
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
async fn deletion_requires_matching_confirmation(pool: PgPool) {
    let blobs = BlobStore::in_memory();
    let f = seed(&pool, &blobs, "acme").await;
    let mut conn = pool.acquire().await.unwrap();
    let actor = f.owner;
    let org = Target::organization(f.org_id);

    let err = deletion::schedule(&mut conn, org, "globex", actor, DEFAULT_RETENTION).await;
    assert!(matches!(err, Err(DeletionError::ConfirmationMismatch)));

    let purge_after = deletion::schedule(&mut conn, org, "acme", actor, DEFAULT_RETENTION)
        .await
        .unwrap();
    let days = (purge_after - chrono::Utc::now()).num_hours() as f64 / 24.0;
    assert!(
        (6.9..=7.0).contains(&days),
        "purge_after is {days} days away"
    );

    let again = deletion::schedule(&mut conn, org, "acme", actor, DEFAULT_RETENTION).await;
    assert!(matches!(again, Err(DeletionError::AlreadyScheduled)));

    
    
    deletion::restore(&mut conn, org, actor).await.unwrap();

    
    let case = Target::case(f.org_id, f.case_id);
    let err = deletion::schedule(&mut conn, case, "1043", actor, DEFAULT_RETENTION).await;
    assert!(matches!(err, Err(DeletionError::ConfirmationMismatch)));
    deletion::schedule(&mut conn, case, "#1042", actor, DEFAULT_RETENTION)
        .await
        .unwrap();

    let audited = count(
        &pool,
        "SELECT count(*) FROM audit_events WHERE org_id = $1 AND action LIKE '%.deletion_scheduled'",
        f.org_id,
    )
    .await;
    assert_eq!(audited, 2);
}

#[sqlx::test]
async fn other_orgs_rows_are_not_reachable(pool: PgPool) {
    let blobs = BlobStore::in_memory();
    let a = seed(&pool, &blobs, "acme").await;
    let b = seed(&pool, &blobs, "globex").await;
    let mut conn = pool.acquire().await.unwrap();

    
    let result = deletion::schedule(
        &mut conn,
        Target::case(a.org_id, b.case_id),
        "1042",
        Actor::System,
        DEFAULT_RETENTION,
    )
    .await;
    assert!(matches!(result, Err(DeletionError::NotFound)));
}

#[sqlx::test]
async fn restore_works_only_during_retention(pool: PgPool) {
    let blobs = BlobStore::in_memory();
    let f = seed(&pool, &blobs, "acme").await;
    let mut conn = pool.acquire().await.unwrap();
    let case = Target::case(f.org_id, f.case_id);

    deletion::schedule(&mut conn, case, "1042", Actor::System, DEFAULT_RETENTION)
        .await
        .unwrap();
    deletion::restore(&mut conn, case, Actor::System)
        .await
        .unwrap();
    assert!(matches!(
        deletion::restore(&mut conn, case, Actor::System).await,
        Err(DeletionError::NotScheduled)
    ));

    
    deletion::schedule(&mut conn, case, "1042", Actor::System, DEFAULT_RETENTION)
        .await
        .unwrap();
    assert_eq!(
        deletion::purge_due(&pool, &blobs).await.unwrap(),
        PurgeReport::default()
    );
    assert!(blobs.exists(&f.attachment_key).await.unwrap());

    
    deletion::restore(&mut conn, case, Actor::System)
        .await
        .unwrap();
    deletion::schedule(&mut conn, case, "1042", Actor::System, Duration::ZERO)
        .await
        .unwrap();
    assert!(matches!(
        deletion::restore(&mut conn, case, Actor::System).await,
        Err(DeletionError::RetentionEnded)
    ));
}

#[sqlx::test]
async fn purging_an_organization_removes_all_its_data_and_files(pool: PgPool) {
    let blobs = BlobStore::in_memory();
    let doomed = seed(&pool, &blobs, "acme").await;
    let survivor = seed(&pool, &blobs, "globex").await;
    
    let orphan_key = format!("org/{}/uploads/tmp", doomed.org_id);
    blobs.put(&orphan_key, b"x".to_vec()).await.unwrap();

    let mut conn = pool.acquire().await.unwrap();
    deletion::schedule(
        &mut conn,
        Target::organization(doomed.org_id),
        "acme",
        doomed.owner,
        Duration::ZERO,
    )
    .await
    .unwrap();

    let report = deletion::purge_due(&pool, &blobs).await.unwrap();
    assert_eq!(report.organizations, 1);
    assert_eq!(
        report.cases, 0,
        "children go by cascade, not as separate purges"
    );
    assert_eq!(report.files_failed, 0);

    for sql in [
        "SELECT count(*) FROM organizations WHERE id = $1",
        "SELECT count(*) FROM workspaces WHERE org_id = $1",
        "SELECT count(*) FROM contacts WHERE org_id = $1",
        "SELECT count(*) FROM cases WHERE org_id = $1",
        "SELECT count(*) FROM case_messages WHERE org_id = $1",
        "SELECT count(*) FROM attachments WHERE org_id = $1",
        "SELECT count(*) FROM audit_events WHERE org_id = $1",
    ] {
        assert_eq!(count(&pool, sql, doomed.org_id).await, 0, "{sql}");
    }
    assert!(!blobs.exists(&doomed.attachment_key).await.unwrap());
    assert!(!blobs.exists(&orphan_key).await.unwrap());
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM blob_deletions WHERE $1 IS NOT NULL",
            doomed.org_id
        )
        .await,
        0
    );

    
    let platform_audit = count(
        &pool,
        "SELECT count(*) FROM audit_events WHERE org_id IS NULL AND action = 'organization.purged' AND target_id = $1",
        doomed.org_id,
    )
    .await;
    assert_eq!(platform_audit, 1);

    
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM cases WHERE org_id = $1",
            survivor.org_id
        )
        .await,
        1
    );
    assert!(blobs.exists(&survivor.attachment_key).await.unwrap());
}

#[sqlx::test]
async fn purging_a_case_removes_its_attachments_and_files(pool: PgPool) {
    let blobs = BlobStore::in_memory();
    let f = seed(&pool, &blobs, "acme").await;
    let mut conn = pool.acquire().await.unwrap();

    deletion::schedule(
        &mut conn,
        Target::case(f.org_id, f.case_id),
        "1042",
        Actor::System,
        Duration::ZERO,
    )
    .await
    .unwrap();

    let report = deletion::purge_due(&pool, &blobs).await.unwrap();
    assert_eq!((report.cases, report.files_deleted), (1, 1));
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM attachments WHERE id = $1",
            f.attachment_id
        )
        .await,
        0
    );
    assert!(!blobs.exists(&f.attachment_key).await.unwrap());
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM organizations WHERE id = $1",
            f.org_id
        )
        .await,
        1
    );
}

#[sqlx::test]
async fn purging_a_workspace_removes_its_cases_but_keeps_the_org(pool: PgPool) {
    let blobs = BlobStore::in_memory();
    let f = seed(&pool, &blobs, "acme").await;
    let mut conn = pool.acquire().await.unwrap();

    deletion::schedule(
        &mut conn,
        Target::workspace(f.org_id, f.workspace_id),
        "support",
        Actor::System,
        Duration::ZERO,
    )
    .await
    .unwrap();

    let report = deletion::purge_due(&pool, &blobs).await.unwrap();
    assert_eq!((report.workspaces, report.files_deleted), (1, 1));
    assert_eq!(
        count(&pool, "SELECT count(*) FROM cases WHERE id = $1", f.case_id).await,
        0
    );
    assert!(!blobs.exists(&f.attachment_key).await.unwrap());
    
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM contacts WHERE org_id = $1",
            f.org_id
        )
        .await,
        1
    );
}

#[sqlx::test]
async fn deleting_requires_the_matching_permission(pool: PgPool) {
    let blobs = BlobStore::in_memory();
    let f = seed(&pool, &blobs, "acme").await;
    let agent_role = role_id(&pool, f.org_id, "agent").await;
    let agent = Actor::User(member_with_role(&pool, f.org_id, agent_role, None).await);
    let mut conn = pool.acquire().await.unwrap();
    let case = Target::case(f.org_id, f.case_id);

    
    for (target, confirmation) in [
        (case, "1042"),
        (Target::organization(f.org_id), "acme"),
        (Target::workspace(f.org_id, f.workspace_id), "support"),
    ] {
        let err =
            deletion::schedule(&mut conn, target, confirmation, agent, DEFAULT_RETENTION).await;
        assert!(
            matches!(err, Err(DeletionError::Forbidden)),
            "{target:?}: {err:?}"
        );
    }
    
    deletion::schedule(
        &mut conn,
        Target::attachment(f.org_id, f.attachment_id),
        "fire.jpg",
        agent,
        DEFAULT_RETENTION,
    )
    .await
    .unwrap();

    
    let deleters = roles::create_role(
        &mut conn,
        f.org_id,
        f.owner,
        NewRole {
            name: "Case deleters",
            permissions: &[Permission::CasesDelete],
        },
    )
    .await
    .unwrap();
    let elsewhere = create_workspace(&pool, f.org_id, "it").await;
    let other_deleter =
        Actor::User(member_with_role(&pool, f.org_id, deleters.id, Some(elsewhere)).await);
    let err = deletion::schedule(&mut conn, case, "1042", other_deleter, DEFAULT_RETENTION).await;
    assert!(matches!(err, Err(DeletionError::Forbidden)), "{err:?}");

    
    let local_deleter =
        Actor::User(member_with_role(&pool, f.org_id, deleters.id, Some(f.workspace_id)).await);
    deletion::schedule(&mut conn, case, "1042", local_deleter, DEFAULT_RETENTION)
        .await
        .unwrap();
    let err = deletion::restore(&mut conn, case, agent).await;
    assert!(matches!(err, Err(DeletionError::Forbidden)), "{err:?}");
    deletion::restore(&mut conn, case, local_deleter)
        .await
        .unwrap();
}
