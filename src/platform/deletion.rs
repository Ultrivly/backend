








use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{Connection, PgConnection, PgPool};
use uuid::Uuid;

use crate::audit::{self, Actor};
use crate::platform::authz::{self, AuthzError, Permission};
use crate::platform::blob::BlobStore;


pub const DEFAULT_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);


const BATCH_SIZE: i64 = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Organization,
    Workspace,
    Case,
    Attachment,
}



#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub kind: Kind,
    pub org_id: Uuid,
    pub id: Uuid,
}

impl Target {
    pub fn organization(org_id: Uuid) -> Self {
        Self {
            kind: Kind::Organization,
            org_id,
            id: org_id,
        }
    }

    pub fn workspace(org_id: Uuid, id: Uuid) -> Self {
        Self {
            kind: Kind::Workspace,
            org_id,
            id,
        }
    }

    pub fn case(org_id: Uuid, id: Uuid) -> Self {
        Self {
            kind: Kind::Case,
            org_id,
            id,
        }
    }

    pub fn attachment(org_id: Uuid, id: Uuid) -> Self {
        Self {
            kind: Kind::Attachment,
            org_id,
            id,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeletionError {
    #[error("not found")]
    NotFound,
    #[error("permission denied")]
    Forbidden,
    
    
    #[error("confirmation does not match")]
    ConfirmationMismatch,
    #[error("already scheduled for deletion")]
    AlreadyScheduled,
    #[error("not scheduled for deletion")]
    NotScheduled,
    #[error("the retention period has ended; it can no longer be restored")]
    RetentionEnded,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

impl From<AuthzError> for DeletionError {
    fn from(err: AuthzError) -> Self {
        match err {
            AuthzError::Forbidden => DeletionError::Forbidden,
            AuthzError::Database(err) => DeletionError::Database(err),
        }
    }
}



struct Statements {
    type_name: &'static str,
    
    
    lookup: &'static str,
    
    schedule: &'static str,
    restore: &'static str,
    
    due: &'static str,
    purge: &'static str,
}

impl Kind {
    
    
    pub fn permission(self) -> Permission {
        match self {
            Kind::Organization => Permission::OrganizationDelete,
            Kind::Workspace => Permission::WorkspacesManage,
            Kind::Case => Permission::CasesDelete,
            Kind::Attachment => Permission::CasesEdit,
        }
    }

    fn statements(self) -> &'static Statements {
        match self {
            Kind::Organization => &ORGANIZATION,
            Kind::Workspace => &WORKSPACE,
            Kind::Case => &CASE,
            Kind::Attachment => &ATTACHMENT,
        }
    }
}

const ORGANIZATION: Statements = Statements {
    type_name: "organization",
    lookup: "SELECT slug, NULL::uuid, deleted_at, purge_after FROM organizations WHERE id = $1 AND id = $2 FOR UPDATE",
    schedule: "UPDATE organizations SET deleted_at = now(), purge_after = now() + make_interval(secs => $3)
               WHERE id = $1 AND id = $2 RETURNING purge_after",
    restore: "UPDATE organizations SET deleted_at = NULL, purge_after = NULL WHERE id = $1 AND id = $2",
    due: "SELECT id, id FROM organizations WHERE purge_after <= now() ORDER BY purge_after LIMIT $1",
    purge: "DELETE FROM organizations WHERE id = $1 AND id = $2 AND purge_after <= now()",
};

const WORKSPACE: Statements = Statements {
    type_name: "workspace",
    lookup: "SELECT slug, NULL::uuid, deleted_at, purge_after FROM workspaces WHERE org_id = $1 AND id = $2 FOR UPDATE",
    schedule:
        "UPDATE workspaces SET deleted_at = now(), purge_after = now() + make_interval(secs => $3)
               WHERE org_id = $1 AND id = $2 RETURNING purge_after",
    restore: "UPDATE workspaces SET deleted_at = NULL, purge_after = NULL WHERE org_id = $1 AND id = $2",
    due: "SELECT org_id, id FROM workspaces WHERE purge_after <= now() ORDER BY purge_after LIMIT $1",
    purge: "DELETE FROM workspaces WHERE org_id = $1 AND id = $2 AND purge_after <= now()",
};

const CASE: Statements = Statements {
    type_name: "case",
    lookup: "SELECT number::text, workspace_id, deleted_at, purge_after FROM cases WHERE org_id = $1 AND id = $2 FOR UPDATE",
    schedule: "UPDATE cases SET deleted_at = now(), purge_after = now() + make_interval(secs => $3)
               WHERE org_id = $1 AND id = $2 RETURNING purge_after",
    restore: "UPDATE cases SET deleted_at = NULL, purge_after = NULL WHERE org_id = $1 AND id = $2",
    due: "SELECT org_id, id FROM cases WHERE purge_after <= now() ORDER BY purge_after LIMIT $1",
    purge: "DELETE FROM cases WHERE org_id = $1 AND id = $2 AND purge_after <= now()",
};

const ATTACHMENT: Statements = Statements {
    type_name: "attachment",
    lookup: "SELECT a.file_name, c.workspace_id, a.deleted_at, a.purge_after
             FROM attachments a JOIN cases c ON c.org_id = a.org_id AND c.id = a.case_id
             WHERE a.org_id = $1 AND a.id = $2 FOR UPDATE OF a",
    schedule:
        "UPDATE attachments SET deleted_at = now(), purge_after = now() + make_interval(secs => $3)
               WHERE org_id = $1 AND id = $2 RETURNING purge_after",
    restore: "UPDATE attachments SET deleted_at = NULL, purge_after = NULL WHERE org_id = $1 AND id = $2",
    due: "SELECT org_id, id FROM attachments WHERE purge_after <= now() ORDER BY purge_after LIMIT $1",
    purge: "DELETE FROM attachments WHERE org_id = $1 AND id = $2 AND purge_after <= now()",
};

type Lookup = (
    String,
    Option<Uuid>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
);

async fn lookup_authorized(
    conn: &mut PgConnection,
    target: Target,
    actor: Actor,
) -> Result<Lookup, DeletionError> {
    let row: Lookup = sqlx::query_as(target.kind.statements().lookup)
        .bind(target.org_id)
        .bind(target.id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(DeletionError::NotFound)?;
    match target.kind {
        Kind::Organization => {
            authz::require_ignoring_org_deletion(
                conn,
                target.org_id,
                actor,
                Permission::OrganizationDelete,
            )
            .await?
        }
        kind => authz::require_in(conn, target.org_id, row.1, actor, kind.permission()).await?,
    }
    Ok(row)
}

pub async fn schedule(
    conn: &mut PgConnection,
    target: Target,
    confirmation: &str,
    actor: Actor,
    retention: Duration,
) -> Result<DateTime<Utc>, DeletionError> {
    let sql = target.kind.statements();
    let mut tx = conn.begin().await?;

    let (expected, _, deleted_at, _) = lookup_authorized(&mut tx, target, actor).await?;
    if deleted_at.is_some() {
        return Err(DeletionError::AlreadyScheduled);
    }
    let confirmation = confirmation.trim();
    let confirmation = match target.kind {
        Kind::Case => confirmation.strip_prefix('#').unwrap_or(confirmation),
        _ => confirmation,
    };
    if confirmation != expected {
        return Err(DeletionError::ConfirmationMismatch);
    }

    let purge_after: DateTime<Utc> = sqlx::query_scalar(sql.schedule)
        .bind(target.org_id)
        .bind(target.id)
        .bind(retention.as_secs_f64())
        .fetch_one(&mut *tx)
        .await?;

    audit::record(
        &mut tx,
        audit::Event {
            org_id: Some(target.org_id),
            actor,
            action: &format!("{}.deletion_scheduled", sql.type_name),
            target_type: sql.type_name,
            target_id: target.id,
            metadata: json!({ "purge_after": purge_after.to_rfc3339() }),
        },
    )
    .await?;

    tx.commit().await?;
    Ok(purge_after)
}


pub async fn restore(
    conn: &mut PgConnection,
    target: Target,
    actor: Actor,
) -> Result<(), DeletionError> {
    let sql = target.kind.statements();
    let mut tx = conn.begin().await?;

    let (_, _, deleted_at, purge_after) = lookup_authorized(&mut tx, target, actor).await?;
    if deleted_at.is_none() {
        return Err(DeletionError::NotScheduled);
    }
    if purge_after.is_some_and(|at| at <= Utc::now()) {
        return Err(DeletionError::RetentionEnded);
    }

    sqlx::query(sql.restore)
        .bind(target.org_id)
        .bind(target.id)
        .execute(&mut *tx)
        .await?;

    audit::record(
        &mut tx,
        audit::Event {
            org_id: Some(target.org_id),
            actor,
            action: &format!("{}.deletion_cancelled", sql.type_name),
            target_type: sql.type_name,
            target_id: target.id,
            metadata: json!({}),
        },
    )
    .await?;

    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PurgeReport {
    pub organizations: u64,
    pub workspaces: u64,
    pub cases: u64,
    pub attachments: u64,
    pub files_deleted: u64,
    
    pub files_failed: u64,
}



pub async fn purge_due(pool: &PgPool, blobs: &BlobStore) -> anyhow::Result<PurgeReport> {
    let mut report = PurgeReport::default();

    
    
    for kind in [
        Kind::Organization,
        Kind::Workspace,
        Kind::Case,
        Kind::Attachment,
    ] {
        loop {
            let due: Vec<(Uuid, Uuid)> = sqlx::query_as(kind.statements().due)
                .bind(BATCH_SIZE)
                .fetch_all(pool)
                .await?;
            for &(org_id, id) in &due {
                if purge_one(pool, Target { kind, org_id, id }).await? {
                    *match kind {
                        Kind::Organization => &mut report.organizations,
                        Kind::Workspace => &mut report.workspaces,
                        Kind::Case => &mut report.cases,
                        Kind::Attachment => &mut report.attachments,
                    } += 1;
                }
            }
            if (due.len() as i64) < BATCH_SIZE {
                break;
            }
        }
    }

    let (deleted, failed) = delete_queued_files(pool, blobs).await?;
    report.files_deleted = deleted;
    report.files_failed = failed;
    Ok(report)
}


async fn purge_one(pool: &PgPool, target: Target) -> anyhow::Result<bool> {
    let sql = target.kind.statements();
    let mut tx = pool.begin().await?;

    
    
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *tx)
        .await?;

    let deleted = sqlx::query(sql.purge)
        .bind(target.org_id)
        .bind(target.id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Ok(false);
    }

    let org_gone = target.kind == Kind::Organization;
    if org_gone {
        
        
        sqlx::query("INSERT INTO blob_deletions (storage_key, is_prefix) VALUES ($1, true)")
            .bind(format!("org/{}/", target.org_id))
            .execute(&mut *tx)
            .await?;
    }

    audit::record(
        &mut tx,
        audit::Event {
            
            
            org_id: (!org_gone).then_some(target.org_id),
            actor: Actor::System,
            action: &format!("{}.purged", sql.type_name),
            target_type: sql.type_name,
            target_id: target.id,
            metadata: json!({ "org_id": target.org_id }),
        },
    )
    .await?;

    tx.commit().await?;
    tracing::info!(kind = sql.type_name, id = %target.id, org_id = %target.org_id, "purged");
    Ok(true)
}



async fn delete_queued_files(pool: &PgPool, blobs: &BlobStore) -> anyhow::Result<(u64, u64)> {
    let (mut deleted, mut failed) = (0, 0);
    loop {
        let mut tx = pool.begin().await?;
        let batch: Vec<(i64, String, bool)> = sqlx::query_as(
            "SELECT id, storage_key, is_prefix FROM blob_deletions
             WHERE next_attempt_at <= now() ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED",
        )
        .bind(BATCH_SIZE)
        .fetch_all(&mut *tx)
        .await?;

        for (id, key, is_prefix) in &batch {
            let result = if *is_prefix {
                blobs.delete_prefix(key).await
            } else {
                blobs.delete(key).await
            };
            match result {
                Ok(()) => {
                    sqlx::query("DELETE FROM blob_deletions WHERE id = $1")
                        .bind(id)
                        .execute(&mut *tx)
                        .await?;
                    deleted += 1;
                }
                Err(err) => {
                    tracing::warn!(storage_key = key, "file deletion failed, will retry: {err}");
                    sqlx::query(
                        "UPDATE blob_deletions
                         SET attempts = attempts + 1, last_error = $2,
                             next_attempt_at = now() + least(interval '1 hour', interval '30 seconds' * power(2, attempts))
                         WHERE id = $1",
                    )
                    .bind(id)
                    .bind(err.to_string())
                    .execute(&mut *tx)
                    .await?;
                    failed += 1;
                }
            }
        }

        tx.commit().await?;
        if (batch.len() as i64) < BATCH_SIZE {
            return Ok((deleted, failed));
        }
    }
}
