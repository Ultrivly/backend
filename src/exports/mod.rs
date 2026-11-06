use std::io::Write;

use chrono::{DateTime, Utc};
use futures::TryStreamExt;
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection, PgPool};
use uuid::Uuid;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

use crate::audit::Actor;
use crate::identity::orgs::record;
use crate::platform::authz::{self, Permission};
use crate::platform::blob::BlobStore;
use crate::platform::error::{ServiceError, ServiceResult, conflict};
use crate::platform::jobs::{self, NewJob};
use crate::platform::page::Page;

pub const BUILD: &str = "export.build";
pub const FORMAT_VERSION: u32 = 1;
const RETENTION_DAYS: i32 = 7;
const MAX_ACTIVE: i64 = 3;

macro_rules! org_rows {
    ($table:literal) => {
        concat!("SELECT to_jsonb(t) FROM ", $table, " t WHERE t.org_id = $1")
    };
}

const ORG_TABLES: &[(&str, &str)] = &[
    ("organization", "SELECT to_jsonb(t) FROM organizations t WHERE t.id = $1"),
    (
        "users",
        "SELECT jsonb_build_object('id', u.id, 'email', u.email, 'display_name', u.display_name,
                                   'email_verified_at', u.email_verified_at, 'disabled_at', u.disabled_at)
         FROM users u JOIN memberships m ON m.user_id = u.id WHERE m.org_id = $1",
    ),
    ("workspaces", org_rows!("workspaces")),
    ("memberships", org_rows!("memberships")),
    ("roles", org_rows!("roles")),
    ("role_permissions", org_rows!("role_permissions")),
    ("membership_roles", org_rows!("membership_roles")),
    ("departments", org_rows!("departments")),
    ("teams", org_rows!("teams")),
    ("team_members", org_rows!("team_members")),
    ("queues", org_rows!("queues")),
    ("contacts", org_rows!("contacts")),
    ("contact_identities", org_rows!("contact_identities")),
    ("case_statuses", org_rows!("case_statuses")),
    ("case_priorities", org_rows!("case_priorities")),
    ("custom_field_definitions", org_rows!("custom_field_definitions")),
    ("sla_policies", org_rows!("sla_policies")),
    ("cases", org_rows!("cases")),
    ("case_messages", org_rows!("case_messages")),
    ("case_events", org_rows!("case_events")),
    ("case_links", org_rows!("case_links")),
    ("attachments", org_rows!("attachments")),
    ("saved_views", org_rows!("saved_views")),
    ("kb_categories", org_rows!("kb_categories")),
    ("kb_articles", org_rows!("kb_articles")),
    ("workflows", org_rows!("workflows")),
    ("workflow_versions", org_rows!("workflow_versions")),
    ("workflow_runs", org_rows!("workflow_runs")),
    ("webhook_endpoints", org_rows!("webhook_endpoints")),
    ("webhook_deliveries", org_rows!("webhook_deliveries")),
    ("api_credentials", org_rows!("api_credentials")),
    ("channels", org_rows!("channels")),
    ("plugin_installs", org_rows!("plugin_installs")),
    ("ai_settings", org_rows!("ai_settings")),
    ("sso_connections", org_rows!("sso_connections")),
    ("invitations", org_rows!("invitations")),
    ("audit_events", org_rows!("audit_events")),
];

macro_rules! contact_cases {
    () => {
        "SELECT id FROM cases WHERE org_id = $1 AND requester_contact_id = $2"
    };
}

const CONTACT_TABLES: &[(&str, &str)] = &[
    (
        "contact",
        "SELECT to_jsonb(t) FROM contacts t WHERE t.org_id = $1 AND t.id = $2",
    ),
    (
        "contact_identities",
        "SELECT to_jsonb(t) FROM contact_identities t WHERE t.org_id = $1 AND t.contact_id = $2",
    ),
    (
        "cases",
        "SELECT to_jsonb(t) FROM cases t WHERE t.org_id = $1 AND t.requester_contact_id = $2",
    ),
    (
        "case_messages",
        concat!(
            "SELECT to_jsonb(t) FROM case_messages t WHERE t.org_id = $1 AND (t.author_contact_id = $2 OR t.case_id IN (",
            contact_cases!(),
            "))"
        ),
    ),
    (
        "case_events",
        concat!(
            "SELECT to_jsonb(t) FROM case_events t WHERE t.org_id = $1 AND t.case_id IN (",
            contact_cases!(),
            ")"
        ),
    ),
    (
        "attachments",
        concat!(
            "SELECT to_jsonb(t) FROM attachments t WHERE t.org_id = $1 AND t.case_id IN (",
            contact_cases!(),
            ")"
        ),
    ),
];

const ORG_FILES: &str = "SELECT id, file_name, storage_key FROM attachments WHERE org_id = $1 AND deleted_at IS NULL ORDER BY id";
const CONTACT_FILES: &str = concat!(
    "SELECT a.id, a.file_name, a.storage_key FROM attachments a
     LEFT JOIN case_messages m ON m.org_id = a.org_id AND m.id = a.message_id
     WHERE a.org_id = $1 AND a.deleted_at IS NULL AND (m.visibility IS NULL OR m.visibility = 'public')
       AND a.case_id IN (",
    contact_cases!(),
    ") ORDER BY a.id"
);

pub fn redact(mut row: Value) -> Value {
    if let Some(object) = row.as_object_mut() {
        object.retain(|key, _| {
            !(key.ends_with("_ciphertext")
                || key.ends_with("_hash")
                || key == "search_vector"
                || key == "storage_key")
        });
    }
    row
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Export {
    pub id: Uuid,
    pub kind: String,
    pub contact_id: Option<Uuid>,
    pub requested_by: Option<Uuid>,
    pub status: String,
    pub size_bytes: Option<i64>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

macro_rules! export_columns {
    () => {
        "id, kind, contact_id, requested_by, status, size_bytes, error, created_at, completed_at, expires_at"
    };
}

pub async fn request(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    contact_id: Option<Uuid>,
) -> ServiceResult<Export> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::DataExport).await?;
    if let Some(contact_id) = contact_id {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM contacts WHERE org_id = $1 AND id = $2)",
        )
        .bind(org_id)
        .bind(contact_id)
        .fetch_one(&mut *tx)
        .await?;
        if !exists {
            return Err(ServiceError::NotFound);
        }
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 7))")
        .bind(org_id)
        .execute(&mut *tx)
        .await?;
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM data_exports WHERE org_id = $1 AND status IN ('pending', 'running')",
    )
    .bind(org_id)
    .fetch_one(&mut *tx)
    .await?;
    if active >= MAX_ACTIVE {
        return Err(conflict(
            "too_many_exports",
            "wait for a running export to finish before requesting another",
        ));
    }
    let id = Uuid::now_v7();
    let kind = if contact_id.is_some() {
        "contact"
    } else {
        "organization"
    };
    let export: Export = sqlx::query_as(concat!(
        "INSERT INTO data_exports (id, org_id, kind, contact_id, requested_by) VALUES ($1, $2, $3, $4, $5) RETURNING ",
        export_columns!()
    ))
    .bind(id)
    .bind(org_id)
    .bind(kind)
    .bind(contact_id)
    .bind(match actor {
        Actor::User(user_id) => Some(user_id),
        _ => None,
    })
    .fetch_one(&mut *tx)
    .await?;
    jobs::enqueue(
        &mut tx,
        NewJob {
            org_id: Some(org_id),
            max_attempts: 3,
            ..NewJob::new(BUILD, json!({ "export_id": id, "org_id": org_id }))
        },
    )
    .await?;
    record(
        &mut tx,
        org_id,
        actor,
        "export.requested",
        "export",
        id,
        json!({ "kind": kind, "contact_id": contact_id }),
    )
    .await?;
    tx.commit().await?;
    Ok(export)
}

pub async fn list(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    page: Page,
) -> ServiceResult<Vec<Export>> {
    authz::require(conn, org_id, actor, Permission::DataExport).await?;
    Ok(sqlx::query_as(concat!(
        "SELECT ",
        export_columns!(),
        " FROM data_exports WHERE org_id = $1 AND ($2::uuid IS NULL OR id < $2) ORDER BY id DESC LIMIT $3"
    ))
    .bind(org_id)
    .bind(page.cursor)
    .bind(page.limit + 1)
    .fetch_all(conn)
    .await?)
}

pub async fn get(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> ServiceResult<Export> {
    authz::require(conn, org_id, actor, Permission::DataExport).await?;
    sqlx::query_as(concat!(
        "SELECT ",
        export_columns!(),
        " FROM data_exports WHERE org_id = $1 AND id = $2"
    ))
    .bind(org_id)
    .bind(id)
    .fetch_optional(conn)
    .await?
    .ok_or(ServiceError::NotFound)
}

pub async fn download(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> ServiceResult<(Export, String)> {
    let mut tx = conn.begin().await?;
    let export = get(&mut tx, org_id, actor, id).await?;
    let key: Option<String> = sqlx::query_scalar(
        "SELECT storage_key FROM data_exports
         WHERE org_id = $1 AND id = $2 AND status = 'ready' AND expires_at > now()",
    )
    .bind(org_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .flatten();
    let key = key.ok_or(conflict(
        "export_not_ready",
        "this export is not ready or has expired",
    ))?;
    record(
        &mut tx,
        org_id,
        actor,
        "export.downloaded",
        "export",
        id,
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok((export, key))
}

pub async fn build(pool: &PgPool, blobs: &BlobStore, payload: &Value) -> anyhow::Result<()> {
    let id: Uuid = payload["export_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid export job"))?;
    let org_id: Uuid = payload["org_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid export job"))?;
    let row: Option<(String, Option<Uuid>)> = sqlx::query_as(
        "UPDATE data_exports SET status = 'running', error = NULL
         WHERE org_id = $1 AND id = $2 AND status IN ('pending', 'running')
         RETURNING kind, contact_id",
    )
    .bind(org_id)
    .bind(id)
    .fetch_optional(pool)
    .await?;
    let Some((kind, contact_id)) = row else {
        return Ok(());
    };
    match write_archive(pool, blobs, org_id, id, &kind, contact_id).await {
        Ok((key, size)) => {
            sqlx::query(
                "UPDATE data_exports SET status = 'ready', storage_key = $3, size_bytes = $4, completed_at = now(),
                        expires_at = now() + make_interval(days => $5)
                 WHERE org_id = $1 AND id = $2",
            )
            .bind(org_id)
            .bind(id)
            .bind(&key)
            .bind(size as i64)
            .bind(RETENTION_DAYS)
            .execute(pool)
            .await?;
            Ok(())
        }
        Err(err) => {
            sqlx::query(
                "UPDATE data_exports SET status = 'failed', error = left($3, 500), completed_at = now()
                 WHERE org_id = $1 AND id = $2",
            )
            .bind(org_id)
            .bind(id)
            .bind(format!("{err:#}"))
            .execute(pool)
            .await?;
            Err(err)
        }
    }
}

fn safe_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(|c| c == '.' || c == ' ');
    if trimmed.is_empty() {
        "file".into()
    } else {
        trimmed.chars().take(150).collect()
    }
}

async fn write_archive(
    pool: &PgPool,
    blobs: &BlobStore,
    org_id: Uuid,
    id: Uuid,
    kind: &str,
    contact_id: Option<Uuid>,
) -> anyhow::Result<(String, u64)> {
    let file = tempfile::NamedTempFile::new()?;
    let mut zip = ZipWriter::new(file.reopen()?);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .large_file(true);
    let (tables, files) = match contact_id {
        Some(_) => (CONTACT_TABLES, CONTACT_FILES),
        None => (ORG_TABLES, ORG_FILES),
    };
    let mut counts = serde_json::Map::new();
    let mut conn = pool.acquire().await?;
    for (name, sql) in tables {
        zip.start_file(format!("data/{name}.jsonl"), options)?;
        let mut query = sqlx::query_scalar::<_, Value>(*sql).bind(org_id);
        if let Some(contact_id) = contact_id {
            query = query.bind(contact_id);
        }
        let mut rows = query.fetch(&mut *conn);
        let mut count = 0u64;
        while let Some(row) = rows.try_next().await? {
            serde_json::to_writer(&mut zip, &redact(row))?;
            zip.write_all(b"\n")?;
            count += 1;
        }
        counts.insert((*name).into(), json!(count));
    }
    let mut query = sqlx::query_as::<_, (Uuid, String, String)>(files).bind(org_id);
    if let Some(contact_id) = contact_id {
        query = query.bind(contact_id);
    }
    let attachments = query.fetch_all(&mut *conn).await?;
    drop(conn);
    let mut missing = Vec::new();
    for (attachment_id, file_name, storage_key) in &attachments {
        match blobs.get(storage_key).await {
            Ok(bytes) => {
                zip.start_file(
                    format!("attachments/{attachment_id}/{}", safe_name(file_name)),
                    options,
                )?;
                zip.write_all(&bytes)?;
            }
            Err(err) => {
                tracing::warn!(%attachment_id, "attachment missing from export: {err}");
                missing.push(*attachment_id);
            }
        }
    }
    zip.start_file("manifest.json", options)?;
    serde_json::to_writer_pretty(
        &mut zip,
        &json!({
            "format_version": FORMAT_VERSION,
            "export_id": id,
            "org_id": org_id,
            "kind": kind,
            "contact_id": contact_id,
            "generated_at": Utc::now(),
            "rows": counts,
            "attachments": attachments.len() - missing.len(),
            "missing_attachments": missing,
            "redacted": "encrypted secrets, token and password hashes, storage keys and search indexes are left out",
        }),
    )?;
    zip.finish()?;
    let key = format!("org/{org_id}/exports/{id}.zip");
    let size = blobs.put_file(&key, file.path()).await?;
    Ok((key, size))
}

pub async fn expire(pool: &PgPool) -> sqlx::Result<u64> {
    let mut tx = pool.begin().await?;
    let keys: Vec<Option<String>> = sqlx::query_scalar(
        "DELETE FROM data_exports
         WHERE (expires_at < now()) OR (status = 'failed' AND completed_at < now() - interval '7 days')
         RETURNING storage_key",
    )
    .fetch_all(&mut *tx)
    .await?;
    for key in keys.iter().flatten() {
        sqlx::query("INSERT INTO blob_deletions (storage_key) VALUES ($1)")
            .bind(key)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(keys.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_never_leave_in_exports() {
        let row = redact(json!({
            "id": 1, "secret_ciphertext": "x", "token_hash": "y", "search_vector": "z", "storage_key": "org/1/a", "name": "ok"
        }));
        assert_eq!(row, json!({ "id": 1, "name": "ok" }));
    }

    #[test]
    fn archive_names_cannot_escape_their_folder() {
        assert_eq!(safe_name("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(safe_name(".."), "file");
        assert_eq!(safe_name("report final.pdf"), "report final.pdf");
    }
}
