use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::Actor;
use crate::cases::messages::can_see_internal;
use crate::cases::records::{self, history};
use crate::platform::authz::{self, Permission};
use crate::platform::blob::BlobStore;
use crate::platform::error::{ServiceError, ServiceResult, invalid};

pub const MAX_BYTES: usize = 25 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Attachment {
    pub id: Uuid,
    pub case_id: Uuid,
    pub message_id: Option<Uuid>,
    pub file_name: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub created_at: DateTime<Utc>,
    #[serde(skip)]
    pub storage_key: String,
    #[serde(skip)]
    pub internal: bool,
}

macro_rules! attachment_select {
    () => {
        "SELECT a.id, a.case_id, a.message_id, a.file_name, a.content_type, a.size_bytes, a.created_at,
                a.storage_key, coalesce(m.visibility = 'internal', false) AS internal
         FROM attachments a LEFT JOIN case_messages m ON m.id = a.message_id"
    };
}

pub fn sanitize_file_name(name: &str) -> ServiceResult<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or_default();
    let clean: String = base
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '"' | '<' | '>' | '|' | '*' | '?' | ':'))
        .collect();
    let clean = clean.trim().trim_start_matches('.').to_string();
    if clean.is_empty() || clean.chars().count() > 255 {
        return Err(invalid("file_name", "must be between 1 and 255 characters"));
    }
    Ok(clean)
}

fn valid_content_type(value: &str) -> bool {
    let mut parts = value.splitn(2, '/');
    let token = |s: &str| {
        !s.is_empty()
            && s.len() <= 100
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '+' | '.' | '_'))
    };
    matches!((parts.next(), parts.next()), (Some(a), Some(b)) if token(a) && token(b))
}

pub async fn upload(
    conn: &mut PgConnection,
    blobs: &BlobStore,
    org_id: Uuid,
    actor: Actor,
    case_id: Uuid,
    message_id: Option<Uuid>,
    file_name: &str,
    content_type: &str,
    bytes: Vec<u8>,
) -> ServiceResult<Attachment> {
    let file_name = sanitize_file_name(file_name)?;
    let content_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let content_type = if valid_content_type(&content_type) {
        content_type
    } else {
        "application/octet-stream".to_string()
    };
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(invalid("file", "must be between 1 byte and 25 MB"));
    }

    let mut tx = conn.begin().await?;
    let case = records::load(&mut tx, org_id, case_id, true).await?;
    records::readable(&mut tx, org_id, actor, &case).await?;
    authz::require_in(
        &mut tx,
        org_id,
        Some(case.workspace_id),
        actor,
        Permission::CasesEdit,
    )
    .await?;
    if let Some(message_id) = message_id {
        let visibility: Option<String> = sqlx::query_scalar(
            "SELECT visibility FROM case_messages WHERE org_id = $1 AND case_id = $2 AND id = $3",
        )
        .bind(org_id)
        .bind(case_id)
        .bind(message_id)
        .fetch_optional(&mut *tx)
        .await?;
        match visibility.as_deref() {
            None => return Err(invalid("message_id", "is not a message on this case")),
            Some("internal") => {
                authz::require_in(
                    &mut tx,
                    org_id,
                    Some(case.workspace_id),
                    actor,
                    Permission::CasesViewInternalNotes,
                )
                .await?
            }
            Some(_) => {}
        }
    }

    let id = Uuid::now_v7();
    let key = format!("org/{org_id}/cases/{case_id}/{id}");
    sqlx::query(
        "INSERT INTO attachments (id, org_id, case_id, message_id, file_name, content_type, size_bytes, sha256, storage_key)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(org_id)
    .bind(case_id)
    .bind(message_id)
    .bind(&file_name)
    .bind(&content_type)
    .bind(bytes.len() as i64)
    .bind(Sha256::digest(&bytes).to_vec())
    .bind(&key)
    .execute(&mut *tx)
    .await?;
    history(
        &mut tx,
        org_id,
        case_id,
        actor,
        "attachment_added",
        json!({ "attachment_id": id, "file_name": file_name }),
    )
    .await?;
    blobs
        .put(&key, bytes)
        .await
        .map_err(|e| ServiceError::Internal(anyhow::anyhow!("storing attachment: {e}")))?;
    let attachment = sqlx::query_as(concat!(attachment_select!(), " WHERE a.id = $1"))
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(attachment)
}

pub async fn list(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    case_id: Uuid,
) -> ServiceResult<Vec<Attachment>> {
    let case = records::get(conn, org_id, actor, case_id).await?;
    let internal = can_see_internal(conn, org_id, case.workspace_id, actor).await?;
    Ok(sqlx::query_as(concat!(
        attachment_select!(),
        " WHERE a.org_id = $1 AND a.case_id = $2 AND a.deleted_at IS NULL
          AND (m.visibility IS DISTINCT FROM 'internal' OR $3)
          ORDER BY a.created_at"
    ))
    .bind(org_id)
    .bind(case_id)
    .bind(internal)
    .fetch_all(conn)
    .await?)
}

pub async fn download(
    conn: &mut PgConnection,
    blobs: &BlobStore,
    org_id: Uuid,
    actor: Actor,
    attachment_id: Uuid,
) -> ServiceResult<(Attachment, Vec<u8>)> {
    let attachment: Attachment = sqlx::query_as(concat!(
        attachment_select!(),
        " WHERE a.org_id = $1 AND a.id = $2 AND a.deleted_at IS NULL"
    ))
    .bind(org_id)
    .bind(attachment_id)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(ServiceError::NotFound)?;
    let case = records::get(conn, org_id, actor, attachment.case_id).await?;
    if attachment.internal && !can_see_internal(conn, org_id, case.workspace_id, actor).await? {
        return Err(ServiceError::NotFound);
    }
    let bytes = blobs
        .get(&attachment.storage_key)
        .await
        .map_err(|e| ServiceError::Internal(anyhow::anyhow!("reading attachment: {e}")))?;
    Ok((attachment, bytes))
}

#[cfg(test)]
mod tests {
    use super::{sanitize_file_name, valid_content_type};

    #[test]
    fn file_names_lose_paths_and_dangerous_characters() {
        assert_eq!(sanitize_file_name("../../etc/passwd").unwrap(), "passwd");
        assert_eq!(
            sanitize_file_name("C:\\Users\\a\\report.pdf").unwrap(),
            "report.pdf"
        );
        assert_eq!(
            sanitize_file_name("in\"voice\r\n.pdf").unwrap(),
            "invoice.pdf"
        );
        assert_eq!(sanitize_file_name(".htaccess").unwrap(), "htaccess");
        assert!(sanitize_file_name("..").is_err());
    }

    #[test]
    fn content_types_are_simple_tokens() {
        assert!(valid_content_type("image/png"));
        assert!(valid_content_type("application/vnd.ms-excel"));
        assert!(!valid_content_type("text/html\r\nx-evil: 1"));
        assert!(!valid_content_type("nonsense"));
    }
}
