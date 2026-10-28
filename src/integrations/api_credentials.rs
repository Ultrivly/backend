use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::{self, Actor};
use crate::platform::authz::{self, Permission};
use crate::platform::error::{ServiceError, ServiceResult, invalid, text};
use crate::platform::secrets::{random_token, token_hash};

pub const TOKEN_PREFIX: &str = "ult_";
const MAX_LIFETIME_DAYS: i64 = 365 * 2;

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct ApiCredentialInfo {
    pub id: Uuid,
    pub name: String,
    pub token_prefix: String,
    pub permissions: Vec<String>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct CreatedCredential {
    pub info: ApiCredentialInfo,
    pub token: String,
}

pub struct NewCredential<'a> {
    pub name: &'a str,
    pub permissions: &'a [Permission],
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authenticated {
    pub id: Uuid,
    pub org_id: Uuid,
}

impl Authenticated {
    pub fn actor(self) -> Actor {
        Actor::ApiCredential {
            id: self.id,
            org_id: self.org_id,
        }
    }
}

pub async fn create(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    new: NewCredential<'_>,
) -> ServiceResult<CreatedCredential> {
    let name = text("name", new.name, 100)?;
    if new.permissions.is_empty() {
        return Err(invalid(
            "permissions",
            "must include at least one permission",
        ));
    }
    if new
        .expires_in_days
        .is_some_and(|d| !(1..=MAX_LIFETIME_DAYS).contains(&d))
    {
        return Err(invalid("expires_in_days", "must be between 1 and 730"));
    }
    let permissions: BTreeSet<Permission> = new.permissions.iter().copied().collect();

    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::ApiCredentialsManage).await?;
    let missing =
        authz::missing_permissions(&mut tx, org_id, None, actor, permissions.iter().copied())
            .await?;
    if !missing.is_empty() {
        return Err(ServiceError::CannotGrant(missing));
    }

    let id = Uuid::now_v7();
    let token = format!("{TOKEN_PREFIX}{}", random_token());
    let stored: Vec<&str> = permissions.iter().map(|p| p.as_str()).collect();
    let created_by = match actor {
        Actor::User(user_id) => Some(user_id),
        _ => None,
    };
    let info: ApiCredentialInfo = sqlx::query_as(
        "INSERT INTO api_credentials (id, org_id, name, token_hash, token_prefix, permissions, created_by, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(days => $8::int))
         RETURNING id, name, token_prefix, permissions, created_by, created_at, last_used_at, expires_at, revoked_at",
    )
    .bind(id)
    .bind(org_id)
    .bind(&name)
    .bind(token_hash(&token))
    .bind(&token[..TOKEN_PREFIX.len() + 6])
    .bind(&stored)
    .bind(created_by)
    .bind(new.expires_in_days)
    .fetch_one(&mut *tx)
    .await?;

    audit::record(
        &mut tx,
        audit::Event {
            org_id: Some(org_id),
            actor,
            action: "api_credential.created",
            target_type: "api_credential",
            target_id: id,
            metadata: json!({ "name": name, "permissions": stored, "expires_at": info.expires_at }),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(CreatedCredential { info, token })
}

pub async fn list(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
) -> ServiceResult<Vec<ApiCredentialInfo>> {
    authz::require(conn, org_id, actor, Permission::ApiCredentialsManage).await?;
    Ok(sqlx::query_as(
        "SELECT id, name, token_prefix, permissions, created_by, created_at, last_used_at, expires_at, revoked_at
         FROM api_credentials WHERE org_id = $1 ORDER BY created_at DESC",
    )
    .bind(org_id)
    .fetch_all(conn)
    .await?)
}

pub async fn revoke(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    credential_id: Uuid,
) -> ServiceResult<()> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::ApiCredentialsManage).await?;
    let revoked = sqlx::query(
        "UPDATE api_credentials SET revoked_at = now()
         WHERE org_id = $1 AND id = $2 AND revoked_at IS NULL",
    )
    .bind(org_id)
    .bind(credential_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if revoked == 0 {
        return Err(ServiceError::NotFound);
    }
    audit::record(
        &mut tx,
        audit::Event {
            org_id: Some(org_id),
            actor,
            action: "api_credential.revoked",
            target_type: "api_credential",
            target_id: credential_id,
            metadata: json!({}),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn authenticate(
    conn: &mut PgConnection,
    token: &str,
) -> sqlx::Result<Option<Authenticated>> {
    if !token.starts_with(TOKEN_PREFIX) {
        return Ok(None);
    }
    let row: Option<(Uuid, Uuid)> = sqlx::query_as(
        "UPDATE api_credentials c SET last_used_at = now()
         FROM organizations o
         WHERE c.token_hash = $1 AND o.id = c.org_id AND o.deleted_at IS NULL
           AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at > now())
         RETURNING c.id, c.org_id",
    )
    .bind(token_hash(token))
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|(id, org_id)| Authenticated { id, org_id }))
}
