use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::{Connection, PgConnection, PgPool};
use uuid::Uuid;

use crate::audit::Actor;
use crate::cases::{Priority, Status};
use crate::identity::orgs::{record, require_member};
use crate::platform::authz::{self, Permission};
use crate::platform::error::{
    ServiceError, ServiceResult, conflict, invalid, text, unique_violation,
};
use crate::platform::events::{self, Cause};

const CATEGORIES: &[&str] = &["new", "open", "pending", "resolved", "closed"];
const FIELD_TYPES: &[&str] = &["text", "number", "boolean", "date", "select"];

fn check_key(field: &'static str, key: &str) -> ServiceResult<()> {
    let ok = (1..=50).contains(&key.len())
        && key.starts_with(|c: char| c.is_ascii_lowercase())
        && key
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if ok {
        Ok(())
    } else {
        Err(invalid(
            field,
            "must be lowercase letters, digits, and underscores, starting with a letter",
        ))
    }
}

fn foreign_key_in_use(err: &sqlx::Error) -> bool {
    err.as_database_error().and_then(|e| e.code()).as_deref() == Some("23503")
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatusInput {
    pub key: Option<String>,
    pub label: Option<String>,
    pub category: Option<String>,
    pub position: Option<i32>,
    pub is_default: Option<bool>,
}

pub async fn save_status(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    existing: Option<Uuid>,
    input: StatusInput,
) -> ServiceResult<Status> {
    let label = input
        .label
        .as_deref()
        .map(|l| text("label", l, 100))
        .transpose()?;
    if let Some(category) = &input.category
        && !CATEGORIES.contains(&category.as_str())
    {
        return Err(invalid(
            "category",
            "must be new, open, pending, resolved, or closed",
        ));
    }
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::OrganizationManage).await?;
    if input.is_default == Some(true) {
        sqlx::query("UPDATE case_statuses SET is_default = false WHERE org_id = $1")
            .bind(org_id)
            .execute(&mut *tx)
            .await?;
    }
    let id = match existing {
        Some(id) => {
            if input.is_default == Some(false) {
                return Err(invalid(
                    "is_default",
                    "make another status the default instead",
                ));
            }
            let updated = sqlx::query(
                "UPDATE case_statuses SET label = coalesce($3, label), position = coalesce($4, position),
                     is_default = coalesce($5, is_default)
                 WHERE org_id = $1 AND id = $2",
            )
            .bind(org_id)
            .bind(id)
            .bind(&label)
            .bind(input.position)
            .bind(input.is_default)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if updated == 0 {
                return Err(ServiceError::NotFound);
            }
            id
        }
        None => {
            let key = input.key.as_deref().unwrap_or_default();
            check_key("key", key)?;
            let category = input
                .category
                .as_deref()
                .ok_or(invalid("category", "is required"))?;
            let id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO case_statuses (id, org_id, key, label, category, position, is_default)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(id)
            .bind(org_id)
            .bind(key)
            .bind(label.as_deref().unwrap_or(key))
            .bind(category)
            .bind(input.position.unwrap_or(100))
            .bind(input.is_default.unwrap_or(false))
            .execute(&mut *tx)
            .await
            .map_err(|err| {
                if unique_violation(&err, "case_statuses_org_id_key_key") {
                    conflict("key_taken", "a status with this key already exists")
                } else {
                    err.into()
                }
            })?;
            id
        }
    };
    record(
        &mut tx,
        org_id,
        actor,
        "case_status.saved",
        "case_status",
        id,
        json!({ "label": label }),
    )
    .await?;
    let status = sqlx::query_as(
        "SELECT id, key, label, category, position, is_default FROM case_statuses WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(status)
}

pub async fn delete_status(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> ServiceResult<()> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::OrganizationManage).await?;
    let is_default: Option<bool> =
        sqlx::query_scalar("SELECT is_default FROM case_statuses WHERE org_id = $1 AND id = $2")
            .bind(org_id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    match is_default {
        None => return Err(ServiceError::NotFound),
        Some(true) => {
            return Err(conflict(
                "status_is_default",
                "the default status cannot be deleted",
            ));
        }
        Some(false) => {}
    }
    sqlx::query("DELETE FROM case_statuses WHERE org_id = $1 AND id = $2")
        .bind(org_id)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|err| {
            if foreign_key_in_use(&err) {
                conflict("status_in_use", "cases still use this status")
            } else {
                err.into()
            }
        })?;
    record(
        &mut tx,
        org_id,
        actor,
        "case_status.deleted",
        "case_status",
        id,
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
pub struct PriorityInput {
    pub key: Option<String>,
    pub label: Option<String>,
    pub rank: Option<i32>,
    pub is_default: Option<bool>,
}

pub async fn save_priority(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    existing: Option<Uuid>,
    input: PriorityInput,
) -> ServiceResult<Priority> {
    let label = input
        .label
        .as_deref()
        .map(|l| text("label", l, 100))
        .transpose()?;
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::OrganizationManage).await?;
    if input.is_default == Some(true) {
        sqlx::query("UPDATE case_priorities SET is_default = false WHERE org_id = $1")
            .bind(org_id)
            .execute(&mut *tx)
            .await?;
    }
    let id = match existing {
        Some(id) => {
            if input.is_default == Some(false) {
                return Err(invalid(
                    "is_default",
                    "make another priority the default instead",
                ));
            }
            let updated = sqlx::query(
                "UPDATE case_priorities SET label = coalesce($3, label), rank = coalesce($4, rank),
                     is_default = coalesce($5, is_default)
                 WHERE org_id = $1 AND id = $2",
            )
            .bind(org_id)
            .bind(id)
            .bind(&label)
            .bind(input.rank)
            .bind(input.is_default)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if updated == 0 {
                return Err(ServiceError::NotFound);
            }
            id
        }
        None => {
            let key = input.key.as_deref().unwrap_or_default();
            check_key("key", key)?;
            let id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO case_priorities (id, org_id, key, label, rank, is_default)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(id)
            .bind(org_id)
            .bind(key)
            .bind(label.as_deref().unwrap_or(key))
            .bind(input.rank.unwrap_or(0))
            .bind(input.is_default.unwrap_or(false))
            .execute(&mut *tx)
            .await
            .map_err(|err| {
                if unique_violation(&err, "case_priorities_org_id_key_key") {
                    conflict("key_taken", "a priority with this key already exists")
                } else {
                    err.into()
                }
            })?;
            id
        }
    };
    record(
        &mut tx,
        org_id,
        actor,
        "case_priority.saved",
        "case_priority",
        id,
        json!({ "label": label }),
    )
    .await?;
    let priority = sqlx::query_as(
        "SELECT id, key, label, rank, is_default FROM case_priorities WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(priority)
}

pub async fn delete_priority(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> ServiceResult<()> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::OrganizationManage).await?;
    let is_default: Option<bool> =
        sqlx::query_scalar("SELECT is_default FROM case_priorities WHERE org_id = $1 AND id = $2")
            .bind(org_id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    match is_default {
        None => return Err(ServiceError::NotFound),
        Some(true) => {
            return Err(conflict(
                "priority_is_default",
                "the default priority cannot be deleted",
            ));
        }
        Some(false) => {}
    }
    sqlx::query("DELETE FROM case_priorities WHERE org_id = $1 AND id = $2")
        .bind(org_id)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|err| {
            if foreign_key_in_use(&err) {
                conflict("priority_in_use", "cases still use this priority")
            } else {
                err.into()
            }
        })?;
    record(
        &mut tx,
        org_id,
        actor,
        "case_priority.deleted",
        "case_priority",
        id,
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct CustomField {
    pub id: Uuid,
    pub key: String,
    pub label: String,
    pub field_type: String,
    pub options: Vec<String>,
    pub required: bool,
    pub position: i32,
    pub archived_at: Option<chrono::DateTime<chrono::Utc>>,
}

macro_rules! field_columns {
    () => {
        "id, key, label, field_type, options, required, position, archived_at"
    };
}

pub async fn list_custom_fields(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
) -> ServiceResult<Vec<CustomField>> {
    require_member(conn, org_id, actor).await?;
    Ok(sqlx::query_as(concat!(
        "SELECT ",
        field_columns!(),
        " FROM custom_field_definitions WHERE org_id = $1 ORDER BY position, key"
    ))
    .bind(org_id)
    .fetch_all(conn)
    .await?)
}

#[derive(Debug, Clone, Deserialize)]
pub struct CustomFieldInput {
    pub key: Option<String>,
    pub label: Option<String>,
    pub field_type: Option<String>,
    pub options: Option<Vec<String>>,
    pub required: Option<bool>,
    pub position: Option<i32>,
    pub archived: Option<bool>,
}

pub async fn save_custom_field(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    existing: Option<Uuid>,
    input: CustomFieldInput,
) -> ServiceResult<CustomField> {
    let label = input
        .label
        .as_deref()
        .map(|l| text("label", l, 100))
        .transpose()?;
    if let Some(options) = &input.options
        && (options.len() > 100
            || options
                .iter()
                .any(|o| o.trim().is_empty() || o.chars().count() > 100))
    {
        return Err(invalid(
            "options",
            "must be at most 100 values of 1-100 characters",
        ));
    }
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::OrganizationManage).await?;
    let id = match existing {
        Some(id) => {
            let updated = sqlx::query(
                "UPDATE custom_field_definitions SET label = coalesce($3, label), options = coalesce($4, options),
                     required = coalesce($5, required), position = coalesce($6, position),
                     archived_at = CASE WHEN $7 IS NULL THEN archived_at WHEN $7 THEN coalesce(archived_at, now()) ELSE NULL END
                 WHERE org_id = $1 AND id = $2",
            )
            .bind(org_id)
            .bind(id)
            .bind(&label)
            .bind(&input.options)
            .bind(input.required)
            .bind(input.position)
            .bind(input.archived)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if updated == 0 {
                return Err(ServiceError::NotFound);
            }
            id
        }
        None => {
            let key = input.key.as_deref().unwrap_or_default();
            check_key("key", key)?;
            let field_type = input.field_type.as_deref().unwrap_or_default();
            if !FIELD_TYPES.contains(&field_type) {
                return Err(invalid(
                    "field_type",
                    "must be text, number, boolean, date, or select",
                ));
            }
            let options = input.options.clone().unwrap_or_default();
            if field_type == "select" && options.is_empty() {
                return Err(invalid("options", "are required for select fields"));
            }
            let id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO custom_field_definitions (id, org_id, key, label, field_type, options, required, position)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(id)
            .bind(org_id)
            .bind(key)
            .bind(label.as_deref().unwrap_or(key))
            .bind(field_type)
            .bind(&options)
            .bind(input.required.unwrap_or(false))
            .bind(input.position.unwrap_or(0))
            .execute(&mut *tx)
            .await
            .map_err(|err| {
                if unique_violation(&err, "custom_field_definitions_org_id_key_key") {
                    conflict("key_taken", "a field with this key already exists")
                } else {
                    err.into()
                }
            })?;
            id
        }
    };
    record(
        &mut tx,
        org_id,
        actor,
        "custom_field.saved",
        "custom_field",
        id,
        json!({ "label": label }),
    )
    .await?;
    let field = sqlx::query_as(concat!(
        "SELECT ",
        field_columns!(),
        " FROM custom_field_definitions WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(field)
}

pub(crate) async fn validate_custom_fields(
    conn: &mut PgConnection,
    org_id: Uuid,
    input: &Map<String, Value>,
    current: Option<&Value>,
) -> ServiceResult<Value> {
    let defs: Vec<CustomField> = sqlx::query_as(concat!(
        "SELECT ",
        field_columns!(),
        " FROM custom_field_definitions WHERE org_id = $1 AND archived_at IS NULL"
    ))
    .bind(org_id)
    .fetch_all(conn)
    .await?;
    let mut out = current
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (key, value) in input {
        let def = defs.iter().find(|d| &d.key == key).ok_or(invalid(
            "custom_fields",
            "contains a field that is not defined",
        ))?;
        if value.is_null() {
            out.remove(key);
            continue;
        }
        let ok = match def.field_type.as_str() {
            "text" => value.as_str().is_some_and(|s| s.chars().count() <= 1000),
            "number" => value.as_f64().is_some_and(f64::is_finite),
            "boolean" => value.is_boolean(),
            "date" => value
                .as_str()
                .is_some_and(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()),
            "select" => value
                .as_str()
                .is_some_and(|s| def.options.iter().any(|o| o == s)),
            _ => false,
        };
        if !ok {
            return Err(invalid(
                "custom_fields",
                "contains a value of the wrong type",
            ));
        }
        out.insert(key.clone(), value.clone());
    }
    if defs.iter().any(|d| d.required && !out.contains_key(&d.key)) {
        return Err(invalid("custom_fields", "is missing a required field"));
    }
    Ok(Value::Object(out))
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SlaPolicy {
    pub id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub priority_id: Uuid,
    pub first_response_minutes: Option<i32>,
    pub resolution_minutes: Option<i32>,
}

pub async fn list_sla(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
) -> ServiceResult<Vec<SlaPolicy>> {
    require_member(conn, org_id, actor).await?;
    Ok(sqlx::query_as(
        "SELECT id, workspace_id, priority_id, first_response_minutes, resolution_minutes
         FROM sla_policies WHERE org_id = $1 ORDER BY created_at",
    )
    .bind(org_id)
    .fetch_all(conn)
    .await?)
}

#[derive(Debug, Clone, Deserialize)]
pub struct SlaInput {
    pub workspace_id: Option<Uuid>,
    pub priority_id: Uuid,
    pub first_response_minutes: Option<i32>,
    pub resolution_minutes: Option<i32>,
}

pub async fn save_sla(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    input: SlaInput,
) -> ServiceResult<SlaPolicy> {
    let in_range = |m: Option<i32>| m.is_none_or(|m| (1..=525_600).contains(&m));
    if !in_range(input.first_response_minutes) || !in_range(input.resolution_minutes) {
        return Err(invalid(
            "resolution_minutes",
            "must be between 1 minute and 1 year",
        ));
    }
    if input.first_response_minutes.is_none() && input.resolution_minutes.is_none() {
        return Err(invalid(
            "resolution_minutes",
            "set a first response or resolution target",
        ));
    }
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::OrganizationManage).await?;
    let policy: SlaPolicy = sqlx::query_as(
        "INSERT INTO sla_policies (id, org_id, workspace_id, priority_id, first_response_minutes, resolution_minutes)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (org_id, workspace_id, priority_id) DO UPDATE
             SET first_response_minutes = EXCLUDED.first_response_minutes,
                 resolution_minutes = EXCLUDED.resolution_minutes
         RETURNING id, workspace_id, priority_id, first_response_minutes, resolution_minutes",
    )
    .bind(Uuid::now_v7())
    .bind(org_id)
    .bind(input.workspace_id)
    .bind(input.priority_id)
    .bind(input.first_response_minutes)
    .bind(input.resolution_minutes)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| {
        if foreign_key_in_use(&err) {
            invalid("priority_id", "or workspace_id is not in this organization")
        } else {
            err.into()
        }
    })?;
    record(
        &mut tx,
        org_id,
        actor,
        "sla_policy.saved",
        "sla_policy",
        policy.id,
        json!({ "first_response_minutes": policy.first_response_minutes, "resolution_minutes": policy.resolution_minutes }),
    )
    .await?;
    tx.commit().await?;
    Ok(policy)
}

pub async fn delete_sla(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> ServiceResult<()> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::OrganizationManage).await?;
    let deleted = sqlx::query("DELETE FROM sla_policies WHERE org_id = $1 AND id = $2")
        .bind(org_id)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Err(ServiceError::NotFound);
    }
    record(
        &mut tx,
        org_id,
        actor,
        "sla_policy.deleted",
        "sla_policy",
        id,
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn apply_sla(
    conn: &mut PgConnection,
    org_id: Uuid,
    case_id: Uuid,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE cases c SET
             first_response_due_at = c.created_at + make_interval(mins => sp.first_response_minutes),
             resolution_due_at = c.created_at + make_interval(mins => sp.resolution_minutes)
         FROM cases base
         LEFT JOIN LATERAL (
             SELECT first_response_minutes, resolution_minutes FROM sla_policies
             WHERE org_id = base.org_id AND priority_id = base.priority_id
               AND (workspace_id = base.workspace_id OR workspace_id IS NULL)
             ORDER BY workspace_id NULLS LAST LIMIT 1
         ) sp ON true
         WHERE base.id = c.id AND c.org_id = $1 AND c.id = $2",
    )
    .bind(org_id)
    .bind(case_id)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn mark_breaches(pool: &PgPool) -> sqlx::Result<usize> {
    let mut tx = pool.begin().await?;
    let breached: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "UPDATE cases c SET sla_breached_at = now()
         FROM case_statuses s
         WHERE s.id = c.status_id AND c.sla_breached_at IS NULL AND c.deleted_at IS NULL
           AND s.category NOT IN ('resolved', 'closed')
           AND ((c.first_response_due_at < now() AND c.first_response_at IS NULL)
                OR (c.resolution_due_at < now() AND c.resolved_at IS NULL))
         RETURNING c.org_id, c.id",
    )
    .fetch_all(&mut *tx)
    .await?;
    for (org_id, case_id) in &breached {
        events::emit(
            &mut tx,
            *org_id,
            "case.sla_breached",
            "case",
            *case_id,
            json!({ "case_id": case_id }),
            Cause::default(),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(breached.len())
}
