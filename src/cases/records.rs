use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::Actor;
use crate::cases::HistoryEntry;
use crate::cases::contacts;
use crate::identity::orgs::require_member;
use crate::platform::authz::{self, Permission, WorkspaceScope};
use crate::platform::error::{ServiceError, ServiceResult, invalid, text};
use crate::platform::events::{self, Cause};
use crate::platform::page::Page;

pub const CHANNELS: &[&str] = &["web", "email", "chat", "api", "social"];
const MAX_TAGS: usize = 30;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Case {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub number: i64,
    pub subject: String,
    pub description: String,
    pub status_id: Uuid,
    pub status: String,
    pub status_category: String,
    pub priority_id: Uuid,
    pub priority: String,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub requester_contact_id: Uuid,
    pub team_id: Option<Uuid>,
    pub assignee_user_id: Option<Uuid>,
    pub source_channel: String,
    pub first_response_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub closed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

macro_rules! case_select {
    () => {
        "SELECT c.id, c.workspace_id, c.number, c.subject, c.description, c.status_id, s.key AS status,
                s.category AS status_category, c.priority_id, p.key AS priority, c.category, c.tags,
                c.requester_contact_id, c.team_id, c.assignee_user_id, c.source_channel,
                c.first_response_at, c.resolved_at, c.closed_at, c.created_at, c.updated_at
         FROM cases c
         JOIN case_statuses s ON s.id = c.status_id
         JOIN case_priorities p ON p.id = c.priority_id
         JOIN workspaces w ON w.id = c.workspace_id AND w.deleted_at IS NULL"
    };
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CaseFilter {
    pub workspace_id: Option<Uuid>,
    #[serde(default, deserialize_with = "csv")]
    pub status: Vec<String>,
    pub status_category: Option<String>,
    #[serde(default, deserialize_with = "csv")]
    pub priority: Vec<String>,
    pub team_id: Option<Uuid>,
    pub assignee_user_id: Option<Uuid>,
    #[serde(default)]
    pub unassigned: bool,
    #[serde(default, deserialize_with = "csv")]
    pub tags: Vec<String>,
    pub requester_contact_id: Option<Uuid>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
    pub q: Option<String>,
}

fn csv<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default())
}

fn nonempty(values: &[String]) -> Option<&[String]> {
    (!values.is_empty()).then_some(values)
}

pub async fn list(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    filter: &CaseFilter,
    page: Page,
) -> ServiceResult<Vec<Case>> {
    require_member(conn, org_id, actor).await?;
    let scope = authz::workspaces_with(conn, org_id, actor, Permission::CasesRead).await?;
    if scope == WorkspaceScope::Only(Vec::new()) {
        return Err(ServiceError::Forbidden);
    }
    let q = filter.q.as_deref().map(str::trim).filter(|q| !q.is_empty());
    if q.is_some_and(|q| q.len() > 200) {
        return Err(invalid("q", "is too long"));
    }
    Ok(sqlx::query_as(concat!(
        case_select!(),
        " WHERE c.org_id = $1 AND c.deleted_at IS NULL
           AND ($2::uuid[] IS NULL OR c.workspace_id = ANY($2))
           AND ($3::uuid IS NULL OR c.workspace_id = $3)
           AND ($4::text[] IS NULL OR s.key = ANY($4))
           AND ($5::text IS NULL OR s.category = $5)
           AND ($6::text[] IS NULL OR p.key = ANY($6))
           AND ($7::uuid IS NULL OR c.team_id = $7)
           AND ($8::uuid IS NULL OR c.assignee_user_id = $8)
           AND (NOT $9 OR c.assignee_user_id IS NULL)
           AND ($10::text[] IS NULL OR c.tags @> $10)
           AND ($11::uuid IS NULL OR c.requester_contact_id = $11)
           AND ($12::timestamptz IS NULL OR c.created_at >= $12)
           AND ($13::timestamptz IS NULL OR c.created_at < $13)
           AND ($14::text IS NULL OR c.search_vector @@ websearch_to_tsquery('simple', $14))
           AND ($15::uuid IS NULL OR c.id < $15)
         ORDER BY c.id DESC LIMIT $16"
    ))
    .bind(org_id)
    .bind(scope.ids())
    .bind(filter.workspace_id)
    .bind(nonempty(&filter.status))
    .bind(filter.status_category.as_deref())
    .bind(nonempty(&filter.priority))
    .bind(filter.team_id)
    .bind(filter.assignee_user_id)
    .bind(filter.unassigned)
    .bind(nonempty(&filter.tags))
    .bind(filter.requester_contact_id)
    .bind(filter.created_after)
    .bind(filter.created_before)
    .bind(q)
    .bind(page.cursor)
    .bind(page.limit + 1)
    .fetch_all(conn)
    .await?)
}

pub(crate) async fn load(
    conn: &mut PgConnection,
    org_id: Uuid,
    case_id: Uuid,
    lock: bool,
) -> ServiceResult<Case> {
    let sql = if lock {
        concat!(
            case_select!(),
            " WHERE c.org_id = $1 AND c.id = $2 AND c.deleted_at IS NULL FOR UPDATE OF c"
        )
    } else {
        concat!(
            case_select!(),
            " WHERE c.org_id = $1 AND c.id = $2 AND c.deleted_at IS NULL"
        )
    };
    sqlx::query_as(sql)
        .bind(org_id)
        .bind(case_id)
        .fetch_optional(conn)
        .await?
        .ok_or(ServiceError::NotFound)
}

pub async fn get(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    case_id: Uuid,
) -> ServiceResult<Case> {
    let case = load(conn, org_id, case_id, false).await?;
    readable(conn, org_id, actor, &case).await?;
    Ok(case)
}

pub(crate) async fn readable(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    case: &Case,
) -> ServiceResult<()> {
    authz::require_in(
        conn,
        org_id,
        Some(case.workspace_id),
        actor,
        Permission::CasesRead,
    )
    .await
    .map_err(|_| ServiceError::NotFound)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Requester {
    Existing { contact_id: Uuid },
    Email { email: String, name: Option<String> },
}

#[derive(Debug, Clone, Deserialize)]
pub struct NewCase {
    pub workspace_id: Uuid,
    pub subject: String,
    #[serde(default)]
    pub description: String,
    pub requester: Requester,
    pub status: Option<String>,
    pub priority: Option<String>,
    pub category: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub team_id: Option<Uuid>,
    pub assignee_user_id: Option<Uuid>,
    pub source_channel: Option<String>,
}

pub async fn create(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    new: NewCase,
    cause: Cause,
) -> ServiceResult<Case> {
    let subject = text("subject", &new.subject, 500)?;
    if new.description.chars().count() > 100_000 {
        return Err(invalid("description", "is too long"));
    }
    let tags = normalize_tags(&new.tags)?;
    let category = new
        .category
        .as_deref()
        .map(|c| text("category", c, 100))
        .transpose()?;
    let channel = new.source_channel.as_deref().unwrap_or("api");
    if !CHANNELS.contains(&channel) {
        return Err(invalid("source_channel", "is not a known channel"));
    }

    let mut tx = conn.begin().await?;
    workspace_open(&mut tx, org_id, new.workspace_id).await?;
    authz::require_in(
        &mut tx,
        org_id,
        Some(new.workspace_id),
        actor,
        Permission::CasesCreate,
    )
    .await?;
    if new.team_id.is_some() || new.assignee_user_id.is_some() {
        authz::require_in(
            &mut tx,
            org_id,
            Some(new.workspace_id),
            actor,
            Permission::CasesAssign,
        )
        .await?;
    }
    if let Some(team_id) = new.team_id {
        check_team(&mut tx, org_id, new.workspace_id, team_id).await?;
    }
    if let Some(user_id) = new.assignee_user_id {
        check_assignee(&mut tx, org_id, new.workspace_id, user_id).await?;
    }
    let status_id = status_id(&mut tx, org_id, new.status.as_deref()).await?;
    let priority_id = priority_id(&mut tx, org_id, new.priority.as_deref()).await?;
    let contact_id = match &new.requester {
        Requester::Existing { contact_id } => {
            contacts::load(&mut tx, org_id, *contact_id).await?;
            *contact_id
        }
        Requester::Email { email, name } => {
            contacts::find_or_create(&mut tx, org_id, email, name.as_deref(), None, cause).await?
        }
    };
    let number: i64 = sqlx::query_scalar(
        "UPDATE case_number_counters SET last_value = last_value + 1 WHERE org_id = $1 RETURNING last_value",
    )
    .bind(org_id)
    .fetch_one(&mut *tx)
    .await?;

    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO cases (id, org_id, workspace_id, number, subject, description, status_id, priority_id,
                            category, tags, requester_contact_id, team_id, assignee_user_id, source_channel)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(id)
    .bind(org_id)
    .bind(new.workspace_id)
    .bind(number)
    .bind(&subject)
    .bind(new.description.trim())
    .bind(status_id)
    .bind(priority_id)
    .bind(&category)
    .bind(&tags)
    .bind(contact_id)
    .bind(new.team_id)
    .bind(new.assignee_user_id)
    .bind(channel)
    .execute(&mut *tx)
    .await?;

    history(
        &mut tx,
        org_id,
        id,
        actor,
        "created",
        json!({ "number": number, "source_channel": channel }),
    )
    .await?;
    events::emit(
        &mut tx,
        org_id,
        "case.created",
        "case",
        id,
        json!({ "case_id": id, "number": number, "workspace_id": new.workspace_id }),
        cause,
    )
    .await?;
    let case = load(&mut tx, org_id, id, false).await?;
    tx.commit().await?;
    Ok(case)
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CaseChanges {
    pub subject: Option<String>,
    pub description: Option<String>,
    pub status: Option<String>,
    pub priority: Option<String>,
    #[serde(default, deserialize_with = "double")]
    pub category: Option<Option<String>>,
    pub tags: Option<Vec<String>>,
    #[serde(default, deserialize_with = "double")]
    pub team_id: Option<Option<Uuid>>,
    #[serde(default, deserialize_with = "double")]
    pub assignee_user_id: Option<Option<Uuid>>,
}

fn double<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

pub async fn update(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    case_id: Uuid,
    changes: CaseChanges,
    cause: Cause,
) -> ServiceResult<Case> {
    let mut tx = conn.begin().await?;
    let before = load(&mut tx, org_id, case_id, true).await?;
    readable(&mut tx, org_id, actor, &before).await?;
    let ws = Some(before.workspace_id);
    let mut diff = serde_json::Map::new();

    let edits = changes.subject.is_some()
        || changes.description.is_some()
        || changes.priority.is_some()
        || changes.category.is_some()
        || changes.tags.is_some()
        || changes.status.is_some();
    if edits {
        authz::require_in(&mut tx, org_id, ws, actor, Permission::CasesEdit).await?;
    }
    if changes.team_id.is_some() || changes.assignee_user_id.is_some() {
        authz::require_in(&mut tx, org_id, ws, actor, Permission::CasesAssign).await?;
    }

    let subject = changes
        .subject
        .as_deref()
        .map(|s| text("subject", s, 500))
        .transpose()?;
    if changes
        .description
        .as_ref()
        .is_some_and(|d| d.chars().count() > 100_000)
    {
        return Err(invalid("description", "is too long"));
    }
    let category = match &changes.category {
        Some(Some(c)) => Some(Some(text("category", c, 100)?)),
        Some(None) => Some(None),
        None => None,
    };
    let tags = changes.tags.as_deref().map(normalize_tags).transpose()?;

    let new_status = match changes.status.as_deref() {
        Some(key) => {
            let (id, category): (Uuid, String) = sqlx::query_as(
                "SELECT id, category FROM case_statuses WHERE org_id = $1 AND key = $2",
            )
            .bind(org_id)
            .bind(key)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(invalid("status", "is not a status in this organization"))?;
            let closing = matches!(category.as_str(), "resolved" | "closed");
            let reopening =
                matches!(before.status_category.as_str(), "resolved" | "closed") && !closing;
            if (closing || reopening) && id != before.status_id {
                authz::require_in(&mut tx, org_id, ws, actor, Permission::CasesResolve).await?;
            }
            (id != before.status_id).then_some((id, key.to_string(), category))
        }
        None => None,
    };
    let new_priority = match changes.priority.as_deref() {
        Some(key) => Some(priority_id(&mut tx, org_id, Some(key)).await?),
        None => None,
    };
    if let Some(Some(team_id)) = changes.team_id {
        check_team(&mut tx, org_id, before.workspace_id, team_id).await?;
    }
    if let Some(Some(user_id)) = changes.assignee_user_id {
        check_assignee(&mut tx, org_id, before.workspace_id, user_id).await?;
    }

    sqlx::query(
        "UPDATE cases SET
             subject = coalesce($3, subject),
             description = coalesce($4, description),
             status_id = coalesce($5, status_id),
             priority_id = coalesce($6, priority_id),
             category = CASE WHEN $7 THEN $8 ELSE category END,
             tags = coalesce($9, tags),
             team_id = CASE WHEN $10 THEN $11 ELSE team_id END,
             assignee_user_id = CASE WHEN $12 THEN $13 ELSE assignee_user_id END,
             resolved_at = CASE
                 WHEN $14::text IN ('resolved', 'closed') THEN coalesce(resolved_at, now())
                 WHEN $14::text IS NOT NULL THEN NULL
                 ELSE resolved_at END,
             closed_at = CASE
                 WHEN $14::text = 'closed' THEN coalesce(closed_at, now())
                 WHEN $14::text IS NOT NULL THEN NULL
                 ELSE closed_at END
         WHERE org_id = $1 AND id = $2",
    )
    .bind(org_id)
    .bind(case_id)
    .bind(&subject)
    .bind(changes.description.as_deref().map(str::trim))
    .bind(new_status.as_ref().map(|(id, _, _)| *id))
    .bind(new_priority)
    .bind(category.is_some())
    .bind(category.clone().flatten())
    .bind(&tags)
    .bind(changes.team_id.is_some())
    .bind(changes.team_id.flatten())
    .bind(changes.assignee_user_id.is_some())
    .bind(changes.assignee_user_id.flatten())
    .bind(new_status.as_ref().map(|(_, _, c)| c.as_str()))
    .execute(&mut *tx)
    .await?;

    let after = load(&mut tx, org_id, case_id, false).await?;
    let mut field = |name: &str, from: Value, to: Value| {
        if from != to {
            diff.insert(name.into(), json!({ "from": from, "to": to }));
        }
    };
    field("subject", json!(before.subject), json!(after.subject));
    field(
        "description",
        json!(before.description.len()),
        json!(after.description.len()),
    );
    field("status", json!(before.status), json!(after.status));
    field("priority", json!(before.priority), json!(after.priority));
    field("category", json!(before.category), json!(after.category));
    field("tags", json!(before.tags), json!(after.tags));
    field("team_id", json!(before.team_id), json!(after.team_id));
    field(
        "assignee_user_id",
        json!(before.assignee_user_id),
        json!(after.assignee_user_id),
    );

    if !diff.is_empty() {
        let data = Value::Object(diff.clone());
        history(&mut tx, org_id, case_id, actor, "updated", data.clone()).await?;
        events::emit(
            &mut tx,
            org_id,
            "case.updated",
            "case",
            case_id,
            json!({ "case_id": case_id, "changes": data }),
            cause,
        )
        .await?;
        if diff.contains_key("status") {
            events::emit(
                &mut tx,
                org_id,
                "case.status_changed",
                "case",
                case_id,
                json!({ "case_id": case_id, "from": before.status, "to": after.status }),
                cause,
            )
            .await?;
        }
        if diff.contains_key("assignee_user_id") || diff.contains_key("team_id") {
            events::emit(
                &mut tx,
                org_id,
                "case.assigned",
                "case",
                case_id,
                json!({ "case_id": case_id, "assignee_user_id": after.assignee_user_id, "team_id": after.team_id }),
                cause,
            )
            .await?;
        }
    }
    tx.commit().await?;
    Ok(after)
}

pub async fn history_list(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    case_id: Uuid,
    page: Page,
) -> ServiceResult<Vec<HistoryEntry>> {
    get(conn, org_id, actor, case_id).await?;
    Ok(sqlx::query_as(
        "SELECT id, kind, actor_kind, actor_id, data, occurred_at FROM case_events
         WHERE org_id = $1 AND case_id = $2 AND ($3::uuid IS NULL OR id < $3)
         ORDER BY id DESC LIMIT $4",
    )
    .bind(org_id)
    .bind(case_id)
    .bind(page.cursor)
    .bind(page.limit + 1)
    .fetch_all(conn)
    .await?)
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct CaseLink {
    pub linked_case_id: Uuid,
    pub kind: String,
    pub created_at: DateTime<Utc>,
}

pub async fn links(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    case_id: Uuid,
) -> ServiceResult<Vec<CaseLink>> {
    get(conn, org_id, actor, case_id).await?;
    Ok(sqlx::query_as(
        "SELECT linked_case_id, kind, created_at FROM case_links WHERE org_id = $1 AND case_id = $2
         UNION ALL
         SELECT case_id, CASE WHEN kind = 'duplicate_of' THEN 'duplicated_by' ELSE kind END, created_at
         FROM case_links WHERE org_id = $1 AND linked_case_id = $2
         ORDER BY created_at",
    )
    .bind(org_id)
    .bind(case_id)
    .fetch_all(conn)
    .await?)
}

pub async fn set_link(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    case_id: Uuid,
    linked_case_id: Uuid,
    kind: &str,
    linked: bool,
) -> ServiceResult<()> {
    if !matches!(kind, "related" | "duplicate_of") {
        return Err(invalid("kind", "must be related or duplicate_of"));
    }
    if case_id == linked_case_id {
        return Err(invalid("linked_case_id", "must be a different case"));
    }
    let mut tx = conn.begin().await?;
    for id in [case_id, linked_case_id] {
        let case = load(&mut tx, org_id, id, false).await?;
        readable(&mut tx, org_id, actor, &case).await?;
        authz::require_in(
            &mut tx,
            org_id,
            Some(case.workspace_id),
            actor,
            Permission::CasesEdit,
        )
        .await?;
    }
    if linked {
        sqlx::query(
            "INSERT INTO case_links (org_id, case_id, linked_case_id, kind) VALUES ($1, $2, $3, $4)
             ON CONFLICT DO NOTHING",
        )
        .bind(org_id)
        .bind(case_id)
        .bind(linked_case_id)
        .bind(kind)
        .execute(&mut *tx)
        .await?;
    } else {
        sqlx::query("DELETE FROM case_links WHERE org_id = $1 AND case_id = $2 AND linked_case_id = $3 AND kind = $4")
            .bind(org_id)
            .bind(case_id)
            .bind(linked_case_id)
            .bind(kind)
            .execute(&mut *tx)
            .await?;
    }
    history(
        &mut tx,
        org_id,
        case_id,
        actor,
        if linked { "linked" } else { "unlinked" },
        json!({ "linked_case_id": linked_case_id, "kind": kind }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn history(
    conn: &mut PgConnection,
    org_id: Uuid,
    case_id: Uuid,
    actor: Actor,
    kind: &str,
    data: Value,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO case_events (id, org_id, case_id, kind, actor_kind, actor_id, data)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(Uuid::now_v7())
    .bind(org_id)
    .bind(case_id)
    .bind(kind)
    .bind(actor.kind())
    .bind(actor.id())
    .bind(data)
    .execute(conn)
    .await?;
    Ok(())
}

pub(crate) async fn workspace_open(
    conn: &mut PgConnection,
    org_id: Uuid,
    workspace_id: Uuid,
) -> ServiceResult<()> {
    let open: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM workspaces WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL)",
    )
    .bind(org_id)
    .bind(workspace_id)
    .fetch_one(conn)
    .await?;
    if open {
        Ok(())
    } else {
        Err(invalid(
            "workspace_id",
            "is not a workspace in this organization",
        ))
    }
}

async fn check_team(
    conn: &mut PgConnection,
    org_id: Uuid,
    workspace_id: Uuid,
    team_id: Uuid,
) -> ServiceResult<()> {
    let ok: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM teams WHERE org_id = $1 AND id = $2 AND workspace_id = $3 AND archived_at IS NULL)",
    )
    .bind(org_id)
    .bind(team_id)
    .bind(workspace_id)
    .fetch_one(conn)
    .await?;
    if ok {
        Ok(())
    } else {
        Err(invalid(
            "team_id",
            "is not an active team in this workspace",
        ))
    }
}

async fn check_assignee(
    conn: &mut PgConnection,
    org_id: Uuid,
    workspace_id: Uuid,
    user_id: Uuid,
) -> ServiceResult<()> {
    let held = authz::effective_permissions(conn, org_id, user_id, Some(workspace_id)).await?;
    if held.contains(&Permission::CasesRead) {
        Ok(())
    } else {
        Err(invalid(
            "assignee_user_id",
            "must be an active member who can read cases in this workspace",
        ))
    }
}

pub(crate) async fn status_id(
    conn: &mut PgConnection,
    org_id: Uuid,
    key: Option<&str>,
) -> ServiceResult<Uuid> {
    sqlx::query_scalar(
        "SELECT id FROM case_statuses WHERE org_id = $1 AND (key = $2 OR ($2 IS NULL AND is_default))",
    )
    .bind(org_id)
    .bind(key)
    .fetch_optional(conn)
    .await?
    .ok_or(invalid("status", "is not a status in this organization"))
}

pub(crate) async fn priority_id(
    conn: &mut PgConnection,
    org_id: Uuid,
    key: Option<&str>,
) -> ServiceResult<Uuid> {
    sqlx::query_scalar(
        "SELECT id FROM case_priorities WHERE org_id = $1 AND (key = $2 OR ($2 IS NULL AND is_default))",
    )
    .bind(org_id)
    .bind(key)
    .fetch_optional(conn)
    .await?
    .ok_or(invalid("priority", "is not a priority in this organization"))
}

pub(crate) fn normalize_tags(tags: &[String]) -> ServiceResult<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for tag in tags {
        let tag = tag.trim().to_lowercase();
        let valid = (1..=50).contains(&tag.len())
            && tag
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':' | '.'));
        if !valid {
            return Err(invalid(
                "tags",
                "must be 1-50 letters, digits, '-', '_', ':' or '.'",
            ));
        }
        if !out.contains(&tag) {
            out.push(tag);
        }
    }
    if out.len() > MAX_TAGS {
        return Err(invalid("tags", "has too many entries"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::normalize_tags;

    #[test]
    fn tags_are_normalized_and_validated() {
        assert_eq!(
            normalize_tags(&[" VIP ".into(), "vip".into(), "billing:refund".into()]).unwrap(),
            ["vip", "billing:refund"]
        );
        assert!(normalize_tags(&["has space".into()]).is_err());
        assert!(normalize_tags(&["".into()]).is_err());
    }
}
