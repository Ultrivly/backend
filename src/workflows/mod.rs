use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection, PgPool};
use uuid::Uuid;

use crate::audit::Actor;
use crate::cases::messages;
use crate::cases::records::{self, Case, CaseChanges, normalize_tags};
use crate::identity::orgs::record;
use crate::platform::authz::{self, Permission};
use crate::platform::error::{ServiceError, ServiceResult, invalid, text};
use crate::platform::events::{self, Cause, MAX_DEPTH};
use crate::platform::page::Page;

const MAX_RUNS_PER_HOUR: i64 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    CaseCreated,
    CaseUpdated,
    CaseStatusChanged,
    CaseAssigned,
    CaseMessageAdded,
}

impl Trigger {
    fn event_kind(self) -> &'static str {
        match self {
            Trigger::CaseCreated => "case.created",
            Trigger::CaseUpdated => "case.updated",
            Trigger::CaseStatusChanged => "case.status_changed",
            Trigger::CaseAssigned => "case.assigned",
            Trigger::CaseMessageAdded => "case.message_added",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Status,
    StatusCategory,
    Priority,
    SourceChannel,
    TeamId,
    AssigneeUserId,
    Tags,
    Subject,
    Category,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Eq,
    Neq,
    In,
    Contains,
    IsEmpty,
    IsNotEmpty,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub field: Field,
    pub op: Op,
    #[serde(default)]
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    SetStatus { status: String },
    SetPriority { priority: String },
    AddTags { tags: Vec<String> },
    RemoveTags { tags: Vec<String> },
    AssignTeam { team_id: Option<Uuid> },
    AssignUser { user_id: Option<Uuid> },
    AddNote { body: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    pub trigger: Trigger,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    pub actions: Vec<Action>,
}

impl Definition {
    fn validate(&self) -> ServiceResult<()> {
        if self.actions.is_empty() || self.actions.len() > 10 {
            return Err(invalid("definition", "must have between 1 and 10 actions"));
        }
        if self.conditions.len() > 20 {
            return Err(invalid("definition", "has too many conditions"));
        }
        for condition in &self.conditions {
            let needs_value = !matches!(condition.op, Op::IsEmpty | Op::IsNotEmpty);
            let ok = match condition.op {
                Op::In => condition.value.as_array().is_some_and(|a| !a.is_empty() && a.len() <= 50),
                _ if needs_value => condition.value.is_string(),
                _ => true,
            };
            if !ok {
                return Err(invalid("definition", "has a condition with an invalid value"));
            }
        }
        for action in &self.actions {
            match action {
                Action::AddTags { tags } | Action::RemoveTags { tags } => {
                    normalize_tags(tags)?;
                }
                Action::AddNote { body } if body.trim().is_empty() || body.chars().count() > 10_000 => {
                    return Err(invalid("definition", "has a note that is empty or too long"));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Workflow {
    pub id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub name: String,
    pub enabled: bool,
    pub published_version_id: Option<Uuid>,
    pub latest_version: i32,
    pub definition: Definition,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

type WorkflowRow = (Uuid, Option<Uuid>, String, bool, Option<Uuid>, i32, Value, DateTime<Utc>, DateTime<Utc>);

macro_rules! workflow_select {
    () => {
        "SELECT w.id, w.workspace_id, w.name, w.enabled, w.published_version_id, v.version, v.definition,
                w.created_at, w.updated_at
         FROM workflows w
         JOIN LATERAL (SELECT version, definition FROM workflow_versions
                       WHERE workflow_id = w.id ORDER BY version DESC LIMIT 1) v ON true"
    };
}

fn workflow_from(row: WorkflowRow) -> ServiceResult<Workflow> {
    let (id, workspace_id, name, enabled, published_version_id, latest_version, definition, created_at, updated_at) = row;
    Ok(Workflow {
        id,
        workspace_id,
        name,
        enabled,
        published_version_id,
        latest_version,
        definition: serde_json::from_value(definition).map_err(anyhow::Error::from)?,
        created_at,
        updated_at,
    })
}

pub async fn list(conn: &mut PgConnection, org_id: Uuid, actor: Actor) -> ServiceResult<Vec<Workflow>> {
    authz::require(conn, org_id, actor, Permission::WorkflowsManage).await?;
    let rows: Vec<WorkflowRow> = sqlx::query_as(concat!(workflow_select!(), " WHERE w.org_id = $1 ORDER BY w.name"))
        .bind(org_id)
        .fetch_all(conn)
        .await?;
    rows.into_iter().map(workflow_from).collect()
}

pub async fn get(conn: &mut PgConnection, org_id: Uuid, actor: Actor, id: Uuid) -> ServiceResult<Workflow> {
    authz::require(conn, org_id, actor, Permission::WorkflowsManage).await?;
    load(conn, org_id, id).await
}

async fn load(conn: &mut PgConnection, org_id: Uuid, id: Uuid) -> ServiceResult<Workflow> {
    let row: WorkflowRow = sqlx::query_as(concat!(workflow_select!(), " WHERE w.org_id = $1 AND w.id = $2"))
        .bind(org_id)
        .bind(id)
        .fetch_optional(conn)
        .await?
        .ok_or(ServiceError::NotFound)?;
    workflow_from(row)
}

async fn check_references(conn: &mut PgConnection, org_id: Uuid, definition: &Definition) -> ServiceResult<()> {
    for action in &definition.actions {
        let ok: bool = match action {
            Action::SetStatus { status } => {
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM case_statuses WHERE org_id = $1 AND key = $2)")
                    .bind(org_id)
                    .bind(status)
                    .fetch_one(&mut *conn)
                    .await?
            }
            Action::SetPriority { priority } => {
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM case_priorities WHERE org_id = $1 AND key = $2)")
                    .bind(org_id)
                    .bind(priority)
                    .fetch_one(&mut *conn)
                    .await?
            }
            Action::AssignTeam { team_id: Some(team_id) } => {
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM teams WHERE org_id = $1 AND id = $2)")
                    .bind(org_id)
                    .bind(team_id)
                    .fetch_one(&mut *conn)
                    .await?
            }
            Action::AssignUser { user_id: Some(user_id) } => {
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM memberships WHERE org_id = $1 AND user_id = $2)")
                    .bind(org_id)
                    .bind(user_id)
                    .fetch_one(&mut *conn)
                    .await?
            }
            _ => true,
        };
        if !ok {
            return Err(invalid("definition", "refers to a status, priority, team, or member that does not exist"));
        }
    }
    Ok(())
}

pub async fn create(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    name: &str,
    workspace_id: Option<Uuid>,
    definition: Definition,
) -> ServiceResult<Workflow> {
    let name = text("name", name, 200)?;
    definition.validate()?;
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::WorkflowsManage).await?;
    check_references(&mut tx, org_id, &definition).await?;
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO workflows (id, org_id, workspace_id, name) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(org_id)
        .bind(workspace_id)
        .bind(&name)
        .execute(&mut *tx)
        .await
        .map_err(|err| {
            if err.as_database_error().and_then(|e| e.code()).as_deref() == Some("23503") {
                invalid("workspace_id", "is not a workspace in this organization")
            } else {
                err.into()
            }
        })?;
    insert_version(&mut tx, org_id, id, 1, &definition, actor).await?;
    record(&mut tx, org_id, actor, "workflow.created", "workflow", id, json!({ "name": name })).await?;
    let workflow = load(&mut tx, org_id, id).await?;
    tx.commit().await?;
    Ok(workflow)
}

async fn insert_version(
    conn: &mut PgConnection,
    org_id: Uuid,
    workflow_id: Uuid,
    version: i32,
    definition: &Definition,
    actor: Actor,
) -> ServiceResult<Uuid> {
    let id = Uuid::now_v7();
    let created_by = match actor {
        Actor::User(id) => Some(id),
        _ => None,
    };
    sqlx::query(
        "INSERT INTO workflow_versions (id, org_id, workflow_id, version, definition, created_by)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(org_id)
    .bind(workflow_id)
    .bind(version)
    .bind(serde_json::to_value(definition).map_err(anyhow::Error::from)?)
    .bind(created_by)
    .execute(conn)
    .await?;
    Ok(id)
}

pub async fn update(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
    name: Option<&str>,
    definition: Option<Definition>,
) -> ServiceResult<Workflow> {
    let name = name.map(|n| text("name", n, 200)).transpose()?;
    if let Some(definition) = &definition {
        definition.validate()?;
    }
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::WorkflowsManage).await?;
    let current = load(&mut tx, org_id, id).await?;
    if let Some(name) = &name {
        sqlx::query("UPDATE workflows SET name = $3 WHERE org_id = $1 AND id = $2")
            .bind(org_id)
            .bind(id)
            .bind(name)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(definition) = &definition {
        check_references(&mut tx, org_id, definition).await?;
        insert_version(&mut tx, org_id, id, current.latest_version + 1, definition, actor).await?;
    }
    record(
        &mut tx,
        org_id,
        actor,
        "workflow.updated",
        "workflow",
        id,
        json!({ "name": name, "new_version": definition.is_some() }),
    )
    .await?;
    let workflow = load(&mut tx, org_id, id).await?;
    tx.commit().await?;
    Ok(workflow)
}

pub async fn set_enabled(conn: &mut PgConnection, org_id: Uuid, actor: Actor, id: Uuid, enabled: bool) -> ServiceResult<Workflow> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::WorkflowsPublish).await?;
    let updated = sqlx::query(
        "UPDATE workflows SET enabled = $3,
             published_version_id = CASE WHEN $3 THEN
                 (SELECT id FROM workflow_versions WHERE workflow_id = $2 ORDER BY version DESC LIMIT 1)
             ELSE published_version_id END
         WHERE org_id = $1 AND id = $2",
    )
    .bind(org_id)
    .bind(id)
    .bind(enabled)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if updated == 0 {
        return Err(ServiceError::NotFound);
    }
    record(
        &mut tx,
        org_id,
        actor,
        if enabled { "workflow.published" } else { "workflow.disabled" },
        "workflow",
        id,
        json!({}),
    )
    .await?;
    let workflow = load(&mut tx, org_id, id).await?;
    tx.commit().await?;
    Ok(workflow)
}

pub async fn delete(conn: &mut PgConnection, org_id: Uuid, actor: Actor, id: Uuid) -> ServiceResult<()> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::WorkflowsManage).await?;
    sqlx::query("SET CONSTRAINTS workflows_published_version_fkey DEFERRED")
        .execute(&mut *tx)
        .await?;
    let deleted = sqlx::query("DELETE FROM workflows WHERE org_id = $1 AND id = $2")
        .bind(org_id)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Err(ServiceError::NotFound);
    }
    record(&mut tx, org_id, actor, "workflow.deleted", "workflow", id, json!({})).await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Run {
    pub id: Uuid,
    pub version_id: Uuid,
    pub event_id: Uuid,
    pub case_id: Option<Uuid>,
    pub status: String,
    pub steps: Value,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub async fn runs(conn: &mut PgConnection, org_id: Uuid, actor: Actor, workflow_id: Uuid, page: Page) -> ServiceResult<Vec<Run>> {
    authz::require(conn, org_id, actor, Permission::WorkflowsManage).await?;
    Ok(sqlx::query_as(
        "SELECT id, version_id, event_id, case_id, status, steps, error, created_at FROM workflow_runs
         WHERE org_id = $1 AND workflow_id = $2 AND ($3::uuid IS NULL OR id < $3)
         ORDER BY id DESC LIMIT $4",
    )
    .bind(org_id)
    .bind(workflow_id)
    .bind(page.cursor)
    .bind(page.limit + 1)
    .fetch_all(conn)
    .await?)
}

fn field_value(case: &Case, field: Field) -> Value {
    match field {
        Field::Status => json!(case.status),
        Field::StatusCategory => json!(case.status_category),
        Field::Priority => json!(case.priority),
        Field::SourceChannel => json!(case.source_channel),
        Field::TeamId => json!(case.team_id),
        Field::AssigneeUserId => json!(case.assignee_user_id),
        Field::Tags => json!(case.tags),
        Field::Subject => json!(case.subject),
        Field::Category => json!(case.category),
    }
}

pub fn matches(case: &Case, condition: &Condition) -> bool {
    let actual = field_value(case, condition.field);
    let empty = actual.is_null() || actual.as_array().is_some_and(|a| a.is_empty()) || actual == json!("");
    let as_text = |v: &Value| v.as_str().map(|s| s.to_lowercase());
    match condition.op {
        Op::IsEmpty => empty,
        Op::IsNotEmpty => !empty,
        Op::Eq => actual == condition.value,
        Op::Neq => actual != condition.value,
        Op::In => condition.value.as_array().is_some_and(|options| options.contains(&actual)),
        Op::Contains => match (&actual, as_text(&condition.value)) {
            (Value::Array(items), _) => items.contains(&condition.value),
            (Value::String(s), Some(needle)) => s.to_lowercase().contains(&needle),
            _ => false,
        },
    }
}

pub async fn evaluate(pool: &PgPool, event_id: Uuid) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    let Some(event) = events::load(&mut conn, event_id).await? else {
        return Ok(());
    };
    if event.depth >= MAX_DEPTH || event.subject_type != "case" {
        return Ok(());
    }
    let recent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workflow_runs WHERE org_id = $1 AND created_at > now() - interval '1 hour'",
    )
    .bind(event.org_id)
    .fetch_one(&mut *conn)
    .await?;
    if recent >= MAX_RUNS_PER_HOUR {
        tracing::warn!(org_id = %event.org_id, "workflow run limit reached; skipping event");
        return Ok(());
    }
    let candidates: Vec<(Uuid, Option<Uuid>, Uuid, Value)> = sqlx::query_as(
        "SELECT w.id, w.workspace_id, v.id, v.definition FROM workflows w
         JOIN workflow_versions v ON v.id = w.published_version_id
         WHERE w.org_id = $1 AND w.enabled",
    )
    .bind(event.org_id)
    .fetch_all(&mut *conn)
    .await?;

    for (workflow_id, workspace_id, version_id, definition) in candidates {
        let Ok(definition) = serde_json::from_value::<Definition>(definition) else {
            continue;
        };
        if definition.trigger.event_kind() != event.kind {
            continue;
        }
        let run_id = Uuid::now_v7();
        let claimed = sqlx::query(
            "INSERT INTO workflow_runs (id, org_id, workflow_id, version_id, event_id, case_id, status)
             VALUES ($1, $2, $3, $4, $5, $6, 'skipped') ON CONFLICT (version_id, event_id) DO NOTHING",
        )
        .bind(run_id)
        .bind(event.org_id)
        .bind(workflow_id)
        .bind(version_id)
        .bind(event.id)
        .bind(event.subject_id)
        .execute(&mut *conn)
        .await?
        .rows_affected();
        if claimed == 0 {
            continue;
        }
        let actor = Actor::Workflow {
            id: workflow_id,
            org_id: event.org_id,
        };
        let case = match records::load(&mut conn, event.org_id, event.subject_id, false).await {
            Ok(case) => case,
            Err(_) => continue,
        };
        if workspace_id.is_some_and(|w| w != case.workspace_id)
            || !definition.conditions.iter().all(|c| matches(&case, c))
        {
            continue;
        }
        let cause = Cause::next(event.id, event.depth);
        let mut steps = Vec::new();
        let mut failure = None;
        for action in &definition.actions {
            match apply(&mut conn, event.org_id, actor, case.id, action, cause).await {
                Ok(()) => steps.push(json!({ "action": action, "status": "succeeded" })),
                Err(err) => {
                    steps.push(json!({ "action": action, "status": "failed", "error": err.to_string() }));
                    failure = Some(err.to_string());
                    break;
                }
            }
        }
        sqlx::query("UPDATE workflow_runs SET status = $2, steps = $3, error = $4 WHERE id = $1")
            .bind(run_id)
            .bind(if failure.is_some() { "failed" } else { "succeeded" })
            .bind(json!(steps))
            .bind(failure)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

async fn apply(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    case_id: Uuid,
    action: &Action,
    cause: Cause,
) -> ServiceResult<()> {
    let changes = match action {
        Action::SetStatus { status } => CaseChanges {
            status: Some(status.clone()),
            ..CaseChanges::default()
        },
        Action::SetPriority { priority } => CaseChanges {
            priority: Some(priority.clone()),
            ..CaseChanges::default()
        },
        Action::AddTags { tags } | Action::RemoveTags { tags } => {
            let current = records::load(conn, org_id, case_id, false).await?;
            let tags = normalize_tags(tags)?;
            let next: Vec<String> = if matches!(action, Action::AddTags { .. }) {
                current.tags.iter().cloned().chain(tags).collect()
            } else {
                current.tags.into_iter().filter(|t| !tags.contains(t)).collect()
            };
            CaseChanges {
                tags: Some(next),
                ..CaseChanges::default()
            }
        }
        Action::AssignTeam { team_id } => CaseChanges {
            team_id: Some(*team_id),
            ..CaseChanges::default()
        },
        Action::AssignUser { user_id } => CaseChanges {
            assignee_user_id: Some(*user_id),
            ..CaseChanges::default()
        },
        Action::AddNote { body } => {
            messages::add(conn, org_id, actor, case_id, "internal", body, Some("text"), cause).await?;
            return Ok(());
        }
    };
    records::update(conn, org_id, actor, case_id, changes, cause).await?;
    Ok(())
}
