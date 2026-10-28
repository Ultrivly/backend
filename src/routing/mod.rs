use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::Actor;
use crate::identity::orgs::{record, require_member};
use crate::platform::authz::{self, Permission};
use crate::platform::error::{
    ServiceError, ServiceResult, conflict, invalid, text, unique_violation,
};

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Department {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Team {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub department_id: Option<Uuid>,
    pub name: String,
    pub archived_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub member_user_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueCriteria {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statuses: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub priorities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unassigned: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Queue {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub team_id: Option<Uuid>,
    pub name: String,
    pub criteria: QueueCriteria,
    pub position: i32,
    pub created_at: DateTime<Utc>,
}

pub async fn list_departments(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
) -> ServiceResult<Vec<Department>> {
    require_member(conn, org_id, actor).await?;
    Ok(sqlx::query_as(
        "SELECT id, name, created_at FROM departments WHERE org_id = $1 ORDER BY name",
    )
    .bind(org_id)
    .fetch_all(conn)
    .await?)
}

pub async fn create_department(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    name: &str,
) -> ServiceResult<Department> {
    let name = text("name", name, 200)?;
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::TeamsManage).await?;
    let id = Uuid::now_v7();
    let department: Department = sqlx::query_as(
        "INSERT INTO departments (id, org_id, name) VALUES ($1, $2, $3) RETURNING id, name, created_at",
    )
    .bind(id)
    .bind(org_id)
    .bind(&name)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| map_unique(err, "departments_org_id_name_key"))?;
    record(
        &mut tx,
        org_id,
        actor,
        "department.created",
        "department",
        id,
        json!({ "name": name }),
    )
    .await?;
    tx.commit().await?;
    Ok(department)
}

pub async fn rename_department(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
    name: &str,
) -> ServiceResult<Department> {
    let name = text("name", name, 200)?;
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::TeamsManage).await?;
    let department: Department = sqlx::query_as(
        "UPDATE departments SET name = $3 WHERE org_id = $1 AND id = $2 RETURNING id, name, created_at",
    )
    .bind(org_id)
    .bind(id)
    .bind(&name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| map_unique(err, "departments_org_id_name_key"))?
    .ok_or(ServiceError::NotFound)?;
    record(
        &mut tx,
        org_id,
        actor,
        "department.updated",
        "department",
        id,
        json!({ "name": name }),
    )
    .await?;
    tx.commit().await?;
    Ok(department)
}

pub async fn delete_department(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> ServiceResult<()> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::TeamsManage).await?;
    let deleted = sqlx::query("DELETE FROM departments WHERE org_id = $1 AND id = $2")
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
        "department.deleted",
        "department",
        id,
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

macro_rules! team_select {
    () => {
        "SELECT t.id, t.workspace_id, t.department_id, t.name, t.archived_at, t.created_at,
                coalesce(array_agg(tm.user_id) FILTER (WHERE tm.user_id IS NOT NULL), '{}') AS member_user_ids
         FROM teams t LEFT JOIN team_members tm ON tm.team_id = t.id"
    };
}

pub async fn list_teams(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    workspace_id: Option<Uuid>,
) -> ServiceResult<Vec<Team>> {
    require_member(conn, org_id, actor).await?;
    Ok(sqlx::query_as(concat!(
        team_select!(),
        " WHERE t.org_id = $1 AND ($2::uuid IS NULL OR t.workspace_id = $2)
          GROUP BY t.id ORDER BY t.name"
    ))
    .bind(org_id)
    .bind(workspace_id)
    .fetch_all(conn)
    .await?)
}

pub async fn get_team(conn: &mut PgConnection, org_id: Uuid, id: Uuid) -> ServiceResult<Team> {
    sqlx::query_as(concat!(
        team_select!(),
        " WHERE t.org_id = $1 AND t.id = $2 GROUP BY t.id"
    ))
    .bind(org_id)
    .bind(id)
    .fetch_optional(conn)
    .await?
    .ok_or(ServiceError::NotFound)
}

pub struct NewTeam<'a> {
    pub workspace_id: Uuid,
    pub department_id: Option<Uuid>,
    pub name: &'a str,
}

pub async fn create_team(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    new: NewTeam<'_>,
) -> ServiceResult<Team> {
    let name = text("name", new.name, 200)?;
    let mut tx = conn.begin().await?;
    authz::require_in(
        &mut tx,
        org_id,
        Some(new.workspace_id),
        actor,
        Permission::TeamsManage,
    )
    .await?;
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO teams (id, org_id, workspace_id, department_id, name) VALUES ($1, $2, $3, $4, $5)")
        .bind(id)
        .bind(org_id)
        .bind(new.workspace_id)
        .bind(new.department_id)
        .bind(&name)
        .execute(&mut *tx)
        .await
        .map_err(|err| {
            if unique_violation(&err, "teams_workspace_id_name_key") {
                conflict("name_taken", "a team with this name already exists in the workspace")
            } else if err.as_database_error().and_then(|e| e.code()).as_deref() == Some("23503") {
                invalid("workspace_id", "or department_id does not exist in this organization")
            } else {
                err.into()
            }
        })?;
    record(
        &mut tx,
        org_id,
        actor,
        "team.created",
        "team",
        id,
        json!({ "name": name, "workspace_id": new.workspace_id }),
    )
    .await?;
    let team = get_team(&mut tx, org_id, id).await?;
    tx.commit().await?;
    Ok(team)
}

#[derive(Default)]
pub struct TeamChanges<'a> {
    pub name: Option<&'a str>,
    pub department_id: Option<Option<Uuid>>,
    pub archived: Option<bool>,
}

pub async fn update_team(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
    changes: TeamChanges<'_>,
) -> ServiceResult<Team> {
    let name = changes.name.map(|n| text("name", n, 200)).transpose()?;
    let mut tx = conn.begin().await?;
    let team = get_team(&mut tx, org_id, id).await?;
    authz::require_in(
        &mut tx,
        org_id,
        Some(team.workspace_id),
        actor,
        Permission::TeamsManage,
    )
    .await?;
    sqlx::query(
        "UPDATE teams SET name = coalesce($3, name),
             department_id = CASE WHEN $4 THEN $5 ELSE department_id END,
             archived_at = CASE WHEN $6 IS NULL THEN archived_at WHEN $6 THEN coalesce(archived_at, now()) ELSE NULL END
         WHERE org_id = $1 AND id = $2",
    )
    .bind(org_id)
    .bind(id)
    .bind(&name)
    .bind(changes.department_id.is_some())
    .bind(changes.department_id.flatten())
    .bind(changes.archived)
    .execute(&mut *tx)
    .await
    .map_err(|err| {
        if unique_violation(&err, "teams_workspace_id_name_key") {
            conflict("name_taken", "a team with this name already exists in the workspace")
        } else if err.as_database_error().and_then(|e| e.code()).as_deref() == Some("23503") {
            invalid("department_id", "does not exist in this organization")
        } else {
            err.into()
        }
    })?;
    record(
        &mut tx,
        org_id,
        actor,
        "team.updated",
        "team",
        id,
        json!({ "name": name, "department_id": changes.department_id, "archived": changes.archived }),
    )
    .await?;
    let team = get_team(&mut tx, org_id, id).await?;
    tx.commit().await?;
    Ok(team)
}

pub async fn set_team_member(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    team_id: Uuid,
    user_id: Uuid,
    member: bool,
) -> ServiceResult<Team> {
    let mut tx = conn.begin().await?;
    let team = get_team(&mut tx, org_id, team_id).await?;
    authz::require_in(
        &mut tx,
        org_id,
        Some(team.workspace_id),
        actor,
        Permission::TeamsManage,
    )
    .await?;
    if member {
        sqlx::query("INSERT INTO team_members (org_id, team_id, user_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
            .bind(org_id)
            .bind(team_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(|err| {
                if err.as_database_error().and_then(|e| e.code()).as_deref() == Some("23503") {
                    invalid("user_id", "is not a member of this organization")
                } else {
                    err.into()
                }
            })?;
    } else {
        sqlx::query("DELETE FROM team_members WHERE org_id = $1 AND team_id = $2 AND user_id = $3")
            .bind(org_id)
            .bind(team_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
    }
    record(
        &mut tx,
        org_id,
        actor,
        if member {
            "team.member_added"
        } else {
            "team.member_removed"
        },
        "team",
        team_id,
        json!({ "user_id": user_id }),
    )
    .await?;
    let team = get_team(&mut tx, org_id, team_id).await?;
    tx.commit().await?;
    Ok(team)
}

pub async fn delete_team(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> ServiceResult<()> {
    let mut tx = conn.begin().await?;
    let team = get_team(&mut tx, org_id, id).await?;
    authz::require_in(
        &mut tx,
        org_id,
        Some(team.workspace_id),
        actor,
        Permission::TeamsManage,
    )
    .await?;
    sqlx::query("DELETE FROM teams WHERE org_id = $1 AND id = $2")
        .bind(org_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    record(
        &mut tx,
        org_id,
        actor,
        "team.deleted",
        "team",
        id,
        json!({ "name": team.name }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

type QueueRow = (
    Uuid,
    Uuid,
    Option<Uuid>,
    String,
    serde_json::Value,
    i32,
    DateTime<Utc>,
);

fn queue_from(row: QueueRow) -> ServiceResult<Queue> {
    let (id, workspace_id, team_id, name, criteria, position, created_at) = row;
    Ok(Queue {
        id,
        workspace_id,
        team_id,
        name,
        criteria: serde_json::from_value(criteria).map_err(anyhow::Error::from)?,
        position,
        created_at,
    })
}

pub async fn list_queues(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    workspace_id: Option<Uuid>,
) -> ServiceResult<Vec<Queue>> {
    require_member(conn, org_id, actor).await?;
    let rows: Vec<QueueRow> = sqlx::query_as(
        "SELECT id, workspace_id, team_id, name, criteria, position, created_at FROM queues
         WHERE org_id = $1 AND ($2::uuid IS NULL OR workspace_id = $2) ORDER BY position, name",
    )
    .bind(org_id)
    .bind(workspace_id)
    .fetch_all(conn)
    .await?;
    rows.into_iter().map(queue_from).collect()
}

pub async fn get_queue(conn: &mut PgConnection, org_id: Uuid, id: Uuid) -> ServiceResult<Queue> {
    let row: QueueRow = sqlx::query_as(
        "SELECT id, workspace_id, team_id, name, criteria, position, created_at FROM queues
         WHERE org_id = $1 AND id = $2",
    )
    .bind(org_id)
    .bind(id)
    .fetch_optional(conn)
    .await?
    .ok_or(ServiceError::NotFound)?;
    queue_from(row)
}

pub struct QueueInput<'a> {
    pub workspace_id: Uuid,
    pub team_id: Option<Uuid>,
    pub name: &'a str,
    pub criteria: QueueCriteria,
    pub position: i32,
}

pub async fn save_queue(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    existing: Option<Uuid>,
    input: QueueInput<'_>,
) -> ServiceResult<Queue> {
    let name = text("name", input.name, 200)?;
    if input.criteria.tags.len() > 20
        || input.criteria.statuses.len() > 20
        || input.criteria.priorities.len() > 20
    {
        return Err(invalid("criteria", "has too many values"));
    }
    let mut tx = conn.begin().await?;
    authz::require_in(
        &mut tx,
        org_id,
        Some(input.workspace_id),
        actor,
        Permission::TeamsManage,
    )
    .await?;
    let id = existing.unwrap_or_else(Uuid::now_v7);
    let criteria = serde_json::to_value(&input.criteria).map_err(anyhow::Error::from)?;
    let result = if let Some(existing) = existing {
        let current = get_queue(&mut tx, org_id, existing).await?;
        authz::require_in(
            &mut tx,
            org_id,
            Some(current.workspace_id),
            actor,
            Permission::TeamsManage,
        )
        .await?;
        sqlx::query(
            "UPDATE queues SET workspace_id = $3, team_id = $4, name = $5, criteria = $6, position = $7
             WHERE org_id = $1 AND id = $2",
        )
        .bind(org_id)
        .bind(id)
        .bind(input.workspace_id)
        .bind(input.team_id)
        .bind(&name)
        .bind(&criteria)
        .bind(input.position)
        .execute(&mut *tx)
        .await
    } else {
        sqlx::query(
            "INSERT INTO queues (id, org_id, workspace_id, team_id, name, criteria, position)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(id)
        .bind(org_id)
        .bind(input.workspace_id)
        .bind(input.team_id)
        .bind(&name)
        .bind(&criteria)
        .bind(input.position)
        .execute(&mut *tx)
        .await
    };
    result.map_err(|err| {
        if unique_violation(&err, "queues_workspace_id_name_key") {
            conflict(
                "name_taken",
                "a queue with this name already exists in the workspace",
            )
        } else if err.as_database_error().and_then(|e| e.code()).as_deref() == Some("23503") {
            invalid(
                "workspace_id",
                "or team_id does not exist in this organization",
            )
        } else {
            err.into()
        }
    })?;
    record(
        &mut tx,
        org_id,
        actor,
        if existing.is_some() {
            "queue.updated"
        } else {
            "queue.created"
        },
        "queue",
        id,
        json!({ "name": name, "criteria": criteria }),
    )
    .await?;
    let queue = get_queue(&mut tx, org_id, id).await?;
    tx.commit().await?;
    Ok(queue)
}

pub async fn delete_queue(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> ServiceResult<()> {
    let mut tx = conn.begin().await?;
    let queue = get_queue(&mut tx, org_id, id).await?;
    authz::require_in(
        &mut tx,
        org_id,
        Some(queue.workspace_id),
        actor,
        Permission::TeamsManage,
    )
    .await?;
    sqlx::query("DELETE FROM queues WHERE org_id = $1 AND id = $2")
        .bind(org_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    record(
        &mut tx,
        org_id,
        actor,
        "queue.deleted",
        "queue",
        id,
        json!({ "name": queue.name }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

fn map_unique(err: sqlx::Error, constraint: &str) -> ServiceError {
    if unique_violation(&err, constraint) {
        conflict("name_taken", "this name is already in use")
    } else {
        err.into()
    }
}
