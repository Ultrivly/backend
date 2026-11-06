use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::audit::Actor;
use crate::platform::authz::{self, Permission};
use crate::platform::error::{ServiceResult, invalid};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReportQuery {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub workspace_id: Option<Uuid>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Bucket {
    pub key: Option<String>,
    pub count: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Day {
    pub day: DateTime<Utc>,
    pub created: i64,
    pub resolved: i64,
}

pub const DEFINITIONS: &[(&str, &str)] = &[
    ("created", "Cases created within the period."),
    (
        "resolved",
        "Cases whose resolved_at falls within the period.",
    ),
    (
        "open_by_status",
        "Cases currently in a status whose category is not resolved or closed.",
    ),
    (
        "open_by_priority",
        "Currently open cases grouped by priority.",
    ),
    (
        "open_by_team",
        "Currently open cases grouped by owning team; null means no team.",
    ),
    (
        "open_by_assignee",
        "Currently open cases grouped by assignee; null means unassigned.",
    ),
    (
        "resolution_hours",
        "Hours from creation to resolution for cases resolved within the period.",
    ),
    (
        "first_response_hours",
        "Hours from creation to the first public reply by a member, for cases created within the period that have one.",
    ),
    (
        "daily",
        "Cases created and resolved per UTC day within the period.",
    ),
    (
        "workflow_runs",
        "Workflow runs within the period by outcome.",
    ),
];

pub async fn summary(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    query: &ReportQuery,
) -> ServiceResult<Value> {
    authz::require_in(
        conn,
        org_id,
        query.workspace_id,
        actor,
        Permission::ReportsView,
    )
    .await?;
    let to = query.to.unwrap_or_else(Utc::now);
    let from = query.from.unwrap_or(to - Duration::days(30));
    if from >= to {
        return Err(invalid("from", "must be before to"));
    }
    if to - from > Duration::days(366) {
        return Err(invalid("from", "the period can be at most one year"));
    }
    let ws = query.workspace_id;

    let (created, resolved): (i64, i64) = sqlx::query_as(
        "SELECT
            count(*) FILTER (WHERE created_at >= $3 AND created_at < $4),
            count(*) FILTER (WHERE resolved_at >= $3 AND resolved_at < $4)
         FROM cases WHERE org_id = $1 AND deleted_at IS NULL AND ($2::uuid IS NULL OR workspace_id = $2)",
    )
    .bind(org_id)
    .bind(ws)
    .bind(from)
    .bind(to)
    .fetch_one(&mut *conn)
    .await?;

    let open_by_status: Vec<Bucket> = sqlx::query_as(
        "SELECT s.key AS key, count(*) AS count FROM cases c JOIN case_statuses s ON s.id = c.status_id
         WHERE c.org_id = $1 AND c.deleted_at IS NULL AND ($2::uuid IS NULL OR c.workspace_id = $2)
           AND s.category NOT IN ('resolved', 'closed')
         GROUP BY s.key ORDER BY count(*) DESC",
    )
    .bind(org_id)
    .bind(ws)
    .fetch_all(&mut *conn)
    .await?;
    let open_by_priority: Vec<Bucket> = sqlx::query_as(
        "SELECT p.key AS key, count(*) AS count FROM cases c
         JOIN case_statuses s ON s.id = c.status_id JOIN case_priorities p ON p.id = c.priority_id
         WHERE c.org_id = $1 AND c.deleted_at IS NULL AND ($2::uuid IS NULL OR c.workspace_id = $2)
           AND s.category NOT IN ('resolved', 'closed')
         GROUP BY p.key ORDER BY count(*) DESC",
    )
    .bind(org_id)
    .bind(ws)
    .fetch_all(&mut *conn)
    .await?;
    let open_by_team: Vec<Bucket> = sqlx::query_as(
        "SELECT c.team_id::text AS key, count(*) AS count FROM cases c JOIN case_statuses s ON s.id = c.status_id
         WHERE c.org_id = $1 AND c.deleted_at IS NULL AND ($2::uuid IS NULL OR c.workspace_id = $2)
           AND s.category NOT IN ('resolved', 'closed')
         GROUP BY c.team_id ORDER BY count(*) DESC",
    )
    .bind(org_id)
    .bind(ws)
    .fetch_all(&mut *conn)
    .await?;
    let open_by_assignee: Vec<Bucket> = sqlx::query_as(
        "SELECT c.assignee_user_id::text AS key, count(*) AS count FROM cases c JOIN case_statuses s ON s.id = c.status_id
         WHERE c.org_id = $1 AND c.deleted_at IS NULL AND ($2::uuid IS NULL OR c.workspace_id = $2)
           AND s.category NOT IN ('resolved', 'closed')
         GROUP BY c.assignee_user_id ORDER BY count(*) DESC",
    )
    .bind(org_id)
    .bind(ws)
    .fetch_all(&mut *conn)
    .await?;

    let (resolution_avg, resolution_median): (Option<f64>, Option<f64>) = sqlx::query_as(
        "SELECT avg(h), percentile_cont(0.5) WITHIN GROUP (ORDER BY h)
         FROM (SELECT (extract(epoch FROM resolved_at - created_at) / 3600.0)::float8 AS h FROM cases
               WHERE org_id = $1 AND deleted_at IS NULL AND ($2::uuid IS NULL OR workspace_id = $2)
                 AND resolved_at >= $3 AND resolved_at < $4) t",
    )
    .bind(org_id)
    .bind(ws)
    .bind(from)
    .bind(to)
    .fetch_one(&mut *conn)
    .await?;
    let (response_avg, response_median): (Option<f64>, Option<f64>) = sqlx::query_as(
        "SELECT avg(h), percentile_cont(0.5) WITHIN GROUP (ORDER BY h)
         FROM (SELECT (extract(epoch FROM first_response_at - created_at) / 3600.0)::float8 AS h FROM cases
               WHERE org_id = $1 AND deleted_at IS NULL AND ($2::uuid IS NULL OR workspace_id = $2)
                 AND first_response_at IS NOT NULL AND created_at >= $3 AND created_at < $4) t",
    )
    .bind(org_id)
    .bind(ws)
    .bind(from)
    .bind(to)
    .fetch_one(&mut *conn)
    .await?;

    let daily: Vec<Day> = sqlx::query_as(
        "SELECT d AS day,
                (SELECT count(*) FROM cases WHERE org_id = $1 AND deleted_at IS NULL
                   AND ($2::uuid IS NULL OR workspace_id = $2)
                   AND created_at >= d AND created_at < d + interval '1 day') AS created,
                (SELECT count(*) FROM cases WHERE org_id = $1 AND deleted_at IS NULL
                   AND ($2::uuid IS NULL OR workspace_id = $2)
                   AND resolved_at >= d AND resolved_at < d + interval '1 day') AS resolved
         FROM generate_series(date_trunc('day', $3::timestamptz AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
                              $4::timestamptz, interval '1 day') AS d",
    )
    .bind(org_id)
    .bind(ws)
    .bind(from)
    .bind(to)
    .fetch_all(&mut *conn)
    .await?;

    let workflow_runs: Vec<Bucket> = sqlx::query_as(
        "SELECT status AS key, count(*) AS count FROM workflow_runs
         WHERE org_id = $1 AND created_at >= $2 AND created_at < $3 GROUP BY status",
    )
    .bind(org_id)
    .bind(from)
    .bind(to)
    .fetch_all(&mut *conn)
    .await?;

    Ok(json!({
        "period": { "from": from, "to": to, "workspace_id": ws },
        "created": created,
        "resolved": resolved,
        "open_by_status": open_by_status,
        "open_by_priority": open_by_priority,
        "open_by_team": open_by_team,
        "open_by_assignee": open_by_assignee,
        "resolution_hours": { "average": resolution_avg, "median": resolution_median },
        "first_response_hours": { "average": response_avg, "median": response_median },
        "daily": daily,
        "workflow_runs": workflow_runs,
        "definitions": DEFINITIONS.iter().map(|(k, v)| (k.to_string(), json!(v))).collect::<serde_json::Map<_, _>>(),
    }))
}
