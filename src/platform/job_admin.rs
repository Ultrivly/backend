use serde_json::json;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

use crate::audit::Actor;
use crate::identity::orgs::record;
use crate::platform::authz::{self, Permission};
use crate::platform::error::{ServiceError, ServiceResult, conflict, invalid};
use crate::platform::jobs::{self, JobFilter, JobInfo, Retry, STATES};
use crate::platform::page::Page;

pub async fn list(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    state: Option<&str>,
    kind: Option<&str>,
    page: Page,
) -> ServiceResult<Vec<JobInfo>> {
    authz::require(conn, org_id, actor, Permission::OrganizationManage).await?;
    if state.is_some_and(|s| !STATES.contains(&s)) {
        return Err(invalid(
            "state",
            "must be queued, running, succeeded, or dead",
        ));
    }
    Ok(jobs::list(
        conn,
        JobFilter {
            org_id: Some(org_id),
            state,
            kind,
        },
        page.cursor,
        page.limit + 1,
    )
    .await?)
}

pub async fn retry(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> ServiceResult<()> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::OrganizationManage).await?;
    match jobs::retry(&mut tx, id, Some(org_id)).await? {
        Retry::Queued => {}
        Retry::NotFound => return Err(ServiceError::NotFound),
        Retry::AlreadyQueued => {
            return Err(conflict(
                "already_queued",
                "an identical job is already queued",
            ));
        }
    }
    record(&mut tx, org_id, actor, "job.retried", "job", id, json!({})).await?;
    tx.commit().await?;
    Ok(())
}
