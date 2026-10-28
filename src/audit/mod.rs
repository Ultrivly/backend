



use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    User(Uuid),
    ApiCredential {
        id: Uuid,
        org_id: Uuid,
    },
    Workflow {
        id: Uuid,
        org_id: Uuid,
    },
    
    System,
}

impl Actor {
    pub fn kind(self) -> &'static str {
        match self {
            Actor::User(_) => "user",
            Actor::ApiCredential { .. } => "api_credential",
            Actor::Workflow { .. } => "workflow",
            Actor::System => "system",
        }
    }

    pub fn id(self) -> Option<Uuid> {
        match self {
            Actor::User(id) => Some(id),
            Actor::ApiCredential { id, .. } | Actor::Workflow { id, .. } => Some(id),
            Actor::System => None,
        }
    }
}

pub struct Event<'a> {
    
    pub org_id: Option<Uuid>,
    pub actor: Actor,
    
    pub action: &'a str,
    pub target_type: &'a str,
    pub target_id: Uuid,
    pub metadata: Value,
}

pub async fn record(conn: &mut PgConnection, event: Event<'_>) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO audit_events (id, org_id, actor_kind, actor_id, action, target_type, target_id, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(Uuid::now_v7())
    .bind(event.org_id)
    .bind(event.actor.kind())
    .bind(event.actor.id())
    .bind(event.action)
    .bind(event.target_type)
    .bind(event.target_id)
    .bind(event.metadata)
    .execute(conn)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct Entry {
    pub id: Uuid,
    pub actor_kind: String,
    pub actor_id: Option<Uuid>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub metadata: Value,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct Filter {
    pub action: Option<String>,
    pub target_id: Option<Uuid>,
    pub actor_id: Option<Uuid>,
}

pub async fn list(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    filter: &Filter,
    page: crate::platform::page::Page,
) -> crate::platform::error::ServiceResult<Vec<Entry>> {
    use crate::platform::authz::{self, Permission};
    authz::require(conn, org_id, actor, Permission::AuditView).await?;
    Ok(sqlx::query_as(
        "SELECT id, actor_kind, actor_id, action, target_type, target_id, metadata, occurred_at
         FROM audit_events
         WHERE org_id = $1
           AND ($2::text IS NULL OR action LIKE $2 || '%')
           AND ($3::uuid IS NULL OR target_id = $3)
           AND ($4::uuid IS NULL OR actor_id = $4)
           AND ($5::uuid IS NULL OR id < $5)
         ORDER BY id DESC LIMIT $6",
    )
    .bind(org_id)
    .bind(filter.action.as_deref())
    .bind(filter.target_id)
    .bind(filter.actor_id)
    .bind(page.cursor)
    .bind(page.limit + 1)
    .fetch_all(conn)
    .await?)
}
