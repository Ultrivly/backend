


use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::platform::authz::{self, Permission};
use crate::platform::secrets::{random_token, token_hash};


pub const ABSOLUTE_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);

pub const IDLE_TIMEOUT: Duration = Duration::from_secs(7 * 24 * 60 * 60);

const TOUCH_INTERVAL_SECS: f64 = 5.0 * 60.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Password,
    
    Sso {
        connection_id: Uuid,
    },
    
    Social,
}

impl AuthMethod {
    fn as_str(self) -> &'static str {
        match self {
            AuthMethod::Password => "password",
            AuthMethod::Sso { .. } => "sso",
            AuthMethod::Social => "social",
        }
    }

    fn connection_id(self) -> Option<Uuid> {
        match self {
            AuthMethod::Sso { connection_id } => Some(connection_id),
            _ => None,
        }
    }
}


#[derive(Debug, Clone, Default)]
pub struct ClientInfo {
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub method: AuthMethod,
    
    pub mfa_verified: bool,
    pub expires_at: DateTime<Utc>,
}



#[derive(Debug)]
pub struct NewSession {
    pub session: Session,
    pub token: String,
}

pub(crate) async fn create(
    conn: &mut PgConnection,
    user_id: Uuid,
    method: AuthMethod,
    mfa_verified: bool,
    client: &ClientInfo,
) -> sqlx::Result<NewSession> {
    let id = Uuid::now_v7();
    let token = random_token();
    let expires_at: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO sessions (id, user_id, token_hash, auth_method, sso_connection_id,
                               mfa_verified_at, ip_address, user_agent, expires_at)
         VALUES ($1, $2, $3, $4, $5, CASE WHEN $6 THEN now() END, $7, $8,
                 now() + make_interval(secs => $9))
         RETURNING expires_at",
    )
    .bind(id)
    .bind(user_id)
    .bind(token_hash(&token))
    .bind(method.as_str())
    .bind(method.connection_id())
    .bind(mfa_verified)
    .bind(client.ip_address)
    .bind(client.user_agent.as_deref())
    .bind(ABSOLUTE_LIFETIME.as_secs_f64())
    .fetch_one(conn)
    .await?;

    Ok(NewSession {
        session: Session {
            id,
            user_id,
            method,
            mfa_verified,
            expires_at,
        },
        token,
    })
}



pub async fn authenticate(conn: &mut PgConnection, token: &str) -> sqlx::Result<Option<Session>> {
    
    type Row = (Uuid, Uuid, String, Option<Uuid>, bool, DateTime<Utc>);
    let row: Option<Row> = sqlx::query_as(
        "UPDATE sessions s
         SET last_seen_at = CASE
             WHEN s.last_seen_at < now() - make_interval(secs => $3) THEN now()
             ELSE s.last_seen_at END
         FROM users u
         WHERE s.token_hash = $1 AND u.id = s.user_id AND u.disabled_at IS NULL
           AND s.revoked_at IS NULL
           AND s.expires_at > now()
           AND s.last_seen_at > now() - make_interval(secs => $2)
         RETURNING s.id, s.user_id, s.auth_method, s.sso_connection_id,
                   s.mfa_verified_at IS NOT NULL, s.expires_at",
    )
    .bind(token_hash(token))
    .bind(IDLE_TIMEOUT.as_secs_f64())
    .bind(TOUCH_INTERVAL_SECS)
    .fetch_optional(conn)
    .await?;

    Ok(row.map(
        |(id, user_id, method, connection_id, mfa_verified, expires_at)| Session {
            id,
            user_id,
            method: match (method.as_str(), connection_id) {
                ("sso", Some(connection_id)) => AuthMethod::Sso { connection_id },
                ("social", _) => AuthMethod::Social,
                _ => AuthMethod::Password,
            },
            mfa_verified,
            expires_at,
        },
    ))
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionInfo {
    pub id: Uuid,
    pub method: &'static str,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub current: bool,
}


pub async fn list(
    conn: &mut PgConnection,
    user_id: Uuid,
    current: Uuid,
) -> sqlx::Result<Vec<SessionInfo>> {
    type Row = (
        Uuid,
        String,
        DateTime<Utc>,
        DateTime<Utc>,
        Option<IpAddr>,
        Option<String>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, auth_method, created_at, last_seen_at, ip_address, user_agent
         FROM sessions
         WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
           AND last_seen_at > now() - make_interval(secs => $2)
         ORDER BY created_at DESC",
    )
    .bind(user_id)
    .bind(IDLE_TIMEOUT.as_secs_f64())
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, method, created_at, last_seen_at, ip_address, user_agent)| SessionInfo {
                id,
                method: match method.as_str() {
                    "sso" => "sso",
                    "social" => "social",
                    _ => "password",
                },
                created_at,
                last_seen_at,
                ip_address,
                user_agent,
                current: id == current,
            },
        )
        .collect())
}


pub async fn revoke_own(
    conn: &mut PgConnection,
    user_id: Uuid,
    session_id: Uuid,
) -> sqlx::Result<bool> {
    Ok(sqlx::query(
        "UPDATE sessions SET revoked_at = now()
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
    .bind(session_id)
    .bind(user_id)
    .execute(conn)
    .await?
    .rows_affected()
        == 1)
}


pub async fn revoke(conn: &mut PgConnection, session_id: Uuid) -> sqlx::Result<()> {
    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
        .bind(session_id)
        .execute(conn)
        .await?;
    Ok(())
}


pub async fn revoke_all(
    conn: &mut PgConnection,
    user_id: Uuid,
    except: Option<Uuid>,
) -> sqlx::Result<u64> {
    Ok(sqlx::query(
        "UPDATE sessions SET revoked_at = now()
         WHERE user_id = $1 AND revoked_at IS NULL AND id IS DISTINCT FROM $2",
    )
    .bind(user_id)
    .bind(except)
    .execute(conn)
    .await?
    .rows_affected())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OrgAccessError {
    
    #[error("this organization requires signing in with single sign-on")]
    SsoRequired,
    
    #[error("this organization requires multi-factor authentication")]
    MfaRequired,
}










pub async fn check_org_access(
    conn: &mut PgConnection,
    session: &Session,
    org_id: Uuid,
) -> Result<Result<(), OrgAccessError>, sqlx::Error> {
    let (require_mfa, connections, enforced_connections): (bool, Vec<Uuid>, Vec<Uuid>) =
        sqlx::query_as(
            "SELECT o.require_mfa,
                    coalesce(array_agg(c.id) FILTER (WHERE c.id IS NOT NULL), '{}'),
                    coalesce(array_agg(c.id) FILTER (WHERE c.enforced), '{}')
             FROM organizations o
             LEFT JOIN sso_connections c ON c.org_id = o.id AND c.enabled
             WHERE o.id = $1
             GROUP BY o.id",
        )
        .bind(org_id)
        .fetch_optional(&mut *conn)
        .await?
        .unwrap_or_default();

    let session_connection = match session.method {
        AuthMethod::Sso { connection_id } => Some(connection_id),
        _ => None,
    };
    let via_enforced_sso = session_connection.is_some_and(|c| enforced_connections.contains(&c));
    if !enforced_connections.is_empty() && !via_enforced_sso {
        let break_glass = authz::effective_permissions(conn, org_id, session.user_id, None)
            .await?
            .contains(&Permission::SecurityManage);
        if !break_glass {
            return Ok(Err(OrgAccessError::SsoRequired));
        }
    }

    let via_own_sso = session_connection.is_some_and(|c| connections.contains(&c));
    if require_mfa && !via_own_sso && !session.mfa_verified {
        return Ok(Err(OrgAccessError::MfaRequired));
    }
    Ok(Ok(()))
}
