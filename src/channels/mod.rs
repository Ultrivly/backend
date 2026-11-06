pub mod mail_domains;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Connection, PgConnection, PgPool};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::audit::Actor;
use crate::cases::contacts;
use crate::cases::messages::{Message, message_select};
use crate::cases::records::{self, NewCase, Requester, history};
use crate::identity::accounts::normalize_email;
use crate::identity::orgs::record;
use crate::integrations::webhooks::sign;
use crate::platform::authz::{self, Permission};
use crate::platform::error::{ServiceError, ServiceResult, conflict, invalid, text};
use crate::platform::events::{self, Cause};
use crate::platform::jobs::{self, NewJob};
use crate::platform::mail::{Email, Mailer, send_checked};
use crate::platform::secrets::{Secrets, random_token, token_hash};

pub const EMAIL_REPLY: &str = "channel.email_reply";
const SIGNATURE_TOLERANCE_SECS: i64 = 300;
const CHAT_SESSION_DAYS: i64 = 30;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Channel {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub kind: String,
    pub name: String,
    pub address: Option<String>,
    pub allowed_origins: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

macro_rules! channel_columns {
    () => {
        "id, workspace_id, kind, name, address, allowed_origins, enabled, created_at, updated_at"
    };
}

fn secret_context(id: Uuid) -> String {
    format!("channel:{id}")
}

fn check_origins(origins: &[String]) -> ServiceResult<Vec<String>> {
    if origins.len() > 20 {
        return Err(invalid("allowed_origins", "has too many entries"));
    }
    origins
        .iter()
        .map(|o| {
            let url = url::Url::parse(o.trim()).map_err(|_| {
                invalid(
                    "allowed_origins",
                    "must be origins like https://www.example.com",
                )
            })?;
            let local = url
                .host_str()
                .is_some_and(|h| h == "localhost" || h == "127.0.0.1");
            if !(url.scheme() == "https" || (url.scheme() == "http" && local))
                || url.path() != "/"
                || url.query().is_some()
            {
                return Err(invalid(
                    "allowed_origins",
                    "must be origins like https://www.example.com",
                ));
            }
            Ok(url.origin().ascii_serialization())
        })
        .collect()
}

pub struct NewChannel<'a> {
    pub workspace_id: Uuid,
    pub kind: &'a str,
    pub name: &'a str,
    pub address: Option<&'a str>,
    pub allowed_origins: &'a [String],
}

pub async fn list(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
) -> ServiceResult<Vec<Channel>> {
    authz::require(conn, org_id, actor, Permission::WorkspacesManage).await?;
    Ok(sqlx::query_as(concat!(
        "SELECT ",
        channel_columns!(),
        " FROM channels WHERE org_id = $1 ORDER BY created_at"
    ))
    .bind(org_id)
    .fetch_all(conn)
    .await?)
}

pub async fn create(
    conn: &mut PgConnection,
    secrets: &Secrets,
    org_id: Uuid,
    actor: Actor,
    new: NewChannel<'_>,
) -> ServiceResult<(Channel, String)> {
    if !matches!(new.kind, "email" | "chat" | "social") {
        return Err(invalid("kind", "must be email, chat, or social"));
    }
    let name = text("name", new.name, 100)?;
    let address = match (new.kind, new.address) {
        ("email", Some(a)) => Some(
            normalize_email(a)
                .map_err(|_| invalid("address", "must be the support email address"))?
                .to_lowercase(),
        ),
        ("email", None) => return Err(invalid("address", "is required for email channels")),
        _ => None,
    };
    let origins = check_origins(new.allowed_origins)?;
    if new.kind == "chat" && origins.is_empty() {
        return Err(invalid(
            "allowed_origins",
            "list the websites that embed the chat widget",
        ));
    }
    let mut tx = conn.begin().await?;
    authz::require_in(
        &mut tx,
        org_id,
        Some(new.workspace_id),
        actor,
        Permission::WorkspacesManage,
    )
    .await?;
    records::workspace_open(&mut tx, org_id, new.workspace_id).await?;
    let id = Uuid::now_v7();
    let secret = format!("chsec_{}", random_token());
    let channel: Channel = sqlx::query_as(concat!(
        "INSERT INTO channels (id, org_id, workspace_id, kind, name, address, secret_ciphertext, allowed_origins)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING ",
        channel_columns!()
    ))
    .bind(id)
    .bind(org_id)
    .bind(new.workspace_id)
    .bind(new.kind)
    .bind(&name)
    .bind(&address)
    .bind(secrets.encrypt(&secret_context(id), secret.as_bytes()))
    .bind(&origins)
    .fetch_one(&mut *tx)
    .await?;
    record(
        &mut tx,
        org_id,
        actor,
        "channel.created",
        "channel",
        id,
        json!({ "kind": new.kind, "name": name }),
    )
    .await?;
    tx.commit().await?;
    Ok((channel, secret))
}

pub struct ChannelChanges<'a> {
    pub name: Option<&'a str>,
    pub enabled: Option<bool>,
    pub allowed_origins: Option<&'a [String]>,
}

pub async fn update(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
    changes: ChannelChanges<'_>,
) -> ServiceResult<Channel> {
    let name = changes.name.map(|n| text("name", n, 100)).transpose()?;
    let origins = changes.allowed_origins.map(check_origins).transpose()?;
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::WorkspacesManage).await?;
    let channel: Channel = sqlx::query_as(concat!(
        "UPDATE channels SET name = coalesce($3, name), enabled = coalesce($4, enabled),
             allowed_origins = coalesce($5, allowed_origins)
         WHERE org_id = $1 AND id = $2 RETURNING ",
        channel_columns!()
    ))
    .bind(org_id)
    .bind(id)
    .bind(&name)
    .bind(changes.enabled)
    .bind(&origins)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ServiceError::NotFound)?;
    record(
        &mut tx,
        org_id,
        actor,
        "channel.updated",
        "channel",
        id,
        json!({ "enabled": changes.enabled }),
    )
    .await?;
    tx.commit().await?;
    Ok(channel)
}

pub async fn rotate_secret(
    conn: &mut PgConnection,
    secrets: &Secrets,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> ServiceResult<String> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::WorkspacesManage).await?;
    let secret = format!("chsec_{}", random_token());
    let updated =
        sqlx::query("UPDATE channels SET secret_ciphertext = $3 WHERE org_id = $1 AND id = $2")
            .bind(org_id)
            .bind(id)
            .bind(secrets.encrypt(&secret_context(id), secret.as_bytes()))
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
        "channel.secret_rotated",
        "channel",
        id,
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(secret)
}

pub async fn delete(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> ServiceResult<()> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::WorkspacesManage).await?;
    let deleted = sqlx::query("DELETE FROM channels WHERE org_id = $1 AND id = $2")
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
        "channel.deleted",
        "channel",
        id,
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

struct Live {
    id: Uuid,
    org_id: Uuid,
    workspace_id: Uuid,
    address: Option<String>,
    allowed_origins: Vec<String>,
    secret: Vec<u8>,
}

type LiveRow = (Uuid, Uuid, Option<String>, Vec<String>, Vec<u8>);

async fn live(conn: &mut PgConnection, channel_id: Uuid, kind: &str) -> ServiceResult<Live> {
    let row: Option<LiveRow> = sqlx::query_as(
        "SELECT c.org_id, c.workspace_id, c.address, c.allowed_origins, c.secret_ciphertext FROM channels c
         JOIN organizations o ON o.id = c.org_id AND o.deleted_at IS NULL
         JOIN workspaces w ON w.id = c.workspace_id AND w.deleted_at IS NULL
         WHERE c.id = $1 AND c.kind = $2 AND c.enabled",
    )
    .bind(channel_id)
    .bind(kind)
    .fetch_optional(conn)
    .await?;
    let (org_id, workspace_id, address, allowed_origins, secret) =
        row.ok_or(ServiceError::NotFound)?;
    Ok(Live {
        id: channel_id,
        org_id,
        workspace_id,
        address,
        allowed_origins,
        secret,
    })
}

pub fn verify_signature(secret: &str, header: Option<&str>, body: &[u8], now: i64) -> bool {
    let Some((t, v1)) = header
        .and_then(|h| h.strip_prefix("t="))
        .and_then(|h| h.split_once(",v1="))
    else {
        return false;
    };
    let Ok(t) = t.parse::<i64>() else {
        return false;
    };
    if (now - t).abs() > SIGNATURE_TOLERANCE_SECS {
        return false;
    }
    bool::from(sign(secret, t, body).as_bytes().ct_eq(v1.as_bytes()))
}

async fn authenticate_inbound(
    conn: &mut PgConnection,
    secrets: &Secrets,
    channel_id: Uuid,
    kind: &str,
    signature: Option<&str>,
    body: &[u8],
) -> ServiceResult<Live> {
    let channel = live(conn, channel_id, kind).await?;
    let secret = String::from_utf8(secrets.decrypt(&secret_context(channel.id), &channel.secret)?)
        .map_err(anyhow::Error::from)?;
    if !verify_signature(&secret, signature, body, Utc::now().timestamp()) {
        return Err(ServiceError::Forbidden);
    }
    Ok(channel)
}

fn normalize_message_id(id: &str) -> Option<String> {
    let id = id
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim();
    (!id.is_empty() && id.len() <= 500 && !id.chars().any(char::is_control)).then(|| id.to_string())
}

async fn append(
    conn: &mut PgConnection,
    org_id: Uuid,
    case_id: Uuid,
    contact_id: Uuid,
    body: &str,
    source: &str,
    external_id: Option<&str>,
) -> ServiceResult<Uuid> {
    let status: String = sqlx::query_scalar(
        "SELECT s.category FROM cases c JOIN case_statuses s ON s.id = c.status_id WHERE c.id = $1 FOR UPDATE OF c",
    )
    .bind(case_id)
    .fetch_one(&mut *conn)
    .await?;
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO case_messages (id, org_id, case_id, visibility, author_kind, author_contact_id, body,
                                    body_format, source_channel, external_message_id)
         VALUES ($1, $2, $3, 'public', 'contact', $4, $5, 'text', $6, $7)",
    )
    .bind(id)
    .bind(org_id)
    .bind(case_id)
    .bind(contact_id)
    .bind(body)
    .bind(source)
    .bind(external_id)
    .execute(&mut *conn)
    .await?;
    if status == "resolved" {
        let open: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM case_statuses WHERE org_id = $1 AND category = 'open' ORDER BY position LIMIT 1",
        )
        .bind(org_id)
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(open) = open {
            sqlx::query("UPDATE cases SET status_id = $2, resolved_at = NULL WHERE id = $1")
                .bind(case_id)
                .bind(open)
                .execute(&mut *conn)
                .await?;
            events::emit(
                conn,
                org_id,
                "case.status_changed",
                "case",
                case_id,
                json!({ "case_id": case_id, "from": "resolved", "to": "open" }),
                Cause::default(),
            )
            .await?;
        }
    }
    sqlx::query("UPDATE cases SET updated_at = now() WHERE id = $1")
        .bind(case_id)
        .execute(&mut *conn)
        .await?;
    history(
        conn,
        org_id,
        case_id,
        Actor::System,
        "message_added",
        json!({ "message_id": id, "visibility": "public", "source": source }),
    )
    .await?;
    events::emit(
        conn,
        org_id,
        "case.message_added",
        "case",
        case_id,
        json!({ "case_id": case_id, "message_id": id, "visibility": "public", "author_kind": "contact" }),
        Cause::default(),
    )
    .await?;
    Ok(id)
}

#[allow(clippy::too_many_arguments)]
async fn open_case(
    conn: &mut PgConnection,
    channel: &Live,
    source: &str,
    subject: &str,
    body: &str,
    contact_id: Uuid,
    thread_id: Option<String>,
    unverified: bool,
) -> ServiceResult<Uuid> {
    let subject: String = subject.trim().chars().take(500).collect();
    let case = records::create(
        conn,
        channel.org_id,
        Actor::System,
        NewCase {
            workspace_id: channel.workspace_id,
            subject: if subject.is_empty() {
                "(no subject)".into()
            } else {
                subject
            },
            description: body.chars().take(100_000).collect(),
            requester: Requester::Existing { contact_id },
            status: None,
            priority: None,
            category: None,
            tags: Vec::new(),
            team_id: None,
            assignee_user_id: None,
            source_channel: Some(source.into()),
            custom_fields: Default::default(),
            channel_id: Some(channel.id),
            channel_thread_id: thread_id,
            requester_unverified: unverified,
        },
        Cause::default(),
    )
    .await?;
    Ok(case.id)
}

#[derive(Debug, Deserialize)]
pub struct Address {
    pub email: String,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct InboundEmail {
    pub from: Address,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub text: String,
    pub message_id: String,
    pub in_reply_to: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub auto_submitted: bool,
}

#[derive(Debug, Serialize)]
pub struct Received {
    pub case_id: Option<Uuid>,
    pub duplicate: bool,
}

pub async fn receive_email(
    pool: &PgPool,
    secrets: &Secrets,
    channel_id: Uuid,
    signature: Option<&str>,
    body: &[u8],
) -> ServiceResult<Received> {
    let mut tx = pool.begin().await?;
    let channel =
        authenticate_inbound(&mut tx, secrets, channel_id, "email", signature, body).await?;
    let email: InboundEmail = serde_json::from_slice(body)
        .map_err(|_| invalid("body", "is not a valid inbound email"))?;
    let from = normalize_email(&email.from.email)
        .map_err(|_| invalid("from", "is not a valid email address"))?
        .to_lowercase();
    if email.auto_submitted || channel.address.as_deref() == Some(from.as_str()) {
        return Ok(Received {
            case_id: None,
            duplicate: false,
        });
    }
    let message_id =
        normalize_message_id(&email.message_id).ok_or(invalid("message_id", "is required"))?;
    if email.text.chars().count() > 100_000 {
        return Err(invalid("text", "is too long"));
    }
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT case_id FROM case_messages WHERE org_id = $1 AND source_channel = 'email' AND external_message_id = $2",
    )
    .bind(channel.org_id)
    .bind(&message_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(case_id) = existing {
        return Ok(Received {
            case_id: Some(case_id),
            duplicate: true,
        });
    }

    let contact_id = contacts::find_or_create(
        &mut tx,
        channel.org_id,
        &from,
        email.from.name.as_deref(),
        None,
        Cause::default(),
    )
    .await?;
    let mut related: Vec<String> = email
        .references
        .iter()
        .filter_map(|r| normalize_message_id(r))
        .collect();
    related.extend(email.in_reply_to.as_deref().and_then(normalize_message_id));
    related.truncate(50);
    let mut case_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT m.case_id FROM case_messages m
         JOIN cases c ON c.id = m.case_id AND c.deleted_at IS NULL
         JOIN case_statuses s ON s.id = c.status_id AND s.category <> 'closed'
         WHERE m.org_id = $1 AND m.external_message_id = ANY($2) AND c.requester_contact_id = $3
         ORDER BY m.created_at DESC LIMIT 1",
    )
    .bind(channel.org_id)
    .bind(&related)
    .bind(contact_id)
    .fetch_optional(&mut *tx)
    .await?;
    if case_id.is_none()
        && let Some(number) = subject_number(&email.subject)
    {
        case_id = sqlx::query_scalar(
            "SELECT c.id FROM cases c JOIN case_statuses s ON s.id = c.status_id AND s.category <> 'closed'
             WHERE c.org_id = $1 AND c.number = $2 AND c.requester_contact_id = $3 AND c.deleted_at IS NULL",
        )
        .bind(channel.org_id)
        .bind(number)
        .bind(contact_id)
        .fetch_optional(&mut *tx)
        .await?;
    }
    let case_id = match case_id {
        Some(id) => id,
        None => {
            open_case(
                &mut tx,
                &channel,
                "email",
                &email.subject,
                &email.text,
                contact_id,
                None,
                false,
            )
            .await?
        }
    };
    append(
        &mut tx,
        channel.org_id,
        case_id,
        contact_id,
        email.text.trim(),
        "email",
        Some(&message_id),
    )
    .await?;
    tx.commit().await?;
    Ok(Received {
        case_id: Some(case_id),
        duplicate: false,
    })
}

fn subject_number(subject: &str) -> Option<i64> {
    let start = subject.rfind("[#")? + 2;
    let end = subject[start..].find(']')? + start;
    subject[start..end].parse().ok().filter(|n| *n > 0)
}

pub async fn queue_email_reply(
    conn: &mut PgConnection,
    org_id: Uuid,
    case_id: Uuid,
    message_id: Uuid,
) -> sqlx::Result<()> {
    let is_email: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM cases c JOIN channels ch ON ch.id = c.channel_id
                        WHERE c.id = $1 AND ch.kind = 'email' AND ch.enabled)",
    )
    .bind(case_id)
    .fetch_one(&mut *conn)
    .await?;
    if is_email {
        let key = message_id.to_string();
        jobs::enqueue(
            conn,
            NewJob {
                org_id: Some(org_id),
                dedupe_key: Some(&key),
                max_attempts: 8,
                ..NewJob::new(EMAIL_REPLY, json!({ "message_id": message_id }))
            },
        )
        .await?;
    }
    Ok(())
}

pub async fn send_email_reply(
    pool: &PgPool,
    secrets: &Secrets,
    mailer: &Mailer,
    message_id: Uuid,
) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    type Row = (
        Uuid,
        String,
        Option<String>,
        i64,
        String,
        Option<String>,
        Option<String>,
        String,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT m.org_id, m.body, m.external_message_id, c.number, c.subject, ct.email, ch.address, ch.name
         FROM case_messages m
         JOIN cases c ON c.id = m.case_id AND c.deleted_at IS NULL
         JOIN contacts ct ON ct.id = c.requester_contact_id
         JOIN channels ch ON ch.id = c.channel_id
         WHERE m.id = $1 AND m.visibility = 'public'",
    )
    .bind(message_id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((org_id, body, sent, number, subject, to, address, channel_name)) = row else {
        return Ok(());
    };
    let (Some(to), Some(address), None) = (to, address, sent) else {
        return Ok(());
    };
    let last_inbound: Option<String> = sqlx::query_scalar(
        "SELECT m.external_message_id FROM case_messages m JOIN case_messages me ON me.id = $1
         WHERE m.case_id = me.case_id AND m.source_channel = 'email' AND m.external_message_id IS NOT NULL
         ORDER BY m.created_at DESC LIMIT 1",
    )
    .bind(message_id)
    .fetch_optional(&mut *conn)
    .await?;
    let domain = address
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or("localhost");
    let own_id = format!("{message_id}@{domain}");
    let subject = if subject.contains(&format!("[#{number}]")) {
        format!("Re: {subject}")
    } else {
        format!("Re: {subject} [#{number}]")
    };
    let dkim = mail_domains::signing_key(&mut conn, secrets, org_id, &address).await?;
    let from = dkim.as_ref().map(|_| match &channel_name {
        name if !name.trim().is_empty() => format!(
            "\"{}\" <{address}>",
            name.replace(['"', '\\', '\r', '\n'], "")
        ),
        _ => address.clone(),
    });
    drop(conn);
    let sent_now = send_checked(
        pool,
        mailer,
        &Email {
            to,
            subject: subject.replace(['\r', '\n'], " "),
            body,
            message_id: Some(format!("<{own_id}>")),
            in_reply_to: last_inbound.map(|id| format!("<{id}>")),
            reply_to: Some(address),
            from,
            dkim,
            ..Email::default()
        },
    )
    .await?;
    if !sent_now {
        return Ok(());
    }
    let mut conn = pool.acquire().await?;
    sqlx::query("UPDATE case_messages SET external_message_id = $3 WHERE org_id = $1 AND id = $2")
        .bind(org_id)
        .bind(message_id)
        .bind(&own_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct InboundSocial {
    pub platform: String,
    pub external_user_id: String,
    pub name: Option<String>,
    pub text: String,
    pub message_id: String,
    pub thread_id: String,
}

pub async fn receive_social(
    pool: &PgPool,
    secrets: &Secrets,
    channel_id: Uuid,
    signature: Option<&str>,
    body: &[u8],
) -> ServiceResult<Received> {
    let mut tx = pool.begin().await?;
    let channel =
        authenticate_inbound(&mut tx, secrets, channel_id, "social", signature, body).await?;
    let message: InboundSocial = serde_json::from_slice(body)
        .map_err(|_| invalid("body", "is not a valid inbound message"))?;
    let platform = message.platform.trim().to_lowercase();
    let platform_ok = (1..=30).contains(&platform.len())
        && platform.starts_with(|c: char| c.is_ascii_lowercase())
        && platform
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !platform_ok {
        return Err(invalid("platform", "must be a short lowercase identifier"));
    }
    for (field, value) in [
        ("external_user_id", &message.external_user_id),
        ("message_id", &message.message_id),
        ("thread_id", &message.thread_id),
    ] {
        if value.trim().is_empty() || value.len() > 200 {
            return Err(invalid(field, "must be between 1 and 200 characters"));
        }
    }
    let text = message.text.trim();
    if text.is_empty() || text.chars().count() > 100_000 {
        return Err(invalid("text", "must be between 1 and 100000 characters"));
    }
    let external_id = format!("{platform}:{}", message.message_id.trim());
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT case_id FROM case_messages WHERE org_id = $1 AND source_channel = 'social' AND external_message_id = $2",
    )
    .bind(channel.org_id)
    .bind(&external_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(case_id) = existing {
        return Ok(Received {
            case_id: Some(case_id),
            duplicate: true,
        });
    }

    let contact_id: Uuid = match sqlx::query_scalar::<_, Uuid>(
        "SELECT contact_id FROM contact_identities WHERE org_id = $1 AND platform = $2 AND external_id = $3",
    )
    .bind(channel.org_id)
    .bind(&platform)
    .bind(message.external_user_id.trim())
    .fetch_optional(&mut *tx)
    .await?
    {
        Some(id) => id,
        None => {
            let id = Uuid::now_v7();
            let name: String = message
                .name
                .as_deref()
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .unwrap_or(message.external_user_id.trim())
                .chars()
                .take(200)
                .collect();
            sqlx::query("INSERT INTO contacts (id, org_id, display_name) VALUES ($1, $2, $3)")
                .bind(id)
                .bind(channel.org_id)
                .bind(&name)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "INSERT INTO contact_identities (org_id, contact_id, platform, external_id) VALUES ($1, $2, $3, $4)",
            )
            .bind(channel.org_id)
            .bind(id)
            .bind(&platform)
            .bind(message.external_user_id.trim())
            .execute(&mut *tx)
            .await?;
            id
        }
    };
    let thread = format!("{platform}:{}", message.thread_id.trim());
    let open: Option<Uuid> = sqlx::query_scalar(
        "SELECT c.id FROM cases c JOIN case_statuses s ON s.id = c.status_id AND s.category <> 'closed'
         WHERE c.org_id = $1 AND c.channel_id = $2 AND c.channel_thread_id = $3 AND c.deleted_at IS NULL",
    )
    .bind(channel.org_id)
    .bind(channel.id)
    .bind(&thread)
    .fetch_optional(&mut *tx)
    .await?;
    let case_id = match open {
        Some(id) => id,
        None => {
            sqlx::query("UPDATE cases SET channel_thread_id = NULL WHERE org_id = $1 AND channel_id = $2 AND channel_thread_id = $3")
                .bind(channel.org_id)
                .bind(channel.id)
                .bind(&thread)
                .execute(&mut *tx)
                .await?;
            let subject: String = text.chars().take(80).collect();
            open_case(
                &mut tx,
                &channel,
                "social",
                &subject,
                text,
                contact_id,
                Some(thread),
                false,
            )
            .await?
        }
    };
    append(
        &mut tx,
        channel.org_id,
        case_id,
        contact_id,
        text,
        "social",
        Some(&external_id),
    )
    .await?;
    tx.commit().await?;
    Ok(Received {
        case_id: Some(case_id),
        duplicate: false,
    })
}

pub async fn chat_origin_allowed(
    conn: &mut PgConnection,
    channel_id: Uuid,
    origin: Option<&str>,
) -> ServiceResult<bool> {
    let channel = live(conn, channel_id, "chat").await?;
    Ok(origin.is_some_and(|o| channel.allowed_origins.iter().any(|a| a == o)))
}

#[derive(Debug, Serialize)]
pub struct ChatStarted {
    pub conversation_id: Uuid,
    pub token: String,
}

pub async fn start_chat(
    pool: &PgPool,
    channel_id: Uuid,
    origin: Option<&str>,
    name: &str,
    email: &str,
    message: &str,
) -> ServiceResult<ChatStarted> {
    let mut tx = pool.begin().await?;
    let channel = live(&mut tx, channel_id, "chat").await?;
    if !origin.is_some_and(|o| channel.allowed_origins.iter().any(|a| a == o)) {
        return Err(ServiceError::Forbidden);
    }
    let message = message.trim();
    if message.is_empty() || message.chars().count() > 10_000 {
        return Err(invalid("message", "must be between 1 and 10000 characters"));
    }
    let name = text("name", name, 200)?;
    let email =
        normalize_email(email).map_err(|_| invalid("email", "is not a valid email address"))?;
    let contact_id = contacts::find_or_create(
        &mut tx,
        channel.org_id,
        email,
        Some(&name),
        None,
        Cause::default(),
    )
    .await?;
    let subject: String = message.chars().take(80).collect();
    let case_id = open_case(
        &mut tx, &channel, "chat", &subject, message, contact_id, None, true,
    )
    .await?;
    append(
        &mut tx,
        channel.org_id,
        case_id,
        contact_id,
        message,
        "chat",
        None,
    )
    .await?;
    let token = random_token();
    sqlx::query(
        "INSERT INTO chat_sessions (token_hash, org_id, channel_id, case_id, expires_at)
         VALUES ($1, $2, $3, $4, now() + make_interval(days => $5::int))",
    )
    .bind(token_hash(&token))
    .bind(channel.org_id)
    .bind(channel.id)
    .bind(case_id)
    .bind(CHAT_SESSION_DAYS as i32)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(ChatStarted {
        conversation_id: case_id,
        token,
    })
}

async fn chat_session(
    conn: &mut PgConnection,
    channel_id: Uuid,
    case_id: Uuid,
    token: &str,
) -> ServiceResult<(Uuid, Uuid)> {
    let row: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT s.org_id, c.requester_contact_id FROM chat_sessions s
         JOIN cases c ON c.id = s.case_id AND c.deleted_at IS NULL
         JOIN channels ch ON ch.id = s.channel_id AND ch.enabled
         WHERE s.token_hash = $1 AND s.channel_id = $2 AND s.case_id = $3 AND s.expires_at > now()",
    )
    .bind(token_hash(token))
    .bind(channel_id)
    .bind(case_id)
    .fetch_optional(conn)
    .await?;
    row.ok_or(ServiceError::NotFound)
}

pub async fn chat_messages(
    conn: &mut PgConnection,
    channel_id: Uuid,
    case_id: Uuid,
    token: &str,
    after: Option<Uuid>,
) -> ServiceResult<Vec<Message>> {
    chat_session(conn, channel_id, case_id, token).await?;
    Ok(sqlx::query_as(concat!(
        message_select!(),
        " WHERE m.case_id = $1 AND m.visibility = 'public' AND ($2::uuid IS NULL OR m.id > $2)
          ORDER BY m.id LIMIT 200"
    ))
    .bind(case_id)
    .bind(after)
    .fetch_all(conn)
    .await?)
}

pub async fn chat_reply(
    pool: &PgPool,
    channel_id: Uuid,
    case_id: Uuid,
    token: &str,
    body: &str,
) -> ServiceResult<Uuid> {
    let body = body.trim();
    if body.is_empty() || body.chars().count() > 10_000 {
        return Err(invalid("body", "must be between 1 and 10000 characters"));
    }
    let mut tx = pool.begin().await?;
    let (org_id, contact_id) = chat_session(&mut tx, channel_id, case_id, token).await?;
    let closed: bool = sqlx::query_scalar(
        "SELECT s.category = 'closed' FROM cases c JOIN case_statuses s ON s.id = c.status_id WHERE c.id = $1",
    )
    .bind(case_id)
    .fetch_one(&mut *tx)
    .await?;
    if closed {
        return Err(conflict("case_closed", "this conversation has ended"));
    }
    let id = append(&mut tx, org_id, case_id, contact_id, body, "chat", None).await?;
    tx.commit().await?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_expire_and_must_match() {
        let body = br#"{"a":1}"#;
        let now = 1_000_000;
        let header = format!("t={now},v1={}", sign("chsec_x", now, body));
        assert!(verify_signature("chsec_x", Some(&header), body, now + 10));
        assert!(!verify_signature("chsec_x", Some(&header), body, now + 301));
        assert!(!verify_signature("chsec_y", Some(&header), body, now));
        assert!(!verify_signature("chsec_x", Some(&header), b"{}", now));
        assert!(!verify_signature("chsec_x", None, body, now));
    }

    #[test]
    fn subjects_and_message_ids() {
        assert_eq!(subject_number("Re: Printer [#42]"), Some(42));
        assert_eq!(subject_number("Re: Printer"), None);
        assert_eq!(
            normalize_message_id(" <abc@x.test> ").as_deref(),
            Some("abc@x.test")
        );
        assert!(normalize_message_id("a\r\nb").is_none());
    }

    #[test]
    fn origins_are_normalized() {
        assert_eq!(
            check_origins(&["https://www.example.com/".into()]).unwrap(),
            ["https://www.example.com"]
        );
        assert!(check_origins(&["http://example.com".into()]).is_err());
        assert!(check_origins(&["https://example.com/path".into()]).is_err());
        assert!(check_origins(&["http://localhost:3000".into()]).is_ok());
    }
}
