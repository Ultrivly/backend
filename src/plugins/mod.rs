use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::{Connection, PgConnection, PgPool};
use uuid::Uuid;

use crate::audit::Actor;
use crate::cases::records::{self, Case};
use crate::identity::orgs::record;
use crate::integrations::api_credentials::{self, NewCredential};
use crate::integrations::webhooks::{self, NewEndpoint, sign};
use crate::platform::authz::{self, Permission};
use crate::platform::error::{ServiceError, ServiceResult, conflict, invalid, unique_violation};
use crate::platform::events::KINDS;
use crate::platform::jobs::{self, NewJob};
use crate::platform::net::HttpClient;
use crate::platform::secrets::{Secrets, random_token};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputSpec {
    pub key: String,
    pub label: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSpec {
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub inputs: Vec<InputSpec>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub key: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default)]
    pub actions: Vec<ActionSpec>,
}

fn identifier(value: &str, max: usize) -> bool {
    (1..=max).contains(&value.len())
        && value.starts_with(|c: char| c.is_ascii_lowercase())
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'))
}

impl Manifest {
    pub fn validate(&self) -> ServiceResult<Vec<Permission>> {
        let bad = |reason| invalid("manifest", reason);
        if !identifier(&self.key, 63) {
            return Err(bad("has an invalid key"));
        }
        if self.name.trim().is_empty()
            || self.name.chars().count() > 100
            || self.version.is_empty()
            || self.version.len() > 50
        {
            return Err(bad("has an invalid name or version"));
        }
        if self.events.len() > 20
            || self
                .events
                .iter()
                .any(|e| e != "*" && !KINDS.contains(&e.as_str()))
        {
            return Err(bad("subscribes to unknown events"));
        }
        if self.actions.len() > 20 {
            return Err(bad("declares too many actions"));
        }
        let mut keys = Vec::new();
        for action in &self.actions {
            if !identifier(&action.key, 50)
                || keys.contains(&&action.key)
                || action.name.trim().is_empty()
            {
                return Err(bad("has an invalid or duplicate action"));
            }
            keys.push(&action.key);
            if action.inputs.len() > 20
                || action.inputs.iter().any(|i| {
                    !identifier(&i.key, 50)
                        || i.label.trim().is_empty()
                        || !matches!(i.kind.as_str(), "text" | "number" | "boolean")
                })
            {
                return Err(bad("has an invalid action input"));
            }
        }
        self.permissions
            .iter()
            .map(|p| {
                p.parse::<Permission>()
                    .map_err(|_| bad("requests an unknown permission"))
            })
            .collect()
    }

    fn action(&self, key: &str) -> Option<&ActionSpec> {
        self.actions.iter().find(|a| a.key == key)
    }
}

pub fn check_input(spec: &ActionSpec, input: &Map<String, Value>) -> ServiceResult<()> {
    for (key, value) in input {
        let Some(field) = spec.inputs.iter().find(|i| &i.key == key) else {
            return Err(invalid(
                "input",
                "contains a field the action does not accept",
            ));
        };
        let ok = match field.kind.as_str() {
            "text" => value.as_str().is_some_and(|s| s.chars().count() <= 10_000),
            "number" => value.as_f64().is_some_and(f64::is_finite),
            "boolean" => value.is_boolean(),
            _ => false,
        };
        if !ok {
            return Err(invalid("input", "contains a value of the wrong type"));
        }
    }
    if spec
        .inputs
        .iter()
        .any(|i| i.required && !input.contains_key(&i.key))
    {
        return Err(invalid("input", "is missing a required field"));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Builtin {
    SlackNotify,
}

impl Builtin {
    pub const ALL: &[Builtin] = &[Builtin::SlackNotify];

    pub fn find(key: &str) -> Option<Builtin> {
        Self::ALL.iter().copied().find(|b| b.manifest().key == key)
    }

    pub fn manifest(self) -> Manifest {
        match self {
            Builtin::SlackNotify => Manifest {
                key: "slack_notify".into(),
                name: "Slack notifications".into(),
                version: "1".into(),
                permissions: Vec::new(),
                events: Vec::new(),
                actions: vec![ActionSpec {
                    key: "notify".into(),
                    name: "Post to Slack".into(),
                    inputs: vec![InputSpec {
                        key: "text".into(),
                        label: "Message ({number} and {subject} are replaced)".into(),
                        kind: "text".into(),
                        required: true,
                    }],
                }],
            },
        }
    }

    fn validate_config(self, config: &Value) -> ServiceResult<Value> {
        match self {
            Builtin::SlackNotify => {
                let url = config["webhook_url"].as_str().unwrap_or_default();
                let parsed = url::Url::parse(url)
                    .map_err(|_| invalid("config", "needs a Slack webhook_url"))?;
                if parsed.scheme() != "https" || parsed.host_str() != Some("hooks.slack.com") {
                    return Err(invalid(
                        "config",
                        "webhook_url must be an https://hooks.slack.com URL",
                    ));
                }
                Ok(json!({ "webhook_url": parsed.to_string() }))
            }
        }
    }

    async fn run(
        self,
        http: &HttpClient,
        config: &Value,
        action: &str,
        input: &Map<String, Value>,
        case: &Case,
    ) -> anyhow::Result<()> {
        match (self, action) {
            (Builtin::SlackNotify, "notify") => {
                let text = input["text"]
                    .as_str()
                    .unwrap_or_default()
                    .replace("{number}", &case.number.to_string())
                    .replace("{subject}", &case.subject);
                let url = config["webhook_url"].as_str().unwrap_or_default();
                let status = http
                    .post(
                        url,
                        &[("content-type", "application/json".into())],
                        serde_json::to_vec(&json!({ "text": text }))?,
                    )
                    .await?;
                if !(200..300).contains(&status) {
                    anyhow::bail!("Slack answered {status}");
                }
                Ok(())
            }
            _ => anyhow::bail!("unknown action {action}"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Install {
    pub id: Uuid,
    pub kind: String,
    pub plugin_key: String,
    pub name: String,
    pub base_url: Option<String>,
    pub manifest: Manifest,
    pub permissions: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

type InstallRow = (
    Uuid,
    String,
    String,
    String,
    Option<String>,
    Value,
    Vec<String>,
    bool,
    DateTime<Utc>,
);

macro_rules! install_columns {
    () => {
        "id, kind, plugin_key, name, base_url, manifest, permissions, enabled, created_at"
    };
}

fn install_from(row: InstallRow) -> ServiceResult<Install> {
    let (id, kind, plugin_key, name, base_url, manifest, permissions, enabled, created_at) = row;
    Ok(Install {
        id,
        kind,
        plugin_key,
        name,
        base_url,
        manifest: serde_json::from_value(manifest).map_err(anyhow::Error::from)?,
        permissions,
        enabled,
        created_at,
    })
}

fn context(id: Uuid, part: &str) -> String {
    format!("plugin:{id}:{part}")
}

pub fn catalogue() -> Vec<Manifest> {
    Builtin::ALL.iter().map(|b| b.manifest()).collect()
}

pub async fn list(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
) -> ServiceResult<Vec<Install>> {
    authz::require(conn, org_id, actor, Permission::PluginsManage).await?;
    let rows: Vec<InstallRow> = sqlx::query_as(concat!(
        "SELECT ",
        install_columns!(),
        " FROM plugin_installs WHERE org_id = $1 ORDER BY created_at"
    ))
    .bind(org_id)
    .fetch_all(conn)
    .await?;
    rows.into_iter().map(install_from).collect()
}

pub(crate) async fn load(
    conn: &mut PgConnection,
    org_id: Uuid,
    id: Uuid,
) -> ServiceResult<Install> {
    let row: InstallRow = sqlx::query_as(concat!(
        "SELECT ",
        install_columns!(),
        " FROM plugin_installs WHERE org_id = $1 AND id = $2"
    ))
    .bind(org_id)
    .bind(id)
    .fetch_optional(conn)
    .await?
    .ok_or(ServiceError::NotFound)?;
    install_from(row)
}

pub async fn install_builtin(
    conn: &mut PgConnection,
    secrets: &Secrets,
    org_id: Uuid,
    actor: Actor,
    key: &str,
    config: &Value,
) -> ServiceResult<Install> {
    let builtin = Builtin::find(key).ok_or(invalid("plugin_key", "is not a built-in plugin"))?;
    let config = builtin.validate_config(config)?;
    let manifest = builtin.manifest();
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::PluginsManage).await?;
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO plugin_installs (id, org_id, kind, plugin_key, name, manifest, config_ciphertext, secret_ciphertext)
         VALUES ($1, $2, 'builtin', $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(org_id)
    .bind(&manifest.key)
    .bind(&manifest.name)
    .bind(serde_json::to_value(&manifest).map_err(anyhow::Error::from)?)
    .bind(secrets.encrypt(&context(id, "config"), config.to_string().as_bytes()))
    .bind(secrets.encrypt(&context(id, "secret"), random_token().as_bytes()))
    .execute(&mut *tx)
    .await
    .map_err(already_installed)?;
    record(
        &mut tx,
        org_id,
        actor,
        "plugin.installed",
        "plugin",
        id,
        json!({ "key": manifest.key }),
    )
    .await?;
    let install = load(&mut tx, org_id, id).await?;
    tx.commit().await?;
    Ok(install)
}

fn already_installed(err: sqlx::Error) -> ServiceError {
    if unique_violation(&err, "plugin_installs_org_id_plugin_key_key") {
        conflict("already_installed", "this plugin is already installed")
    } else {
        err.into()
    }
}

#[derive(Debug, Serialize)]
pub struct WebhookInstall {
    pub install: Install,
    pub api_token: Option<String>,
    pub signing_secret: String,
}

pub async fn install_webhook(
    conn: &mut PgConnection,
    http: &HttpClient,
    secrets: &Secrets,
    org_id: Uuid,
    actor: Actor,
    base_url: &str,
) -> ServiceResult<WebhookInstall> {
    let base =
        url::Url::parse(base_url.trim()).map_err(|_| invalid("base_url", "is not a valid URL"))?;
    http.policy()
        .check_url(&base)
        .map_err(|_| invalid("base_url", "must be a public https URL"))?;
    if base.query().is_some() || !base.username().is_empty() {
        return Err(invalid(
            "base_url",
            "must not contain a query or credentials",
        ));
    }
    let base = base.as_str().trim_end_matches('/').to_string();
    authz::require(conn, org_id, actor, Permission::PluginsManage).await?;

    let (status, body) = http
        .get(&format!("{base}/manifest"))
        .await
        .map_err(|_| invalid("base_url", "did not serve a plugin manifest"))?;
    if !(200..300).contains(&status) {
        return Err(invalid("base_url", "did not serve a plugin manifest"));
    }
    let manifest: Manifest =
        serde_json::from_slice(&body).map_err(|_| invalid("manifest", "is not valid"))?;
    let permissions = manifest.validate()?;
    let missing =
        authz::missing_permissions(conn, org_id, None, actor, permissions.iter().copied()).await?;
    if !missing.is_empty() {
        return Err(ServiceError::CannotGrant(missing));
    }

    let mut tx = conn.begin().await?;
    let api_token = if permissions.is_empty() {
        None
    } else {
        Some(
            api_credentials::create(
                &mut tx,
                org_id,
                actor,
                NewCredential {
                    name: &format!(
                        "Plugin: {}",
                        manifest.name.chars().take(80).collect::<String>()
                    ),
                    permissions: &permissions,
                    expires_in_days: None,
                },
            )
            .await?,
        )
    };
    let (endpoint, signing_secret) = if manifest.events.is_empty() {
        (None, format!("whsec_{}", random_token()))
    } else {
        let (endpoint, secret) = webhooks::create(
            &mut tx,
            http.policy(),
            secrets,
            org_id,
            actor,
            NewEndpoint {
                url: &format!("{base}/events"),
                description: &format!("Plugin {}", manifest.key),
                events: &manifest.events,
            },
        )
        .await?;
        (Some(endpoint.id), secret)
    };
    let id = Uuid::now_v7();
    let stored: Vec<&str> = permissions.iter().map(|p| p.as_str()).collect();
    sqlx::query(
        "INSERT INTO plugin_installs (id, org_id, kind, plugin_key, name, base_url, manifest, secret_ciphertext,
                                      permissions, api_credential_id, webhook_endpoint_id)
         VALUES ($1, $2, 'webhook', $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(id)
    .bind(org_id)
    .bind(&manifest.key)
    .bind(manifest.name.trim())
    .bind(&base)
    .bind(serde_json::to_value(&manifest).map_err(anyhow::Error::from)?)
    .bind(secrets.encrypt(&context(id, "secret"), signing_secret.as_bytes()))
    .bind(&stored)
    .bind(api_token.as_ref().map(|t| t.info.id))
    .bind(endpoint)
    .execute(&mut *tx)
    .await
    .map_err(already_installed)?;
    record(
        &mut tx,
        org_id,
        actor,
        "plugin.installed",
        "plugin",
        id,
        json!({ "key": manifest.key, "base_url": base, "permissions": stored, "events": manifest.events }),
    )
    .await?;
    let install = load(&mut tx, org_id, id).await?;
    tx.commit().await?;
    Ok(WebhookInstall {
        install,
        api_token: api_token.map(|t| t.token),
        signing_secret,
    })
}

pub async fn set_enabled(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
    enabled: bool,
) -> ServiceResult<Install> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::PluginsManage).await?;
    let ids: Option<(Option<Uuid>,)> = sqlx::query_as(
        "UPDATE plugin_installs SET enabled = $3 WHERE org_id = $1 AND id = $2 RETURNING webhook_endpoint_id",
    )
    .bind(org_id)
    .bind(id)
    .bind(enabled)
    .fetch_optional(&mut *tx)
    .await?;
    let (endpoint,) = ids.ok_or(ServiceError::NotFound)?;
    if let Some(endpoint) = endpoint {
        sqlx::query("UPDATE webhook_endpoints SET enabled = $2 WHERE id = $1")
            .bind(endpoint)
            .bind(enabled)
            .execute(&mut *tx)
            .await?;
    }
    record(
        &mut tx,
        org_id,
        actor,
        if enabled {
            "plugin.enabled"
        } else {
            "plugin.disabled"
        },
        "plugin",
        id,
        json!({}),
    )
    .await?;
    let install = load(&mut tx, org_id, id).await?;
    tx.commit().await?;
    Ok(install)
}

pub async fn uninstall(
    conn: &mut PgConnection,
    org_id: Uuid,
    actor: Actor,
    id: Uuid,
) -> ServiceResult<()> {
    let mut tx = conn.begin().await?;
    authz::require(&mut tx, org_id, actor, Permission::PluginsManage).await?;
    let ids: Option<(Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "DELETE FROM plugin_installs WHERE org_id = $1 AND id = $2 RETURNING api_credential_id, webhook_endpoint_id",
    )
    .bind(org_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let (credential, endpoint) = ids.ok_or(ServiceError::NotFound)?;
    if let Some(credential) = credential {
        sqlx::query(
            "UPDATE api_credentials SET revoked_at = coalesce(revoked_at, now()) WHERE id = $1",
        )
        .bind(credential)
        .execute(&mut *tx)
        .await?;
    }
    if let Some(endpoint) = endpoint {
        sqlx::query("DELETE FROM webhook_endpoints WHERE id = $1")
            .bind(endpoint)
            .execute(&mut *tx)
            .await?;
    }
    record(
        &mut tx,
        org_id,
        actor,
        "plugin.uninstalled",
        "plugin",
        id,
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn check_action(
    conn: &mut PgConnection,
    org_id: Uuid,
    install_id: Uuid,
    action: &str,
    input: &Map<String, Value>,
) -> ServiceResult<()> {
    let install = load(conn, org_id, install_id)
        .await
        .map_err(|_| invalid("definition", "refers to a plugin that is not installed"))?;
    let spec = install.manifest.action(action).ok_or(invalid(
        "definition",
        "refers to a plugin action that does not exist",
    ))?;
    check_input(spec, input)
}

pub const RUN_ACTION: &str = "plugin.action";

pub async fn queue_action(
    conn: &mut PgConnection,
    secrets: &Secrets,
    org_id: Uuid,
    install_id: Uuid,
    action: &str,
    input: &Map<String, Value>,
    case_id: Uuid,
) -> ServiceResult<()> {
    let payload = json!({ "org_id": org_id, "install_id": install_id, "action": action, "input": input, "case_id": case_id });
    jobs::enqueue(
        conn,
        NewJob {
            org_id: Some(org_id),
            max_attempts: 5,
            ..NewJob::new(RUN_ACTION, jobs::seal(secrets, RUN_ACTION, &payload))
        },
    )
    .await?;
    Ok(())
}

pub async fn run_job(
    pool: &PgPool,
    http: &HttpClient,
    secrets: &Secrets,
    payload: &Value,
) -> anyhow::Result<()> {
    let payload = jobs::unseal(secrets, RUN_ACTION, payload)?;
    let id = |key: &str| -> anyhow::Result<Uuid> {
        payload[key]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("invalid plugin job"))
    };
    let (org_id, install_id, case_id) = (id("org_id")?, id("install_id")?, id("case_id")?);
    let action = payload["action"].as_str().unwrap_or_default();
    let input = payload["input"].as_object().cloned().unwrap_or_default();
    let mut conn = pool.acquire().await?;
    let Ok(case) = records::load(&mut conn, org_id, case_id, false).await else {
        return Ok(());
    };
    drop(conn);
    run_action(
        pool, http, secrets, org_id, install_id, action, &input, &case,
    )
    .await
}

type ActionRow = (
    String,
    String,
    Option<String>,
    Value,
    Option<Vec<u8>>,
    Vec<u8>,
    bool,
);

#[allow(clippy::too_many_arguments)]
async fn run_action(
    pool: &PgPool,
    http: &HttpClient,
    secrets: &Secrets,
    org_id: Uuid,
    install_id: Uuid,
    action: &str,
    input: &Map<String, Value>,
    case: &Case,
) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    let row: Option<ActionRow> = sqlx::query_as(
        "SELECT kind, plugin_key, base_url, manifest, config_ciphertext, secret_ciphertext, enabled
         FROM plugin_installs WHERE org_id = $1 AND id = $2",
    )
    .bind(org_id)
    .bind(install_id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((kind, key, base_url, manifest, config, secret, enabled)) = row else {
        anyhow::bail!("plugin is not installed");
    };
    if !enabled {
        anyhow::bail!("plugin is disabled");
    }
    let manifest: Manifest = serde_json::from_value(manifest)?;
    let spec = manifest
        .action(action)
        .ok_or_else(|| anyhow::anyhow!("unknown plugin action"))?;
    check_input(spec, input).map_err(|e| anyhow::anyhow!("{e}"))?;
    match (kind.as_str(), base_url) {
        ("builtin", _) => {
            let builtin = Builtin::find(&key)
                .ok_or_else(|| anyhow::anyhow!("built-in plugin no longer exists"))?;
            let config: Value = match config {
                Some(c) => {
                    serde_json::from_slice(&secrets.decrypt(&context(install_id, "config"), &c)?)?
                }
                None => Value::Null,
            };
            builtin.run(http, &config, action, input, case).await
        }
        ("webhook", Some(base)) => {
            let secret =
                String::from_utf8(secrets.decrypt(&context(install_id, "secret"), &secret)?)?;
            let body = serde_json::to_vec(&json!({
                "install_id": install_id,
                "org_id": org_id,
                "action": action,
                "input": input,
                "case": {
                    "id": case.id, "number": case.number, "subject": case.subject, "status": case.status,
                    "priority": case.priority, "tags": case.tags, "workspace_id": case.workspace_id,
                },
            }))?;
            let timestamp = Utc::now().timestamp();
            let status = http
                .post(
                    &format!("{base}/actions/{action}"),
                    &[
                        ("content-type", "application/json".into()),
                        (
                            "ultrivly-signature",
                            format!("t={timestamp},v1={}", sign(&secret, timestamp, &body)),
                        ),
                    ],
                    body,
                )
                .await?;
            if !(200..300).contains(&status) {
                anyhow::bail!("plugin answered {status}");
            }
            Ok(())
        }
        _ => anyhow::bail!("plugin install is misconfigured"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifests_are_validated() {
        let mut manifest = Builtin::SlackNotify.manifest();
        assert!(manifest.validate().is_ok());
        manifest.permissions = vec!["cases.fly".into()];
        assert!(manifest.validate().is_err());
        let mut manifest = Builtin::SlackNotify.manifest();
        manifest.events = vec!["case.exploded".into()];
        assert!(manifest.validate().is_err());
        let json = json!({ "key": "x", "name": "X", "version": "1", "run": "rm -rf /" });
        assert!(serde_json::from_value::<Manifest>(json).is_err());
    }

    #[test]
    fn slack_config_must_point_at_slack() {
        assert!(
            Builtin::SlackNotify
                .validate_config(&json!({ "webhook_url": "https://hooks.slack.com/services/x" }))
                .is_ok()
        );
        assert!(
            Builtin::SlackNotify
                .validate_config(&json!({ "webhook_url": "https://evil.example/x" }))
                .is_err()
        );
        assert!(
            Builtin::SlackNotify
                .validate_config(&json!({ "webhook_url": "http://hooks.slack.com/x" }))
                .is_err()
        );
    }
}
