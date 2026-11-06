use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::ai;
use crate::http::error::ApiResult;
use crate::http::security::limit_key;
use crate::http::{AppState, Caller, org_actor};
use crate::integrations::webhooks::{self, EndpointChanges};
use crate::platform::job_admin;
use crate::platform::page::{PageQuery, Paged};
use crate::plugins;
use crate::reporting::{self, ReportQuery};
use crate::workflows::{self, Definition};

const AI_PER_HOUR: i32 = 300;

pub async fn list_webhooks(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "webhooks": webhooks::list(&mut conn, org_id, actor).await? }),
    ))
}

#[derive(Deserialize)]
pub struct WebhookRequest {
    url: Option<String>,
    description: Option<String>,
    events: Option<Vec<String>>,
    enabled: Option<bool>,
}

pub async fn create_webhook(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<WebhookRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let (endpoint, secret) = webhooks::create(
        &mut conn,
        state.sso.http.policy(),
        &state.secrets,
        org_id,
        actor,
        webhooks::NewEndpoint {
            url: body.url.as_deref().unwrap_or_default(),
            description: body.description.as_deref().unwrap_or_default(),
            events: &body.events.unwrap_or_default(),
        },
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "webhook": endpoint, "secret": secret })),
    ))
}

pub async fn update_webhook(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<WebhookRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let endpoint = webhooks::update(
        &mut conn,
        state.sso.http.policy(),
        org_id,
        actor,
        id,
        EndpointChanges {
            url: body.url.as_deref(),
            description: body.description.as_deref(),
            events: body.events.as_deref(),
            enabled: body.enabled,
        },
    )
    .await?;
    Ok(Json(json!({ "webhook": endpoint })))
}

pub async fn delete_webhook(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    webhooks::delete(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn rotate_webhook_secret(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let secret = webhooks::rotate_secret(&mut conn, &state.secrets, org_id, actor, id).await?;
    Ok(Json(json!({ "secret": secret })))
}

pub async fn webhook_deliveries(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Query(page): Query<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let page = page.page()?;
    let mut conn = state.pool.acquire().await?;
    let rows = webhooks::deliveries(&mut conn, org_id, actor, id, page).await?;
    Ok(Json(Paged::new(rows, page, |d| d.id)))
}

pub async fn redeliver(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    webhooks::redeliver(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::ACCEPTED)
}

pub async fn list_workflows(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "workflows": workflows::list(&mut conn, org_id, actor).await? }),
    ))
}

#[derive(Deserialize)]
pub struct CreateWorkflowRequest {
    name: String,
    workspace_id: Option<Uuid>,
    definition: Definition,
}

pub async fn create_workflow(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<CreateWorkflowRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let workflow = workflows::create(
        &mut conn,
        org_id,
        actor,
        &body.name,
        body.workspace_id,
        body.definition,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(json!({ "workflow": workflow }))))
}

pub async fn get_workflow(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "workflow": workflows::get(&mut conn, org_id, actor, id).await? }),
    ))
}

#[derive(Deserialize)]
pub struct UpdateWorkflowRequest {
    name: Option<String>,
    definition: Option<Definition>,
}

pub async fn update_workflow(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateWorkflowRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let workflow = workflows::update(
        &mut conn,
        org_id,
        actor,
        id,
        body.name.as_deref(),
        body.definition,
    )
    .await?;
    Ok(Json(json!({ "workflow": workflow })))
}

pub async fn publish_workflow(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let workflow = workflows::set_enabled(&mut conn, org_id, actor, id, true).await?;
    Ok(Json(json!({ "workflow": workflow })))
}

pub async fn disable_workflow(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let workflow = workflows::set_enabled(&mut conn, org_id, actor, id, false).await?;
    Ok(Json(json!({ "workflow": workflow })))
}

pub async fn delete_workflow(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    workflows::delete(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn workflow_runs(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Query(page): Query<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let page = page.page()?;
    let mut conn = state.pool.acquire().await?;
    let rows = workflows::runs(&mut conn, org_id, actor, id, page).await?;
    Ok(Json(Paged::new(rows, page, |r| r.id)))
}

pub async fn report_summary(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Query(query): Query<ReportQuery>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        reporting::summary(&mut conn, org_id, actor, &query).await?,
    ))
}

pub async fn plugin_catalogue() -> impl IntoResponse {
    Json(json!({ "plugins": plugins::catalogue() }))
}

pub async fn list_plugins(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "plugins": plugins::list(&mut conn, org_id, actor).await? }),
    ))
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InstallRequest {
    Builtin {
        plugin_key: String,
        #[serde(default)]
        config: serde_json::Value,
    },
    Webhook {
        base_url: String,
    },
}

pub async fn install_plugin(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<InstallRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let body = match body {
        InstallRequest::Builtin { plugin_key, config } => {
            let install = plugins::install_builtin(
                &mut conn,
                &state.secrets,
                org_id,
                actor,
                &plugin_key,
                &config,
            )
            .await?;
            json!({ "plugin": install })
        }
        InstallRequest::Webhook { base_url } => {
            let installed = plugins::install_webhook(
                &mut conn,
                &state.sso.http,
                &state.secrets,
                org_id,
                actor,
                &base_url,
            )
            .await?;
            json!({
                "plugin": installed.install,
                "api_token": installed.api_token,
                "signing_secret": installed.signing_secret,
            })
        }
    };
    Ok((StatusCode::CREATED, Json(body)))
}

#[derive(Deserialize)]
pub struct PluginChanges {
    enabled: bool,
}

pub async fn update_plugin(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<PluginChanges>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(json!({
        "plugin": plugins::set_enabled(&mut conn, org_id, actor, id, body.enabled).await?
    })))
}

pub async fn uninstall_plugin(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    plugins::uninstall(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_ai_settings(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "ai": ai::get_settings(&mut conn, org_id, actor).await? }),
    ))
}

pub async fn put_ai_settings(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<ai::SettingsInput>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let settings = ai::save_settings(
        &mut conn,
        state.sso.http.policy(),
        &state.secrets,
        org_id,
        actor,
        body,
    )
    .await?;
    Ok(Json(json!({ "ai": settings })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssistRequest {
    task: ai::Task,
}

pub async fn ai_assist(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, case_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<AssistRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    limit_key(
        &state,
        &format!("ai:{org_id}"),
        AI_PER_HOUR,
        Duration::from_secs(3600),
    )
    .await?;
    let suggestion = ai::assist(
        &state.pool,
        &state.sso.http,
        &state.secrets,
        org_id,
        actor,
        case_id,
        body.task,
    )
    .await?;
    Ok(Json(json!({ "suggestion": suggestion })))
}

#[derive(Deserialize)]
pub struct JobQuery {
    state: Option<String>,
    kind: Option<String>,
    #[serde(flatten)]
    page: PageQuery,
}

pub async fn list_jobs(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Query(query): Query<JobQuery>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let page = query.page.page()?;
    let mut conn = state.pool.acquire().await?;
    let rows = job_admin::list(
        &mut conn,
        org_id,
        actor,
        query.state.as_deref(),
        query.kind.as_deref(),
        page,
    )
    .await?;
    Ok(Json(Paged::new(rows, page, |j| j.id)))
}

pub async fn retry_job(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    job_admin::retry(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::ACCEPTED)
}
