use std::time::Duration;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::cases::settings::{self, CustomFieldInput, PriorityInput, SlaInput, StatusInput};
use crate::cases::views;
use crate::channels::{self, ChannelChanges, NewChannel};
use crate::http::error::{ApiError, ApiResult};
use crate::http::security::{Client, limit_ip, limit_key};
use crate::http::{AppState, Caller, org_actor};
use crate::platform::page::{PageQuery, Paged};

pub async fn create_status(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<StatusInput>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let status = settings::save_status(&mut conn, org_id, actor, None, body).await?;
    Ok((StatusCode::CREATED, Json(json!({ "status": status }))))
}

pub async fn update_status(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<StatusInput>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "status": settings::save_status(&mut conn, org_id, actor, Some(id), body).await? }),
    ))
}

pub async fn delete_status(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    settings::delete_status(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn create_priority(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<PriorityInput>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let priority = settings::save_priority(&mut conn, org_id, actor, None, body).await?;
    Ok((StatusCode::CREATED, Json(json!({ "priority": priority }))))
}

pub async fn update_priority(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<PriorityInput>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "priority": settings::save_priority(&mut conn, org_id, actor, Some(id), body).await? }),
    ))
}

pub async fn delete_priority(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    settings::delete_priority(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_custom_fields(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "custom_fields": settings::list_custom_fields(&mut conn, org_id, actor).await? }),
    ))
}

pub async fn create_custom_field(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<CustomFieldInput>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let field = settings::save_custom_field(&mut conn, org_id, actor, None, body).await?;
    Ok((StatusCode::CREATED, Json(json!({ "custom_field": field }))))
}

pub async fn update_custom_field(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<CustomFieldInput>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let field = settings::save_custom_field(&mut conn, org_id, actor, Some(id), body).await?;
    Ok(Json(json!({ "custom_field": field })))
}

pub async fn list_sla(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "sla_policies": settings::list_sla(&mut conn, org_id, actor).await? }),
    ))
}

pub async fn save_sla(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<SlaInput>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "sla_policy": settings::save_sla(&mut conn, org_id, actor, body).await? }),
    ))
}

pub async fn delete_sla(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    settings::delete_sla(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_views(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "views": views::list(&mut conn, org_id, actor).await? }),
    ))
}

#[derive(Deserialize)]
pub struct ViewRequest {
    name: String,
    filter: Value,
    #[serde(default)]
    shared: bool,
}

pub async fn create_view(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<ViewRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let view = views::save(
        &mut conn,
        org_id,
        actor,
        None,
        &body.name,
        body.filter,
        body.shared,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(json!({ "view": view }))))
}

pub async fn update_view(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<ViewRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let view = views::save(
        &mut conn,
        org_id,
        actor,
        Some(id),
        &body.name,
        body.filter,
        body.shared,
    )
    .await?;
    Ok(Json(json!({ "view": view })))
}

pub async fn delete_view(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    views::delete(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn view_cases(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Query(page): Query<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let page = page.page()?;
    let mut conn = state.pool.acquire().await?;
    let rows = views::cases(&mut conn, org_id, actor, id, page).await?;
    Ok(Json(Paged::new(rows, page, |c| c.id)))
}

pub async fn list_channels(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "channels": channels::list(&mut conn, org_id, actor).await? }),
    ))
}

#[derive(Deserialize)]
pub struct ChannelRequest {
    workspace_id: Option<Uuid>,
    kind: Option<String>,
    name: Option<String>,
    address: Option<String>,
    allowed_origins: Option<Vec<String>>,
    enabled: Option<bool>,
}

pub async fn create_channel(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<ChannelRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let workspace_id = body.workspace_id.ok_or_else(|| {
        ApiError::from(crate::platform::error::invalid(
            "workspace_id",
            "is required",
        ))
    })?;
    let mut conn = state.pool.acquire().await?;
    let (channel, secret) = channels::create(
        &mut conn,
        &state.secrets,
        org_id,
        actor,
        NewChannel {
            workspace_id,
            kind: body.kind.as_deref().unwrap_or_default(),
            name: body.name.as_deref().unwrap_or_default(),
            address: body.address.as_deref(),
            allowed_origins: body.allowed_origins.as_deref().unwrap_or_default(),
        },
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "channel": channel, "secret": secret })),
    ))
}

pub async fn update_channel(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<ChannelRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let channel = channels::update(
        &mut conn,
        org_id,
        actor,
        id,
        ChannelChanges {
            name: body.name.as_deref(),
            enabled: body.enabled,
            allowed_origins: body.allowed_origins.as_deref(),
        },
    )
    .await?;
    Ok(Json(json!({ "channel": channel })))
}

pub async fn rotate_channel_secret(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let secret = channels::rotate_secret(&mut conn, &state.secrets, org_id, actor, id).await?;
    Ok(Json(json!({ "secret": secret })))
}

pub async fn delete_channel(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    channels::delete(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn count_inbound(kind: &'static str, outcome: &'static str) {
    metrics::counter!("ultrivly_channel_messages_total", "kind" => kind, "outcome" => outcome)
        .increment(1);
}

fn outcome(received: &channels::Received) -> &'static str {
    match (received.duplicate, received.case_id) {
        (true, _) => "duplicate",
        (false, Some(_)) => "accepted",
        (false, None) => "ignored",
    }
}

fn signature(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("ultrivly-signature")
        .and_then(|v| v.to_str().ok())
}

pub async fn inbound_email(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    limit_key(
        &state,
        &format!("channel:{id}:inbound"),
        600,
        Duration::from_secs(60),
    )
    .await?;
    let received =
        channels::receive_email(&state.pool, &state.secrets, id, signature(&headers), &body)
            .await
            .inspect_err(|_| count_inbound("email", "rejected"))?;
    count_inbound("email", outcome(&received));
    Ok((StatusCode::ACCEPTED, Json(json!(received))))
}

pub async fn inbound_social(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    limit_key(
        &state,
        &format!("channel:{id}:inbound"),
        600,
        Duration::from_secs(60),
    )
    .await?;
    let received =
        channels::receive_social(&state.pool, &state.secrets, id, signature(&headers), &body)
            .await
            .inspect_err(|_| count_inbound("social", "rejected"))?;
    count_inbound("social", outcome(&received));
    Ok((StatusCode::ACCEPTED, Json(json!(received))))
}

fn origin(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
}

fn with_cors(response: impl IntoResponse, origin: Option<&str>) -> Response {
    let mut response = response.into_response();
    if let Some(origin) = origin.and_then(|o| HeaderValue::from_str(o).ok()) {
        let headers = response.headers_mut();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));
        headers.insert(
            header::HeaderName::from_static("cross-origin-resource-policy"),
            HeaderValue::from_static("cross-origin"),
        );
    }
    response
}

async fn allowed_origin(
    state: &AppState,
    channel_id: Uuid,
    headers: &HeaderMap,
) -> ApiResult<Option<String>> {
    let mut conn = state.pool.acquire().await?;
    let origin = origin(headers);
    if channels::chat_origin_allowed(&mut conn, channel_id, origin).await? {
        Ok(origin.map(String::from))
    } else {
        Err(ApiError::forbidden())
    }
}

pub async fn chat_preflight(
    State(state): State<AppState>,
    Path(params): Path<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let Some(channel_id) = params
        .get("channel_id")
        .and_then(|id| id.parse::<Uuid>().ok())
    else {
        return ApiError::not_found().into_response();
    };
    match allowed_origin(&state, channel_id, &headers).await {
        Ok(origin) => {
            let mut response = with_cors(StatusCode::NO_CONTENT, origin.as_deref());
            let h = response.headers_mut();
            h.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("GET, POST"),
            );
            h.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static("content-type, authorization"),
            );
            h.insert(
                header::ACCESS_CONTROL_MAX_AGE,
                HeaderValue::from_static("600"),
            );
            response
        }
        Err(err) => err.into_response(),
    }
}

#[derive(Deserialize)]
pub struct StartChat {
    name: String,
    email: String,
    message: String,
}

pub async fn chat_start(
    State(state): State<AppState>,
    client: Client,
    Path(channel_id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<StartChat>,
) -> Response {
    let origin = origin(&headers).map(String::from);
    let result = async {
        limit_ip(&state, &client, "chat_start", 10, Duration::from_secs(3600)).await?;
        let started = channels::start_chat(
            &state.pool,
            channel_id,
            origin.as_deref(),
            &body.name,
            &body.email,
            &body.message,
        )
        .await?;
        count_inbound("chat", "accepted");
        Ok::<_, ApiError>((StatusCode::CREATED, Json(json!(started))))
    }
    .await;
    with_cors(result, origin.as_deref())
}

fn chat_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

#[derive(Deserialize)]
pub struct AfterQuery {
    after: Option<Uuid>,
}

pub async fn chat_messages(
    State(state): State<AppState>,
    client: Client,
    Path((channel_id, case_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<AfterQuery>,
    headers: HeaderMap,
) -> Response {
    let origin = origin(&headers).map(String::from);
    let result = async {
        limit_ip(&state, &client, "chat_poll", 600, Duration::from_secs(600)).await?;
        allowed_origin(&state, channel_id, &headers).await?;
        let token = chat_token(&headers).ok_or_else(ApiError::unauthenticated)?;
        let mut conn = state.pool.acquire().await?;
        let messages = channels::chat_messages(&mut conn, channel_id, case_id, token, query.after).await?;
        let messages: Vec<Value> = messages
            .into_iter()
            .map(|m| json!({ "id": m.id, "from": if m.author_kind == "contact" { "you" } else { "agent" },
                             "author_name": if m.author_kind == "contact" { m.author_name } else { None },
                             "body": m.body, "created_at": m.created_at }))
            .collect();
        Ok::<_, ApiError>(Json(json!({ "messages": messages })))
    }
    .await;
    with_cors(result, origin.as_deref())
}

#[derive(Deserialize)]
pub struct ChatMessage {
    body: String,
}

pub async fn chat_send(
    State(state): State<AppState>,
    client: Client,
    Path((channel_id, case_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<ChatMessage>,
) -> Response {
    let origin = origin(&headers).map(String::from);
    let result = async {
        limit_ip(&state, &client, "chat_send", 120, Duration::from_secs(600)).await?;
        allowed_origin(&state, channel_id, &headers).await?;
        let token = chat_token(&headers).ok_or_else(ApiError::unauthenticated)?;
        let id = channels::chat_reply(&state.pool, channel_id, case_id, token, &body.body).await?;
        Ok::<_, ApiError>((StatusCode::CREATED, Json(json!({ "id": id }))))
    }
    .await;
    with_cors(result, origin.as_deref())
}
