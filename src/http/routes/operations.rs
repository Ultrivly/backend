use std::time::Duration;

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use chrono::Utc;

use crate::channels::{self, mail_domains};
use crate::exports;
use crate::http::error::{ApiError, ApiResult};
use crate::http::security::limit_key;
use crate::http::{AppState, Caller, org_actor};
use crate::platform::error::invalid;
use crate::platform::mail::{self, MailEvents};
use crate::platform::page::{PageQuery, Paged};

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ExportRequest {
    contact_id: Option<Uuid>,
}

pub async fn request_export(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    body: Option<Json<ExportRequest>>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let mut conn = state.pool.acquire().await?;
    let export = exports::request(&mut conn, org_id, actor, body.contact_id).await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "export": export }))))
}

pub async fn list_exports(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Query(query): Query<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let page = query.page()?;
    let mut conn = state.pool.acquire().await?;
    let rows = exports::list(&mut conn, org_id, actor, page).await?;
    Ok(Json(Paged::new(rows, page, |e| e.id)))
}

pub async fn get_export(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "export": exports::get(&mut conn, org_id, actor, id).await? }),
    ))
}

pub async fn download_export(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let (export, key) = exports::download(&mut conn, org_id, actor, id).await?;
    drop(conn);
    let (size, stream) = state.blobs.stream(&key).await.map_err(ApiError::internal)?;
    let mut response = Response::new(Body::from_stream(stream));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!(
            "attachment; filename=\"ultrivly-{}-export-{}.zip\"",
            export.kind, export.id
        ))
        .map_err(ApiError::internal)?,
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

pub async fn mail_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    let Some(secret) = state.mail_events_secret.as_deref() else {
        return Err(ApiError::not_found());
    };
    limit_key(&state, "mail_events", 1200, Duration::from_secs(60)).await?;
    let signature = headers
        .get("ultrivly-signature")
        .and_then(|v| v.to_str().ok());
    if !channels::verify_signature(secret, signature, &body, Utc::now().timestamp()) {
        return Err(ApiError::forbidden());
    }
    let events: MailEvents = serde_json::from_slice(&body)
        .map_err(|_| ApiError::from(invalid("body", "is not a valid list of mail events")))?;
    if events.events.len() > 500 {
        return Err(invalid("events", "may contain at most 500 events").into());
    }
    let suppressed = mail::apply_events(&state.pool, &events.events).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "received": events.events.len(), "suppressed": suppressed })),
    ))
}

pub async fn list_mail_domains(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "mail_domains": mail_domains::list(&mut conn, org_id, actor).await? }),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailDomainRequest {
    domain: String,
}

pub async fn add_mail_domain(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<MailDomainRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let domain = mail_domains::add(&mut conn, &state.secrets, org_id, actor, &body.domain).await?;
    Ok((StatusCode::CREATED, Json(json!({ "mail_domain": domain }))))
}

pub async fn verify_mail_domain(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    limit_key(
        &state,
        &format!("mail_domain_verify:{org_id}"),
        30,
        Duration::from_secs(3600),
    )
    .await?;
    let mut conn = state.pool.acquire().await?;
    let name = mail_domains::dns_name(&mut conn, org_id, actor, id).await?;
    drop(conn);
    let records = match mail_domains::lookup_txt(&name).await {
        Ok(records) => records,
        Err(err) => {
            tracing::info!(%org_id, "DNS lookup for mail domain failed: {err}");
            Vec::new()
        }
    };
    let mut conn = state.pool.acquire().await?;
    let domain = mail_domains::verify(&mut conn, org_id, actor, id, &records).await?;
    Ok(Json(json!({ "mail_domain": domain })))
}

pub async fn remove_mail_domain(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    mail_domains::remove(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}
