use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::audit::Actor;
use crate::http::error::ApiResult;
use crate::http::security::{Client, limit_ip, limit_key};
use crate::http::{AppState, Authenticated, require_org_access};
use crate::identity::emails;
use crate::identity::invitations::{self, NewInvitation};
use crate::worker;

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Deserialize)]
pub struct CreateRequest {
    email: String,
    role_id: Uuid,
    workspace_id: Option<Uuid>,
}

pub async fn create(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Path(org_id): Path<Uuid>,
    Json(body): Json<CreateRequest>,
) -> ApiResult<impl IntoResponse> {
    require_org_access(&state, &session, org_id).await?;
    
    
    limit_key(&state, &format!("org:{org_id}:invitations"), 200, DAY).await?;
    limit_key(
        &state,
        &format!("user:{}:invitations", session.user_id),
        100,
        DAY,
    )
    .await?;

    let mut conn = state.pool.acquire().await?;
    let created = invitations::create(
        &mut conn,
        org_id,
        Actor::User(session.user_id),
        NewInvitation {
            email: &body.email,
            role_id: body.role_id,
            workspace_id: body.workspace_id,
        },
    )
    .await?;
    let email = emails::invitation(
        &created.email,
        &state.public_url,
        &created.token,
        &created.org_name,
        &created.inviter_name,
    );
    worker::enqueue_email(&mut conn, &state.secrets, &email).await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": created.id }))))
}

pub async fn list(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    require_org_access(&state, &session, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let open = invitations::list_open(&mut conn, org_id, Actor::User(session.user_id)).await?;
    Ok(Json(json!({ "invitations": open })))
}

pub async fn revoke(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    require_org_access(&state, &session, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    invitations::revoke(&mut conn, org_id, Actor::User(session.user_id), id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct AcceptRequest {
    token: String,
}

pub async fn accept(
    State(state): State<AppState>,
    client: Client,
    Authenticated(session): Authenticated,
    Json(body): Json<AcceptRequest>,
) -> ApiResult<impl IntoResponse> {
    limit_ip(&state, &client, "token", 30, Duration::from_secs(3600)).await?;
    let mut conn = state.pool.acquire().await?;
    let org_id = invitations::accept(&mut conn, &session, &body.token).await?;
    Ok(Json(json!({ "org_id": org_id })))
}
