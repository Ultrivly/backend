use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::http::error::ApiResult;
use crate::http::security::{Client, limit_ip};
use crate::http::{AppState, Caller, org_actor};
use crate::knowledge::{self, ArticleFilter, ArticleInput};
use crate::platform::page::{PageQuery, Paged};

pub async fn list_categories(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(json!({ "categories": knowledge::list_categories(&mut conn, org_id, actor).await? })))
}

#[derive(Deserialize)]
pub struct CategoryRequest {
    name: String,
    #[serde(default)]
    position: i32,
}

pub async fn create_category(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<CategoryRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let category = knowledge::save_category(&mut conn, org_id, actor, None, &body.name, body.position).await?;
    Ok((StatusCode::CREATED, Json(json!({ "category": category }))))
}

pub async fn update_category(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<CategoryRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let category = knowledge::save_category(&mut conn, org_id, actor, Some(id), &body.name, body.position).await?;
    Ok(Json(json!({ "category": category })))
}

pub async fn delete_category(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    knowledge::delete_category(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_articles(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Query(filter): Query<ArticleFilter>,
    Query(page): Query<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let page = page.page()?;
    let mut conn = state.pool.acquire().await?;
    let rows = knowledge::list_articles(&mut conn, org_id, actor, &filter, page).await?;
    Ok(Json(Paged::new(rows, page, |a| a.id)))
}

pub async fn create_article(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<ArticleInput>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let article = knowledge::create_article(&mut conn, org_id, actor, body).await?;
    Ok((StatusCode::CREATED, Json(json!({ "article": article }))))
}

pub async fn get_article(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(json!({ "article": knowledge::get_article(&mut conn, org_id, actor, id).await? })))
}

pub async fn update_article(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<ArticleInput>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let article = knowledge::update_article(&mut conn, org_id, actor, id, body).await?;
    Ok(Json(json!({ "article": article })))
}

#[derive(Deserialize)]
pub struct StateRequest {
    state: String,
}

pub async fn set_article_state(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<StateRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let article = knowledge::set_state(&mut conn, org_id, actor, id, &body.state).await?;
    Ok(Json(json!({ "article": article })))
}

pub async fn delete_article(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    knowledge::delete_article(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct HelpQuery {
    q: Option<String>,
}

pub async fn help_center(
    State(state): State<AppState>,
    client: Client,
    Path(org_slug): Path<String>,
    Query(query): Query<HelpQuery>,
    Query(page): Query<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    limit_ip(&state, &client, "help_center", 300, Duration::from_secs(60)).await?;
    let page = page.page()?;
    let mut conn = state.pool.acquire().await?;
    let rows = knowledge::help_center(&mut conn, &org_slug, query.q.as_deref(), page).await?;
    Ok(Json(Paged::new(rows, page, |a| a.id)))
}

pub async fn help_article(
    State(state): State<AppState>,
    client: Client,
    Path((org_slug, slug)): Path<(String, String)>,
) -> ApiResult<impl IntoResponse> {
    limit_ip(&state, &client, "help_center", 300, Duration::from_secs(60)).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(json!({ "article": knowledge::help_article(&mut conn, &org_slug, &slug).await? })))
}
