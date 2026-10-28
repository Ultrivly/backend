use std::time::Duration;

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::cases::records::{self, CaseChanges, CaseFilter, NewCase};
use crate::cases::{self, attachments, contacts, messages, portal};
use crate::http::error::{ApiError, ApiResult};
use crate::http::security::limit_key;
use crate::http::{AppState, Authenticated, Caller, org_actor};
use crate::platform::deletion::{self, DEFAULT_RETENTION, Target};
use crate::platform::events::Cause;
use crate::platform::page::{PageQuery, Paged};
use crate::routing::{self, NewTeam, QueueCriteria, QueueInput, TeamChanges};

#[derive(Deserialize)]
pub struct WorkspaceQuery {
    workspace_id: Option<Uuid>,
}

pub async fn list_departments(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "departments": routing::list_departments(&mut conn, org_id, actor).await? }),
    ))
}

#[derive(Deserialize)]
pub struct NameRequest {
    name: String,
}

pub async fn create_department(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<NameRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let department = routing::create_department(&mut conn, org_id, actor, &body.name).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "department": department })),
    ))
}

pub async fn rename_department(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<NameRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let department = routing::rename_department(&mut conn, org_id, actor, id, &body.name).await?;
    Ok(Json(json!({ "department": department })))
}

pub async fn delete_department(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    routing::delete_department(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_teams(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Query(query): Query<WorkspaceQuery>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "teams": routing::list_teams(&mut conn, org_id, actor, query.workspace_id).await? }),
    ))
}

#[derive(Deserialize)]
pub struct CreateTeamRequest {
    workspace_id: Uuid,
    department_id: Option<Uuid>,
    name: String,
}

pub async fn create_team(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<CreateTeamRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let team = routing::create_team(
        &mut conn,
        org_id,
        actor,
        NewTeam {
            workspace_id: body.workspace_id,
            department_id: body.department_id,
            name: &body.name,
        },
    )
    .await?;
    Ok((StatusCode::CREATED, Json(json!({ "team": team }))))
}

#[derive(Deserialize)]
pub struct UpdateTeamRequest {
    name: Option<String>,
    #[serde(default, deserialize_with = "double")]
    department_id: Option<Option<Uuid>>,
    archived: Option<bool>,
}

fn double<'de, D>(deserializer: D) -> Result<Option<Option<Uuid>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<Uuid>::deserialize(deserializer).map(Some)
}

pub async fn update_team(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateTeamRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let team = routing::update_team(
        &mut conn,
        org_id,
        actor,
        id,
        TeamChanges {
            name: body.name.as_deref(),
            department_id: body.department_id,
            archived: body.archived,
        },
    )
    .await?;
    Ok(Json(json!({ "team": team })))
}

pub async fn delete_team(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    routing::delete_team(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_team_member(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id, user_id)): Path<(Uuid, Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let team = routing::set_team_member(&mut conn, org_id, actor, id, user_id, true).await?;
    Ok(Json(json!({ "team": team })))
}

pub async fn remove_team_member(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id, user_id)): Path<(Uuid, Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let team = routing::set_team_member(&mut conn, org_id, actor, id, user_id, false).await?;
    Ok(Json(json!({ "team": team })))
}

pub async fn list_queues(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Query(query): Query<WorkspaceQuery>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "queues": routing::list_queues(&mut conn, org_id, actor, query.workspace_id).await? }),
    ))
}

#[derive(Deserialize)]
pub struct QueueRequest {
    workspace_id: Uuid,
    team_id: Option<Uuid>,
    name: String,
    #[serde(default)]
    criteria: QueueCriteria,
    #[serde(default)]
    position: i32,
}

pub async fn create_queue(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<QueueRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let queue = routing::save_queue(&mut conn, org_id, actor, None, queue_input(&body)).await?;
    Ok((StatusCode::CREATED, Json(json!({ "queue": queue }))))
}

fn queue_input(body: &QueueRequest) -> QueueInput<'_> {
    QueueInput {
        workspace_id: body.workspace_id,
        team_id: body.team_id,
        name: &body.name,
        criteria: body.criteria.clone(),
        position: body.position,
    }
}

pub async fn update_queue(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<QueueRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let queue = routing::save_queue(&mut conn, org_id, actor, Some(id), queue_input(&body)).await?;
    Ok(Json(json!({ "queue": queue })))
}

pub async fn delete_queue(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    routing::delete_queue(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn queue_cases(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Query(page): Query<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let page = page.page()?;
    let mut conn = state.pool.acquire().await?;
    let queue = routing::get_queue(&mut conn, org_id, id).await?;
    let filter = CaseFilter {
        workspace_id: Some(queue.workspace_id),
        status: queue.criteria.statuses,
        priority: queue.criteria.priorities,
        team_id: queue.criteria.team_id.or(queue.team_id),
        unassigned: queue.criteria.unassigned.unwrap_or(false),
        tags: queue.criteria.tags,
        ..CaseFilter::default()
    };
    let rows = records::list(&mut conn, org_id, actor, &filter, page).await?;
    Ok(Json(Paged::new(rows, page, |c| c.id)))
}

pub async fn statuses(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(json!({
        "statuses": cases::statuses(&mut conn, org_id, actor).await?,
        "priorities": cases::priorities(&mut conn, org_id, actor).await?,
    })))
}

#[derive(Deserialize)]
pub struct ContactQuery {
    q: Option<String>,
}

pub async fn list_contacts(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Query(query): Query<ContactQuery>,
    Query(page): Query<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let page = page.page()?;
    let mut conn = state.pool.acquire().await?;
    let rows = contacts::list(&mut conn, org_id, actor, query.q.as_deref(), page).await?;
    Ok(Json(Paged::new(rows, page, |c| c.id)))
}

#[derive(Deserialize)]
pub struct ContactRequest {
    email: Option<String>,
    display_name: Option<String>,
}

pub async fn create_contact(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<ContactRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let contact = contacts::create(
        &mut conn,
        org_id,
        actor,
        body.email.as_deref(),
        body.display_name.as_deref().unwrap_or_default(),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(json!({ "contact": contact }))))
}

pub async fn get_contact(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "contact": contacts::get(&mut conn, org_id, actor, id).await? }),
    ))
}

pub async fn update_contact(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<ContactRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let contact = contacts::update(
        &mut conn,
        org_id,
        actor,
        id,
        body.email.as_deref(),
        body.display_name.as_deref(),
    )
    .await?;
    Ok(Json(json!({ "contact": contact })))
}

pub async fn list_cases(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Query(filter): Query<CaseFilter>,
    Query(page): Query<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let page = page.page()?;
    let mut conn = state.pool.acquire().await?;
    let rows = records::list(&mut conn, org_id, actor, &filter, page).await?;
    Ok(Json(Paged::new(rows, page, |c| c.id)))
}

pub async fn create_case(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<NewCase>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let case = records::create(&mut conn, org_id, actor, body, Cause::default()).await?;
    Ok((StatusCode::CREATED, Json(json!({ "case": case }))))
}

pub async fn get_case(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "case": records::get(&mut conn, org_id, actor, id).await? }),
    ))
}

pub async fn update_case(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<CaseChanges>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let case = records::update(&mut conn, org_id, actor, id, body, Cause::default()).await?;
    Ok(Json(json!({ "case": case })))
}

#[derive(Deserialize)]
pub struct ConfirmRequest {
    confirm: String,
}

pub async fn delete_case(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<ConfirmRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let purge_after = deletion::schedule(
        &mut conn,
        Target::case(org_id, id),
        &body.confirm,
        actor,
        DEFAULT_RETENTION,
    )
    .await?;
    Ok(Json(json!({ "purge_after": purge_after })))
}

pub async fn restore_case(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    deletion::restore(&mut conn, Target::case(org_id, id), actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn case_history(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Query(page): Query<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let page = page.page()?;
    let mut conn = state.pool.acquire().await?;
    let rows = records::history_list(&mut conn, org_id, actor, id, page).await?;
    Ok(Json(Paged::new(rows, page, |e| e.id)))
}

pub async fn list_messages(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "messages": messages::list(&mut conn, org_id, actor, id).await? }),
    ))
}

#[derive(Deserialize)]
pub struct MessageRequest {
    visibility: String,
    body: String,
    body_format: Option<String>,
}

pub async fn add_message(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<MessageRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let message = messages::add(
        &mut conn,
        org_id,
        actor,
        id,
        &body.visibility,
        &body.body,
        body.body_format.as_deref(),
        Cause::default(),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(json!({ "message": message }))))
}

pub async fn list_links(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "links": records::links(&mut conn, org_id, actor, id).await? }),
    ))
}

#[derive(Deserialize)]
pub struct LinkRequest {
    linked_case_id: Uuid,
    kind: String,
}

pub async fn add_link(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<LinkRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    records::set_link(
        &mut conn,
        org_id,
        actor,
        id,
        body.linked_case_id,
        &body.kind,
        true,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove_link(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<LinkRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    records::set_link(
        &mut conn,
        org_id,
        actor,
        id,
        body.linked_case_id,
        &body.kind,
        false,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_attachments(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "attachments": attachments::list(&mut conn, org_id, actor, id).await? }),
    ))
}

#[derive(Deserialize)]
pub struct UploadQuery {
    file_name: String,
    message_id: Option<Uuid>,
}

pub async fn upload_attachment(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Query(query): Query<UploadQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let mut conn = state.pool.acquire().await?;
    let attachment = attachments::upload(
        &mut conn,
        &state.blobs,
        org_id,
        actor,
        id,
        query.message_id,
        &query.file_name,
        content_type,
        body.to_vec(),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "attachment": attachment })),
    ))
}

pub async fn download_attachment(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Response> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let (attachment, bytes) =
        attachments::download(&mut conn, &state.blobs, org_id, actor, id).await?;
    let ascii: String = attachment
        .file_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let encoded: String = url::form_urlencoded::byte_serialize(attachment.file_name.as_bytes())
        .collect::<String>()
        .replace('+', "%20");
    let disposition = format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{encoded}");
    let mut response = Response::new(Body::from(bytes));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&attachment.content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition).map_err(ApiError::internal)?,
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    Ok(response)
}

#[derive(Deserialize)]
pub struct AttachmentDeleteRequest {
    confirm: String,
}

pub async fn delete_attachment(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<AttachmentDeleteRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let purge_after = deletion::schedule(
        &mut conn,
        Target::attachment(org_id, id),
        &body.confirm,
        actor,
        DEFAULT_RETENTION,
    )
    .await?;
    Ok(Json(json!({ "purge_after": purge_after })))
}

pub async fn portal_cases(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Query(page): Query<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    let page = page.page()?;
    let mut conn = state.pool.acquire().await?;
    let rows = portal::list(&mut conn, session.user_id, page).await?;
    Ok(Json(Paged::new(rows, page, |c| c.id)))
}

pub async fn portal_case(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let mut conn = state.pool.acquire().await?;
    let (case, messages) = portal::get(&mut conn, session.user_id, id).await?;
    Ok(Json(json!({ "case": case, "messages": messages })))
}

#[derive(Deserialize)]
pub struct PortalReply {
    body: String,
}

pub async fn portal_reply(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Path(id): Path<Uuid>,
    Json(body): Json<PortalReply>,
) -> ApiResult<impl IntoResponse> {
    limit_key(
        &state,
        &format!("user:{}:portal_reply", session.user_id),
        60,
        Duration::from_secs(3600),
    )
    .await?;
    let mut conn = state.pool.acquire().await?;
    let message = portal::reply(&mut conn, session.user_id, id, &body.body).await?;
    Ok((StatusCode::CREATED, Json(json!({ "message": message }))))
}

#[derive(Deserialize)]
pub struct PortalSubmit {
    subject: String,
    #[serde(default)]
    description: String,
}

pub async fn portal_submit(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Path(workspace_id): Path<Uuid>,
    Json(body): Json<PortalSubmit>,
) -> ApiResult<impl IntoResponse> {
    limit_key(
        &state,
        &format!("user:{}:portal_submit", session.user_id),
        20,
        Duration::from_secs(86400),
    )
    .await?;
    let mut conn = state.pool.acquire().await?;
    let case = portal::submit(
        &mut conn,
        session.user_id,
        workspace_id,
        &body.subject,
        &body.description,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(json!({ "case": case }))))
}
