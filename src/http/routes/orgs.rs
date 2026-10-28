use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::audit;
use crate::http::error::{ApiError, ApiResult};
use crate::http::security::limit_key;
use crate::http::{AppState, Authenticated, Caller, org_actor};
use crate::identity::members::{self, RoleAssignment};
use crate::identity::orgs::{self, OrgChanges, WorkspaceChanges};
use crate::identity::roles::{self, NewRole, RoleChanges};
use crate::identity::saml::NewSamlConnection;
use crate::identity::sso::{ConnectionChanges, NewConnection};
use crate::identity::{self, CreateOrganizationError, NewOrganization, accounts};
use crate::integrations::api_credentials::{self, NewCredential};
use crate::platform::authz::Permission;
use crate::platform::deletion::{self, DEFAULT_RETENTION, Target};
use crate::platform::error::{ServiceError, invalid};
use crate::platform::page::{PageQuery, Paged};

fn permissions(names: &[String]) -> Result<Vec<Permission>, ApiError> {
    names
        .iter()
        .map(|n| n.parse::<Permission>())
        .collect::<Result<_, _>>()
        .map_err(|_| invalid("permissions", "contains an unknown permission").into())
}

pub async fn permission_catalogue() -> Json<Value> {
    let names: Vec<&str> = Permission::ALL.iter().map(|p| p.as_str()).collect();
    Json(json!({ "permissions": names }))
}

pub async fn list_mine(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<impl IntoResponse> {
    let mut conn = state.pool.acquire().await?;
    let profile = accounts::profile(&mut conn, session.user_id).await?;
    Ok(Json(json!({ "organizations": profile.organizations })))
}

#[derive(Deserialize)]
pub struct CreateOrgRequest {
    name: String,
    slug: String,
    workspace_name: String,
    workspace_slug: String,
}

pub async fn create(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Json(body): Json<CreateOrgRequest>,
) -> ApiResult<impl IntoResponse> {
    limit_key(
        &state,
        &format!("user:{}:create_org", session.user_id),
        10,
        Duration::from_secs(86400),
    )
    .await?;
    let mut conn = state.pool.acquire().await?;
    if !accounts::profile(&mut conn, session.user_id)
        .await?
        .email_verified
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "email_not_verified",
            "verify your email address before creating an organization",
        ));
    }
    let created = identity::create_organization(
        &mut conn,
        NewOrganization {
            name: &body.name,
            slug: &body.slug,
            workspace_name: &body.workspace_name,
            workspace_slug: &body.workspace_slug,
            owner_user_id: session.user_id,
        },
    )
    .await
    .map_err(|err| match err {
        CreateOrganizationError::Invalid { field, reason } => invalid(field, reason).into(),
        CreateOrganizationError::SlugTaken => ApiError::new(
            StatusCode::CONFLICT,
            "slug_taken",
            "an organization with this slug already exists",
        )
        .field("slug"),
        CreateOrganizationError::OwnerNotFound => ApiError::unauthenticated(),
        CreateOrganizationError::Database(err) => ApiError::internal(err),
    })?;
    let org = orgs::get(
        &mut conn,
        created.org_id,
        crate::audit::Actor::User(session.user_id),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "organization": org, "workspace_id": created.workspace_id })),
    ))
}

pub async fn get(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "organization": orgs::get(&mut conn, org_id, actor).await? }),
    ))
}

#[derive(Deserialize)]
pub struct UpdateOrgRequest {
    name: Option<String>,
    require_mfa: Option<bool>,
}

pub async fn update(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<UpdateOrgRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let org = orgs::update(
        &mut conn,
        org_id,
        actor,
        OrgChanges {
            name: body.name.as_deref(),
            require_mfa: body.require_mfa,
        },
    )
    .await?;
    Ok(Json(json!({ "organization": org })))
}

#[derive(Deserialize)]
pub struct ConfirmRequest {
    confirm: String,
}

pub async fn delete_org(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<ConfirmRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let purge_after = deletion::schedule(
        &mut conn,
        Target::organization(org_id),
        &body.confirm,
        actor,
        DEFAULT_RETENTION,
    )
    .await?;
    Ok(Json(json!({ "purge_after": purge_after })))
}

pub async fn restore_org(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    deletion::restore(&mut conn, Target::organization(org_id), actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_workspaces(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "workspaces": orgs::list_workspaces(&mut conn, org_id, actor).await? }),
    ))
}

#[derive(Deserialize)]
pub struct CreateWorkspaceRequest {
    name: String,
    slug: String,
}

pub async fn create_workspace(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<CreateWorkspaceRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let workspace =
        orgs::create_workspace(&mut conn, org_id, actor, &body.name, &body.slug).await?;
    Ok((StatusCode::CREATED, Json(json!({ "workspace": workspace }))))
}

#[derive(Deserialize)]
pub struct UpdateWorkspaceRequest {
    name: Option<String>,
    portal_enabled: Option<bool>,
}

pub async fn update_workspace(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateWorkspaceRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let workspace = orgs::update_workspace(
        &mut conn,
        org_id,
        actor,
        id,
        WorkspaceChanges {
            name: body.name.as_deref(),
            portal_enabled: body.portal_enabled,
        },
    )
    .await?;
    Ok(Json(json!({ "workspace": workspace })))
}

pub async fn delete_workspace(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<ConfirmRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let purge_after = deletion::schedule(
        &mut conn,
        Target::workspace(org_id, id),
        &body.confirm,
        actor,
        DEFAULT_RETENTION,
    )
    .await?;
    Ok(Json(json!({ "purge_after": purge_after })))
}

pub async fn restore_workspace(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    deletion::restore(&mut conn, Target::workspace(org_id, id), actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_members(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    Ok(Json(
        json!({ "members": members::list(&mut conn, org_id, actor).await? }),
    ))
}

#[derive(Deserialize)]
pub struct UpdateMemberRequest {
    status: String,
}

pub async fn update_member(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateMemberRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    members::set_status(&mut conn, org_id, actor, id, &body.status).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove_member(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    members::remove(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct RoleAssignmentRequest {
    role_id: Uuid,
    workspace_id: Option<Uuid>,
}

pub async fn assign_role(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<RoleAssignmentRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    members::assign_role(
        &mut conn,
        org_id,
        actor,
        RoleAssignment {
            membership_id: id,
            role_id: body.role_id,
            workspace_id: body.workspace_id,
        },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove_role(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<RoleAssignmentRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    members::remove_role(
        &mut conn,
        org_id,
        actor,
        RoleAssignment {
            membership_id: id,
            role_id: body.role_id,
            workspace_id: body.workspace_id,
        },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_roles(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let roles = roles::list_roles(&mut conn, org_id, actor).await?;
    Ok(Json(
        json!({ "roles": roles.iter().map(role_json).collect::<Vec<_>>() }),
    ))
}

fn role_json(role: &roles::Role) -> Value {
    json!({
        "id": role.id,
        "key": role.key,
        "name": role.name,
        "is_builtin": role.is_builtin,
        "permissions": role.permissions.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
    })
}

#[derive(Deserialize)]
pub struct RoleRequest {
    name: Option<String>,
    permissions: Option<Vec<String>>,
}

pub async fn create_role(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<RoleRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let permissions = permissions(&body.permissions.unwrap_or_default())?;
    let mut conn = state.pool.acquire().await?;
    let role = roles::create_role(
        &mut conn,
        org_id,
        actor,
        NewRole {
            name: body.name.as_deref().unwrap_or_default(),
            permissions: &permissions,
        },
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "role": role_json(&role) })),
    ))
}

pub async fn update_role(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<RoleRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let permissions = body.permissions.as_deref().map(permissions).transpose()?;
    let mut conn = state.pool.acquire().await?;
    let role = roles::update_role(
        &mut conn,
        org_id,
        id,
        actor,
        RoleChanges {
            name: body.name.as_deref(),
            permissions: permissions.as_deref(),
        },
    )
    .await?;
    Ok(Json(json!({ "role": role_json(&role) })))
}

pub async fn delete_role(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    roles::delete_role(&mut conn, org_id, id, actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_sso(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let connections = state.sso.list_connections(&mut conn, org_id, actor).await?;
    Ok(Json(json!({ "connections": connections })))
}

#[derive(Deserialize)]
pub struct CreateSsoRequest {
    protocol: String,
    name: String,
    issuer_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    idp_metadata_xml: Option<String>,
    #[serde(default)]
    email_domains: Vec<String>,
    #[serde(default)]
    jit_provisioning: bool,
    default_role_id: Option<Uuid>,
    #[serde(default)]
    enforced: bool,
}

pub async fn create_sso(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<CreateSsoRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let domains: Vec<&str> = body.email_domains.iter().map(String::as_str).collect();
    let mut conn = state.pool.acquire().await?;
    let id = match body.protocol.as_str() {
        "oidc" => {
            state
                .sso
                .create_connection(
                    &mut conn,
                    org_id,
                    actor,
                    NewConnection {
                        name: &body.name,
                        issuer_url: body.issuer_url.as_deref().unwrap_or_default(),
                        client_id: body.client_id.as_deref().unwrap_or_default(),
                        client_secret: body.client_secret.as_deref().unwrap_or_default(),
                        email_domains: &domains,
                        jit_provisioning: body.jit_provisioning,
                        default_role_id: body.default_role_id,
                        enforced: body.enforced,
                    },
                )
                .await?
        }
        "saml" => {
            state
                .sso
                .create_saml_connection(
                    &mut conn,
                    org_id,
                    actor,
                    NewSamlConnection {
                        name: &body.name,
                        idp_metadata_xml: body.idp_metadata_xml.as_deref().unwrap_or_default(),
                        email_domains: &domains,
                        jit_provisioning: body.jit_provisioning,
                        default_role_id: body.default_role_id,
                        enforced: body.enforced,
                    },
                )
                .await?
        }
        _ => return Err(invalid("protocol", "must be oidc or saml").into()),
    };
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

#[derive(Deserialize)]
pub struct UpdateSsoRequest {
    enabled: Option<bool>,
    enforced: Option<bool>,
    jit_provisioning: Option<bool>,
    #[serde(default, deserialize_with = "double_option")]
    default_role_id: Option<Option<Uuid>>,
    email_domains: Option<Vec<String>>,
    client_secret: Option<String>,
}

fn double_option<'de, D>(deserializer: D) -> Result<Option<Option<Uuid>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<Uuid>::deserialize(deserializer).map(Some)
}

pub async fn update_sso(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateSsoRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let domains: Option<Vec<&str>> = body
        .email_domains
        .as_ref()
        .map(|d| d.iter().map(String::as_str).collect());
    let mut conn = state.pool.acquire().await?;
    state
        .sso
        .update_connection(
            &mut conn,
            org_id,
            id,
            actor,
            ConnectionChanges {
                enabled: body.enabled,
                enforced: body.enforced,
                jit_provisioning: body.jit_provisioning,
                default_role_id: body.default_role_id,
                email_domains: domains.as_deref(),
                client_secret: body.client_secret.as_deref(),
            },
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct SamlMetadataRequest {
    idp_metadata_xml: String,
}

pub async fn replace_saml_metadata(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
    Json(body): Json<SamlMetadataRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    state
        .sso
        .replace_saml_metadata(&mut conn, org_id, id, actor, &body.idp_metadata_xml)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_sso(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    state
        .sso
        .delete_connection(&mut conn, org_id, id, actor)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn audit_events(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Query(filter): Query<audit::Filter>,
    Query(page): Query<PageQuery>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let page = page.page()?;
    let mut conn = state.pool.acquire().await?;
    let rows = audit::list(&mut conn, org_id, actor, &filter, page).await?;
    Ok(Json(Paged::new(rows, page, |e| e.id)))
}

pub async fn list_api_credentials(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    let credentials = api_credentials::list(&mut conn, org_id, actor).await?;
    Ok(Json(json!({ "api_credentials": credentials })))
}

#[derive(Deserialize)]
pub struct CreateCredentialRequest {
    name: String,
    permissions: Vec<String>,
    expires_in_days: Option<i64>,
}

pub async fn create_api_credential(
    State(state): State<AppState>,
    caller: Caller,
    Path(org_id): Path<Uuid>,
    Json(body): Json<CreateCredentialRequest>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    if !matches!(caller, Caller::Session(_)) {
        return Err(ServiceError::Forbidden.into());
    }
    let permissions = permissions(&body.permissions)?;
    let mut conn = state.pool.acquire().await?;
    let created = api_credentials::create(
        &mut conn,
        org_id,
        actor,
        NewCredential {
            name: &body.name,
            permissions: &permissions,
            expires_in_days: body.expires_in_days,
        },
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "api_credential": created.info, "token": created.token })),
    ))
}

pub async fn revoke_api_credential(
    State(state): State<AppState>,
    caller: Caller,
    Path((org_id, id)): Path<(Uuid, Uuid)>,
) -> ApiResult<impl IntoResponse> {
    let actor = org_actor(&state, &caller, org_id).await?;
    let mut conn = state.pool.acquire().await?;
    api_credentials::revoke(&mut conn, org_id, actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}
