







use std::collections::HashMap;
use std::time::Duration;

use axum::Form;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::http::error::{ApiError, ApiResult};
use crate::http::routes::auth::sign_in_response;
use crate::http::security::{Client, limit_ip};
use crate::http::{AppState, Authenticated};
use crate::identity::accounts::SignIn;
use crate::identity::sso::{Provider, Sso, SsoError, SsoOutcome};

const STATE_COOKIE_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Deserialize)]
pub struct StartQuery {
    
    provider: Option<String>,
    
    org: Option<String>,
    redirect_to: Option<String>,
}

pub async fn start(
    State(state): State<AppState>,
    client: Client,
    jar: CookieJar,
    Query(query): Query<StartQuery>,
) -> Response {
    if let Err(err) = limit_ip(&state, &client, "sso_start", 60, Duration::from_secs(600)).await {
        return err.into_response();
    }
    let result = async {
        let mut conn = state.pool.acquire().await?;
        let connection;
        let provider = match (&query.provider, &query.org) {
            (Some(key), None) => Provider::Social(key),
            (None, Some(slug)) => {
                let (id, protocol) = Sso::connection_for_org(&mut conn, slug)
                    .await?
                    .ok_or(SsoError::Unavailable)?;
                if protocol == "saml" {
                    let (url, request_id) = state
                        .sso
                        .begin_saml(&mut conn, id, query.redirect_to.as_deref(), None)
                        .await?;
                    return Ok(Begun::Saml(url, request_id));
                }
                connection = id;
                Provider::Connection(connection)
            }
            _ => return Err(SsoError::Unavailable),
        };
        state
            .sso
            .begin(&mut conn, provider, query.redirect_to.as_deref(), None)
            .await
            .map(Begun::Oidc)
    }
    .await;
    match result {
        Ok(Begun::Oidc(url)) => redirect_to_provider(&state, jar, &url),
        Ok(Begun::Saml(url, request_id)) => saml_redirect(&state, jar, &url, request_id),
        Err(err) => error_redirect(err),
    }
}

#[derive(Deserialize)]
pub struct LinkRequest {
    provider: Option<String>,
    connection_id: Option<Uuid>,
    redirect_to: Option<String>,
}



pub async fn link(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    jar: CookieJar,
    Json(body): Json<LinkRequest>,
) -> ApiResult<impl IntoResponse> {
    let provider = match (&body.provider, body.connection_id) {
        (Some(key), None) => Provider::Social(key),
        (None, Some(id)) => Provider::Connection(id),
        _ => {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid",
                "give exactly one of provider or connection_id",
            ));
        }
    };
    let mut conn = state.pool.acquire().await?;
    if let Provider::Connection(id) = provider
        && Sso::connection_protocol(&mut conn, id).await?.as_deref() == Some("saml")
    {
        let (url, request_id) = state
            .sso
            .begin_saml(
                &mut conn,
                id,
                body.redirect_to.as_deref(),
                Some(session.user_id),
            )
            .await?;
        let jar = jar.add(saml_cookie(&state, request_id));
        return Ok((jar, Json(json!({ "url": url }))));
    }
    let url = state
        .sso
        .begin(
            &mut conn,
            provider,
            body.redirect_to.as_deref(),
            Some(session.user_id),
        )
        .await?;
    let jar = jar.add(state_cookie(&state, &url));
    Ok((jar, Json(json!({ "url": url }))))
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
}

pub async fn callback(
    State(state): State<AppState>,
    client: Client,
    jar: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let expected = jar.get(state.cookies.oidc).map(|c| c.value().to_string());
    let jar = jar.remove(state.expired(state.cookies.oidc));

    if query.error.is_some() {
        return (jar, sign_in_redirect("sso_cancelled")).into_response();
    }
    let (Some(returned), Some(code)) = (query.state, query.code) else {
        return (jar, sign_in_redirect("sso_state_invalid")).into_response();
    };
    let same_browser =
        expected.is_some_and(|e| bool::from(e.as_bytes().ct_eq(returned.as_bytes())));
    if !same_browser {
        return (jar, sign_in_redirect("sso_state_invalid")).into_response();
    }

    let mut conn = match state.pool.acquire().await {
        Ok(conn) => conn,
        Err(err) => return ApiError::from(err).into_response(),
    };
    match state
        .sso
        .complete(&mut conn, &returned, &code, &client.0)
        .await
    {
        Ok(outcome) => finish_redirect(&state, jar, outcome),
        Err(err) => (jar, error_redirect(err)).into_response(),
    }
}

fn redirect_to_provider(state: &AppState, jar: CookieJar, url: &str) -> Response {
    (jar.add(state_cookie(state, url)), Redirect::to(url)).into_response()
}


fn state_cookie(state: &AppState, url: &str) -> axum_extra::extract::cookie::Cookie<'static> {
    let value = url::Url::parse(url)
        .ok()
        .and_then(|u| {
            u.query_pairs()
                .find(|(k, _)| k == "state")
                .map(|(_, v)| v.into_owned())
        })
        .unwrap_or_default();
    state.cookie(state.cookies.oidc, value, STATE_COOKIE_TTL)
}

fn with_redirect(response: Response, target: &str) -> Response {
    let (mut parts, _) = response.into_parts();
    parts.status = StatusCode::SEE_OTHER;
    if let Ok(location) = HeaderValue::from_str(target) {
        parts.headers.insert(header::LOCATION, location);
    }
    parts.headers.remove(header::CONTENT_TYPE);
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, axum::body::Body::empty())
}

fn error_redirect(err: SsoError) -> Response {
    let code = ApiError::from(err).code;
    sign_in_redirect(code)
}

fn sign_in_redirect(code: &str) -> Response {
    let query: String = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(HashMap::from([("error", code)]))
        .finish();
    Redirect::to(&format!("/sign-in?{query}")).into_response()
}

enum Begun {
    Oidc(String),
    Saml(String, String),
}

const SAML_COOKIE_TTL: Duration = Duration::from_secs(10 * 60);

fn saml_cookie(
    state: &AppState,
    request_id: String,
) -> axum_extra::extract::cookie::Cookie<'static> {
    state.cross_site_cookie(state.cookies.saml, request_id, SAML_COOKIE_TTL)
}

fn saml_redirect(state: &AppState, jar: CookieJar, url: &str, request_id: String) -> Response {
    (jar.add(saml_cookie(state, request_id)), Redirect::to(url)).into_response()
}

pub async fn saml_metadata(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    let result = async {
        let mut conn = state.pool.acquire().await?;
        state.sso.saml_sp_metadata(&mut conn, id).await
    }
    .await;
    match result {
        Ok(xml) => (
            [(header::CONTENT_TYPE, "application/samlmetadata+xml")],
            xml,
        )
            .into_response(),
        Err(err) => ApiError::from(err).into_response(),
    }
}

#[derive(Deserialize)]
pub struct AcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
}

pub async fn saml_acs(
    State(state): State<AppState>,
    client: Client,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    Form(form): Form<AcsForm>,
) -> Response {
    let request_id = jar.get(state.cookies.saml).map(|c| c.value().to_string());
    let jar =
        jar.remove(state.cross_site_cookie(state.cookies.saml, String::new(), Duration::ZERO));
    let Some(request_id) = request_id else {
        return (jar, sign_in_redirect("sso_state_invalid")).into_response();
    };
    let mut conn = match state.pool.acquire().await {
        Ok(conn) => conn,
        Err(err) => return ApiError::from(err).into_response(),
    };
    match state
        .sso
        .complete_saml(&mut conn, id, &form.saml_response, &request_id, &client.0)
        .await
    {
        Ok(outcome) => finish_redirect(&state, jar, outcome),
        Err(err) => (jar, error_redirect(err)).into_response(),
    }
}

fn finish_redirect(state: &AppState, jar: CookieJar, outcome: SsoOutcome) -> Response {
    match outcome {
        SsoOutcome::SignedIn {
            sign_in,
            redirect_to,
        } => {
            let target = match &sign_in {
                SignIn::Complete(_) => redirect_to.unwrap_or_else(|| "/".into()),
                SignIn::MfaRequired { .. } => "/sign-in/mfa".into(),
            };
            with_redirect(
                sign_in_response(state, jar, sign_in).into_response(),
                &target,
            )
        }
        SsoOutcome::Linked { redirect_to, .. } => (
            jar,
            Redirect::to(&redirect_to.unwrap_or_else(|| "/settings/security".into())),
        )
            .into_response(),
    }
}
