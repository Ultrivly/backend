




use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::http::error::{ApiError, ApiResult};
use crate::http::security::limit_key;
use crate::http::{AppState, Authenticated};
use crate::identity::passkeys::Passkeys;
use crate::identity::sessions::{self, AuthMethod, Session};
use crate::identity::{accounts, emails, mfa};
use crate::worker;
use webauthn_rs::prelude::RegisterPublicKeyCredential;


const TOTP_ISSUER: &str = "Ultrivly";

pub async fn profile(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<impl IntoResponse> {
    let mut conn = state.pool.acquire().await?;
    let profile = accounts::profile(&mut conn, session.user_id).await?;
    let method = match session.method {
        AuthMethod::Password => "password",
        AuthMethod::Sso { .. } => "sso",
        AuthMethod::Social => "social",
    };
    Ok(Json(json!({
        "user": profile,
        "session": {
            "id": session.id,
            "method": method,
            "mfa_verified": session.mfa_verified,
            "expires_at": session.expires_at,
        },
    })))
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    current_password: Option<String>,
    new_password: String,
}

pub async fn change_password(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Json(body): Json<ChangePasswordRequest>,
) -> ApiResult<impl IntoResponse> {
    limit_key(
        &state,
        &format!("user:{}:password", session.user_id),
        10,
        Duration::from_secs(3600),
    )
    .await?;
    let mut conn = state.pool.acquire().await?;
    accounts::change_password(
        &mut conn,
        &session,
        body.current_password.as_deref(),
        &body.new_password,
    )
    .await?;
    let email = accounts::email_of(&mut conn, session.user_id).await?;
    worker::enqueue_email(&mut conn, &state.secrets, &emails::password_changed(&email)).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn resend_verification(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<impl IntoResponse> {
    limit_key(
        &state,
        &format!("user:{}:verify", session.user_id),
        5,
        Duration::from_secs(3600),
    )
    .await?;
    let mut conn = state.pool.acquire().await?;
    let token = accounts::resend_email_verification(&mut conn, session.user_id).await?;
    let email = accounts::email_of(&mut conn, session.user_id).await?;
    worker::enqueue_email(
        &mut conn,
        &state.secrets,
        &emails::verify_email(&email, &state.public_url, &token),
    )
    .await?;
    Ok(StatusCode::ACCEPTED)
}

pub async fn list_sessions(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<impl IntoResponse> {
    let mut conn = state.pool.acquire().await?;
    let sessions = sessions::list(&mut conn, session.user_id, session.id).await?;
    Ok(Json(json!({ "sessions": sessions })))
}

pub async fn revoke_session(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let mut conn = state.pool.acquire().await?;
    if !sessions::revoke_own(&mut conn, session.user_id, id).await? {
        return Err(ApiError::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn sign_out_others(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<impl IntoResponse> {
    let mut conn = state.pool.acquire().await?;
    let count = sessions::revoke_all(&mut conn, session.user_id, Some(session.id)).await?;
    Ok(Json(json!({ "signed_out": count })))
}



async fn reauthenticate_if_protected(
    state: &AppState,
    session: &Session,
    proof: &Reauthentication,
) -> ApiResult<()> {
    let mut conn = state.pool.acquire().await?;
    if mfa::has_mfa(&mut conn, session.user_id).await? {
        reauthenticate(state, session, proof).await?;
    }
    Ok(())
}

pub async fn start_totp(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Json(proof): Json<Reauthentication>,
) -> ApiResult<impl IntoResponse> {
    reauthenticate_if_protected(&state, &session, &proof).await?;
    let mut conn = state.pool.acquire().await?;
    let enrollment =
        mfa::start_totp_enrollment(&mut conn, &state.secrets, session.user_id, TOTP_ISSUER).await?;
    Ok(Json(json!({
        "factor_id": enrollment.factor_id,
        "secret": enrollment.secret,
        "otpauth_uri": enrollment.otpauth_uri,
    })))
}

#[derive(Deserialize)]
pub struct ConfirmTotpRequest {
    factor_id: Uuid,
    code: String,
}

pub async fn confirm_totp(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Json(body): Json<ConfirmTotpRequest>,
) -> ApiResult<impl IntoResponse> {
    limit_key(
        &state,
        &format!("user:{}:mfa", session.user_id),
        5,
        Duration::from_secs(600),
    )
    .await?;
    let mut conn = state.pool.acquire().await?;
    let codes = mfa::confirm_totp_enrollment(
        &mut conn,
        &state.secrets,
        session.user_id,
        body.factor_id,
        &body.code,
        Some(&session),
    )
    .await?;
    Ok(Json(json!({ "recovery_codes": codes })))
}


#[derive(Deserialize)]
pub struct Reauthentication {
    password: Option<String>,
    code: Option<String>,
}

async fn reauthenticate(
    state: &AppState,
    session: &Session,
    proof: &Reauthentication,
) -> ApiResult<()> {
    limit_key(
        state,
        &format!("user:{}:reauth", session.user_id),
        5,
        Duration::from_secs(600),
    )
    .await?;
    let mut conn = state.pool.acquire().await?;
    if let Some(password) = &proof.password
        && accounts::confirm_password(&mut conn, session.user_id, password).await?
    {
        return Ok(());
    }
    if let Some(code) = &proof.code {
        mfa::verify_session(&mut conn, &state.secrets, session, code).await?;
        return Ok(());
    }
    Err(ApiError::new(
        StatusCode::UNAUTHORIZED,
        "reauthentication_required",
        "confirm with your password or a current code",
    ))
}

pub async fn disable_totp(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Json(proof): Json<Reauthentication>,
) -> ApiResult<impl IntoResponse> {
    reauthenticate(&state, &session, &proof).await?;
    let mut conn = state.pool.acquire().await?;
    mfa::disable_totp(&mut conn, session.user_id).await?;
    let email = accounts::email_of(&mut conn, session.user_id).await?;
    worker::enqueue_email(&mut conn, &state.secrets, &emails::mfa_disabled(&email)).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Json(proof): Json<Reauthentication>,
) -> ApiResult<impl IntoResponse> {
    reauthenticate(&state, &session, &proof).await?;
    let mut conn = state.pool.acquire().await?;
    let codes = mfa::regenerate_recovery_codes(&mut conn, session.user_id).await?;
    Ok(Json(json!({ "recovery_codes": codes })))
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    code: String,
}



pub async fn verify_mfa(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Json(body): Json<VerifyRequest>,
) -> ApiResult<impl IntoResponse> {
    limit_key(
        &state,
        &format!("user:{}:mfa", session.user_id),
        5,
        Duration::from_secs(600),
    )
    .await?;
    let mut conn = state.pool.acquire().await?;
    mfa::verify_session(&mut conn, &state.secrets, &session, &body.code).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_passkeys(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
) -> ApiResult<impl IntoResponse> {
    let mut conn = state.pool.acquire().await?;
    let passkeys = Passkeys::list(&mut conn, session.user_id).await?;
    Ok(Json(json!({ "passkeys": passkeys })))
}

#[derive(Deserialize)]
pub struct StartPasskeyRequest {
    label: String,
    #[serde(flatten)]
    proof: Reauthentication,
}


pub async fn start_passkey(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Json(body): Json<StartPasskeyRequest>,
) -> ApiResult<impl IntoResponse> {
    reauthenticate_if_protected(&state, &session, &body.proof).await?;
    let mut conn = state.pool.acquire().await?;
    let (ceremony_id, options) = state
        .passkeys
        .start_registration(&mut conn, session.user_id, &body.label)
        .await?;
    Ok(Json(
        json!({ "ceremony_id": ceremony_id, "options": options }),
    ))
}

#[derive(Deserialize)]
pub struct FinishPasskeyRequest {
    ceremony_id: Uuid,
    credential: RegisterPublicKeyCredential,
}

pub async fn finish_passkey(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Json(body): Json<FinishPasskeyRequest>,
) -> ApiResult<impl IntoResponse> {
    let mut conn = state.pool.acquire().await?;
    let codes = state
        .passkeys
        .finish_registration(
            &mut conn,
            session.user_id,
            body.ceremony_id,
            &body.credential,
            Some(&session),
        )
        .await?;
    Ok(Json(json!({ "recovery_codes": codes })))
}

pub async fn remove_passkey(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    Path(id): Path<Uuid>,
    Json(proof): Json<Reauthentication>,
) -> ApiResult<impl IntoResponse> {
    reauthenticate(&state, &session, &proof).await?;
    let mut conn = state.pool.acquire().await?;
    Passkeys::remove(&mut conn, session.user_id, id).await?;
    let email = accounts::email_of(&mut conn, session.user_id).await?;
    worker::enqueue_email(&mut conn, &state.secrets, &emails::mfa_disabled(&email)).await?;
    Ok(StatusCode::NO_CONTENT)
}
