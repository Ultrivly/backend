




use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::json;

use crate::http::AppState;
use crate::http::error::{ApiError, ApiResult};
use crate::http::security::{Client, limit_ip};
use crate::identity::accounts::{self, AuthError, MFA_CHALLENGE_TTL, SignIn};
use crate::identity::sessions::{self, NewSession};
use crate::identity::{emails, mfa};
use crate::worker;

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(60 * 60);

#[derive(Deserialize)]
pub struct SignUpRequest {
    email: String,
    display_name: String,
    password: String,
}

pub async fn sign_up(
    State(state): State<AppState>,
    client: Client,
    Json(body): Json<SignUpRequest>,
) -> ApiResult<impl IntoResponse> {
    limit_ip(&state, &client, "sign_up", 10, HOUR).await?;
    let mut conn = state.pool.acquire().await?;
    let email = body.email.trim();
    let message = match accounts::sign_up(&mut conn, email, &body.display_name, &body.password)
        .await
    {
        Ok(created) => emails::verify_email(email, &state.public_url, &created.verification_token),
        
        Err(AuthError::EmailTaken) => emails::sign_up_attempted(email, &state.public_url),
        Err(err) => return Err(err.into()),
    };
    worker::enqueue_email(&mut conn, &state.secrets, &message).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "status": "check_your_email" })),
    ))
}

#[derive(Deserialize)]
pub struct SignInRequest {
    email: String,
    password: String,
}

pub async fn sign_in(
    State(state): State<AppState>,
    client: Client,
    jar: CookieJar,
    Json(body): Json<SignInRequest>,
) -> ApiResult<impl IntoResponse> {
    limit_ip(&state, &client, "sign_in", 30, 10 * MINUTE).await?;
    let mut conn = state.pool.acquire().await?;
    let outcome =
        accounts::sign_in_with_password(&mut conn, &body.email, &body.password, &client.0).await?;
    Ok(sign_in_response(&state, jar, outcome))
}



pub(crate) fn sign_in_response(
    state: &AppState,
    jar: CookieJar,
    outcome: SignIn,
) -> impl IntoResponse + use<> {
    match outcome {
        SignIn::Complete(new) => signed_in(state, jar, new).into_response(),
        SignIn::MfaRequired { challenge } => {
            let jar =
                jar.add(state.cookie(state.cookies.mfa, challenge.clone(), MFA_CHALLENGE_TTL));
            (
                jar,
                Json(json!({ "status": "mfa_required", "challenge": challenge })),
            )
                .into_response()
        }
    }
}

fn signed_in(state: &AppState, jar: CookieJar, new: NewSession) -> impl IntoResponse + use<> {
    let user_id = new.session.user_id;
    let jar = jar
        .add(state.session_cookie(new.token))
        .remove(state.expired(state.cookies.mfa));
    (
        jar,
        Json(json!({ "status": "signed_in", "user_id": user_id })),
    )
}

#[derive(Deserialize)]
pub struct MfaRequest {
    
    challenge: Option<String>,
    code: String,
}

pub async fn complete_mfa(
    State(state): State<AppState>,
    client: Client,
    jar: CookieJar,
    Json(body): Json<MfaRequest>,
) -> ApiResult<impl IntoResponse> {
    limit_ip(&state, &client, "mfa", 30, 10 * MINUTE).await?;
    let challenge = body
        .challenge
        .or_else(|| jar.get(state.cookies.mfa).map(|c| c.value().to_string()))
        .ok_or_else(|| ApiError::from(mfa::MfaError::InvalidChallenge))?;
    let mut conn = state.pool.acquire().await?;
    let new = mfa::complete_challenge(&mut conn, &state.secrets, &challenge, &body.code, &client.0)
        .await?;
    Ok(signed_in(&state, jar, new))
}

pub async fn sign_out(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<impl IntoResponse> {
    if let Some(token) = jar.get(state.cookies.session) {
        let mut conn = state.pool.acquire().await?;
        if let Some(session) = sessions::authenticate(&mut conn, token.value()).await? {
            sessions::revoke(&mut conn, session.id).await?;
        }
    }
    let jar = jar.remove(state.expired(state.cookies.session));
    Ok((jar, StatusCode::NO_CONTENT))
}

#[derive(Deserialize)]
pub struct TokenRequest {
    token: String,
}

pub async fn verify_email(
    State(state): State<AppState>,
    client: Client,
    Json(body): Json<TokenRequest>,
) -> ApiResult<impl IntoResponse> {
    limit_ip(&state, &client, "token", 30, HOUR).await?;
    let mut conn = state.pool.acquire().await?;
    accounts::verify_email(&mut conn, &body.token).await?;
    Ok(Json(json!({ "status": "verified" })))
}

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    email: String,
}

pub async fn forgot_password(
    State(state): State<AppState>,
    client: Client,
    Json(body): Json<ForgotPasswordRequest>,
) -> ApiResult<impl IntoResponse> {
    limit_ip(&state, &client, "forgot_password", 10, HOUR).await?;
    
    
    let mut conn = state.pool.acquire().await?;
    worker::enqueue_password_reset(&mut conn, &state.secrets, &body.email).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "status": "check_your_email" })),
    ))
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    token: String,
    password: String,
}

pub async fn reset_password(
    State(state): State<AppState>,
    client: Client,
    Json(body): Json<ResetPasswordRequest>,
) -> ApiResult<impl IntoResponse> {
    limit_ip(&state, &client, "token", 30, HOUR).await?;
    let mut conn = state.pool.acquire().await?;
    let user_id = accounts::reset_password(&mut conn, &body.token, &body.password).await?;
    let email = accounts::email_of(&mut conn, user_id).await?;
    worker::enqueue_email(&mut conn, &state.secrets, &emails::password_changed(&email)).await?;
    Ok(Json(json!({ "status": "password_reset" })))
}

#[derive(Deserialize)]
pub struct PasskeyChallengeRequest {
    challenge: Option<String>,
}



pub async fn start_passkey_mfa(
    State(state): State<AppState>,
    client: Client,
    jar: CookieJar,
    Json(body): Json<PasskeyChallengeRequest>,
) -> ApiResult<impl IntoResponse> {
    limit_ip(&state, &client, "mfa", 30, 10 * MINUTE).await?;
    let challenge = challenge_from(&state, &jar, body.challenge)?;
    let mut conn = state.pool.acquire().await?;
    let (ceremony_id, options) = state
        .passkeys
        .start_challenge(&mut conn, &challenge)
        .await?;
    Ok(Json(
        json!({ "ceremony_id": ceremony_id, "options": options }),
    ))
}

#[derive(Deserialize)]
pub struct PasskeyAnswerRequest {
    challenge: Option<String>,
    ceremony_id: uuid::Uuid,
    credential: webauthn_rs::prelude::PublicKeyCredential,
}

pub async fn finish_passkey_mfa(
    State(state): State<AppState>,
    client: Client,
    jar: CookieJar,
    Json(body): Json<PasskeyAnswerRequest>,
) -> ApiResult<impl IntoResponse> {
    limit_ip(&state, &client, "mfa", 30, 10 * MINUTE).await?;
    let challenge = challenge_from(&state, &jar, body.challenge)?;
    let mut conn = state.pool.acquire().await?;
    let new = state
        .passkeys
        .complete_challenge(
            &mut conn,
            &challenge,
            body.ceremony_id,
            &body.credential,
            &client.0,
        )
        .await?;
    Ok(signed_in(&state, jar, new))
}


fn challenge_from(state: &AppState, jar: &CookieJar, body: Option<String>) -> ApiResult<String> {
    body.or_else(|| jar.get(state.cookies.mfa).map(|c| c.value().to_string()))
        .ok_or_else(|| ApiError::from(mfa::MfaError::InvalidChallenge))
}
