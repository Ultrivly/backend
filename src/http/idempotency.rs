use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::http::AppState;
use crate::http::error::ApiError;
use crate::identity::sessions;
use crate::integrations::api_credentials;

const MAX_BODY: usize = 30 * 1024 * 1024;
const MAX_STORED_RESPONSE: usize = 1024 * 1024;

fn org_from_path(path: &str) -> Option<Uuid> {
    let mut parts = path.trim_start_matches('/').split('/');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("api"), Some("v1"), Some("orgs"), Some(id)) => id.parse().ok(),
        _ => None,
    }
}

fn credentials(state: &AppState, request: &Request) -> (Option<String>, Option<String>) {
    let bearer = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.trim().to_string());
    let session = CookieJar::from_headers(request.headers())
        .get(state.cookies.session)
        .map(|c| c.value().to_string());
    (bearer, session)
}

async fn principal(
    state: &AppState,
    bearer: Option<String>,
    session: Option<String>,
) -> Option<Uuid> {
    let mut conn = state.pool.acquire().await.ok()?;
    if let Some(token) = bearer {
        return api_credentials::authenticate(&mut conn, &token)
            .await
            .ok()
            .flatten()
            .map(|k| k.id);
    }
    sessions::authenticate(&mut conn, &session?)
        .await
        .ok()
        .flatten()
        .map(|s| s.user_id)
}

pub async fn idempotency(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(key) = request
        .headers()
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    else {
        return next.run(request).await;
    };
    let Some(org_id) =
        org_from_path(request.uri().path()).filter(|_| request.method() == Method::POST)
    else {
        return next.run(request).await;
    };
    if key.is_empty() || key.len() > 255 || key.chars().any(|c| c.is_control()) {
        return ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_idempotency_key",
            "Idempotency-Key must be 1-255 printable characters",
        )
        .into_response();
    }
    let (bearer, session) = credentials(&state, &request);
    let Some(principal) = principal(&state, bearer, session).await else {
        return next.run(request).await;
    };

    let (parts, body) = request.into_parts();
    let Ok(bytes) = to_bytes(body, MAX_BODY).await else {
        return ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "request body is too large",
        )
        .into_response();
    };
    let mut hasher = Sha256::new();
    hasher.update(parts.method.as_str());
    hasher.update(b" ");
    hasher.update(parts.uri.path());
    hasher.update(b"\n");
    hasher.update(&bytes);
    let request_hash = hasher.finalize().to_vec();

    let inserted = sqlx::query(
        "INSERT INTO idempotency_keys (org_id, principal_id, key, request_hash, expires_at)
         VALUES ($1, $2, $3, $4, now() + interval '24 hours')
         ON CONFLICT (org_id, principal_id, key) DO NOTHING",
    )
    .bind(org_id)
    .bind(principal)
    .bind(&key)
    .bind(&request_hash)
    .execute(&state.pool)
    .await;
    let request = Request::from_parts(parts, Body::from(bytes));
    match inserted {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => return replay(&state, org_id, principal, &key, &request_hash).await,
        Err(_) => return next.run(request).await,
    }

    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    let bytes = to_bytes(body, MAX_BODY).await.unwrap_or_default();
    let status = parts.status;
    let sealed = (!bytes.is_empty()).then(|| {
        state
            .secrets
            .encrypt(&response_context(org_id, principal, &key), &bytes)
    });
    let outcome = if status.is_server_error() || bytes.len() > MAX_STORED_RESPONSE {
        sqlx::query(
            "DELETE FROM idempotency_keys WHERE org_id = $1 AND principal_id = $2 AND key = $3",
        )
        .bind(org_id)
        .bind(principal)
        .bind(&key)
        .execute(&state.pool)
        .await
    } else {
        sqlx::query(
            "UPDATE idempotency_keys SET completed = true, response_status = $4, response_ciphertext = $5
             WHERE org_id = $1 AND principal_id = $2 AND key = $3",
        )
        .bind(org_id)
        .bind(principal)
        .bind(&key)
        .bind(status.as_u16() as i16)
        .bind(sealed)
        .execute(&state.pool)
        .await
    };
    if let Err(err) = outcome {
        tracing::warn!("recording idempotent response failed: {err}");
    }
    Response::from_parts(parts, Body::from(bytes))
}

type StoredKey = (Vec<u8>, bool, Option<i16>, Option<Vec<u8>>);

fn response_context(org_id: Uuid, principal: Uuid, key: &str) -> String {
    format!("idempotency:{org_id}:{principal}:{key}")
}

async fn replay(
    state: &AppState,
    org_id: Uuid,
    principal: Uuid,
    key: &str,
    request_hash: &[u8],
) -> Response {
    let row: Result<Option<StoredKey>, _> = sqlx::query_as(
        "SELECT request_hash, completed, response_status, response_ciphertext FROM idempotency_keys
         WHERE org_id = $1 AND principal_id = $2 AND key = $3",
    )
    .bind(org_id)
    .bind(principal)
    .bind(key)
    .fetch_optional(&state.pool)
    .await;
    match row {
        Ok(Some((hash, _, _, _))) if hash != request_hash => ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "idempotency_key_reused",
            "this Idempotency-Key was used for a different request",
        )
        .into_response(),
        Ok(Some((_, false, _, _))) => ApiError::new(
            StatusCode::CONFLICT,
            "idempotency_in_progress",
            "a request with this Idempotency-Key is still being processed",
        )
        .into_response(),
        Ok(Some((_, true, status, body))) => {
            let status = status
                .and_then(|s| StatusCode::from_u16(s as u16).ok())
                .unwrap_or(StatusCode::OK);
            let body = body.and_then(|sealed| {
                state
                    .secrets
                    .decrypt(&response_context(org_id, principal, key), &sealed)
                    .ok()
            });
            let mut response = match body {
                Some(body) => (
                    status,
                    [(header::CONTENT_TYPE, "application/json")],
                    Body::from(body),
                )
                    .into_response(),
                None => status.into_response(),
            };
            response
                .headers_mut()
                .insert("idempotent-replayed", HeaderValue::from_static("true"));
            response
        }
        Ok(None) | Err(_) => ApiError::new(
            StatusCode::CONFLICT,
            "idempotency_in_progress",
            "retry this request",
        )
        .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::org_from_path;

    #[test]
    fn org_scoped_paths_only() {
        let id = uuid::Uuid::now_v7();
        assert_eq!(org_from_path(&format!("/api/v1/orgs/{id}/cases")), Some(id));
        assert_eq!(org_from_path("/api/v1/orgs"), None);
        assert_eq!(org_from_path("/api/v1/auth/sign-in"), None);
    }
}
