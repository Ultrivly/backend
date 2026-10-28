use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::http::AppState;
use crate::platform::migrations;


pub async fn live() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}


pub async fn ready(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    match migrations::status(&state.pool).await {
        Ok(status) if status.is_current() => (StatusCode::OK, Json(json!({ "status": "ready" }))),
        Ok(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "migrations_pending" })),
        ),
        Err(err) => {
            tracing::warn!("readiness check failed: {err:#}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "database_unavailable" })),
            )
        }
    }
}
