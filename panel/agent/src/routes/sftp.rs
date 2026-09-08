//! Agent-side endpoints for per-site SFTP accounts (GH #108). Thin: all the
//! actual provisioning/teardown logic lives in `services::sftp_accounts`, so
//! this file is only request validation + response shaping, matching every
//! other route module here.

use axum::{
    extract::Path,
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::Deserialize;

use super::{is_valid_domain, AppState};
use crate::services::sftp_accounts;

type ApiErr = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, msg: &str) -> ApiErr {
    (status, Json(serde_json::json!({ "error": msg })))
}

#[derive(Deserialize)]
struct EnableRequest {
    uid: i32,
    gid: i32,
}

#[derive(Deserialize)]
struct DisableRequest {
    uid: i32,
    gid: i32,
    /// Whether this was the last SFTP-enabled site on the box — decided by
    /// the backend from the `sites` table, never re-derived here.
    last_sftp_site: bool,
}

#[derive(Deserialize)]
struct SetPasswordRequest {
    uid: i32,
    password: String,
}

/// POST /sftp/sites/{domain}/enable
async fn enable(
    Path(domain): Path<String>,
    Json(body): Json<EnableRequest>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    if !is_valid_domain(&domain) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid domain"));
    }
    sftp_accounts::provision(&domain, body.uid, body.gid)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// POST /sftp/sites/{domain}/disable
async fn disable(
    Path(domain): Path<String>,
    Json(body): Json<DisableRequest>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    if !is_valid_domain(&domain) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid domain"));
    }
    sftp_accounts::deprovision(&domain, body.uid, body.gid, body.last_sftp_site)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// POST /sftp/sites/{domain}/password
async fn set_password(
    Path(domain): Path<String>,
    Json(body): Json<SetPasswordRequest>,
) -> Result<Json<serde_json::Value>, ApiErr> {
    if !is_valid_domain(&domain) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid domain"));
    }
    if body.password.len() < 12 {
        return Err(err(StatusCode::BAD_REQUEST, "Password must be at least 12 characters"));
    }
    sftp_accounts::set_password(body.uid, &body.password)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/sftp/sites/{domain}/enable", post(enable))
        .route("/sftp/sites/{domain}/disable", post(disable))
        .route("/sftp/sites/{domain}/password", post(set_password))
}
