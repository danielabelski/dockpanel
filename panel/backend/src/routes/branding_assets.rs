use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
    Json,
};
use sha2::{Digest, Sha256};
use std::fs;

use crate::auth::AdminUser;
use crate::error::{err, internal_error, ApiError};
use crate::services::activity;
use crate::AppState;

const BRANDING_DIR: &str = "/var/lib/dockpanel/branding";
const MAX_LOGO_BYTES: usize = 2 * 1024 * 1024;

#[derive(serde::Serialize)]
pub struct LogoUploadResponse {
    pub logo_url: String,
}

/// POST /api/branding/logo — Admin-only image upload.
///
/// Body: raw image bytes. Header `Content-Type` must be one of the allowed
/// types. Magic bytes are also checked so a malicious caller can't just send
/// `Content-Type: image/png` with arbitrary content. Returns the relative URL
/// (`/api/branding/logo/<filename>`) which the caller is expected to write to
/// the `logo_url` setting via PUT /api/settings.
pub async fn upload_logo(
    State(state): State<AppState>,
    AdminUser(claims): AdminUser,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<LogoUploadResponse>, ApiError> {
    if body.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "Empty body"));
    }
    if body.len() > MAX_LOGO_BYTES {
        return Err(err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Logo too large (max 2 MB)",
        ));
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    let ext = match (content_type.as_str(), detect_image_kind(&body)) {
        ("image/png", Some("png")) => "png",
        ("image/jpeg" | "image/jpg", Some("jpeg")) => "jpg",
        ("image/webp", Some("webp")) => "webp",
        ("", Some(kind)) => match kind {
            "png" => "png",
            "jpeg" => "jpg",
            "webp" => "webp",
            _ => return Err(err(StatusCode::BAD_REQUEST, "Unsupported image format")),
        },
        _ => {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "Content-Type must be image/png, image/jpeg, or image/webp and match the file's actual format",
            ))
        }
    };

    fs::create_dir_all(BRANDING_DIR)
        .map_err(|e| internal_error("upload_logo: create dir", e))?;

    let mut hasher = Sha256::new();
    hasher.update(&body);
    let digest = hasher.finalize();
    let hex_short: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    let filename = format!("logo-{hex_short}.{ext}");
    let path = format!("{BRANDING_DIR}/{filename}");

    fs::write(&path, &body)
        .map_err(|e| internal_error("upload_logo: write file", e))?;

    activity::log_activity(
        &state.db,
        claims.sub,
        &claims.email,
        "branding.logo.upload",
        Some("branding"),
        Some(filename.as_str()),
        Some(&format!("bytes={}", body.len())),
        None,
        claims.key_id,
    )
    .await;

    let logo_url = format!("/api/branding/logo/{filename}");
    tracing::info!("Branding logo uploaded by {}: {}", claims.email, filename);
    Ok(Json(LogoUploadResponse { logo_url }))
}

/// GET /api/branding/logo/{filename} — Public read of an uploaded branding logo.
/// No auth: the login page (which is unauthenticated) needs to be able to render
/// the logo via `<img src="/api/branding/logo/...">`. The filename is restricted
/// to the `logo-<hash>.<ext>` shape, so attackers cannot path-traverse.
pub async fn get_logo(
    Path(filename): Path<String>,
) -> Result<Response, ApiError> {
    if !valid_logo_filename(&filename) {
        return Err(err(StatusCode::NOT_FOUND, "Not found"));
    }

    let path = format!("{BRANDING_DIR}/{filename}");
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(err(StatusCode::NOT_FOUND, "Not found"))
        }
        Err(e) => return Err(internal_error("get_logo: read file", e)),
    };

    let content_type = match filename.rsplit('.').next().unwrap_or("") {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        _ => "application/octet-stream",
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .body(axum::body::Body::from(bytes))
        .map_err(|e| internal_error("get_logo: build response", e))
}

fn valid_logo_filename(name: &str) -> bool {
    if !name.starts_with("logo-") {
        return false;
    }
    let Some(dot) = name.rfind('.') else {
        return false;
    };
    let stem = &name[5..dot];
    let ext = &name[dot + 1..];
    let stem_ok = !stem.is_empty() && stem.chars().all(|c| c.is_ascii_hexdigit());
    let ext_ok = matches!(ext, "png" | "jpg" | "jpeg" | "webp");
    stem_ok && ext_ok
}

fn detect_image_kind(body: &[u8]) -> Option<&'static str> {
    if body.len() >= 8 && &body[..8] == b"\x89PNG\r\n\x1a\n" {
        Some("png")
    } else if body.len() >= 3 && &body[..3] == b"\xFF\xD8\xFF" {
        Some("jpeg")
    } else if body.len() >= 12 && &body[..4] == b"RIFF" && &body[8..12] == b"WEBP" {
        Some("webp")
    } else {
        None
    }
}
