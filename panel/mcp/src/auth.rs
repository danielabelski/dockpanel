// Every `#[tool]` method in tools.rs reads /etc/dockpanel/mcp.token to
// authenticate ITS OWN outbound calls to the panel API — but nothing checked
// what the INBOUND caller presented before this file existed. rmcp's
// StreamableHttpServerConfig::default() only restricts the Host header to
// loopback names (a DNS-rebinding guard, documented as unfit for "public
// deployments" in the SDK's own doc comment), which is not caller
// authentication at all — main.rs disables that check (see its comment) once
// this layer exists. Without this middleware, `/mcp` would be reachable by
// anyone who can reach the panel's nginx, on the panel's own admin-scoped
// key, with zero credential of their own required. Found live: nginx forwards
// the real Host header, not "127.0.0.1", so the loopback-only default was
// accidentally the only thing stopping this — an artifact, not a control.
//
// The fix reuses the SAME token file as the shared secret in both
// directions: the operator gives their MCP client the identical `dp_` key
// they saved to mcp.token (already what the setup docs say to do), and this
// middleware requires it verbatim as `Authorization: Bearer <token>` before
// any request reaches the tool router.

use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::backend_client;

/// Byte-length-then-XOR compare so a mismatch doesn't return in time
/// proportional to the number of matching leading bytes. No new dependency
/// for one 4-line comparison.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub async fn require_bearer_token(req: Request, next: Next) -> Response {
    let Ok(expected) = backend_client::load_token() else {
        // Same "not configured" state get_json() already reports per-call —
        // surfaced here too so a misconfigured server fails closed instead of
        // 500ing on every request before a token file even exists.
        return (StatusCode::UNAUTHORIZED, "No panel API key configured — see /etc/dockpanel/mcp.token").into_response();
    };
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match provided {
        // load_token() already trims the file's contents; nothing to re-trim here.
        Some(token) if constant_time_eq(token, &expected) => next.run(req).await,
        _ => (StatusCode::UNAUTHORIZED, "Missing or invalid bearer token").into_response(),
    }
}
