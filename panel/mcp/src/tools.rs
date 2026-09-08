use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::{schemars, tool, tool_handler, tool_router, ServerHandler};
use serde::Deserialize;

use crate::backend_client;

/// v1 ships exactly the 3 tools below — a deliberately small starting set
/// (list_sites / get_security_audit_log / get_fleet_dashboard) to prove the
/// whole pipeline end to end (token loading, the loopback HTTP round-trip,
/// audit attribution via the calling key's `api_key_id`) before the full
/// ~40-tool read-only catalogue lands in the next session. See the design doc
/// (`/home/ovidiu/dockpanel-mcp-design.md` §3, §7) for the complete v1 list
/// and why it stops at read-only for now (the Coolify sequencing, forced by
/// today's audit-attribution gap this same session's migration closes).
#[derive(Clone)]
pub struct DockPanelMcp;

// `Result<String, String>` (rather than a plain `String` with an "Error: ..."
// prefix folded into the Ok text) so `#[tool]`'s generated code sets the MCP
// response's `isError: true` on failure — verified against a live handshake:
// a plain `String` return reports `isError: false` even when the text says
// "Error: ...", which a well-behaved MCP client's branch-on-isError logic
// would silently treat as success.
async fn get_json(path: &str) -> Result<String, String> {
    let token = backend_client::load_token()?;
    let v = backend_client::get(path, &token).await?;
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AuditLogParams {
    /// Maximum rows to return (server caps at 500). Defaults to 100.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Skip this many rows (for pagination). Defaults to 0.
    #[serde(default)]
    pub offset: Option<u32>,
    /// Filter to one severity: "info", "warning", or "critical".
    #[serde(default)]
    pub severity: Option<String>,
}

#[tool_router]
impl DockPanelMcp {
    #[tool(description = "List every site hosted on this DockPanel instance (domain, runtime, status).")]
    async fn list_sites(&self) -> Result<String, String> {
        get_json("/api/sites").await
    }

    #[tool(
        description = "Read the immutable security audit log — logins, lockdowns, key rotations, \
                        and (once a mutating tool exists) MCP-originated actions. High-value for an \
                        agent to self-check what it has already done in this session. Requires an \
                        admin-scoped key."
    )]
    async fn get_security_audit_log(
        &self,
        Parameters(AuditLogParams { limit, offset, severity }): Parameters<AuditLogParams>,
    ) -> Result<String, String> {
        let mut query = Vec::new();
        if let Some(l) = limit {
            query.push(format!("limit={l}"));
        }
        if let Some(o) = offset {
            query.push(format!("offset={o}"));
        }
        if let Some(s) = severity {
            query.push(format!("severity={}", urlencoding::encode(&s)));
        }
        let path = if query.is_empty() {
            "/api/security/audit-log".to_string()
        } else {
            format!("/api/security/audit-log?{}", query.join("&"))
        };
        get_json(&path).await
    }

    #[tool(description = "Get the fleet-wide dashboard overview (server health, resource usage across every registered server).")]
    async fn get_fleet_dashboard(&self) -> Result<String, String> {
        get_json("/api/dashboard/fleet").await
    }
}

#[tool_handler]
impl ServerHandler for DockPanelMcp {
    fn get_info(&self) -> ServerInfo {
        // `Implementation::from_build_env()` (what `ServerInfo::new` fills this
        // field with by default) expands `env!()` inside rmcp's OWN compiled
        // source, so it reports rmcp's crate name/version, not ours — confirmed
        // by an actual handshake, not assumed. Set it explicitly from this
        // crate's own build env instead.
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("dockpanel-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Read-only introspection tools for a DockPanel-managed server fleet. Every call \
                 is attributed in the panel's own audit log to the API key configured for this \
                 MCP server. v1 has no mutating or destructive tools — everything here only \
                 reads state.",
            )
    }
}
