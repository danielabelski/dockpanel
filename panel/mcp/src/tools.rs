use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::{schemars, tool, tool_handler, tool_router, ServerHandler};
use serde::Deserialize;

use crate::backend_client;

/// v1's ~40-tool read-only catalogue (session 1 shipped 3 to prove the
/// pipeline end to end; this session fills in the rest — see the design doc
/// `/home/ovidiu/dockpanel-mcp-design.md` §3, §7). Every tool is a thin GET
/// proxy onto the existing REST API: no new business logic, no new response
/// shapes — the panel API's own JSON is passed through as-is. Zero mutating
/// or destructive tools (the Coolify sequencing, forced by the
/// audit-attribution fix this crate's own migration shipped alongside
/// session 1, before any write-capable tool could exist safely).
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

/// Build a `"?k=v&k2=v2"` query suffix from optional values, URL-encoding
/// each one. Empty string when every pair is `None`. Shared by every tool
/// with more than one optional filter — the alternative (each tool
/// hand-rolling the same `Vec<String>` + `.join("&")` dance) was already
/// duplicated 8+ times over before this existed.
fn query_suffix(pairs: &[(&str, Option<String>)]) -> String {
    let parts: Vec<String> = pairs
        .iter()
        .filter_map(|(k, v)| v.as_ref().map(|v| format!("{k}={}", urlencoding::encode(v))))
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("?{}", parts.join("&"))
    }
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SiteIdParams {
    /// The site's UUID, as returned by `list_sites`.
    pub site_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ContainerIdParams {
    /// The Docker container ID, as returned by `list_apps`.
    pub container_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DatabaseIdParams {
    /// The database's UUID, as returned by `list_databases`.
    pub database_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MonitorIdParams {
    /// The monitor's UUID, as returned by `list_monitors`.
    pub monitor_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DnsZoneIdParams {
    /// The DNS zone's UUID, as returned by `list_dns_zones`.
    pub zone_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SiteScopedPaginationParams {
    /// The site's UUID, as returned by `list_sites`.
    pub site_id: String,
    /// Maximum rows to return. Server-side default applies if omitted.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Skip this many rows (for pagination). Defaults to 0.
    #[serde(default)]
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PaginationParams {
    /// Maximum rows to return. Server-side default applies if omitted.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Skip this many rows (for pagination). Defaults to 0.
    #[serde(default)]
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ServerMetricsParams {
    /// The server's UUID, as returned by `list_servers`.
    pub server_id: String,
    /// Which metric series to return (e.g. "cpu", "memory", "disk"). Omit for all.
    #[serde(default)]
    pub metric_type: Option<String>,
    /// How many hours of history to include. Server-side default applies if omitted.
    #[serde(default)]
    pub hours: Option<i32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SystemLogsParams {
    /// One of "nginx_access", "nginx_error", "syslog", "auth", "php_fpm". Defaults to "nginx_access".
    #[serde(default)]
    pub log_type: Option<String>,
    /// Number of lines to return (server caps at 1000). Defaults to 100.
    #[serde(default)]
    pub lines: Option<u32>,
    /// Only return lines containing this substring.
    #[serde(default)]
    pub filter: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AlertListParams {
    /// Filter by alert status (e.g. "firing", "resolved").
    #[serde(default)]
    pub status: Option<String>,
    /// Filter by alert type (e.g. "backup_failure", "ssl_expiry", "cron_failure").
    #[serde(default)]
    pub alert_type: Option<String>,
    /// Maximum rows to return (server caps at 500). Defaults to 100.
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ActivityListParams {
    /// Maximum rows to return (server caps at 200). Defaults to 50.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Skip this many rows (for pagination). Defaults to 0.
    #[serde(default)]
    pub offset: Option<u32>,
    /// Filter by action category (e.g. "site" matches "site.create", "site.delete").
    #[serde(default)]
    pub action: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IncidentListParams {
    /// Maximum rows to return. Server-side default applies if omitted.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Skip this many rows (for pagination). Defaults to 0.
    #[serde(default)]
    pub offset: Option<u32>,
    /// Filter by incident status.
    #[serde(default)]
    pub status: Option<String>,
}

#[tool_router]
impl DockPanelMcp {
    // ── Sites & apps ────────────────────────────────────────────────────

    #[tool(description = "List every site hosted on this DockPanel instance (domain, runtime, status).")]
    async fn list_sites(&self) -> Result<String, String> {
        get_json("/api/sites").await
    }

    #[tool(description = "Get full detail for one site (runtime, PHP version, SSL, resource limits).")]
    async fn get_site(&self, Parameters(SiteIdParams { site_id }): Parameters<SiteIdParams>) -> Result<String, String> {
        get_json(&format!("/api/sites/{}", urlencoding::encode(&site_id))).await
    }

    #[tool(description = "List every Docker app deployed on this instance (name, image, status, ports).")]
    async fn list_apps(&self) -> Result<String, String> {
        get_json("/api/apps").await
    }

    #[tool(description = "Fetch recent log output for one Docker app container.")]
    async fn get_app_logs(
        &self,
        Parameters(ContainerIdParams { container_id }): Parameters<ContainerIdParams>,
    ) -> Result<String, String> {
        get_json(&format!("/api/apps/{}/logs", urlencoding::encode(&container_id))).await
    }

    #[tool(description = "Get live resource stats (CPU, memory, network) for one Docker app container.")]
    async fn get_app_stats(
        &self,
        Parameters(ContainerIdParams { container_id }): Parameters<ContainerIdParams>,
    ) -> Result<String, String> {
        get_json(&format!("/api/apps/{}/stats", urlencoding::encode(&container_id))).await
    }

    #[tool(description = "List scheduled cron jobs configured for one site.")]
    async fn list_crons(
        &self,
        Parameters(SiteScopedPaginationParams { site_id, limit, offset }): Parameters<SiteScopedPaginationParams>,
    ) -> Result<String, String> {
        let suffix = query_suffix(&[("limit", limit.map(|v| v.to_string())), ("offset", offset.map(|v| v.to_string()))]);
        get_json(&format!("/api/sites/{}/crons{suffix}", urlencoding::encode(&site_id))).await
    }

    #[tool(description = "List backups for one site (metadata only — file listing, not the backup contents; use the panel UI to restore).")]
    async fn list_site_backups(
        &self,
        Parameters(SiteScopedPaginationParams { site_id, limit, offset }): Parameters<SiteScopedPaginationParams>,
    ) -> Result<String, String> {
        let suffix = query_suffix(&[("limit", limit.map(|v| v.to_string())), ("offset", offset.map(|v| v.to_string()))]);
        get_json(&format!("/api/sites/{}/backups{suffix}", urlencoding::encode(&site_id))).await
    }

    #[tool(description = "List all WordPress sites across the fleet (version, plugin/theme counts, vulnerability scan status).")]
    async fn list_wordpress_sites(&self) -> Result<String, String> {
        get_json("/api/wordpress/sites").await
    }

    // ── Databases ───────────────────────────────────────────────────────

    #[tool(description = "List every database on this instance (engine, size, owning site).")]
    async fn list_databases(
        &self,
        Parameters(PaginationParams { limit, offset }): Parameters<PaginationParams>,
    ) -> Result<String, String> {
        let suffix = query_suffix(&[("limit", limit.map(|v| v.to_string())), ("offset", offset.map(|v| v.to_string()))]);
        get_json(&format!("/api/databases{suffix}")).await
    }

    #[tool(description = "List the tables in one database, with row counts (schema only — never returns credentials or row contents).")]
    async fn get_database_tables(
        &self,
        Parameters(DatabaseIdParams { database_id }): Parameters<DatabaseIdParams>,
    ) -> Result<String, String> {
        get_json(&format!("/api/databases/{}/tables", urlencoding::encode(&database_id))).await
    }

    // ── Servers & fleet ─────────────────────────────────────────────────

    #[tool(description = "List every server registered to this DockPanel fleet (hostname, region, agent status).")]
    async fn list_servers(&self) -> Result<String, String> {
        get_json("/api/servers").await
    }

    #[tool(description = "Get time-series resource metrics (CPU/memory/disk) for one server.")]
    async fn get_server_metrics(
        &self,
        Parameters(ServerMetricsParams { server_id, metric_type, hours }): Parameters<ServerMetricsParams>,
    ) -> Result<String, String> {
        let suffix = query_suffix(&[("metric_type", metric_type), ("hours", hours.map(|v| v.to_string()))]);
        get_json(&format!("/api/servers/{}/metrics{suffix}", urlencoding::encode(&server_id))).await
    }

    #[tool(description = "Get the fleet-wide dashboard overview (server health, resource usage across every registered server).")]
    async fn get_fleet_dashboard(&self) -> Result<String, String> {
        get_json("/api/dashboard/fleet").await
    }

    // ── Monitoring & alerting ───────────────────────────────────────────

    #[tool(description = "List uptime monitors configured on this instance (target, interval, current status).")]
    async fn list_monitors(
        &self,
        Parameters(PaginationParams { limit, offset }): Parameters<PaginationParams>,
    ) -> Result<String, String> {
        let suffix = query_suffix(&[("limit", limit.map(|v| v.to_string())), ("offset", offset.map(|v| v.to_string()))]);
        get_json(&format!("/api/monitors{suffix}")).await
    }

    #[tool(description = "Get uptime percentage and check history for one monitor.")]
    async fn get_monitor_uptime(
        &self,
        Parameters(MonitorIdParams { monitor_id }): Parameters<MonitorIdParams>,
    ) -> Result<String, String> {
        get_json(&format!("/api/monitors/{}/uptime", urlencoding::encode(&monitor_id))).await
    }

    #[tool(description = "Read the public status page (component statuses, active incidents) — the same data unauthenticated visitors see.")]
    async fn get_status_page(&self) -> Result<String, String> {
        get_json("/api/status-page/public").await
    }

    #[tool(description = "List active and recent alerts (backup failures, SSL expiry, cron failures, security scans, and more) across the fleet.")]
    async fn list_alerts(
        &self,
        Parameters(AlertListParams { status, alert_type, limit }): Parameters<AlertListParams>,
    ) -> Result<String, String> {
        let suffix = query_suffix(&[("status", status), ("alert_type", alert_type), ("limit", limit.map(|v| v.to_string()))]);
        get_json(&format!("/api/alerts{suffix}")).await
    }

    #[tool(description = "Get a rolled-up count of alerts by severity — the number a dashboard badge would show.")]
    async fn get_alerts_summary(&self) -> Result<String, String> {
        get_json("/api/alerts/summary").await
    }

    #[tool(description = "List on-call schedules (rotation members, cadence) configured for this instance.")]
    async fn list_on_call_schedules(&self) -> Result<String, String> {
        get_json("/api/on-call/schedules").await
    }

    #[tool(description = "List escalation policies (ordered notification steps) available to attach to alert rules.")]
    async fn list_escalation_policies(&self) -> Result<String, String> {
        get_json("/api/escalation-policies").await
    }

    #[tool(description = "List managed incidents (the ones tracked for the public status page), most recent first.")]
    async fn list_incidents(
        &self,
        Parameters(IncidentListParams { limit, offset, status }): Parameters<IncidentListParams>,
    ) -> Result<String, String> {
        let suffix = query_suffix(&[
            ("limit", limit.map(|v| v.to_string())),
            ("offset", offset.map(|v| v.to_string())),
            ("status", status),
        ]);
        get_json(&format!("/api/incidents{suffix}")).await
    }

    // ── Security ────────────────────────────────────────────────────────

    #[tool(description = "Get the security overview for this instance (firewall, fail2ban, panel-jail, canary status at a glance).")]
    async fn get_security_overview(&self) -> Result<String, String> {
        get_json("/api/security/overview").await
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
        let suffix = query_suffix(&[
            ("limit", limit.map(|v| v.to_string())),
            ("offset", offset.map(|v| v.to_string())),
            ("severity", severity),
        ]);
        get_json(&format!("/api/security/audit-log{suffix}")).await
    }

    #[tool(description = "Get the computed security posture score for this instance, with the factors that make it up.")]
    async fn get_security_posture(&self) -> Result<String, String> {
        get_json("/api/security/posture").await
    }

    // ── DNS ─────────────────────────────────────────────────────────────

    #[tool(description = "List DNS zones managed through this instance.")]
    async fn list_dns_zones(&self) -> Result<String, String> {
        get_json("/api/dns/zones").await
    }

    #[tool(description = "List DNS records in one zone.")]
    async fn list_dns_records(
        &self,
        Parameters(DnsZoneIdParams { zone_id }): Parameters<DnsZoneIdParams>,
    ) -> Result<String, String> {
        get_json(&format!("/api/dns/zones/{}/records", urlencoding::encode(&zone_id))).await
    }

    // ── Backups ─────────────────────────────────────────────────────────

    #[tool(description = "Get fleet-wide backup health (coverage, staleness, failure counts across every site and database).")]
    async fn get_backup_orchestrator_health(&self) -> Result<String, String> {
        get_json("/api/backup-orchestrator/health").await
    }

    #[tool(description = "List database backups across the fleet (metadata only — size, timestamp, status; not the dump contents).")]
    async fn list_db_backups(
        &self,
        Parameters(PaginationParams { limit, offset }): Parameters<PaginationParams>,
    ) -> Result<String, String> {
        let suffix = query_suffix(&[("limit", limit.map(|v| v.to_string())), ("offset", offset.map(|v| v.to_string()))]);
        get_json(&format!("/api/backup-orchestrator/db-backups{suffix}")).await
    }

    // ── Mail ────────────────────────────────────────────────────────────

    #[tool(description = "Get the mail server's overall status (Postfix/Dovecot health, queue depth at a glance).")]
    async fn get_mail_status(&self) -> Result<String, String> {
        get_json("/api/mail/status").await
    }

    #[tool(description = "List mail domains configured on this instance (DKIM selector, catch-all status).")]
    async fn list_mail_domains(&self) -> Result<String, String> {
        get_json("/api/mail/domains").await
    }

    // ── Logs & system ───────────────────────────────────────────────────

    #[tool(description = "Fetch recent system-level logs (nginx access/error, syslog, auth, or php-fpm) with an optional substring filter.")]
    async fn get_system_logs(
        &self,
        Parameters(SystemLogsParams { log_type, lines, filter }): Parameters<SystemLogsParams>,
    ) -> Result<String, String> {
        let suffix = query_suffix(&[("type", log_type), ("lines", lines.map(|v| v.to_string())), ("filter", filter)]);
        get_json(&format!("/api/logs{suffix}")).await
    }

    #[tool(description = "Get the panel's own recorded activity feed (who did what, across every resource type) — broader than the security audit log, which covers security-relevant events only.")]
    async fn list_activity(
        &self,
        Parameters(ActivityListParams { limit, offset, action }): Parameters<ActivityListParams>,
    ) -> Result<String, String> {
        let suffix = query_suffix(&[
            ("limit", limit.map(|v| v.to_string())),
            ("offset", offset.map(|v| v.to_string())),
            ("action", action),
        ]);
        get_json(&format!("/api/activity{suffix}")).await
    }

    // ── Panel & fleet ops ───────────────────────────────────────────────

    #[tool(description = "Check whether a panel software update is available and what version this instance is currently running.")]
    async fn get_update_status(&self) -> Result<String, String> {
        get_json("/api/update/status").await
    }

    #[tool(description = "List configured outbound webhook endpoints (URL, event subscriptions) — configuration only, never the inbound webhook receiver URLs third parties call into.")]
    async fn list_webhook_endpoints(&self) -> Result<String, String> {
        get_json("/api/webhook-gateway/endpoints").await
    }

    #[tool(description = "List Git Deploy configurations (repo, branch, deploy target) across the fleet.")]
    async fn list_git_deploys(&self) -> Result<String, String> {
        get_json("/api/git-deploys").await
    }

    #[tool(description = "List Docker Compose stacks deployed on this instance.")]
    async fn list_stacks(&self) -> Result<String, String> {
        get_json("/api/stacks").await
    }

    #[tool(description = "List panel user accounts (email, role, reseller). Requires an admin-scoped key.")]
    async fn list_users(&self) -> Result<String, String> {
        get_json("/api/users").await
    }

    #[tool(
        description = "Get this instance's panel settings. Secret-shaped values (API keys, passwords, tokens) are \
                        masked by the panel API itself before this tool ever sees them. Requires an admin-scoped key."
    )]
    async fn get_settings(&self) -> Result<String, String> {
        get_json("/api/settings").await
    }

    #[tool(description = "List reseller accounts and their resource limits. Requires an admin-scoped key.")]
    async fn list_resellers(&self) -> Result<String, String> {
        get_json("/api/resellers").await
    }

    #[tool(description = "Get anonymized telemetry stats this instance has recorded about its own usage. Requires an admin-scoped key.")]
    async fn get_telemetry_stats(&self) -> Result<String, String> {
        get_json("/api/telemetry/stats").await
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
