# MCP Server Guide

`dockpanel-mcp` exposes read-only fleet introspection to AI agents over the
[Model Context Protocol](https://modelcontextprotocol.io) — the same information
an operator sees in the panel, reachable by an agent over Streamable HTTP.

**v1 is read-only. Zero mutating or destructive tools.** Every call is a thin
proxy onto the existing REST API — no new business logic, no new permissions
model. Mutating tools are planned for a later release, gated behind an
explicit confirmation model; see [FEATURES.md](https://github.com/ovexro/dockpanel/blob/main/FEATURES.md)
for the roadmap.

## Concepts

- **A 4th binary**: `dockpanel-mcp` ships alongside `dockpanel-api`, `dockpanel-agent`
  and the `dockpanel` CLI, but is **not installed running** — it is off by
  default on every install, opt-in only.
- **Its own API key**: authenticates the same way the CLI does — a `dp_`
  key minted from Settings → API Keys, saved to a token file. Independently
  revocable from any other key on the box.
- **Streamable HTTP only**: no stdio transport. The server is meant to be
  reached over the network (by an agent that doesn't run on the same host),
  proxied through nginx at `/mcp` alongside the existing `/api` and `/agent`
  locations.
- **Attributed audit trail**: every call an MCP-originated key makes is
  recorded in the panel's own security audit log, tagged with the key that
  made it — the same table an operator reviews for any other login or action.

## Setup

1. **Mint a key.** Settings → Account → API Keys → **+ Create Key**, name it
   something like "MCP server". Copy the value shown — it will not be shown
   again.
2. **Save the token on the host**, root-only:
   ```
   echo 'dp_...' > /etc/dockpanel/mcp.token
   chown root:root /etc/dockpanel/mcp.token
   chmod 600 /etc/dockpanel/mcp.token
   ```
3. **Start the service:**
   ```
   systemctl enable --now dockpanel-mcp
   ```
4. **Record it in Settings → Services → MCP Server** so the panel's own
   Settings page shows accurate status. This step is bookkeeping only — it
   does not itself start or stop the service.

Once running, the endpoint is `https://<your-panel-domain>/mcp` (nginx
proxies it exactly like `/api` and `/agent`). Point any MCP-capable client
at that URL with the key from step 1 as a bearer token.

### Bind mode

The default (`loopback`) binds `dockpanel-mcp` to `127.0.0.1`, reachable only
through the nginx proxy — the same posture as the API and agent. An advanced
`direct` mode exists (set `LISTEN_ADDR` in `/etc/dockpanel/mcp.env`) that
binds a different address, bypassing nginx and TLS entirely; only use it if
you are fronting the service with your own reverse proxy.

## Tool catalogue (v1, ~40 tools)

This table is a quick reference, hand-maintained — the live `tools/list` MCP
call against your own instance is always authoritative for exact schemas.

| Tool | What it returns |
|---|---|
| `list_sites` / `get_site` | Every hosted site / full detail for one |
| `list_apps` / `get_app_logs` / `get_app_stats` | Docker apps, their logs, their live resource stats |
| `list_crons` | Scheduled cron jobs for one site |
| `list_site_backups` | Site backup metadata (not the contents — no restore tool) |
| `list_wordpress_sites` | Fleet-wide WordPress inventory |
| `list_databases` / `get_database_tables` | Databases and their table/row-count schema (never credentials) |
| `list_servers` / `get_server_metrics` | Fleet servers and their CPU/memory/disk history |
| `get_fleet_dashboard` | The same fleet overview the panel's own dashboard shows |
| `list_monitors` / `get_monitor_uptime` | Uptime monitors and their history |
| `get_status_page` | The public status page, as an unauthenticated visitor sees it |
| `list_alerts` / `get_alerts_summary` | Active/recent alerts, and a rolled-up count by severity |
| `list_on_call_schedules` / `list_escalation_policies` | On-call rotations and escalation policies |
| `list_incidents` | Managed incidents tracked for the status page |
| `get_security_overview` / `get_security_posture` | Firewall/fail2ban/canary status at a glance, and the computed posture score |
| `get_security_audit_log` | The immutable security audit log — logins, lockdowns, key rotations, MCP-originated actions |
| `list_dns_zones` / `list_dns_records` | DNS zones and their records |
| `get_backup_orchestrator_health` / `list_db_backups` | Fleet-wide backup health, and database backup metadata |
| `get_mail_status` / `list_mail_domains` | Mail server health and configured domains |
| `get_system_logs` | nginx/syslog/auth/php-fpm logs, with an optional filter |
| `list_activity` | The panel's own recorded activity feed (broader than the security audit log) |
| `get_update_status` | Whether a panel software update is available |
| `list_webhook_endpoints` | Configured outbound webhook endpoints (never the inbound receiver URLs) |
| `list_git_deploys` | Git Deploy configurations |
| `list_stacks` | Docker Compose stacks |
| `list_users` | Panel user accounts (admin-scoped key required) |
| `get_settings` | Panel settings, with secret-shaped values masked (admin-scoped key required) |
| `list_resellers` | Reseller accounts (admin-scoped key required) |
| `get_telemetry_stats` | This instance's own recorded telemetry (admin-scoped key required) |

## Security notes

- **v1's key model is all-or-nothing**, the same as any other `dp_` API key —
  an MCP-originated key can read anything the account it belongs to could
  read. There is no scoped/read-only key tier yet (`api_keys.scopes` exists
  in the schema for a future release but is not enforced in v1). Mint a
  dedicated account for an agent if you want its blast radius bounded by
  something other than "everything an admin can see."
- **Nothing here can mutate or destroy anything.** Every tool is a GET
  against the existing REST API.
- **Revoke a key the same way you would any other**: Settings → API Keys →
  Revoke. The MCP server will start failing with a clear "not configured"
  error on its next call — no restart needed.
