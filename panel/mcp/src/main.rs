mod auth;
mod backend_client;
mod tools;

use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

const MCP_ENV_PATH: &str = "/etc/dockpanel/mcp.env";
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:3081";

/// Mirrors `api.env`'s `LISTEN_ADDR=` convention (`scripts/setup.sh`) so an
/// operator who already knows how to move the API off loopback has the same
/// knob here — nginx's `/mcp/` location proxies to whatever this resolves to.
/// Defaults to loopback-only when the file (or the key) is absent, which is
/// the safer default for a brand-new surface nobody has opted into yet.
fn listen_addr() -> String {
    std::fs::read_to_string(MCP_ENV_PATH)
        .ok()
        .and_then(|env| {
            env.lines()
                .find_map(|l| l.trim().strip_prefix("LISTEN_ADDR="))
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_string())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let addr = listen_addr();

    // rmcp's own DNS-rebinding guard (`allowed_hosts`) defaults to loopback
    // names only — correct for a locally-run dev server a malicious webpage
    // might blind-request, wrong for this one: nginx forwards the real Host
    // header for every `/mcp` request, so the default rejects 100% of real
    // traffic with "Forbidden: Host header is not allowed" (caught live,
    // going through nginx — a direct loopback curl never exercises it, which
    // is how this shipped once already undetected). Emptying the list
    // disables that check per the library's own documented behavior; it's
    // redundant anyway now that `auth::require_bearer_token` below is the
    // real gate — an attacker who can't produce the token can't do anything
    // regardless of which Host header they send.
    let config = StreamableHttpServerConfig::default().disable_allowed_hosts();
    let service = StreamableHttpService::new(
        || Ok(tools::DockPanelMcp),
        LocalSessionManager::default().into(),
        config,
    );

    // Without this, `/mcp` has no caller authentication at all — every tool
    // call in tools.rs authenticates its OWN outbound request to the panel
    // API from a fixed file, never the inbound one, so anyone who could reach
    // this endpoint got the operator's own admin-scoped access for free.
    let router = axum::Router::new()
        .nest_service("/mcp", service)
        .layer(axum::middleware::from_fn(auth::require_bearer_token));

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Cannot bind {addr}: {e}");
            std::process::exit(1);
        }
    };

    tracing::info!("dockpanel-mcp listening on {addr} (/mcp)");
    if let Err(e) = axum::serve(listener, router).await {
        tracing::error!("Server error: {e}");
        std::process::exit(1);
    }
}
