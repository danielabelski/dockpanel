// Same shape as panel/cli/src/backend_client.rs — a second, independent client
// talking to the panel API over loopback HTTP with a `dp_` key. Deliberately
// NOT shared as a library between the two crates: they read different token
// files (an MCP-originated action gets its own mintable, independently
// revocable key from an operator's actual "MCP client" API key, rather than
// reusing whatever the CLI happens to hold on the same box), and duplicating
// ~60 lines is cheaper than introducing a shared internal crate for one
// function's worth of logic. See routes/api_keys.rs (backend) — a
// `dp_`-prefixed key, hashed the same way `agent.token` is, authenticated by
// auth.rs's `AuthUser` extractor exactly like a session JWT.

const API_ENV_PATH: &str = "/etc/dockpanel/api.env";
const TOKEN_PATH: &str = "/etc/dockpanel/mcp.token";

pub fn load_token() -> Result<String, String> {
    let not_configured = || {
        format!(
            "No panel API key configured at {TOKEN_PATH}.\n\
             Mint one from the panel (Settings \u{2192} API Keys \u{2192} name it \"MCP server\"), \
             then save it to {TOKEN_PATH} (root:root, mode 600)."
        )
    };
    let raw = std::fs::read_to_string(TOKEN_PATH).map_err(|_| not_configured())?;
    let token = raw.trim().to_string();
    // An empty (or whitespace-only) file reads as "present" to a bare
    // read_to_string — without this check a leftover file from a reverted
    // setup silently routes every tool call into a 401 instead of failing
    // with a clear "not configured" message.
    if token.is_empty() {
        return Err(not_configured());
    }
    Ok(token)
}

/// Resolve the panel API's base URL from the SAME `LISTEN_ADDR` its own
/// systemd unit's `EnvironmentFile=` feeds it — always in sync with what the
/// backend actually bound, no new operator config for the common single-box
/// install. Mirrors `panel/cli/src/backend_client.rs::base_url` exactly.
fn base_url() -> Result<String, String> {
    let env = std::fs::read_to_string(API_ENV_PATH)
        .map_err(|e| format!("Cannot read {API_ENV_PATH}: {e}"))?;
    let addr = env
        .lines()
        .find_map(|l| l.trim().strip_prefix("LISTEN_ADDR="))
        .ok_or_else(|| format!("{API_ENV_PATH} has no LISTEN_ADDR — cannot reach the panel API"))?
        .trim();
    Ok(format!("http://{addr}"))
}

/// GET a panel API path and return the parsed JSON body. Read-only by
/// construction — this is the only HTTP verb `dockpanel-mcp` v1 ever issues
/// against the panel API (see the design doc §3: zero mutating tools in v1).
pub async fn get(path: &str, token: &str) -> Result<serde_json::Value, String> {
    let url = format!("{}{path}", base_url()?);
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| format!("Cannot reach the panel API at {url}: {e}"))?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        if let Some(msg) = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get("error").and_then(|m| m.as_str()).map(str::to_string))
        {
            return Err(msg);
        }
        return Err(format!("Panel API returned {status}: {text}"));
    }

    if text.is_empty() {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_str(&text).map_err(|e| {
        let preview = &text[..text.len().min(200)];
        format!("Invalid JSON from panel API: {e}\nBody: {preview}")
    })
}
