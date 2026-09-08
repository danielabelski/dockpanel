//! BYO-API-key LLM root-cause diagnosis for failed Git Deploy builds.
//!
//! Default-off (`ai_diagnosis_enabled`, see `routes::settings::ALLOWED_KEYS`).
//! The operator supplies their own API key for one of four providers —
//! Anthropic, OpenAI, Gemini, or Grok (xAI) — and triggers a diagnosis by hand
//! per failed deploy from the Git Deploys page. Nothing here runs on a
//! schedule or fires automatically: every call is a deliberate, operator-paid
//! request.

use crate::error::{err, internal_error, ApiError};
use axum::http::StatusCode;
use sqlx::PgPool;
use std::time::Duration;

/// Failure output is truncated to this many *characters from the end* before
/// it goes into the prompt — the failing step is almost always the tail of a
/// build log, and this keeps the request small regardless of provider.
const MAX_OUTPUT_CHARS: usize = 8000;

/// Read the 4 `ai_diagnosis_*` settings and decrypt the stored key.
///
/// Returns `Ok(None)` when the feature is off or incompletely configured, so
/// every caller gives one clear "not configured" error instead of a confusing
/// provider-specific failure two steps downstream.
pub struct AiDiagnosisConfig {
    pub provider: String,
    pub model: String,
    pub api_key: String,
}

pub async fn load_config(
    pool: &PgPool,
    jwt_secret: &str,
) -> Result<Option<AiDiagnosisConfig>, ApiError> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT key, value FROM settings WHERE key IN \
         ('ai_diagnosis_enabled', 'ai_diagnosis_provider', 'ai_diagnosis_model', 'ai_diagnosis_api_key')",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| internal_error("ai diagnosis config", e))?;

    let get = |k: &str| {
        rows.iter()
            .find(|(rk, _)| rk == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };

    if get("ai_diagnosis_enabled") != "true" {
        return Ok(None);
    }
    let provider = get("ai_diagnosis_provider");
    let model = get("ai_diagnosis_model");
    let api_key_enc = get("ai_diagnosis_api_key");
    if provider.is_empty() || model.is_empty() || api_key_enc.is_empty() {
        return Ok(None);
    }

    let api_key =
        crate::services::secrets_crypto::decrypt_credential_or_legacy(&api_key_enc, jwt_secret);
    Ok(Some(AiDiagnosisConfig {
        provider,
        model,
        api_key,
    }))
}

/// Strip common secret shapes out of build/deploy output before it leaves the
/// box for a third-party API. A failed build's log is exactly where a leaked
/// env var, DB password, or CI token ends up printed — redaction happens
/// unconditionally, with no setting to turn it off, because the person who
/// can turn it off is not the one whose secret would leak.
fn redact(text: &str) -> String {
    use std::sync::LazyLock;
    static PATTERNS: LazyLock<Vec<regex::Regex>> = LazyLock::new(|| {
        vec![
            // KEY=value / KEY: value style env/config lines, key name implies a secret.
            regex::Regex::new(
                r#"(?i)([A-Za-z0-9_.\-]*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CREDENTIAL)[A-Za-z0-9_.\-]*)\s*[:=]\s*("?)([^\s"'`]{3,})("?)"#,
            )
            .expect("static regex"),
            // Authorization: Bearer/Basic <token>
            regex::Regex::new(r#"(?i)(Authorization\s*:\s*(?:Bearer|Basic)\s+)([A-Za-z0-9\-_.~+/=]{8,})"#)
                .expect("static regex"),
            // postgres://user:password@host, mysql://user:pass@host, redis://:pass@host, etc.
            regex::Regex::new(r#"([A-Za-z][A-Za-z0-9+.\-]*://[^:/\s]+:)([^@/\s]+)(@)"#)
                .expect("static regex"),
            // PEM private key blocks (SSH deploy keys, TLS keys) — drop the whole block.
            regex::Regex::new(
                r#"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"#,
            )
            .expect("static regex"),
        ]
    });

    let mut out = PATTERNS[3].replace_all(text, "[REDACTED PRIVATE KEY]").into_owned();
    out = PATTERNS[0]
        .replace_all(&out, "$1=$2[REDACTED]$4")
        .into_owned();
    out = PATTERNS[1]
        .replace_all(&out, "${1}[REDACTED]")
        .into_owned();
    out = PATTERNS[2]
        .replace_all(&out, "${1}[REDACTED]${3}")
        .into_owned();
    out
}

pub struct FailureContext {
    pub site_name: String,
    pub commit_hash: String,
    pub commit_message: String,
    pub image_tag: String,
    pub output: String,
}

fn build_prompt(ctx: &FailureContext) -> String {
    let redacted = redact(&ctx.output);
    let count = redacted.chars().count();
    let body = if count > MAX_OUTPUT_CHARS {
        let skip = count - MAX_OUTPUT_CHARS;
        format!(
            "...[{skip} earlier characters truncated]...\n{}",
            redacted.chars().skip(skip).collect::<String>()
        )
    } else {
        redacted
    };

    format!(
        "You are helping a system administrator diagnose a failed deployment on their \
         self-hosted server-management panel. Some values below may already be redacted \
         as [REDACTED] — do not ask for them back, work with what's shown.\n\n\
         Site: {}\nCommit: {} ({})\nImage tag: {}\n\n\
         Build/deploy failure output (most recent lines last):\n```\n{}\n```\n\n\
         In plain terms, answer two things: (1) what most likely caused this failure, \
         and (2) the specific, concrete fix to try next. Keep it short — a sysadmin is \
         going to act on this immediately, not read an essay.",
        ctx.site_name, ctx.commit_hash, ctx.commit_message, ctx.image_tag, body,
    )
}

pub async fn explain_failure(
    config: &AiDiagnosisConfig,
    ctx: &FailureContext,
) -> Result<String, ApiError> {
    let prompt = build_prompt(ctx);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(45))
        .build()
        .map_err(|e| internal_error("ai diagnosis http client", e))?;

    match config.provider.as_str() {
        "anthropic" => call_anthropic(&client, config, &prompt).await,
        "openai" => call_openai_compatible(&client, "https://api.openai.com/v1/chat/completions", config, &prompt).await,
        "grok" => call_openai_compatible(&client, "https://api.x.ai/v1/chat/completions", config, &prompt).await,
        "gemini" => call_gemini(&client, config, &prompt).await,
        other => Err(err(
            StatusCode::BAD_REQUEST,
            &format!("Unknown AI diagnosis provider: {other}"),
        )),
    }
}

/// Body text from a failed provider call, truncated so a verbose HTML error
/// page or a pathological response can't blow up our own error payload —
/// this text reaches the operator, never the API key.
fn snippet(body: &str) -> String {
    let mut s: String = body.chars().take(500).collect();
    if body.chars().count() > 500 {
        s.push_str("...");
    }
    s
}

/// Pull a human-readable message out of a failed provider response. Anthropic,
/// OpenAI, and Gemini all nest it as `error.message` (an object) — but xAI's
/// error responses, confirmed live against api.x.ai (not assumed from docs),
/// are the flat shape `{"error": "<string>", "code": "..."}` despite xAI's
/// SUCCESS responses being otherwise OpenAI-shaped. Try the nested form
/// first, then the flat string, so no provider falls through to "unknown
/// error" for what is otherwise a perfectly good message.
fn extract_error_message(body: &serde_json::Value) -> &str {
    body.get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .or_else(|| body.get("error").and_then(|e| e.as_str()))
        .unwrap_or("unknown error")
}

async fn call_anthropic(
    client: &reqwest::Client,
    config: &AiDiagnosisConfig,
    prompt: &str,
) -> Result<String, ApiError> {
    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", &config.api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&serde_json::json!({
            "model": config.model,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        }))
        .send()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &format!("Could not reach Anthropic: {e}")))?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &format!("Anthropic returned an unreadable response: {e}")))?;

    if !status.is_success() {
        return Err(err(
            StatusCode::BAD_GATEWAY,
            &format!("Anthropic API error ({status}): {}", snippet(extract_error_message(&body))),
        ));
    }

    body.get("content")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("text"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| err(StatusCode::BAD_GATEWAY, "Anthropic response had no text content"))
}

async fn call_openai_compatible(
    client: &reqwest::Client,
    url: &str,
    config: &AiDiagnosisConfig,
    prompt: &str,
) -> Result<String, ApiError> {
    let resp = client
        .post(url)
        .bearer_auth(&config.api_key)
        .json(&serde_json::json!({
            "model": config.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1024,
        }))
        .send()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &format!("Could not reach {url}: {e}")))?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &format!("Provider returned an unreadable response: {e}")))?;

    if !status.is_success() {
        return Err(err(
            StatusCode::BAD_GATEWAY,
            &format!("Provider API error ({status}): {}", snippet(extract_error_message(&body))),
        ));
    }

    body.get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| err(StatusCode::BAD_GATEWAY, "Provider response had no message content"))
}

async fn call_gemini(
    client: &reqwest::Client,
    config: &AiDiagnosisConfig,
    prompt: &str,
) -> Result<String, ApiError> {
    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent",
        config.model
    );

    let resp = client
        .post(&url)
        .header("x-goog-api-key", &config.api_key)
        .json(&serde_json::json!({
            "contents": [{"parts": [{"text": prompt}]}],
        }))
        .send()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &format!("Could not reach Gemini: {e}")))?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, &format!("Gemini returned an unreadable response: {e}")))?;

    if !status.is_success() {
        return Err(err(
            StatusCode::BAD_GATEWAY,
            &format!("Gemini API error ({status}): {}", snippet(extract_error_message(&body))),
        ));
    }

    body.get("candidates")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.get(0))
        .and_then(|p| p.get("text"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| err(StatusCode::BAD_GATEWAY, "Gemini response had no text content"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_env_style_secrets() {
        let out = redact("DB_PASSWORD=hunter2\nDEPLOY_TOKEN: ghp_abcdEFGH1234\nPORT=3000");
        assert!(!out.contains("hunter2"));
        assert!(!out.contains("ghp_abcdEFGH1234"));
        assert!(out.contains("PORT=3000"));
    }

    #[test]
    fn redacts_bearer_tokens() {
        let out = redact("curl -H 'Authorization: Bearer sk-live-abc123XYZ789' https://api.example.com");
        assert!(!out.contains("sk-live-abc123XYZ789"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_connection_string_passwords() {
        let out = redact("postgres://dockpanel:S3cretPass!@127.0.0.1:5432/dockpanel");
        assert!(!out.contains("S3cretPass!"));
        assert!(out.contains("postgres://dockpanel:[REDACTED]@127.0.0.1:5432/dockpanel"));
    }

    #[test]
    fn redacts_private_key_blocks() {
        let out = redact("before\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\ndef456\n-----END OPENSSH PRIVATE KEY-----\nafter");
        assert!(!out.contains("abc123"));
        assert!(out.contains("[REDACTED PRIVATE KEY]"));
        assert!(out.contains("before"));
        assert!(out.contains("after"));
    }

    #[test]
    fn leaves_ordinary_output_untouched() {
        let log = "Step 4/9 : RUN npm install\n---> Running in abc123\nnpm ERR! code ENOENT";
        assert_eq!(redact(log), log);
    }

    #[test]
    fn extracts_nested_error_message_openai_anthropic_gemini_shape() {
        let body = serde_json::json!({"error": {"message": "invalid api key", "type": "authentication_error"}});
        assert_eq!(extract_error_message(&body), "invalid api key");
    }

    #[test]
    fn extracts_flat_error_message_xai_shape() {
        // Confirmed live against api.x.ai: {"code":"invalid-argument","error":"..."}
        // — a plain string, not an object with .message. Without this fallback
        // every xAI error reports "unknown error" despite the API returning a
        // perfectly good one.
        let body = serde_json::json!({"code": "invalid-argument", "error": "Incorrect API key provided."});
        assert_eq!(extract_error_message(&body), "Incorrect API key provided.");
    }

    #[test]
    fn falls_back_to_unknown_error_when_neither_shape_matches() {
        let body = serde_json::json!({"something_else": "not an error field"});
        assert_eq!(extract_error_message(&body), "unknown error");
    }

    #[test]
    fn build_prompt_redacts_the_output_field() {
        // redact() is unit-tested directly above; this closes the gap between
        // "redact() works" and "build_prompt actually calls it on the field
        // that reaches the wire" — the two could drift if a future edit read
        // from the wrong field or reordered redact-then-truncate.
        let ctx = FailureContext {
            site_name: "example.com".into(),
            commit_hash: "abc1234".into(),
            commit_message: "test".into(),
            image_tag: "example:latest".into(),
            output: "DB_PASSWORD=hunter2\nbuild failed".into(),
        };
        let prompt = build_prompt(&ctx);
        assert!(!prompt.contains("hunter2"));
        assert!(prompt.contains("build failed"));
    }

    #[test]
    fn truncates_from_the_head_keeping_the_tail() {
        let ctx = FailureContext {
            site_name: "example.com".into(),
            commit_hash: "abc1234".into(),
            commit_message: "test".into(),
            image_tag: "example:latest".into(),
            output: "x".repeat(MAX_OUTPUT_CHARS + 500) + "TAIL_MARKER",
        };
        let prompt = build_prompt(&ctx);
        assert!(prompt.contains("TAIL_MARKER"));
        assert!(prompt.contains("earlier characters truncated"));
    }
}
