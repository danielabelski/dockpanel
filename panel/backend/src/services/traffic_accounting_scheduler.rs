//! Per-site monthly bandwidth accounting (GH #84): polls each site's agent for
//! access-log bytes transferred since the last checkpoint, accumulates a
//! durable monthly total in `site_traffic_usage`, and auto-suspends (then
//! auto-recovers) a site against its own `bandwidth_quota_mb`.
//!
//! Runs independently per site, so one unreachable agent or one slow parse
//! never blocks the rest of the fleet — same shape as `deploy_scheduler` /
//! `drill_scheduler`.

use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

use crate::services::agent::{AgentHandle, AgentRegistry};

#[derive(sqlx::FromRow)]
struct TrafficSite {
    id: Uuid,
    domain: String,
    server_id: Uuid,
    user_id: Uuid,
    enabled: bool,
    bandwidth_quota_mb: Option<i32>,
    bandwidth_suspended_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn month_key(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m").to_string()
}

pub async fn run(
    pool: PgPool,
    agents: AgentRegistry,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) {
    tracing::info!("Traffic accounting scheduler started");

    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(25)) => {}
        _ = shutdown_rx.recv() => {
            tracing::info!("Traffic accounting scheduler shutting down gracefully (during initial delay)");
            return;
        }
    }

    // 5 minutes: frequent enough that a hard quota is enforced promptly without
    // polling every agent's filesystem on every fleet tick like the 60s
    // schedulers do for time-sensitive dispatch (deploys, drills).
    let mut interval = tokio::time::interval(Duration::from_secs(300));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                tick(&pool, &agents).await;
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("Traffic accounting scheduler shutting down gracefully");
                return;
            }
        }
    }
}

async fn tick(pool: &PgPool, agents: &AgentRegistry) {
    let sites: Vec<TrafficSite> = match sqlx::query_as(
        "SELECT id, domain, server_id, user_id, enabled, bandwidth_quota_mb, bandwidth_suspended_at \
         FROM sites",
    )
    .fetch_all(pool)
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Traffic accounting: failed to list sites: {e}");
            return;
        }
    };

    let year_month = month_key(chrono::Utc::now());
    for site in &sites {
        collect_one(pool, agents, site, &year_month).await;
    }
}

async fn collect_one(pool: &PgPool, agents: &AgentRegistry, site: &TrafficSite, year_month: &str) {
    let agent = match agents.for_server(site.server_id).await {
        Ok(a) => a,
        Err(_) => return, // unreachable this tick; try again next tick
    };

    let checkpoint: Option<(i64, i64)> = sqlx::query_as(
        "SELECT log_inode, log_size FROM site_traffic_offsets WHERE site_id = $1",
    )
    .bind(site.id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let path = match checkpoint {
        Some((inode, size)) => format!(
            "/nginx/site-traffic-delta/{}?last_inode={inode}&last_size={size}",
            site.domain
        ),
        None => format!("/nginx/site-traffic-delta/{}", site.domain),
    };

    let resp = match agent.get(&path).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Traffic accounting: delta fetch failed for {}: {e}", site.domain);
            return;
        }
    };

    let new_inode = resp["inode"].as_i64().unwrap_or(0);
    let new_size = resp["size"].as_i64().unwrap_or(0);
    let delta = resp["delta_bytes"].as_i64().unwrap_or(0);

    if let Err(e) = sqlx::query(
        "INSERT INTO site_traffic_offsets (site_id, log_inode, log_size, updated_at) \
         VALUES ($1, $2, $3, NOW()) \
         ON CONFLICT (site_id) DO UPDATE SET log_inode = $2, log_size = $3, updated_at = NOW()",
    )
    .bind(site.id)
    .bind(new_inode)
    .bind(new_size)
    .execute(pool)
    .await
    {
        tracing::warn!("Traffic accounting: failed to persist checkpoint for {}: {e}", site.domain);
    }

    if delta > 0
        && let Err(e) = sqlx::query(
            "INSERT INTO site_traffic_usage (site_id, year_month, bytes_used, updated_at) \
             VALUES ($1, $2, $3, NOW()) \
             ON CONFLICT (site_id, year_month) DO UPDATE \
             SET bytes_used = site_traffic_usage.bytes_used + $3, updated_at = NOW()",
        )
        .bind(site.id)
        .bind(year_month)
        .bind(delta)
        .execute(pool)
        .await
    {
        tracing::warn!("Traffic accounting: failed to accumulate usage for {}: {e}", site.domain);
    }

    match site.bandwidth_quota_mb {
        Some(quota_mb) => {
            if site.enabled && site.bandwidth_suspended_at.is_none() {
                let used: i64 = sqlx::query_scalar(
                    "SELECT bytes_used FROM site_traffic_usage WHERE site_id = $1 AND year_month = $2",
                )
                .bind(site.id)
                .bind(year_month)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten()
                .unwrap_or(0);

                let quota_bytes = (quota_mb as i64).saturating_mul(1024 * 1024);
                if used > quota_bytes {
                    suspend_for_quota(pool, &agent, site, used, quota_mb).await;
                }
            } else if let Some(suspended_at) = site.bandwidth_suspended_at
                && month_key(suspended_at) != year_month
            {
                recover_from_suspension(pool, &agent, site, "new billing month").await;
            }
        }
        None => {
            // Quota was raised to "unlimited" while the site was still marked
            // bandwidth-suspended — lift it now rather than leaving it disabled
            // for a limit that no longer exists.
            if site.bandwidth_suspended_at.is_some() {
                recover_from_suspension(pool, &agent, site, "quota removed").await;
            }
        }
    }
}

async fn suspend_for_quota(
    pool: &PgPool,
    agent: &AgentHandle,
    site: &TrafficSite,
    used_bytes: i64,
    quota_mb: i32,
) {
    if let Err(e) = agent.post(&format!("/nginx/sites/{}/disable", site.domain), None).await {
        tracing::warn!(
            "Traffic accounting: auto-suspend failed to disable {} at the agent: {e}",
            site.domain
        );
        return; // don't flip DB state if the agent-side disable didn't happen
    }
    if let Err(e) = sqlx::query(
        "UPDATE sites SET enabled = false, bandwidth_suspended_at = NOW(), updated_at = NOW() WHERE id = $1",
    )
    .bind(site.id)
    .execute(pool)
    .await
    {
        tracing::warn!("Traffic accounting: auto-suspend DB update failed for {}: {e}", site.domain);
        return;
    }

    let used_mb = used_bytes / 1024 / 1024;
    tracing::warn!(
        "Traffic accounting: auto-suspended {} — {used_mb} MB used of {quota_mb} MB quota",
        site.domain
    );
    crate::services::activity::log_activity_system(
        pool,
        "traffic_accounting_scheduler",
        "site.bandwidth_suspended",
        Some("site"),
        Some(&site.domain),
        Some(&format!("{used_mb} MB used of {quota_mb} MB monthly quota")),
        None,
        Some(site.server_id),
    )
    .await;
    crate::services::notifications::notify_panel(
        pool,
        Some(site.user_id),
        &format!("Site suspended: {}", site.domain),
        &format!(
            "{} exceeded its {quota_mb} MB monthly bandwidth quota ({used_mb} MB used) and has \
             been automatically disabled. Raise the quota to restore it immediately, or it \
             restores automatically next month.",
            site.domain
        ),
        "warning",
        "site",
        Some(&format!("/sites/{}", site.id)),
    )
    .await;
}

async fn recover_from_suspension(pool: &PgPool, agent: &AgentHandle, site: &TrafficSite, reason: &str) {
    if let Err(e) = agent.post(&format!("/nginx/sites/{}/enable", site.domain), None).await {
        tracing::warn!(
            "Traffic accounting: auto-recovery failed to enable {} at the agent: {e}",
            site.domain
        );
        return;
    }
    if let Err(e) = sqlx::query(
        "UPDATE sites SET enabled = true, bandwidth_suspended_at = NULL, updated_at = NOW() WHERE id = $1",
    )
    .bind(site.id)
    .execute(pool)
    .await
    {
        tracing::warn!("Traffic accounting: auto-recovery DB update failed for {}: {e}", site.domain);
        return;
    }

    tracing::info!("Traffic accounting: auto-recovered {} ({reason})", site.domain);
    crate::services::activity::log_activity_system(
        pool,
        "traffic_accounting_scheduler",
        "site.bandwidth_suspension_lifted",
        Some("site"),
        Some(&site.domain),
        Some(reason),
        None,
        Some(site.server_id),
    )
    .await;
    crate::services::notifications::notify_panel(
        pool,
        Some(site.user_id),
        &format!("Site re-enabled: {}", site.domain),
        &format!("{} has been automatically re-enabled ({reason}).", site.domain),
        "info",
        "site",
        Some(&format!("/sites/{}", site.id)),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn month_key_formats_as_year_dash_month() {
        let t = chrono::DateTime::parse_from_rfc3339("2026-09-08T10:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(month_key(t), "2026-09");
    }

    #[test]
    fn month_key_distinguishes_adjacent_months() {
        let aug = chrono::DateTime::parse_from_rfc3339("2026-08-31T23:59:59Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let sep = chrono::DateTime::parse_from_rfc3339("2026-09-01T00:00:01Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_ne!(month_key(aug), month_key(sep));
    }
}
