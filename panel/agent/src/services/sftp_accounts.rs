//! Per-site SFTP accounts (GH #108).
//!
//! Each SFTP-enabled site gets its own Linux uid/gid (allocated by the panel,
//! `sites.sftp_uid`/`sftp_gid`), which becomes the REAL owner of
//! `/var/www/{domain}` — the actual per-tenant isolation. A separate jail tree
//! under `/var/dockpanel-sftp/{domain}` is the OpenSSH `ChrootDirectory`
//! (root-owned, as OpenSSH requires); its one `content/` subdirectory is
//! bind-mounted (a dedicated systemd `.mount` unit, not `/etc/fstab`) onto the
//! real, UNMOVED `/var/www/{domain}` — no nginx/PHP-FPM/WP-CLI/CMS-installer
//! path anywhere else in the codebase ever needs to change. Membership in the
//! shared `SFTP_GROUP` is what scopes sshd's one `Match` block to these users;
//! it is created once and never touched again after the first site enables.
//!
//! `useradd`/`groupadd`/`chown`/`usermod` all run via `safe_command_unsandboxed`
//! (the `systemd-run` escape, same as the `vmail` user in `routes/mail.rs`) —
//! `/etc/passwd`/`shadow`/`group` sit outside the agent's own `ReadWritePaths`.

use crate::safe_cmd::{safe_command, safe_command_unsandboxed};
use sha_crypt::{PasswordHasher, ShaCrypt};

/// The shared secondary group every per-site SFTP user is a member of.
/// `Match Group` in the sshd drop-in scopes the chroot to exactly this group —
/// created once, by name (no fixed gid needed; useradd/sshd both accept names).
pub const SFTP_GROUP: &str = "sftp_sites";

const SSHD_DROPIN: &str = "/etc/ssh/sshd_config.d/99-dockpanel-sftp.conf";

/// Where the panel records which domain owns an allocated uid — read by
/// [`crate::services::ownership::sftp_user`] before any teardown touches a
/// real Linux account. Kept outside both the chroot jail and `/var/www` so
/// the SFTP user's own session can never reach or edit it.
pub const OWNER_MARKER_DIR: &str = "/etc/dockpanel/sftp-owners";

pub fn sftp_username(uid: i32) -> String {
    format!("sftp{uid}")
}

pub fn sftp_groupname(gid: i32) -> String {
    format!("sftpg{gid}")
}

fn jail_root(domain: &str) -> String {
    format!("/var/dockpanel-sftp/{domain}")
}

fn jail_content_dir(domain: &str) -> String {
    format!("{}/content", jail_root(domain))
}

pub fn owner_marker_path(uid: i32) -> String {
    format!("{OWNER_MARKER_DIR}/{uid}.owner")
}

/// Compute the systemd unit name for `content_dir`'s bind mount via
/// `systemd-escape`, rather than hand-rolling systemd's path-escaping rules
/// (`-` -> `\x2d` etc.) — a `.mount` unit's filename MUST exactly match the
/// escaped `Where=` path or systemd will not track the mount against it.
async fn mount_unit_name(content_dir: &str) -> Result<String, String> {
    let output = safe_command("systemd-escape")
        .args(["--path", "--suffix=mount", content_dir])
        .output()
        .await
        .map_err(|e| format!("systemd-escape failed to run: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "systemd-escape failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Provision the SFTP account for `domain`: shared group (once), per-site
/// user+group, the jail tree, the bind-mount unit, and re-owns the site's real
/// content directory. Idempotent on the group/sshd-group-membership steps;
/// NOT idempotent on the user/mount-unit steps (`enable_sftp` on the backend
/// already no-ops when `sftp_enabled` is already true, so this only ever runs
/// once per site).
pub async fn provision(domain: &str, uid: i32, gid: i32) -> Result<(), String> {
    let username = sftp_username(uid);
    let groupname = sftp_groupname(gid);
    let site_dir = format!("/var/www/{domain}");
    if !std::path::Path::new(&site_dir).exists() {
        return Err(format!("{site_dir} does not exist — cannot enable SFTP"));
    }

    // 1. Shared secondary group — idempotent, ignore "already exists".
    let _ = safe_command_unsandboxed("groupadd", &[])
        .args([SFTP_GROUP])
        .output()
        .await;

    // 2. Per-site primary group, then the user itself. Both are genuinely new
    // per site — a failure here must be a real error, not swallowed.
    let out = safe_command_unsandboxed("groupadd", &[])
        .args(["-g", &gid.to_string(), &groupname])
        .output()
        .await
        .map_err(|e| format!("groupadd failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "groupadd {groupname} (gid {gid}) failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let jail = jail_root(domain);
    let out = safe_command_unsandboxed("useradd", &[])
        .args([
            "-u",
            &uid.to_string(),
            "-g",
            &groupname,
            "-G",
            SFTP_GROUP,
            "-d",
            &jail,
            "-s",
            "/usr/sbin/nologin",
            &username,
        ])
        .output()
        .await
        .map_err(|e| format!("useradd failed to run: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        // Roll back the group we just created — a half-provisioned site (group
        // present, no user) is worse than none, since a retry's groupadd would
        // then fail on "already exists" and mask the real problem.
        let _ = safe_command_unsandboxed("groupdel", &[]).args([&groupname]).output().await;
        return Err(format!("useradd {username} (uid {uid}) failed: {stderr}"));
    }

    // 3. Jail tree: root-owned boundary (OpenSSH requires this, not
    // configurable), empty content/ mountpoint. `/var/dockpanel-sftp` is a
    // brand-new top-level directory this feature creates on first use, so a
    // plain `std::fs::create_dir_all` here hits the same EROFS the vmail
    // directory does in `routes/mail.rs`: ProtectSystem=strict namespaces the
    // agent's writable set at unit START, and a path that did not exist then
    // is not in it regardless of what ReadWritePaths later gets updated to
    // say — only the systemd-run escape can create it live. (Live-verified on
    // a fresh VPS: the plain std::fs call failed with exactly this error
    // before this fix.)
    let content_dir = jail_content_dir(domain);
    let out = safe_command_unsandboxed("mkdir", &[])
        .args(["-p", &content_dir])
        .output()
        .await
        .map_err(|e| format!("mkdir failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "Failed to create jail tree {content_dir}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let _ = safe_command_unsandboxed("chown", &[]).args(["root:root", &jail]).output().await;
    let _ = safe_command_unsandboxed("chmod", &[]).args(["0755", &jail]).output().await;

    // 4. Bind-mount content/ onto the REAL, unmoved site directory.
    let unit_name = mount_unit_name(&content_dir).await?;
    let unit = format!(
        "[Unit]\n\
         Description=DockPanel SFTP jail content mount: {domain}\n\
         \n\
         [Mount]\n\
         What={site_dir}\n\
         Where={content_dir}\n\
         Type=none\n\
         Options=bind\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    );
    let unit_path = format!("/etc/systemd/system/{unit_name}");
    if let Err(e) = std::fs::write(&unit_path, &unit) {
        return Err(format!("Failed to write mount unit {unit_path}: {e}"));
    }
    let _ = safe_command("systemctl").args(["daemon-reload"]).output().await;
    let out = safe_command("systemctl")
        .args(["enable", "--now", &unit_name])
        .output()
        .await
        .map_err(|e| format!("Failed to start {unit_name}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "Failed to start {unit_name}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    // 5. The actual isolation: re-own the real site directory. PHP-FPM's pool
    // is re-pointed at this same identity by the caller (`put_site`, driven by
    // `pool_user`/`pool_group` on the next vhost rebuild — the backend sends
    // those the moment `sftp_enabled` flips true).
    let out = safe_command_unsandboxed("chown", &[])
        .args(["-R", &format!("{username}:{groupname}"), &site_dir])
        .output()
        .await
        .map_err(|e| format!("chown failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "chown -R {username}:{groupname} {site_dir} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    // 6. Owner marker — written last, only once every step above has actually
    // succeeded, so a marker on disk is never a promise this function did not
    // keep.
    if let Err(e) = std::fs::create_dir_all(OWNER_MARKER_DIR) {
        return Err(format!("Failed to create {OWNER_MARKER_DIR}: {e}"));
    }
    if let Err(e) = std::fs::write(owner_marker_path(uid), format!("Domain={domain}\n")) {
        return Err(format!("Failed to write owner marker for uid {uid}: {e}"));
    }

    ensure_sshd_dropin().await?;

    tracing::info!("SFTP provisioned for {domain}: user={username} uid={uid} gid={gid}");
    Ok(())
}

/// Tear down everything [`provision`] created. `last_sftp_site` tells us
/// whether to also remove the shared sshd drop-in — the caller (the backend)
/// derives this from the `sites` table, not from re-scanning this box, since
/// the DB is the source of truth for how many sites still have SFTP enabled.
pub async fn deprovision(domain: &str, uid: i32, gid: i32, last_sftp_site: bool) -> Result<(), String> {
    if !crate::services::ownership::sftp_user(uid, domain).may_delete() {
        return Err(format!(
            "uid {uid} does not carry an owner marker naming {domain} — refusing to tear down \
             an account this agent cannot prove belongs to this site"
        ));
    }

    let username = sftp_username(uid);
    let groupname = sftp_groupname(gid);
    let site_dir = format!("/var/www/{domain}");

    // 1. Detach the bind mount FIRST — a chown while the site dir is still
    // mounted into the jail is safe either way (the mount is transparent to
    // path-based tools), but tearing down in this order means a failure here
    // leaves the account still enabled rather than half-disabled.
    let content_dir = jail_content_dir(domain);
    if let Ok(unit_name) = mount_unit_name(&content_dir).await {
        let unit_path = format!("/etc/systemd/system/{unit_name}");
        if std::path::Path::new(&unit_path).exists() {
            let _ = safe_command("systemctl").args(["stop", &unit_name]).output().await;
            let _ = safe_command("systemctl").args(["disable", &unit_name]).output().await;
            let _ = std::fs::remove_file(&unit_path);
            let _ = safe_command("systemctl").args(["daemon-reload"]).output().await;
        }
    }

    // 2. Revert the real content back to the shared identity every other site
    // uses. The caller updates `sftp_enabled = false` and rebuilds the vhost
    // (reverting the PHP-FPM pool) in the SAME transition — order between
    // this and that rebuild does not matter, since both converge on
    // `www-data` and neither reads the other's intermediate state.
    if std::path::Path::new(&site_dir).exists() {
        let _ = safe_command_unsandboxed("chown", &[])
            .args(["-R", "www-data:www-data", &site_dir])
            .output()
            .await;
    }

    // 3. Remove the jail scaffolding — this is agent-created infrastructure,
    // never site data (the real content lived at `site_dir` the whole time).
    // Same unsandboxed-escape requirement as creation (see provision()).
    let jail = jail_root(domain);
    let out = safe_command_unsandboxed("rm", &[]).args(["-rf", &jail]).output().await;
    match out {
        Ok(o) if !o.status.success() => tracing::warn!(
            "Failed to remove jail tree {jail}: {}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => tracing::warn!("Failed to remove jail tree {jail}: {e}"),
        Ok(_) => {}
    }

    // 3.5. Stop this domain's PHP-FPM pool entirely — removed, not merely
    // reverted, and RELOADED before any process is killed.
    //
    // Live-verified this is the actual fix step 4's `pkill` alone is not:
    // killing the pool's workers does not stop the php-fpm MASTER (running
    // as root, unaffected by `pkill -u <uid>`) from immediately respawning
    // new ones under the same uid per `pm.start_servers`/`pm.min_spare_
    // servers` in the pool config that is STILL ON DISK — a pkill-then-
    // userdel sequence lost this race every time, new worker PIDs appearing
    // between the two calls. Only removing the pool file itself and
    // reloading stops the master from wanting workers under this identity
    // at all. Every caller converges on this domain having NO SFTP-owned
    // pool afterward regardless of what it separately does next: `disable`'s
    // vhost rebuild recreates a fresh www-data pool moments later; site
    // deletion's own later pool-file removal (`nginx.rs::delete_site`) finds
    // nothing left and is a no-op, exactly like every other `if path.exists()`
    // step there already tolerates.
    for version in ["8.1", "8.2", "8.3", "8.4", "8.5"] {
        let pool_path = format!("/etc/php/{version}/fpm/pool.d/{}.conf", domain.replace('.', "_"));
        if std::path::Path::new(&pool_path).exists() {
            if let Err(e) = std::fs::remove_file(&pool_path) {
                tracing::warn!("Failed to remove PHP-FPM pool {pool_path} before SFTP teardown: {e}");
            }
            if let Err(e) = crate::services::nginx::reload_php_fpm(version).await {
                tracing::warn!("Failed to reload php{version}-fpm before SFTP teardown: {e}");
            }
        }
    }

    // 4. Kill anything still running as this uid, THEN remove the account.
    //
    // Live-verified twice, via two DIFFERENT callers: `userdel` refuses to
    // remove a uid with a running process, and the PHP-FPM pool's own
    // workers are still alive under it at this point unless the caller
    // happened to revert+reload the pool first. The `disable` path does that
    // (as a necessary step in its own right — the pool must go back to
    // www-data regardless), which was enough to unblock userdel there. Site
    // DELETION's teardown only ever *removes the pool config file*
    // (`nginx.rs::delete_site`, no reload) — deleting the file does not stop
    // an already-running worker, so the exact same "account still exists
    // after teardown reports success" failure reproduced through that path
    // with no shared code to have fixed it in one place. Rather than adding
    // a third caller-side ordering requirement (or trusting a fourth one
    // later gets it right), this function no longer depends on the caller
    // having cleared the uid's processes at all: `pkill -9 -u` first, THEN
    // userdel, makes deprovision() correct on its own regardless of what
    // else is or isn't still running under this identity.
    let _ = safe_command_unsandboxed("pkill", &[]).args(["-9", "-u", &uid.to_string()]).output().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Best-effort (matching every other cleanup step above), but LOGGED — a
    // swallowed failure here previously meant "disabled"/"deleted" could
    // report success while the OS account and its group were still present.
    match safe_command_unsandboxed("userdel", &[]).args([&username]).output().await {
        Ok(o) if !o.status.success() => tracing::warn!(
            "userdel {username} failed (account may still exist): {}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => tracing::warn!("userdel {username} failed to run: {e}"),
        Ok(_) => {}
    }
    match safe_command_unsandboxed("groupdel", &[]).args([&groupname]).output().await {
        Ok(o) if !o.status.success() => tracing::warn!(
            "groupdel {groupname} failed (group may still exist): {}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => tracing::warn!("groupdel {groupname} failed to run: {e}"),
        Ok(_) => {}
    }
    let _ = std::fs::remove_file(owner_marker_path(uid));

    if last_sftp_site {
        let _ = std::fs::remove_file(SSHD_DROPIN);
        let _ = reload_sshd_validated().await;
    }

    tracing::info!("SFTP deprovisioned for {domain}: user={username}");
    Ok(())
}

/// Set (or reset) `domain`'s SFTP password. Hashes in-process (glibc
/// SHA-512-crypt via `sha-crypt`) rather than piping plaintext through
/// `chpasswd`'s stdin — the shared `UnsandboxedCommand` primitive every
/// privileged call here goes through has no stdin support today, and a hash
/// (unlike plaintext) is not sensitive to pass as a `usermod -p` argument;
/// that is the entire reason hashing exists.
pub async fn set_password(uid: i32, plaintext: &str) -> Result<(), String> {
    let username = sftp_username(uid);
    // NOT `ShaCrypt::hash_password()` — its auto-generated salt is
    // `password_hash`'s generic RECOMMENDED_SALT_LEN (16 RAW BYTES), which
    // base64-encodes to 22 characters. SHA-crypt's own spec caps the salt at
    // 16 base64 CHARACTERS; glibc's crypt() (what PAM actually calls to
    // verify a login) truncates an over-long salt to that limit when
    // recomputing the hash, so it silently computes a DIFFERENT digest than
    // the one stored — authentication then fails for every correct password,
    // forever. Live-verified on a fresh VPS: a hash made with the default
    // 16-byte/22-char salt round-tripped through Rust's own crypt.crypt()
    // check as WRONG. 12 raw bytes base64-encodes to exactly 16 characters
    // (12*8/6 = 16, no truncation needed by any spec-compliant verifier).
    let salt: [u8; 12] = {
        use rand::Rng;
        rand::rng().random()
    };
    let hash = ShaCrypt::default()
        .hash_password_with_salt(plaintext.as_bytes(), &salt)
        .map_err(|e| format!("Failed to hash password: {e}"))?;
    let out = safe_command_unsandboxed("usermod", &[])
        .args(["-p", hash.as_str(), &username])
        .output()
        .await
        .map_err(|e| format!("usermod failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "usermod -p failed for {username}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Write the sshd `Match Group` drop-in if it is not already present, then
/// validate and reload — never the bare `restart_sshd`/no-validation path
/// `services::security`'s existing SSH-hardening functions use today, since
/// that path has no `sshd -t` gate anywhere and a malformed Match block would
/// otherwise lock out SSH access on reload with no warning.
async fn ensure_sshd_dropin() -> Result<(), String> {
    if std::path::Path::new(SSHD_DROPIN).exists() {
        return Ok(());
    }
    let block = format!(
        "# Managed by DockPanel — per-site SFTP jails (GH #108). Do not edit by hand;\n\
         # regenerated the next time a site's SFTP account is enabled/disabled.\n\
         Match Group {SFTP_GROUP}\n\
         \tChrootDirectory %h\n\
         \tForceCommand internal-sftp\n\
         \tAllowTcpForwarding no\n\
         \tX11Forwarding no\n"
    );
    if let Err(e) = std::fs::write(SSHD_DROPIN, &block) {
        return Err(format!("Failed to write {SSHD_DROPIN}: {e}"));
    }
    if let Err(e) = reload_sshd_validated().await {
        let _ = std::fs::remove_file(SSHD_DROPIN);
        return Err(e);
    }
    Ok(())
}

/// `sshd -t` then `systemctl reload sshd` — reload, not restart, so an
/// unrelated config change never drops a live SSH session. On a failed
/// validation the caller is responsible for removing whatever it just wrote;
/// this function only ever validates the config CURRENTLY on disk.
async fn reload_sshd_validated() -> Result<(), String> {
    let test = safe_command("sshd").args(["-t"]).output().await
        .map_err(|e| format!("sshd -t failed to run: {e}"))?;
    if !test.status.success() {
        return Err(format!(
            "sshd config invalid after SFTP drop-in change: {}",
            String::from_utf8_lossy(&test.stderr)
        ));
    }
    let out = safe_command("systemctl").args(["reload", "sshd"]).output().await
        .map_err(|e| format!("systemctl reload sshd failed to run: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "systemctl reload sshd failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha_crypt::PasswordVerifier;

    /// The live-verified bug this pins: `$6$rounds=5000$8mwPPcuR8m7wfnYuiMKDK.$...`
    /// (a real hash this code produced before the fix) has a 22-character
    /// salt field. glibc's crypt() — what PAM actually calls to check a
    /// login — truncates a SHA-crypt salt to 16 characters when recomputing
    /// the hash to verify against, so an over-long salt makes EVERY future
    /// login attempt recompute a different digest than the one stored: not a
    /// crash, not an error anywhere, just permanent, silent authentication
    /// failure for a password that is actually correct. `hash_password()`'s
    /// auto-generated salt is `password_hash`'s generic
    /// `RECOMMENDED_SALT_LEN` (16 RAW bytes -> 22 base64 characters); this
    /// must never be used for a SHA-crypt hash a real `usermod -p` is going
    /// to store.
    #[test]
    fn the_generated_salt_is_at_most_sixteen_characters() {
        let salt: [u8; 12] = {
            use rand::Rng;
            rand::rng().random()
        };
        let hash = ShaCrypt::default()
            .hash_password_with_salt(b"irrelevant-test-password", &salt)
            .expect("hashing a test password must succeed");
        let fields: Vec<&str> = hash.as_str().split('$').collect();
        // ["", "6", ("rounds=N" |) salt, digest] — salt is always the
        // second-to-last field regardless of whether rounds= is present.
        let salt_field = fields[fields.len() - 2];
        assert!(
            salt_field.len() <= 16,
            "salt field '{salt_field}' is {} characters — glibc's crypt() will \
             truncate it on verify and every login will fail",
            salt_field.len()
        );
    }

    /// The actual property that matters: a hash this code produces must
    /// verify correctly via the SAME crate used to produce it (a necessary
    /// but not sufficient check — the salt-length assertion above is what
    /// catches the specific cross-implementation gap with glibc, since this
    /// crate happily verifies its OWN over-long-salt hashes without
    /// truncating, which is exactly why the bug was invisible to this check
    /// alone).
    #[test]
    fn a_produced_hash_verifies_against_the_password_that_made_it() {
        let salt: [u8; 12] = {
            use rand::Rng;
            rand::rng().random()
        };
        let hash = ShaCrypt::default()
            .hash_password_with_salt(b"a-real-looking-password-123", &salt)
            .expect("hashing must succeed");
        ShaCrypt::default()
            .verify_password(b"a-real-looking-password-123", &hash)
            .expect("the password that produced this hash must verify against it");
        assert!(
            ShaCrypt::default()
                .verify_password(b"a-different-password", &hash)
                .is_err(),
            "a wrong password must not verify"
        );
    }
}
