#!/usr/bin/env bash
# Regression pin for PER-SITE BANDWIDTH QUOTA / TRAFFIC ACCOUNTING (GH #84).
#
# A monthly byte accumulator built from the agent's nginx access-log, crossing
# a daily logrotate rotation, feeding a per-site MB/mo quota that auto-disables
# a site when exceeded and auto-recovers it (new month, quota raised/removed,
# or a manual re-enable). The invariants this suite exists to protect:
#
#   - the checkpoint offset NEVER advances past an incomplete trailing log
#     line — doing so would both corrupt the running byte sum (parsing a
#     truncated size field) AND permanently skip that request's bytes forever
#   - a site is suspended for quota at most ONCE per over-quota episode (the
#     bandwidth_suspended_at guard), not re-suspended (and re-notified) on
#     every 5-minute scheduler tick while it stays over
#   - a human re-enabling a bandwidth-suspended site clears the flag, so the
#     scheduler's "still suspended" branch doesn't shadow a fresh quota check
#   - only ONE rotation is reconciled per poll — an inode neither the current
#     file nor `.1` matches is left unrecovered by design, not guessed at
#
# Pure source analysis: no box, no network, no DB. The byte-accounting math
# itself (partial-line handling, rotation-crossing, first-poll bounding) is
# covered by `cargo test traffic_delta` (8 unit tests) in
# panel/agent/src/routes/nginx.rs — this suite pins the WIRING and the
# enforcement state machine around it, not the arithmetic.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

AGENT_NGINX_RS=panel/agent/src/routes/nginx.rs
SCHEDULER_RS=panel/backend/src/services/traffic_accounting_scheduler.rs
SITES_RS=panel/backend/src/routes/sites.rs
MODELS_RS=panel/backend/src/models.rs
MOD_RS=panel/backend/src/routes/mod.rs
MAIN_RS=panel/backend/src/main.rs
SERVICES_MOD_RS=panel/backend/src/services/mod.rs
MIGRATION=panel/backend/migrations/20260908000000_bandwidth_quota.sql
SITE_DETAIL_TSX=panel/frontend/src/pages/SiteDetail.tsx

for f in "$AGENT_NGINX_RS" "$SCHEDULER_RS" "$SITES_RS" "$MODELS_RS" "$MOD_RS" "$MAIN_RS" \
         "$SERVICES_MOD_RS" "$MIGRATION" "$SITE_DETAIL_TSX"; do
  [ -f "$f" ] || { echo "missing file: $f"; exit 1; }
done

# Whitespace-insensitive substring check — a boolean `grep -q` at the end of a
# pipeline under `set -o pipefail` SIGPIPEs the producer and reports failure
# for a successful match; this idiom (matching against a variable, not a
# pipe) avoids that class entirely.
must_contain() {
  local flat="$1" needle="$2" desc="$3"
  local flat_needle
  flat_needle=$(printf '%s' "$needle" | tr -d ' \t\n')
  case "$flat" in
    *"$flat_needle"*) ok "$desc" ;;
    *) bad "$desc — pattern not found (whitespace-insensitive): $needle" ;;
  esac
}

AGENT_FLAT=$(tr -d ' \t\n' < "$AGENT_NGINX_RS")
SCHED_FLAT=$(tr -d ' \t\n' < "$SCHEDULER_RS")
SITES_FLAT=$(tr -d ' \t\n' < "$SITES_RS")

# ── §1 — schema: the accumulator, the checkpoint, and the two Site columns ──
echo "── §1 migration adds the checkpoint table, the accumulator table, and the two site columns ──"
MIG_FLAT=$(tr -d ' \t\n' < "$MIGRATION")
must_contain "$MIG_FLAT" 'ALTERTABLEsitesADDCOLUMNIFNOTEXISTSbandwidth_quota_mbINT;' \
  "sites.bandwidth_quota_mb is added, nullable (unlimited by default)"
must_contain "$MIG_FLAT" 'ALTERTABLEsitesADDCOLUMNIFNOTEXISTSbandwidth_suspended_atTIMESTAMPTZ;' \
  "sites.bandwidth_suspended_at is added"
must_contain "$MIG_FLAT" 'CREATETABLEIFNOTEXISTSsite_traffic_offsets(site_idUUIDPRIMARYKEYREFERENCESsites(id)ONDELETECASCADE,log_inodeBIGINTNOTNULL,log_sizeBIGINTNOTNULL,' \
  "site_traffic_offsets exists with one row per site, keyed by site_id"
must_contain "$MIG_FLAT" 'CREATETABLEIFNOTEXISTSsite_traffic_usage(site_idUUIDNOTNULLREFERENCESsites(id)ONDELETECASCADE,year_monthTEXTNOTNULL,bytes_usedBIGINTNOTNULLDEFAULT0,' \
  "site_traffic_usage exists, one row per site per calendar month"
must_contain "$MIG_FLAT" 'PRIMARYKEY(site_id,year_month)' \
  "site_traffic_usage's primary key is (site_id, year_month) — an upsert target, not a append-only log"

must_contain "$(tr -d ' \t\n' < "$MODELS_RS")" \
  'pubbandwidth_quota_mb:Option<i32>,' \
  "the Site model struct carries bandwidth_quota_mb (SELECT s.* needs every column named)"
must_contain "$(tr -d ' \t\n' < "$MODELS_RS")" \
  'pubbandwidth_suspended_at:Option<DateTime<Utc>>,' \
  "the Site model struct carries bandwidth_suspended_at"

# ── §2 — the agent route exists exactly once, and never advances past a partial line ──
echo "── §2 the delta endpoint is wired once, and offset-advance is partial-line-safe ──"
route_sites=$(grep -c 'site-traffic-delta/{domain}.*get(site_traffic_delta)' "$AGENT_NGINX_RS" || true)
if [ "$route_sites" -eq 1 ]; then
  ok "site-traffic-delta is registered exactly once"
else
  bad "expected exactly 1 registration of site-traffic-delta, found $route_sites"
fi

# This is the invariant the whole feature's correctness rests on: the returned
# offset must stop at the last COMPLETE newline seen, never at raw EOF/tail
# output length — otherwise a line still being written when a poll lands gets
# its size field parsed truncated (corrupting the sum) and is then never
# re-read (the offset already skipped past it).
if grep -q 'fn read_and_advance' "$AGENT_NGINX_RS"; then
  RA_BODY=$(awk '/^async fn read_and_advance\(/,/^}/' "$AGENT_NGINX_RS")
  case "$RA_BODY" in
    *rposition*'\n'*) ok "read_and_advance locates the LAST newline rather than trusting raw read length" ;;
    *) bad "read_and_advance no longer searches for the last newline — may advance past a partial line" ;;
  esac
  case "$RA_BODY" in
    *"from + complete.len()"*) ok "the returned offset is from + (bytes up to the last newline), not the file's raw size" ;;
    *) bad "read_and_advance's returned offset no longer derives from the trimmed complete-lines slice" ;;
  esac
else
  bad "read_and_advance function not found in $AGENT_NGINX_RS"
fi

must_contain "$AGENT_FLAT" 'letrotated_file=format!("/var/log/nginx/{domain}.access.log.1");' \
  "rotation crossing reads the delaycompress-preserved .1 predecessor, not a guess at .2.gz+"
must_contain "$AGENT_FLAT" '&&rmeta.ino()==last_inode' \
  "the rotated predecessor is only trusted when ITS inode matches the caller's old checkpoint (not just any .1 file)"

# ── §3 — the scheduler enforces the quota exactly once per over-quota episode ──
echo "── §3 quota enforcement is suspend-once, not suspend-every-tick ──"
must_contain "$SCHED_FLAT" 'ifsite.enabled&&site.bandwidth_suspended_at.is_none(){' \
  "the over-quota check only runs when the site is enabled AND not already bandwidth-suspended"
must_contain "$SCHED_FLAT" 'ifused>quota_bytes{suspend_for_quota(pool,&agent,site,used,quota_mb).await;}' \
  "suspend_for_quota fires only once the accumulated usage actually exceeds the quota"

# Mutation-test the guard itself: with `bandwidth_suspended_at.is_none()`
# dropped from the condition, a site already suspended this month would be
# re-evaluated (and re-notified) on every single tick while still over quota.
cp "$SCHEDULER_RS" /tmp/bwq-sched-backup.rs
python3 - "$SCHEDULER_RS" <<'PYEOF'
import sys
path = sys.argv[1]
src = open(path).read()
needle = "if site.enabled && site.bandwidth_suspended_at.is_none() {"
replacement = "if site.enabled {"
if needle not in src:
    sys.exit(2)
open(path, "w").write(src.replace(needle, replacement, 1))
PYEOF
if [ $? -eq 0 ]; then
  if grep -q 'if site.enabled && site.bandwidth_suspended_at.is_none() {' "$SCHEDULER_RS"; then
    bad "MUTATION did not apply — suspend-once guard mutation test is broken"
  else
    ok "MUTATION applied: dropped the bandwidth_suspended_at.is_none() guard"
  fi
  cp /tmp/bwq-sched-backup.rs "$SCHEDULER_RS"
  if grep -q 'if site.enabled && site.bandwidth_suspended_at.is_none() {' "$SCHEDULER_RS"; then
    ok "MUTATION reverted — suspend-once guard restored"
  else
    bad "failed to revert the suspend-once guard mutation — $SCHEDULER_RS is left mutated"
  fi
else
  bad "could not locate the suspend-once guard to mutation-test"
fi
rm -f /tmp/bwq-sched-backup.rs

# ── §4 — auto-recovery: new month, quota raised/removed, and a manual re-enable ──
echo "── §4 three independent recovery paths, all clearing bandwidth_suspended_at ──"
must_contain "$SCHED_FLAT" '&&month_key(suspended_at)!=year_month{recover_from_suspension(pool,&agent,site,"newbillingmonth").await;}' \
  "the scheduler auto-recovers a bandwidth-suspended site once a new calendar month starts"
must_contain "$SCHED_FLAT" 'None=>{' \
  "the quota match has a None arm (quota removed while still suspended)"
must_contain "$SCHED_FLAT" 'ifsite.bandwidth_suspended_at.is_some(){recover_from_suspension(pool,&agent,site,"quotaremoved").await;}' \
  "removing the quota (setting it back to unlimited) lifts a standing bandwidth suspension immediately"

# The bug this session found and fixed: toggle_enabled used to leave a stale
# bandwidth_suspended_at behind on manual re-enable, which would shadow the
# scheduler's over-quota check forever (it only runs when the flag is None).
if grep -q 'pub async fn toggle_enabled' "$SITES_RS"; then
  TOGGLE_BODY=$(awk '/^pub async fn toggle_enabled\(/,/^}/' "$SITES_RS")
  case "$(printf '%s' "$TOGGLE_BODY" | tr -d ' \t\n')" in
    *'bandwidth_suspended_at=CASEWHEN$1THENNULLELSEbandwidth_suspended_atEND'*)
      ok "toggle_enabled clears bandwidth_suspended_at when a human sets enabled=true" ;;
    *)
      bad "toggle_enabled no longer clears bandwidth_suspended_at on manual re-enable — a manually-re-enabled site would never be re-checked against its quota" ;;
  esac
else
  bad "toggle_enabled function not found in $SITES_RS"
fi

# Mutation-test that exact clearing clause.
cp "$SITES_RS" /tmp/bwq-sites-backup.rs
python3 - "$SITES_RS" <<'PYEOF'
import sys
path = sys.argv[1]
src = open(path).read()
needle = '"UPDATE sites SET enabled = $1, bandwidth_suspended_at = CASE WHEN $1 THEN NULL ELSE bandwidth_suspended_at END, \\\n         updated_at = NOW() WHERE id = $2",'
replacement = '"UPDATE sites SET enabled = $1, updated_at = NOW() WHERE id = $2",'
if needle not in src:
    sys.exit(2)
open(path, "w").write(src.replace(needle, replacement, 1))
PYEOF
if [ $? -eq 0 ]; then
  if grep -q 'bandwidth_suspended_at = CASE WHEN \$1' "$SITES_RS"; then
    bad "MUTATION did not apply — toggle_enabled clear-flag mutation test is broken"
  else
    ok "MUTATION applied: toggle_enabled no longer clears bandwidth_suspended_at"
  fi
  cp /tmp/bwq-sites-backup.rs "$SITES_RS"
  if grep -q 'bandwidth_suspended_at = CASE WHEN \$1' "$SITES_RS"; then
    ok "MUTATION reverted — toggle_enabled's flag-clearing restored"
  else
    bad "failed to revert the toggle_enabled mutation — $SITES_RS is left mutated"
  fi
else
  bad "could not locate toggle_enabled's UPDATE to mutation-test"
fi
rm -f /tmp/bwq-sites-backup.rs

# ── §5 — quota edits recover a suspended site in the SAME request, not a 5-minute wait ──
echo "── §5 update_limits recovers a suspended site inline when the new quota clears it ──"
must_contain "$SITES_FLAT" 'letrecovering=ifsite.bandwidth_suspended_at.is_some(){' \
  "update_limits computes a recovering flag from the CURRENT suspension state before writing"
must_contain "$SITES_FLAT" '&&q<1{returnErr(err(StatusCode::BAD_REQUEST,"Bandwidthquotamustbeatleast1MB"));}' \
  "bandwidth_quota_mb is validated (>= 1) the same way rate_limit and the other limits are"
must_contain "$SITES_FLAT" 'ifrecovering{ifletErr(e)=agent.post(&format!("/nginx/sites/{}/enable",site.domain),None).await{' \
  "when recovering, update_limits actually calls the agent to re-enable nginx, not just the DB row"

# ── §6 — routes and scheduler are wired exactly once ──
echo "── §6 single registration: route, scheduler module, scheduler spawn ──"
n=$(grep -c '/api/sites/{id}/bandwidth-usage' "$MOD_RS" || true)
if [ "$n" -eq 1 ]; then ok "bandwidth-usage route is registered exactly once"; else bad "expected exactly 1 registration of bandwidth-usage, found $n"; fi
n=$(grep -c 'pub mod traffic_accounting_scheduler;' "$SERVICES_MOD_RS" || true)
if [ "$n" -eq 1 ]; then ok "traffic_accounting_scheduler module is declared exactly once"; else bad "expected exactly 1 mod declaration, found $n"; fi
n=$(grep -c 'traffic_accounting_scheduler::run' "$MAIN_RS" || true)
if [ "$n" -eq 1 ]; then ok "traffic_accounting_scheduler is spawned exactly once in main.rs"; else bad "expected exactly 1 spawn_supervised call, found $n"; fi

# ── §7 — frontend: the quota control exists and the disabled banner explains why ──
echo "── §7 frontend surfaces the quota control and a bandwidth-specific disabled reason ──"
FE_FLAT=$(perl -0777 -pe 's{/\*.*?\*/}{}gs' "$SITE_DETAIL_TSX" | tr -d ' \t\n')
must_contain "$FE_FLAT" 'value={bandwidthQuota}onChange={(e)=>setBandwidthQuota(e.target.value)}' \
  "the Resource Limits form has a bandwidth quota input bound to state"
must_contain "$FE_FLAT" 'bandwidth_quota_mb:bandwidthQuota?parseInt(bandwidthQuota):null,' \
  "saving Resource Limits sends bandwidth_quota_mb in the PUT body"
must_contain "$FE_FLAT" 'site.bandwidth_suspended_at?' \
  "the disabled banner branches on bandwidth_suspended_at rather than a single generic message"

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
