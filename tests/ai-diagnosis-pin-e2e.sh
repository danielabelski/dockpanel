#!/usr/bin/env bash
# Regression pin for AI-ASSISTED BUILD/DEPLOY FAILURE DIAGNOSIS.
#
# BYO-API-key (Anthropic/OpenAI/Gemini/Grok) root-cause explanation for a
# failed Git Deploy history entry. Off by default, and — this is the
# invariant this suite exists to protect — triggered ONLY by a manual click
# from the Git Deploys history panel. Nothing calls the LLM on a schedule, on
# every failure automatically, or from any code path but the one endpoint an
# operator's own click reaches. A failed build's own output is exactly where
# a leaked env var, DB password, or deploy-key private key ends up printed,
# and that text leaves the box for a third party the operator chose — so this
# suite also pins that redaction runs unconditionally, with no setting that
# turns it off, and that the stored API key is encrypted at rest through the
# same mechanism as every other integration credential in this codebase
# (pdns_api_key, CDN tokens), not a new one invented for this feature.
#
# Pure source analysis: no box, no network, no build, no LLM API calls. The
# redaction regexes' actual matching behavior is covered by
# `cargo test ai_diagnosis` (6 unit tests) in panel/backend/src/services/
# ai_diagnosis.rs — this suite pins the WIRING around them, not the regexes
# themselves.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

BE=panel/backend/src
FE=panel/frontend/src
SETTINGS_RS=$BE/routes/settings.rs
AI_RS=$BE/services/ai_diagnosis.rs
GIT_DEPLOYS_RS=$BE/routes/git_deploys.rs
MOD_RS=$BE/routes/mod.rs
GIT_DEPLOYS_TSX=$FE/pages/GitDeploys.tsx
SETTINGS_TSX=$FE/pages/Settings.tsx

for f in "$SETTINGS_RS" "$AI_RS" "$GIT_DEPLOYS_RS" "$MOD_RS" "$GIT_DEPLOYS_TSX" "$SETTINGS_TSX"; do
  [ -f "$f" ] || { echo "missing file: $f"; exit 1; }
done

# Whitespace-insensitive substring check, same idiom as
# resource-mutation-audit-log-pin-e2e.sh — a boolean `grep -q` at the end of a
# pipeline under `set -o pipefail` SIGPIPEs the producer and reports failure
# for a successful match; this avoids that class entirely.
must_contain() {
  local flat="$1" needle="$2" desc="$3"
  local flat_needle
  flat_needle=$(printf '%s' "$needle" | tr -d ' \t\n')
  case "$flat" in
    *"$flat_needle"*) ok "$desc" ;;
    *) bad "$desc — pattern not found (whitespace-insensitive): $needle" ;;
  esac
}

AI_FLAT=$(tr -d ' \t\n' < "$AI_RS")
SETTINGS_FLAT=$(tr -d ' \t\n' < "$SETTINGS_RS")
GD_FLAT=$(tr -d ' \t\n' < "$GIT_DEPLOYS_RS")

# ── §1 — off by default, and configured the same way every other setting is ──
echo "── §1 the four settings exist, writable, and the key is encrypted ──"
for k in ai_diagnosis_enabled ai_diagnosis_provider ai_diagnosis_model ai_diagnosis_api_key; do
  n=$(sed -n '/pub const ALLOWED_KEYS/,/^\];/p' "$SETTINGS_RS" | grep -cF "\"$k\"" || true)
  if [ "$n" -gt 0 ]; then ok "$k is in ALLOWED_KEYS"; else bad "$k missing from ALLOWED_KEYS — not settable from the panel"; fi
done
must_contain "$SETTINGS_FLAT" 'pub(crate)constSENSITIVE_KEYS:&[&str]=&["smtp_password","pdns_api_key","ai_diagnosis_api_key"];' \
  "ai_diagnosis_api_key is encrypted at rest via the same SENSITIVE_KEYS list as pdns_api_key"

# A regression this suite exists to catch: `list()` used to hardcode five
# exact key-name comparisons for GET-response masking, independently of
# SENSITIVE_KEYS. A key added to SENSITIVE_KEYS alone would then round-trip
# as raw ciphertext instead of "********" — and a future save could resubmit
# that ciphertext as if it were a real key, corrupting the stored credential.
must_contain "$SETTINGS_FLAT" 'fnis_sensitive_key(key:&str)->bool{SENSITIVE_KEYS.contains(&key)||key.ends_with("_client_secret")}' \
  "list()/update()/import_config() share one is_sensitive_key predicate, not a hand-copied mask list"
n_hardcoded=$(grep -cE 'r\.key == "smtp_password" \|\| r\.key == "pdns_api_key"' "$SETTINGS_RS" || true)
if [ "$n_hardcoded" -eq 0 ]; then
  ok "the old 5-name hardcoded mask list in list() is gone"
else
  bad "list() still hand-lists sensitive key names — a key added to SENSITIVE_KEYS alone will leak ciphertext on GET"
fi

REENCRYPT_RS=$BE/services/credential_reencrypt.rs
must_contain "$(tr -d ' \t\n' < "$REENCRYPT_RS")" "'ai_diagnosis_api_key'" \
  "SENSITIVE_SETTINGS_SQL (credential_reencrypt.rs) covers ai_diagnosis_api_key, so a re-key sweep rotates it too"

# ── §2 — the feature is gated off, and the gate is checked before any network call ──
echo "── §2 default-off gate is load-bearing ──"
must_contain "$AI_FLAT" 'if get("ai_diagnosis_enabled")!="true"{returnOk(None);}' \
  "load_config refuses to return a usable config unless ai_diagnosis_enabled == \"true\""
must_contain "$AI_FLAT" 'ifprovider.is_empty()||model.is_empty()||api_key_enc.is_empty(){returnOk(None);}' \
  "load_config also refuses when provider/model/key are incomplete, not just when disabled"
must_contain "$GD_FLAT" 'let config=crate::services::ai_diagnosis::load_config(&state.db,&state.config.jwt_secret).await?.ok_or_else(||{err(StatusCode::BAD_REQUEST,"AIdiagnosisisnotconfigured.SetaproviderandAPIkeyinSettings→Services.",)})?;' \
  "explain_history refuses with a clear message when AI diagnosis is not configured, rather than calling a provider with an empty key"

# ── §3 — manual trigger only: exactly one call site, exactly one route ──
echo "── §3 nothing calls the LLM except the one operator-triggered endpoint ──"
call_sites=$(grep -rho 'ai_diagnosis::explain_failure(' --include=*.rs "$BE" | wc -l | tr -d ' ')
if [ "$call_sites" -eq 1 ]; then
  ok "ai_diagnosis::explain_failure has exactly 1 call site (no auto-trigger path)"
else
  bad "ai_diagnosis::explain_failure has $call_sites call sites — expected exactly 1 (a new site may be an auto-trigger, spending the operator's credits without a click)"
fi
route_sites=$(grep -c '/history/{history_id}/explain' "$MOD_RS" || true)
if [ "$route_sites" -eq 1 ]; then
  ok "the explain route is registered exactly once"
else
  bad "expected exactly 1 registration of the explain route, found $route_sites"
fi
must_contain "$GD_FLAT" 'require_admin(&claims.role)?;letdeploy:(Uuid,String)=sqlx::query_as("SELECTid,nameFROMgit_deploysWHEREid=$1ANDuser_id=$2",)' \
  "explain_history requires admin and scopes the git_deploy lookup to the caller's own user_id"
must_contain "$GD_FLAT" 'ifentry.status!="failed"{returnErr(err(StatusCode::BAD_REQUEST,"Onlyfaileddeployscanbeexplained",));}' \
  "explain_history refuses to run on anything but a failed deploy"

# ── §4 — redaction runs unconditionally, before truncation, before the network call ──
echo "── §4 redaction is unconditional, not a setting ──"
must_contain "$AI_FLAT" 'fnbuild_prompt(ctx:&FailureContext)->String{letredacted=redact(&ctx.output);' \
  "build_prompt redacts ctx.output before anything else touches it"
# No setting can disable it: redact() must not consult the settings table at all.
if grep -q 'fn redact(' "$AI_RS"; then
  REDACT_BODY=$(awk '/^fn redact\(/,/^}/' "$AI_RS")
  case "$REDACT_BODY" in
    *settings*) bad "redact() references settings — check whether redaction can be disabled" ;;
    *) ok "redact() takes no settings input — there is no switch that can turn it off" ;;
  esac
else
  bad "redact() function not found in $AI_RS"
fi
for pattern_name in "PASSWORD|SECRET|TOKEN" "Bearer" "PRIVATE KEY"; do
  n=$(grep -c "$pattern_name" "$AI_RS" || true)
  if [ "$n" -gt 0 ]; then ok "redaction covers the \"$pattern_name\" shape"; else bad "redaction pattern for \"$pattern_name\" is missing"; fi
done
must_contain "$AI_FLAT" 'constMAX_OUTPUT_CHARS:usize=8000;' "output is truncated to a bounded size before it reaches any provider"

# ── §5 — the frontend button only appears on a failed entry, and never auto-fires ──
echo "── §5 frontend: manual button, gated on failed status ──"
FE_GD_FLAT=$(perl -0777 -pe 's{/\*.*?\*/}{}gs' "$GIT_DEPLOYS_TSX" | tr -d ' \t\n')
must_contain "$FE_GD_FLAT" 'entry.status==="failed"&&(<button' \
  "the Explain with AI button is gated on entry.status === \"failed\""
must_contain "$FE_GD_FLAT" 'onClick={(e)=>{e.stopPropagation();setExpandedLog(entry.id);explainWithAi(entry.id);}}' \
  "the button calls explainWithAi only from an explicit onClick, not an effect"
n_auto=$(grep -cE 'useEffect\(.*explainWithAi' "$GIT_DEPLOYS_TSX" || true)
if [ "$n_auto" -eq 0 ]; then
  ok "explainWithAi is never called from a useEffect (no fire-on-load/fire-on-render path)"
else
  bad "explainWithAi is referenced inside a useEffect — it may fire without a click"
fi

# ── §6 — the settings control actually sends the keys (§9 shape, this feature only) ──
echo "── §6 the Settings.tsx control sends all four keys ──"
FE_SET_FLAT=$(perl -0777 -pe 's{/\*.*?\*/}{}gs' "$SETTINGS_TSX" | tr -d ' \t\n')
for k in ai_diagnosis_enabled ai_diagnosis_provider ai_diagnosis_model; do
  must_contain "$FE_SET_FLAT" "$k:" "Settings.tsx's AI diagnosis card sets $k in the PUT body on save"
done
must_contain "$FE_SET_FLAT" "body.ai_diagnosis_api_key" "Settings.tsx's AI diagnosis card sets body.ai_diagnosis_api_key on save"
must_contain "$FE_SET_FLAT" 'if(apiKey&&apiKey!=="********"){body.ai_diagnosis_api_key=apiKey;}' \
  "the API key field guards against resubmitting the GET-response mask sentinel"

echo
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
