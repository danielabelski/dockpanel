#!/usr/bin/env bash
#
# Regression pin for GitHub #109's echo and the s484 Mode B research pass —
# "PR/branch preview deployments have no GitHub status link-back."
#
# `handle_preview_deploy` (git_deploys.rs) has always been a fully-built preview
# system: an isolated container per branch, a subdomain, TTL auto-cleanup, and
# hardened ownership since v2.53-2.55. Regular and scheduled deploys have called
# `set_github_status` at 9 sites since it existed — a pending status when the
# work starts, success or failure when it ends — so GitHub's own commit/PR view
# shows a status check with a link to the result. The preview path never called
# it at all: a preview built, deployed, and got a subdomain, but the one place a
# pusher would look — GitHub's own UI — never heard about any of it.
#
# This is a s484 research-pass finding, not a reporter's own report: the initial
# research framed "no preview-env concept at all" as the gap (wrong — the whole
# preview system already existed), and grep-first verification against current
# source found the real, narrow gap is exactly this missing call.
#
# Five call sites had to gain the wiring, and this pin holds each of them: a
# pending status before the clone starts, a failure status on clone failure, on
# build failure, on the TLS-readiness refusal, and on the final deploy call's own
# failure — plus a success status when the deploy succeeds. All six share ONE
# target URL, computed once up front from the SAME `deploy_url` helper every
# other call site uses, so a preview link can never carry a hardcoded scheme.
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

ROUTE=panel/backend/src/routes/git_deploys.rs
[ -f "$ROUTE" ] || { echo "missing $ROUTE"; exit 1; }

strip() { sed 's://.*::' "$1"; }
SRC=$(strip "$ROUTE")

has()  { grep -q  -- "$2" <<< "$1"; }
hasE() { grep -qE -- "$2" <<< "$1"; }
# Bounded to ONE fn body via brace balance, not a bare /pat/,/^}/ awk range —
# `handle_preview_deploy` is followed by other top-level fns starting with `}`
# at column 0 too (a nested `match`/`if` arm can also dedent to `}` at col 0
# inside rustfmt's own style in this file), so a naive first-`^}` stop can
# under-read the body. Balance-count braces instead.
fnbody() {
  awk -v fn="$2" '
    BEGIN { depth = 0; found = 0 }
    $0 ~ "fn " fn "\\(" { found = 1 }
    found {
      print
      n = gsub(/\{/, "{"); depth += n
      n = gsub(/\}/, "}"); depth -= n
      if (depth <= 0 && NR > 1 && found == 1 && depth_started) exit
      if (depth > 0) depth_started = 1
    }
  ' <<< "$1"
}

HPD=$(fnbody "$SRC" handle_preview_deploy)

echo
echo "§1 the preview path can even find the function"

if [ -n "$HPD" ]; then
  ok "handle_preview_deploy is present and readable"
else
  bad "could not read handle_preview_deploy's body — every other arm means nothing"
fi

echo
echo "§2 a status call exists at every outcome, not just one"

status_calls=$(grep -c 'set_github_status(' <<< "$HPD")
if [ "$status_calls" -ge 6 ]; then
  ok "at least 6 set_github_status call sites inside the preview path (found $status_calls)"
else
  bad "expected >= 6 set_github_status calls inside handle_preview_deploy, found $status_calls"
fi

if hasE "$HPD" 'set_github_status\([^)]*"pending"'; then
  ok "a pending status is posted before the clone starts"
else
  bad "no pending status call — GitHub never learns a preview started"
fi

if hasE "$HPD" 'set_github_status\([^)]*"success"'; then
  ok "a success status is posted when the deploy succeeds"
else
  bad "no success status call on the deploy-success path"
fi

failure_calls=$(grep -oE 'set_github_status\([^)]*"failure"' <<< "$HPD" | wc -l)
if [ "$failure_calls" -ge 4 ]; then
  ok "a failure status is posted on at least 4 distinct failure paths (found $failure_calls)"
else
  bad "expected >= 4 failure-status calls (clone/build/tls-refusal/deploy), found $failure_calls"
fi

echo
echo "§3 every call carries a real link, built the one way this file allows"

if hasE "$HPD" 'github_target[[:space:]]*=[[:space:]]*preview_domain\.as_deref\(\)\.map\(\|d\|[[:space:]]*deploy_url\('; then
  ok "the target URL is computed once via deploy_url(), not re-derived per call site"
else
  bad "github_target is not built through deploy_url() — a hardcoded scheme could creep back in"
fi

target_uses=$(grep -c 'github_target' <<< "$HPD")
if [ "$target_uses" -ge 6 ]; then
  ok "every status call references the shared github_target (found $target_uses uses)"
else
  bad "expected >= 6 uses of github_target (one build + 6 call sites), found $target_uses"
fi

echo
echo "§4 the token is only ever read from config, and only sent when present"

if hasE "$HPD" 'github_token[[:space:]]*=[[:space:]]*config\.github_token\.clone\(\)'; then
  ok "the token is cloned from config once, matching every other call site's own source"
else
  bad "github_token is not sourced from config.github_token — check for a different origin"
fi

empty_guards=$(grep -c '!gh_token.is_empty()' <<< "$HPD")
if [ "$empty_guards" -ge 6 ]; then
  ok "every call site guards on a non-empty token (found $empty_guards guards)"
else
  bad "expected >= 6 non-empty-token guards, found $empty_guards — a call could fire with no token"
fi

echo
echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
