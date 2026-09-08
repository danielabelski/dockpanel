#!/usr/bin/env bash
#
# Regression pin for the s484 Mode B research pass — "fetch a migration archive
# by URL instead of requiring the operator SFTP it up first."
#
# Before this, `Migration.tsx` told the operator to upload the backup via SFTP
# and paste the resulting path — `analyze()` required `body.path` to already
# exist on the server's disk, full stop. This adds a URL-fetch alternative: the
# AGENT downloads the archive itself into the one subtree it can actually write
# (`/var/backups/dockpanel/migration-fetch/`, NOT the bare `/var/backups/` an
# operator-copied archive can otherwise live anywhere under — a new path outside
# a granted `ReadWritePaths` entry is the exact EROFS class the per-site SFTP
# jail hit), then analysis proceeds exactly as it always did.
#
# A URL a panel admin can point anywhere is a real SSRF surface, so this pin
# holds the safety properties as tightly as the plumbing: the URL is
# scheme-restricted AND SSRF-guarded, the destination is traversal-checked AND
# confined to the one writable subtree, the download is size-capped on BOTH the
# declared Content-Length and the actual streamed byte count (a lying header
# must not be trusted alone), and a partial/oversized download is never mistaken
# for a complete archive (`.part` + rename-on-success only).
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

BACKEND_ROUTE=panel/backend/src/routes/migration.rs
AGENT_ROUTE=panel/agent/src/routes/migration.rs
AGENT_SVC=panel/agent/src/services/migration.rs
TSX=panel/frontend/src/pages/Migration.tsx
for f in "$BACKEND_ROUTE" "$AGENT_ROUTE" "$AGENT_SVC" "$TSX"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done

# NOT the naive `sed 's://.*::'` this repo's other pins use — this file's own
# subject lines contain `"http://"` / `"https://"` string literals, and that
# stripper treats ANY `//` as a comment marker with no regard for what is
# inside a string. It would truncate `if !(u.starts_with("http:` right there,
# silently deleting the rest of the scheme check this suite exists to hold.
# Only strip a `//` NOT immediately preceded by `:` (a real line comment is
# preceded by whitespace or code, never a bare colon) — and handle a comment
# that starts the line with zero indentation as its own case.
strip() { sed -E 's#^//.*$##; s#([^:])//.*#\1#' "$1"; }
SRC_BACKEND=$(strip "$BACKEND_ROUTE")
SRC_AROUTE=$(strip "$AGENT_ROUTE")
SRC_ASVC=$(strip "$AGENT_SVC")
SRC_TSX=$(strip "$TSX")

has()  { grep -q  -- "$2" <<< "$1"; }
hasE() { grep -qE -- "$2" <<< "$1"; }
fnbody() { awk "/(pub )?(async )?fn $2\(/,/^}/" <<< "$1"; }

ANALYZE=$(fnbody "$SRC_BACKEND" analyze)
FETCH_ROUTE=$(fnbody "$SRC_AROUTE" fetch)
FETCH_SVC=$(fnbody "$SRC_ASVC" fetch_archive)

echo
echo "§1 the request accepts a URL, and enforces path XOR url"

if hasE "$SRC_BACKEND" 'pub url: Option<String>'; then
  ok "AnalyzeRequest carries an optional url field"
else
  bad "AnalyzeRequest has no url field — the frontend has nothing to send"
fi

if has "$ANALYZE" 'path.is_empty() && url.is_none()'; then
  ok "analyze rejects the request when NEITHER path nor url is given"
else
  bad "no empty-both guard — a request with neither field could slip through"
fi

if hasE "$ANALYZE" '!path\.is_empty\(\) && url\.is_some\(\)'; then
  ok "analyze rejects the request when BOTH path and url are given"
else
  bad "no both-given guard — ambiguous requests are not rejected"
fi

if hasE "$ANALYZE" 'u\.starts_with\("http://"\) \|\| u\.starts_with\("https://"\)'; then
  ok "the URL is scheme-restricted to http/https on the panel side"
else
  bad "no scheme check on the panel side — any URI scheme could be accepted"
fi

echo
echo "§2 the destination is deterministic and confined before the agent ever sees it"

if hasE "$ANALYZE" '/var/backups/dockpanel/migration-fetch/'; then
  ok "the resolved path is computed under the agent's one writable migration subtree"
else
  bad "resolved_path does not target /var/backups/dockpanel/migration-fetch/"
fi

if hasE "$ANALYZE" 'Uuid::new_v4\(\)'; then
  ok "the destination filename is a fresh UUID, not derived from user input"
else
  bad "the destination filename is not UUID-derived — a URL-controlled name could inject a path"
fi

echo
echo "§3 the agent's fetch route re-validates independently — it does not trust the caller"

if [ -n "$FETCH_ROUTE" ]; then
  ok "the agent's /migration/fetch handler is present and readable"
else
  bad "could not read the agent fetch handler — the arms below mean nothing"
fi

if hasE "$FETCH_ROUTE" 'url\.starts_with\("http://"\) \|\| url\.starts_with\("https://"\)'; then
  ok "the agent independently re-checks the URL scheme"
else
  bad "the agent trusts the panel's scheme check instead of re-validating — defense in depth is gone"
fi

if has "$FETCH_ROUTE" 'ssrf_guard::validate_repo_url_not_internal'; then
  ok "the agent SSRF-guards the host at the point it actually dials it"
else
  bad "no ssrf_guard call — an admin-supplied URL could reach an internal address"
fi

if hasE "$FETCH_ROUTE" 'dest\.contains\("\.\."\)'; then
  ok "the destination is checked for path traversal"
else
  bad "no traversal check on dest"
fi

if has "$FETCH_ROUTE" 'migration::FETCH_DIR'; then
  ok "the destination is confined to FETCH_DIR via the shared constant, not a re-typed literal"
else
  bad "the allowed-directory check does not reference the shared FETCH_DIR constant"
fi

echo
echo "§4 the download is capped on both the declared AND the actual size, and lands atomically"

if hasE "$FETCH_SVC" 'MAX_FETCH_BYTES'; then
  ok "a size cap constant exists"
else
  bad "no MAX_FETCH_BYTES constant — nothing bounds a fetched archive's size"
fi

if hasE "$FETCH_SVC" 'content_length\(\)'; then
  ok "the declared Content-Length is checked before streaming begins"
else
  bad "no content_length() check — an obviously-oversized response isn't rejected early"
fi

if hasE "$FETCH_SVC" 'written[[:space:]]*>[[:space:]]*MAX_FETCH_BYTES'; then
  ok "the ACTUAL streamed byte count is also checked, not just the declared header"
else
  bad "no streamed-byte-count check — a lying or absent Content-Length bypasses the cap entirely"
fi

if hasE "$FETCH_SVC" '\{dest\}\.part'; then
  ok "the download writes to a .part sibling first"
else
  bad "no .part staging file — a crash or a cap trip could leave a truncated file at the real path"
fi

if hasE "$FETCH_SVC" 'tokio::fs::rename\(&part_path, dest\)'; then
  ok "the .part file is renamed into place only after the full response lands"
else
  bad "no rename-on-success — analyze() could be pointed at a file that never finished downloading"
fi

if hasE "$FETCH_SVC" 'remove_file\(&part_path\)'; then
  ok "an over-cap download removes its own partial file rather than leaving it on disk"
else
  bad "a cap trip does not clean up the partial file"
fi

echo
echo "§5 a fetch failure is recorded the same honest way an analyze failure already is"

if hasE "$SRC_BACKEND" "status = 'failed'.*Could not fetch the archive" || hasE "$SRC_BACKEND" 'Could not fetch the archive'; then
  ok "a fetch failure writes a real reason into the migrations row"
else
  bad "no distinct fetch-failure message — the operator would see a generic or absent reason"
fi

if hasE "$SRC_BACKEND" 'if let Some\(fetch_url\) = url'; then
  ok "the fetch step runs before analyze, inside the same spawned task"
else
  bad "no url-gated fetch step found ahead of the analyze call"
fi

echo
echo "§6 the frontend offers both paths and sends exactly one field"

if hasE "$SRC_TSX" 'inputMode === "path" \? \{ path: trimmedPath \} : \{ url: trimmedUrl \}'; then
  ok "the frontend sends path OR url based on the selected mode, never both"
else
  bad "the frontend request body does not branch on inputMode the expected way"
fi

if has "$SRC_TSX" 'Fetch from URL'; then
  ok "the URL-fetch mode is offered in the UI"
else
  bad "no 'Fetch from URL' control in Migration.tsx"
fi

echo
echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
