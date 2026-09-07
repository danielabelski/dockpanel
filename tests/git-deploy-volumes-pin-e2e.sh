#!/usr/bin/env bash
#
# Regression pin for GIT DEPLOY PERSISTENT VOLUMES (#118).
#
# WHAT HAPPENED. A Git Deploy container got no volume and no bind mount, and
# every deploy replaced the container — so anything the app wrote to its own
# filesystem (uploads, a SQLite database, a cache) was destroyed on the NEXT
# deploy. The failure was silent and delayed: everything worked until the
# second deploy, by which point the loss looked unrelated. Reported as a real
# data-loss incident, not a feature request.
#
# WHY THE FIX WAS BIGGER THAN A FIELD. The header that carried this as unbuilt
# work (`panel/agent/src/services/git_build.rs`) named six constraints, and
# each one is a distinct way a naive patch destroys data rather than saving
# it:
#
#   1. TWO `HostConfig` literals exist in this file (base + blue-green). Binds
#      added to only one mount on deploy and UN-mount on the next blue-green
#      update.
#   2. Blue-green runs the old and new container against the SAME host paths
#      for the length of a health check — silent corruption for a
#      single-writer database like SQLite. Any declared volume must force the
#      slower stop/recreate path instead.
#   3. Preview environments must NEVER inherit volumes — a throwaway PR
#      container gaining durable storage defeats the point of "throwaway".
#   4. Delete-time cleanup must derive what to remove from the container's
#      OWN binds (read before it is removed), never from its name alone — a
#      name match is not proof of ownership, the exact class of bug
#      `docker_apps::owned_app_dir` exists to prevent.
#   5. The field is container-path only, host side derived — a free-form
#      host path would be a container-escape surface under this agent's
#      `ProtectSystem=strict` sandbox.
#   6. A deploy that ADDS a volume to an already-running container must
#      rescue whatever is already sitting in that container's writable
#      layer before the recreate deletes it — the exact shape of #110,
#      generalised from `docker_apps::migrate_unmounted_volumes`.
#
# Ship 1-5 without 6 and the FIRST deploy after the fix destroys the files
# the fix exists to save. Pure source analysis: no box, no network, no build,
# no Docker daemon.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[0;32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[0;31m✗\033[0m %s\n' "$1"; }

GIT_SVC=panel/agent/src/services/git_build.rs
GIT_ROUTE=panel/agent/src/routes/git_build.rs
APPS_SVC=panel/agent/src/services/docker_apps.rs
BACKEND=panel/backend/src/routes/git_deploys.rs
for f in "$GIT_SVC" "$GIT_ROUTE" "$APPS_SVC" "$BACKEND"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done

# Strip line comments only — a block-comment stripper is what deleted 485 lines
# of real code until s294 (lesson #384/#391 territory); this deliberately does
# the narrow, safe thing.
code() { sed 's://.*$::' "$1"; }

SVC_CODE=$(code "$GIT_SVC")
SVC_FLAT=$(printf '%s' "$SVC_CODE" | tr -d ' \t\n')
ROUTE_CODE=$(code "$GIT_ROUTE")
ROUTE_FLAT=$(printf '%s' "$ROUTE_CODE" | tr -d ' \t\n')
APPS_CODE=$(code "$APPS_SVC")
APPS_FLAT=$(printf '%s' "$APPS_CODE" | tr -d ' \t\n')
BACKEND_CODE=$(code "$BACKEND")
BACKEND_FLAT=$(printf '%s' "$BACKEND_CODE" | tr -d ' \t\n')

echo "§0 the subjects parse (a truncated subject must not read as a clean sweep)"

for pair in "GIT_SVC:deploy_or_update" "GIT_SVC:cleanup_container" "GIT_ROUTE:deploy_container" "BACKEND:build_deploy_body"; do
  var="${pair%%:*}"; needle="${pair##*:}"
  case "$var" in
    GIT_SVC) hay="$SVC_FLAT" ;;
    GIT_ROUTE) hay="$ROUTE_FLAT" ;;
    BACKEND) hay="$BACKEND_FLAT" ;;
  esac
  case "$hay" in
    *"fn${needle}"*) ok "$needle is still defined in $var" ;;
    *) bad "$needle is MISSING from $var — every arm below is meaningless" ;;
  esac
done

echo
echo "§1 fresh deploy: binds are built under GIT_DATA_DIR, create -> canonicalize -> verify -> seed -> chown"

case "$SVC_FLAT" in
  *'letresolved_str=resolved.to_string_lossy().to_string();if!resolved_str.starts_with(&format!("{GIT_DATA_DIR}/")){'*)
    ok "the fresh-deploy path checks the canonicalised prefix against GIT_DATA_DIR" ;;
  *) bad "the fresh-deploy prefix check against GIT_DATA_DIR is missing or reordered" ;;
esac

CREATE_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'std::fs::create_dir_all(&host_dir)' | head -1 | cut -d: -f1)
CANON_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'std::fs::canonicalize(&host_dir)' | head -1 | cut -d: -f1)
ESCAPE_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'escapes allowed prefix' | head -1 | cut -d: -f1)
SEED_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'seed_volume_from_image(docker, image, vol' | head -1 | cut -d: -f1)
CHOWN_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'chown_to(&resolved_str, owner)' | head -1 | cut -d: -f1)
if [ -n "$CREATE_AT" ] && [ -n "$CANON_AT" ] && [ -n "$ESCAPE_AT" ] && [ -n "$SEED_AT" ] && [ -n "$CHOWN_AT" ] \
   && [ "$CANON_AT" -gt "$CREATE_AT" ] && [ "$ESCAPE_AT" -gt "$CANON_AT" ] \
   && [ "$SEED_AT" -gt "$ESCAPE_AT" ] && [ "$CHOWN_AT" -gt "$ESCAPE_AT" ]; then
  ok "create -> canonicalize -> prefix-check -> seed/chown, in that order"
else
  bad "ordering broken (create=$CREATE_AT canon=$CANON_AT escape=$ESCAPE_AT seed=$SEED_AT chown=$CHOWN_AT)"
fi

case "$SVC_FLAT" in
  *'super::docker_apps::seed_volume_from_image(docker,image,vol,&resolved_str).await;'*)
    ok "a fresh volume is seeded from the image's own shipped files" ;;
  *) bad "seed_volume_from_image is not called on the fresh-deploy path" ;;
esac

echo
echo "§2 blue-green is refused for ANY deploy with a declared volume"

case "$SVC_FLAT" in
  *'ifhas_nginx&&volumes.is_empty(){'*)
    ok "blue-green requires has_nginx AND an empty volumes list" ;;
  *) bad "blue-green's gate no longer checks volumes.is_empty() — the SQLite-corruption guard is gone" ;;
esac

# Positive control on the pin itself: the OLD gate (has_nginx alone) must not
# also satisfy the check above by coincidence.
case "$SVC_FLAT" in
  *'ifhas_nginx{letbg_domain'*)
    bad "an UNGUARDED 'if has_nginx {' immediately preceding the blue-green call still exists" ;;
  *) ok "no unguarded has_nginx branch precedes the blue-green call" ;;
esac

echo
echo "§3 an existing container's binds are read before deciding, and a newly added path is migrated before removal"

case "$SVC_FLAT" in
  *'letexisting_binds:Vec<String>=docker.inspect_container(&container_id,None).await.ok().and_then(|info|info.host_config).and_then(|hc|hc.binds).unwrap_or_default();'*)
    ok "the OLD container's binds are read via a fresh inspect" ;;
  *) bad "the existing container's binds are no longer inspected before recreate" ;;
esac

# A cleared/edited volumes list must filter the OLD binds down to what is still
# declared — dropping this filter would carry a REMOVED path's bind forward
# forever, or (the more dangerous direction) leak a stale bind whose directory
# no longer matches what the operator asked for.
case "$SVC_FLAT" in
  *'declared.contains(&dest)'*)
    ok "kept binds are filtered against the CURRENTLY declared volumes list" ;;
  *) bad "old binds are no longer filtered against the current volumes list" ;;
esac

MIGRATE_CALL_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'super::docker_apps::migrate_unmounted_volumes(' | head -1 | cut -d: -f1)
REMOVE_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'RemoveContainerOptions' | awk -F: '$1 > '"${MIGRATE_CALL_AT:-999999}"' {print $1; exit}')
STOP_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'stop_container(&container_id, Some(StopContainerOptions' | head -1 | cut -d: -f1)
if [ -n "$STOP_AT" ] && [ -n "$MIGRATE_CALL_AT" ] && [ -n "$REMOVE_AT" ] \
   && [ "$MIGRATE_CALL_AT" -gt "$STOP_AT" ] && [ "$REMOVE_AT" -gt "$MIGRATE_CALL_AT" ]; then
  ok "migration runs AFTER stop and BEFORE remove (line $STOP_AT < $MIGRATE_CALL_AT < $REMOVE_AT)"
else
  bad "migration is not sandwiched between stop and remove (stop=$STOP_AT migrate=$MIGRATE_CALL_AT remove=$REMOVE_AT)"
fi

case "$SVC_FLAT" in
  *'migrate_unmounted_volumes(GIT_DATA_DIR,&docker,&container_id,name,image_tag,&unmounted,&mutmigrate_config,'*)
    ok "migration targets GIT_DATA_DIR, not APP_DATA_DIR" ;;
  *) bad "the git-deploy migration call no longer targets GIT_DATA_DIR" ;;
esac

case "$SVC_FLAT" in
  *'returnErr(format!("Abortingdeployof{name}withoutremovingtherunningcontainer:'*)
    ok "a migration failure ABORTS before remove_container ever runs" ;;
  *) bad "a migration failure no longer aborts the recreate — #118's own regression risk" ;;
esac

echo
echo "§4 delete-time cleanup derives the volume directory from the container's OWN binds, never the name alone"

case "$SVC_FLAT" in
  *'fnowned_git_data_dir(name:&str,binds:&[String])->Option<String>{'*)
    ok "owned_git_data_dir exists as its own ownership-proof function" ;;
  *) bad "owned_git_data_dir is missing — cleanup would have to guess the path from the name" ;;
esac

INSPECT_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'inspect_container(&container_name, None).await' | head -1 | cut -d: -f1)
OWNED_CALL_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'owned_git_data_dir(name' | head -1 | cut -d: -f1)
CLEANUP_REMOVE_AT=$(printf '%s\n' "$SVC_CODE" | grep -n 'Removed git container' | head -1 | cut -d: -f1)
if [ -n "$INSPECT_AT" ] && [ -n "$OWNED_CALL_AT" ] && [ -n "$CLEANUP_REMOVE_AT" ] \
   && [ "$OWNED_CALL_AT" -gt "$INSPECT_AT" ] && [ "$OWNED_CALL_AT" -lt "$CLEANUP_REMOVE_AT" ]; then
  ok "ownership is captured in the PRE-removal inspect, before the container is gone"
else
  bad "ownership capture is not positioned before removal (inspect=$INSPECT_AT owned=$OWNED_CALL_AT remove=$CLEANUP_REMOVE_AT)"
fi

# The "container already missing" arm must NOT guess a directory from the name
# — that is precisely the cross-tenant-delete shape #4 exists to close.
NONE_ARM=$(printf '%s\n' "$SVC_CODE" | grep -A4 'Err(_) => (')
NONE_ARM_FLAT=$(printf '%s' "$NONE_ARM" | tr -d ' \t\n')
case "$NONE_ARM_FLAT" in
  *'known_domain.map(str::to_string),known_port,None,'*)
    ok "the container-missing arm answers None for the volume dir, not a name-derived guess" ;;
  *) bad "the container-missing arm no longer answers None for the volume dir" ;;
esac

echo
echo "§5 previews are refused a volumes list at the AGENT boundary, not just by backend convention"

case "$ROUTE_FLAT" in
  *'ifscope!=ownership::GitScope::Deploy&&!body.volumes.is_empty(){'*)
    ok "the agent route itself refuses volumes for any scope but Deploy" ;;
  *) bad "the agent no longer enforces the preview/volumes exclusion — a backend bug would be the only thing left standing between a preview and durable storage" ;;
esac

case "$BACKEND_FLAT" in
  *'volumes:&[],'*)
    ok "the backend's own preview deploy call site passes an empty volumes slice"
    ;;
  *) bad "no preview call site in the backend passes an explicit empty volumes list" ;;
esac

echo
echo "§6 the volume path validator rejects traversal before it ever reaches the filesystem"

case "$ROUTE_FLAT" in
  *'fnis_valid_volume_path(path:&str)->bool{'*'&&!path.contains("..")'*)
    ok "the agent's path validator rejects '..' " ;;
  *) bad "the agent's volume-path validator no longer rejects '..'" ;;
esac
case "$BACKEND_FLAT" in
  *'fnis_valid_volume_path(path:&str)->bool{'*'&&!path.contains("..")'*)
    ok "the backend's path validator (friendly-case duplicate) also rejects '..'" ;;
  *) bad "the backend's volume-path validator no longer rejects '..'" ;;
esac

echo
echo "§7 migrate_unmounted_volumes was GENERALISED, not duplicated — one implementation, two callers"

case "$APPS_FLAT" in
  *'pub(crate)asyncfnmigrate_unmounted_volumes(data_dir:&str,docker:&Docker,container_id:&str,name:&str,image:&str,missing:&[&str],host_config:&mutbollard::service::HostConfig,'*)
    ok "migrate_unmounted_volumes takes data_dir as a parameter (no longer hardcoded to APP_DATA_DIR)" ;;
  *) bad "migrate_unmounted_volumes's signature no longer takes a data_dir parameter — a duplicate may have been written instead" ;;
esac

N_DEFS=$(printf '%s\n' "$APPS_CODE" "$SVC_CODE" | grep -c 'fn migrate_unmounted_volumes')
if [ "$N_DEFS" -eq 1 ]; then
  ok "exactly one definition of migrate_unmounted_volumes exists across both files"
else
  bad "found $N_DEFS definitions of migrate_unmounted_volumes — the logic drifted into a duplicate"
fi

DOCKER_APPS_CALLS=$(printf '%s\n' "$APPS_CODE" | grep -c 'migrate_unmounted_volumes(\s*$\|migrate_unmounted_volumes(APP_DATA_DIR')
if [ "$DOCKER_APPS_CALLS" -ge 3 ]; then
  ok "docker_apps.rs's own 3 call sites (update_app / change_container_image / update_env) still pass APP_DATA_DIR"
else
  bad "fewer than 3 docker_apps.rs call sites pass APP_DATA_DIR to migrate_unmounted_volumes (found $DOCKER_APPS_CALLS)"
fi

echo
echo "§8 unit tests exist where a mistake would otherwise be silent"

SVC_TESTS=$(printf '%s' "$SVC_FLAT")
for arm in \
  'fncleanup_only_deletes_what_this_deploys_own_binds_prove'
do
  case "$SVC_TESTS" in
    *"$arm"*) ok "agent service unit test present: ${arm#fn}" ;;
    *) bad "agent service unit test missing: ${arm#fn}" ;;
  esac
done

for arm in \
  'fnvolume_path_rejects_traversal_and_free_form_hosts' \
  'fnvalidate_volumes_rejects_duplicates_and_the_over_limit_case'
do
  case "$ROUTE_FLAT" in
    *"$arm"*) ok "agent route unit test present: ${arm#fn}" ;;
    *) bad "agent route unit test missing: ${arm#fn}" ;;
  esac
done

case "$BACKEND_FLAT" in
  *'fndeclared_volumes_are_sent'*) ok "backend unit test present: declared_volumes_are_sent" ;;
  *) bad "backend unit test missing: declared_volumes_are_sent" ;;
esac

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[0;32mPASS %d  FAIL 0\033[0m\n' "$PASS"
else
  printf '\033[0;31mPASS %d  FAIL %d\033[0m\n' "$PASS" "$FAIL"
fi
exit $((FAIL > 0))
