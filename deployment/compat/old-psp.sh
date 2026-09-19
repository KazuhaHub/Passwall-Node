#!/usr/bin/env bash
#
# Runs THIS candidate agent against a RELEASED old PSP and checks that the old
# panel's own view of the node changed.
#
# WHY THE OLD PANEL DECIDES THE RESULT. It would be easy to run the agent, see
# it start a core, and call the direction verified. The agent starting proves the
# agent works; it does not prove the two implementations agree. So the assertion
# is read back out of the OLD PANEL'S API — its `node_compatibility` for that node
# has to leave `unknown`, which only happens if it authenticated the report,
# parsed the protocol version and capabilities, and persisted them.
#
# THE PANEL MUST BE THE RELEASED ARTIFACT RUNNING ITS OWN DEPENDENCIES, not this
# candidate binary wearing an old version string. The archive is downloaded and
# its SHA-256 checked against the published sums before anything runs.
#
# And nothing here patches the old panel's parsing, coordination or storage to
# make the candidate fit. If the candidate needs the old panel changed, that is
# the finding, not an obstacle to route around.
set -euo pipefail

OLD_PSP_VERSION="${PSP_OLD_VERSION:-v4.0.0-beta.19}"
OLD_PSP_REPO="${PSP_OLD_REPO:-KazuhaHub/Passwall-Sub-Panel}"
OLD_PSP_PORT="${PSP_OLD_PORT:-8788}"
WORKDIR="${PSP_OLD_WORKDIR:-/tmp/psp-compat-old-psp}"
AGENT_BIN="${PSP_CANDIDATE_AGENT:?set PSP_CANDIDATE_AGENT to the candidate agent binary}"

log() { printf '%s\n' "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

# --------------------------------------------------------------- fetch & verify

fetch_old_psp() {
  local arch sums
  arch=$(uname -m)
  case "$arch" in aarch64|arm64) arch=arm64 ;; x86_64|amd64) arch=amd64 ;; *) fail "unsupported arch $arch" ;; esac
  mkdir -p "$WORKDIR"
  cd "$WORKDIR"
  if [ ! -x "$WORKDIR/psp" ]; then
    log "fetching $OLD_PSP_VERSION ($arch)"
    gh release download "$OLD_PSP_VERSION" --repo "$OLD_PSP_REPO" \
      --pattern "*linux_${arch}.tar.gz" --pattern 'SHA256SUMS.txt' --clobber
    # VERIFIED BEFORE IT RUNS. A released artifact whose integrity nobody checked
    # proves nothing about the release.
    sums=SHA256SUMS.txt
    archive=$(ls passwall-sub-panel_*_linux_${arch}.tar.gz)
    ( grep " ${archive}\$" "$sums" || grep "$archive" "$sums" ) > expected.sha
    sha256sum -c expected.sha || fail "checksum mismatch for $archive"
    tar xzf "$archive" --strip-components=1
  fi
  [ -x "$WORKDIR/psp" ] || fail "no psp binary in $WORKDIR"
}

# --------------------------------------------------------------- run the panel

start_old_psp() {
  rm -rf "$WORKDIR/data" "$WORKDIR/config.yaml"
  ( cd "$WORKDIR" && nohup ./psp > "$WORKDIR/psp.log" 2>&1 & )
  local waited=0
  while ! curl -fsS -o /dev/null --max-time 3 "http://127.0.0.1:$OLD_PSP_PORT/api/version" 2>/dev/null; do
    if [ "$waited" -ge 60 ]; then fail "the old panel never answered on :$OLD_PSP_PORT"; fi
    sleep 2; waited=$((waited + 2))
  done
  log "old PSP up: $(curl -fsS "http://127.0.0.1:$OLD_PSP_PORT/api/version")"
}

admin_token() {
  # The bootstrap password is printed once, on the run that creates the database.
  # `local pw` alone leaves it UNSET, and `set -u` makes `[ -z "$pw" ]` an
  # unbound-variable error rather than a false — the loop never ran.
  local pw="" wait=0
  while [ -z "$pw" ]; do
    pw=$(grep -o 'password=[^ ]*' "$WORKDIR/psp.log" 2>/dev/null | head -1 | cut -d= -f2 || true)
    # `[ cond ] && cmd` is a trap under `set -e`: when cond is FALSE the list
    # returns 1 and the script exits silently, so a wait loop written that way
    # dies on its first empty read instead of waiting. Every guard here is an
    # `if`.
    if [ -n "$pw" ]; then break; fi
    if [ "$wait" -ge 30 ]; then fail "the old panel never printed a bootstrap credential"; fi
    sleep 2; wait=$((wait + 2))
  done
  curl -fsS -X POST -H 'Content-Type: application/json' \
    -d "{\"upn\":\"admin\",\"password\":\"$pw\"}" \
    "http://127.0.0.1:$OLD_PSP_PORT/api/auth/local/login" |
    python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])'
}

create_node() {
  local token="$1"
  curl -fsS -X POST -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    -d "{\"panel_type\":\"psp\",\"name\":\"$2\"}" \
    "http://127.0.0.1:$OLD_PSP_PORT/api/admin/servers"
}

node_state() {
  local token="$1" name="$2"
  curl -fsS -H "Authorization: Bearer $token" "http://127.0.0.1:$OLD_PSP_PORT/api/admin/servers" |
    python3 -c "
import json,sys
want=sys.argv[1]
for s in json.load(sys.stdin).get('items',[]):
    if s.get('name')==want:
        print(s.get('node_compatibility'), s.get('node_protocol_version'), len(s.get('node_capabilities') or []))
        break
" "$name"
}

# --------------------------------------------------------------- the assertion

main() {
  fetch_old_psp
  start_old_psp
  local token; token=$(admin_token)

  # A CONTROL NODE, never given to the agent. Without it a panel that reported
  # every node as observed would look like a pass.
  create_node "$token" "compat-control" >/dev/null

  local node agent_id credential
  node=$(create_node "$token" "compat-candidate")
  agent_id=$(printf '%s' "$node" | python3 -c 'import json,sys;print(json.load(sys.stdin)["agent_id"])')
  credential=$(printf '%s' "$node" | python3 -c 'import json,sys;print(json.load(sys.stdin)["credential"])')

  local rundir="$WORKDIR/agent"
  rm -rf "$rundir"; mkdir -p "$rundir"
  printf '%s' "$credential" > "$rundir/credential"; chmod 600 "$rundir/credential"

  log "running the candidate agent against $OLD_PSP_VERSION"
  # Bounded: the agent is a long-lived process, and this harness wants one
  # converged sync, not a daemon to manage.
  timeout 45 "$AGENT_BIN" \
    -agent-id "$agent_id" \
    -credential-file "$rundir/credential" \
    -data-dir "$rundir" \
    -endpoint "http://127.0.0.1:$OLD_PSP_PORT/v1/node/sync" \
    -allow-insecure-http > "$rundir/agent.log" 2>&1 || true

  local observed control
  observed=$(node_state "$token" "compat-candidate")
  control=$(node_state "$token" "compat-control")
  log "candidate node state: $observed"
  log "control node state:   $control"

  local state
  state=$(printf '%s' "$observed" | awk '{print $1}')
  [ "$state" != "unknown" ] || fail "the old panel still reports the candidate node as unknown; it never accepted a report"
  [ "$(printf '%s' "$control" | awk '{print $1}')" = "unknown" ] ||
    fail "the control node changed too, so this run cannot attribute the change to the agent"

  log "PASS: $OLD_PSP_VERSION accepted the candidate agent (compatibility=$observed)"
}

main "$@"
