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

# The panel this run starts, so it can be stopped by PID rather than by name.
# Naming it (`pkill -x psp`) would reach any other psp on the machine, including
# one belonging to somebody else's work.
OLD_PSP_PID=""

log() { printf '%s\n' "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }

# THE PANEL IS STARTED FOR ONE CASE AND STOPPED WITH IT.
#
# Left running it does two things, and the second is the expensive one. It holds
# the panel port, so the next case cannot bind. And it keeps this script's shell
# alive: bash sits in do_wait on its child, so the process never exits and a
# caller cannot tell "the case passed" from "the harness hung". That is exactly
# what a wedged run looks like from the outside — a `limactl shell` that never
# returns, a `tail` that never sees EOF, and no output at all, because the last
# line was printed an hour and a half earlier.
#
# SIGTERM first, because the panel drains its background workers; SIGKILL only
# for one that does not come back, so a genuine shutdown hang is bounded rather
# than waited on.
stop_old_psp() {
  [ -n "$OLD_PSP_PID" ] || return 0
  kill -0 "$OLD_PSP_PID" 2>/dev/null || return 0
  kill "$OLD_PSP_PID" 2>/dev/null || true
  local waited=0
  while kill -0 "$OLD_PSP_PID" 2>/dev/null; do
    if [ "$waited" -ge 15 ]; then
      log "the panel did not exit after SIGTERM; killing it"
      kill -9 "$OLD_PSP_PID" 2>/dev/null || true
      break
    fi
    sleep 1; waited=$((waited + 1))
  done
}
trap stop_old_psp EXIT

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
  # `exec`, NOT `nohup`, and the difference is not cosmetic: `$!` has to name the
  # PANEL, because that is what `stop_old_psp` kills. uutils' nohup (the one on
  # this VM) forks instead of exec'ing, so `$!` named a wrapper that had already
  # exited and the cleanup killed a PID belonging to nothing — leaving the panel
  # running and the port held, while the script itself exited cleanly and looked
  # fine. GNU nohup execs, so the same line is correct on the runner and wrong
  # here, which is the worst shape a bug can have. With no wrapper process there
  # is nothing to disagree about, and the redirects below are what nohup would
  # have set up anyway.
  ( cd "$WORKDIR" && exec ./psp > "$WORKDIR/psp.log" 2>&1 < /dev/null ) &
  OLD_PSP_PID=$!
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

# node_raw returns the old panel's own DTO for one node, so an assertion can be
# made about WHAT THE OLD PANEL STORED rather than about what the agent sent.
node_raw() {
  local token="$1" name="$2"
  curl -fsS -H "Authorization: Bearer $token" "http://127.0.0.1:$OLD_PSP_PORT/api/admin/servers" |
    python3 -c "
import json,sys
want=sys.argv[1]
for s in json.load(sys.stdin).get('items',[]):
    if s.get('name')==want:
        print(json.dumps(s))
        break
" "$name"
}

# check_b03_b04 asserts the two contract properties a NEWER agent against an OLDER
# panel has to hold. Both are about what the old panel does with what it does not
# understand, which is the half of the wire contract the newer side cannot test on
# its own.
check_b03_b04() {
  local token="$1" raw
  raw=$(node_raw "$token" "compat-candidate")

  # B03: the candidate reports fields this panel predates — host telemetry shipped
  # after it — and the panel must neither reject the report nor invent the fields
  # it never learned. The run already proved it did not reject; this proves it did
  # not start carrying them either.
  local guessed
  guessed=$(printf '%s' "$raw" | python3 -c "
import json,sys
d=json.load(sys.stdin)
# Fields a LATER panel row would carry. Their absence is the assertion: an older
# panel that started echoing them would be reporting on data it never parsed.
present=[k for k in ('node_cpu_percent','node_metric_received_at','node_memory_percent') if k in d]
print(','.join(present))
")
  [ -z "$guessed" ] || fail "B03: the older panel is carrying telemetry fields it predates: $guessed"
  log "B03: the older panel accepted a report carrying fields it predates, and carries none of them itself"

  # B04: a capability the node did not report must not read as permission. The
  # upgrade capability is absent, and the panel says 'limited' — a default that
  # flipped a missing capability to ready would say 'compatible' here.
  local ready state
  state=$(printf '%s' "$raw" | python3 -c "import json,sys;print(json.load(sys.stdin).get('node_compatibility',''))")
  ready=$(printf '%s' "$raw" | python3 -c "import json,sys;print(json.load(sys.stdin).get('node_upgrade_ready'))")
  [ "$state" != "compatible" ] || fail "B04: an absent upgrade capability was read as ready"
  [ "$ready" != "True" ] || fail "B04: node_upgrade_ready is true without the capability"
  log "B04: an absent capability stayed absent (state=$state ready=$ready)"
}

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

  check_b03_b04 "$token"

  log "PASS: $OLD_PSP_VERSION accepted the candidate agent (compatibility=$observed)"
}

main "$@"
