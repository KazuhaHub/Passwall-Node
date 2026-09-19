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
AGENT_PID=""

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
# The agent is long-lived by design — B07 takes the panel away underneath it —
# so nothing bounds it except this. Without it a run that fails early leaves the
# agent syncing forever, which is the same "cannot tell a pass from a hang"
# problem the panel's own cleanup above exists to avoid.
stop_agent() {
  [ -n "$AGENT_PID" ] || return 0
  kill -0 "$AGENT_PID" 2>/dev/null || return 0
  kill "$AGENT_PID" 2>/dev/null || true
  local waited=0
  while kill -0 "$AGENT_PID" 2>/dev/null; do
    if [ "$waited" -ge 10 ]; then
      kill -9 "$AGENT_PID" 2>/dev/null || true
      break
    fi
    sleep 1; waited=$((waited + 1))
  done
}

trap 'stop_agent; stop_old_psp' EXIT

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

launch_old_psp() {
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
}

start_old_psp() {
  rm -rf "$WORKDIR/data" "$WORKDIR/config.yaml"
  launch_old_psp
  log "old PSP up: $(curl -fsS "http://127.0.0.1:$OLD_PSP_PORT/api/version")"
}

# A RESTART KEEPS THE DATABASE, and that is the whole difference from a start.
# The panel's own database holds the node row and its credential, and its
# config.yaml holds the jwt_secret that keeps the admin token valid. Wiping
# either would delete the identity the running agent is holding, so the agent
# could never re-converge and B07 would fail for a reason this harness invented
# rather than for anything the two implementations did.
restart_old_psp() {
  launch_old_psp
  log "old PSP back up: $(curl -fsS "http://127.0.0.1:$OLD_PSP_PORT/api/version")"
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

# wait_converged polls the OLD panel's own view until it stops saying `unknown`,
# and returns whatever it last said rather than failing: the caller decides what
# an unconverged node means, and one of the callers (B07) expects convergence
# and the other (the first case) has to distinguish it from a control node that
# never moved.
wait_converged() {
  local token="$1" name="$2" waited=0 state
  while :; do
    # `|| true` because the panel can be unreachable — this is polled across a
    # restart — and under `set -e` a failing command substitution assigned to a
    # variable ends the script rather than the loop.
    state=$(node_state "$token" "$name" 2>/dev/null | awk '{print $1}') || true
    if [ -n "$state" ] && [ "$state" != "unknown" ]; then printf '%s' "$state"; return 0; fi
    if [ "$waited" -ge 40 ]; then printf 'unknown'; return 0; fi
    sleep 2; waited=$((waited + 2))
  done
}

# B07: THE CONTROL PLANE GOES AWAY AND COMES BACK, WITH THE AGENT STILL RUNNING.
#
# The property is not that the agent survives its panel. It is that a node which
# loses its panel KEEPS THE LAST CONFIGURATION IT WAS GIVEN: a node that dropped
# its config when the panel went away would take the user's traffic down with it,
# and the panel would have no way to know until it came back. So the assertion is
# the applied config's digest, not the agent's liveness — "still running" is also
# true of an agent that threw its configuration away and is idling.
check_b07() {
  local token="$1" name="$2" applied="$3" before="$4"

  [ -s "$applied" ] || fail "B07: the agent never wrote an applied config at $applied"
  [ -n "$before" ] || fail "B07: no digest of the applied config was taken before the outage"

  log "B07: stopping $OLD_PSP_VERSION with the agent still running"
  stop_old_psp
  sleep 10

  kill -0 "$AGENT_PID" 2>/dev/null || fail "B07: the agent exited when its panel went away"

  local during
  during=$(sha256sum "$applied" | awk '{print $1}')
  [ "$during" = "$before" ] ||
    fail "B07: the agent's applied config changed while the panel was unreachable (was $before, now $during)"
  log "B07: the agent kept its last valid config across the outage (sha256 ${during:0:12})"

  log "B07: restarting the panel"
  restart_old_psp
  local state
  state=$(wait_converged "$token" "$name")
  [ "$state" != "unknown" ] || fail "B07: the node did not re-converge after the panel came back"
  log "B07: the node re-converged after the panel returned (compatibility=$state)"
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
  # IN THE BACKGROUND, so the panel can be taken away underneath it at a point
  # this harness chooses: B07 is about a node that has ALREADY converged losing
  # its control plane, and a foreground agent with a fixed cap cannot be
  # interrupted that way. `exec` for the same reason as the panel — `$!` has to
  # name the agent, since that is what the cleanup kills.
  ( exec "$AGENT_BIN" \
      -agent-id "$agent_id" \
      -credential-file "$rundir/credential" \
      -data-dir "$rundir" \
      -endpoint "http://127.0.0.1:$OLD_PSP_PORT/v1/node/sync" \
      -allow-insecure-http > "$rundir/agent.log" 2>&1 ) &
  AGENT_PID=$!

  local state observed control
  state=$(wait_converged "$token" "compat-candidate")
  observed=$(node_state "$token" "compat-candidate")
  control=$(node_state "$token" "compat-control")
  log "candidate node state: $observed"
  log "control node state:   $control"

  [ "$state" != "unknown" ] || fail "the old panel still reports the candidate node as unknown; it never accepted a report"
  [ "$(printf '%s' "$control" | awk '{print $1}')" = "unknown" ] ||
    fail "the control node changed too, so this run cannot attribute the change to the agent"

  check_b03_b04 "$token"

  # The digest is taken BEFORE the outage; afterwards is too late to know what
  # "unchanged" would have meant.
  #
  # Its existence is WAITED FOR rather than assumed from convergence. A node
  # reports to its panel before its core has necessarily written a config, so
  # taking the digest the moment the panel stops saying `unknown` races the file.
  # Under `set -o pipefail` the race does not read as a race either: a failing
  # `sha256sum` in the pipeline below ends the script with no message at all, so
  # the run stops after B04 having printed no verdict — which is what it did.
  local applied="$rundir/runtime/xray/current.json" applied_before="" waited=0
  while [ ! -s "$applied" ]; do
    if [ "$waited" -ge 40 ]; then fail "the agent never wrote an applied config at $applied"; fi
    sleep 2; waited=$((waited + 2))
  done
  applied_before=$(sha256sum "$applied" | awk '{print $1}')
  check_b07 "$token" "compat-candidate" "$applied" "$applied_before"

  log "PASS: $OLD_PSP_VERSION accepted the candidate agent (compatibility=$observed)"
}

main "$@"
