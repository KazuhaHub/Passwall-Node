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
HOST="${PSP_OLD_HOST:-127.0.0.1}"
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

# --------------------------------------------------------------- natives

# A NATIVE NODE BINDS ITS OWN PORT, SO IT MUST NOT PICK ONE THE LAUNCHER PUBLISHED.
#
# R07's launcher publishes 3X-UI's node range (24443-24450) on the host, so a
# native node told to listen on one of those ports cannot: the container's port
# forwarder already holds it. The agent then fails to start its core —
#
#   failed to listen TCP on 24443 > listen tcp 0.0.0.0:24443: bind: address already in use
#
# — rolls the config back, and never reports the inbound. Downstream that reads as
# a panel problem: config_sync_state stays `pending` forever, PSP logs "native
# panel has no cached full report", and provisioning a user onto the node fails
# with "shared client u2@psp.local absent after create". Every one of those was
# this port, and none of them said so.
NODE_PORT="${PSP_OLD_NODE_PORT:-25443}"

# create_inbound gives the native panel a node for a client to attach to. It is
# created BEFORE the agent starts, so the agent's first sync carries it — created
# afterwards, the panel has already tried and failed to provision existing users
# and does not retry that.
create_inbound() {
  local token="$1" panel_id="$2"
  python3 - "$panel_id" "$HOST" "$NODE_PORT" > "$WORKDIR/b02-inbound-request.json" <<'PY'
import json, sys
print(json.dumps({
    "panel_id": int(sys.argv[1]), "display_name": "compat-inbound",
    "server_address": sys.argv[2], "region": "compat",
    "inbound": {"remark": "compat", "enable": True, "listen": "", "port": int(sys.argv[3]),
                "protocol": "vless",
                "settings": json.dumps({"clients": [], "decryption": "none", "fallbacks": []}),
                "stream_settings": json.dumps({"network": "tcp", "security": "none"}),
                "sniffing": json.dumps({"enabled": False, "destOverride": ["http", "tls"]})}}))
PY
  curl -sS -o "$WORKDIR/b02-inbound.json" -w '%{http_code}' \
    -X POST -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    -d "@$WORKDIR/b02-inbound-request.json" \
    "http://127.0.0.1:$OLD_PSP_PORT/api/admin/nodes" || true
}

# node_id_by_name resolves the panel's own numeric id, which the upgrade endpoint
# is addressed by. `node_state` matches on name because that is what the DTO
# carries alongside; the admin routes want the id.
node_id_by_name() {
  local token="$1" name="$2"
  curl -fsS -H "Authorization: Bearer $token" "http://127.0.0.1:$OLD_PSP_PORT/api/admin/servers" |
    python3 -c "
import json,sys
want=sys.argv[1]
for s in json.load(sys.stdin).get('items',[]):
    if s.get('name')==want:
        print(s.get('id'))
        break
" "$name"
}

# task_count reads the panel's OWN durable task rows. The admission path returns
# no task id when it refuses — that is the refusal — so there is nothing to ask
# the API about by id, and "no row exists" is a question only the panel's own
# store can answer. Opened read-only so a check can never be the thing that
# changes what it is measuring.
task_count() {
  local agent_id="$1" kind="${2:-}"
  python3 - "$WORKDIR/data/panel.db" "$agent_id" "$kind" <<'PY'
import sqlite3, sys
db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
kind = sys.argv[3]
if kind:
    rows = db.execute(
        "select count(*) from node_agent_tasks where agent_id=? and kind=?",
        (sys.argv[2], kind),
    ).fetchone()[0]
else:
    rows = db.execute(
        "select count(*) from node_agent_tasks where agent_id=?",
        (sys.argv[2],),
    ).fetchone()[0]
print(rows)
PY
}

# post_report sends a report AS the node, which is the only way to put a node
# into a state this harness chooses rather than the one the candidate happens to
# be in. Used to give one node a capability set the real candidate does not have.
post_report() {
  local credential="$1" body="$2"
  curl -sS -o "$WORKDIR/report.json" -w '%{http_code}' \
    -X POST -H "Authorization: Bearer $credential" -H 'Content-Type: application/json' \
    -d "$body" "http://127.0.0.1:$OLD_PSP_PORT/v1/node/sync" || true
}

report_body() {
  local agent_id="$1" protocol="$2"; shift 2
  python3 - "$agent_id" "$protocol" "$@" <<'PY'
import json, sys, time
print(json.dumps({
    "agent_id": sys.argv[1],
    "protocol_version": int(sys.argv[2]),
    "reported_at_ms": int(time.time() * 1000),
    "capabilities": sys.argv[3:],
    "partial": False,
    # All three streams are required by ValidateNodeReportBase; a state with no
    # etag and no applied version is the valid "nothing applied yet" shape. They
    # are here so that the rejection a case is measuring is the ONLY thing wrong
    # with the report.
    "have": {"config": {}, "roster": {}, "directives": {}},
    "objects": [],
    "listener_counters": [],
    "clients": [],
    "core_state": "running",
}))
PY
}

upgrade_attempt() {
  local token="$1" panel_id="$2"
  curl -sS -o "$WORKDIR/b05.json" -w '%{http_code}' \
    -X POST -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    -H 'Idempotency-Key: psp-compat-b05-admission-1' \
    -d '{"version":"v9.9.9","expected_version":"v1.0.0"}' \
    "http://127.0.0.1:$OLD_PSP_PORT/api/admin/servers/$panel_id/upgrade-node-agent" || true
}

# wait_synced polls the panel's record of whether the node has confirmed the
# configuration it was sent. `pending` means PSP minted a desired config the node
# has not acknowledged; `synced` means it has.
wait_synced() {
  local waited=0 state
  while :; do
    state=$(node_field config_sync_state) || true
    if [ "$state" = "synced" ]; then return 0; fi
    if [ "$waited" -ge 90 ]; then
      log "the node never reached synced (state=${state:-<none>}); its core could not apply the configuration PSP sent"
      return 1
    fi
    sleep 3; waited=$((waited + 3))
  done
}

# node_field reads one column of the single node row this harness creates.
node_field() {
  python3 - "$WORKDIR/data/panel.db" "$1" <<'PY'
import sqlite3, sys
column = sys.argv[2]
if column not in {"config_sync_state", "config_synced_at", "id"}:
    raise SystemExit(f"refusing to read unexpected column {column!r}")
db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
row = db.execute(f"select {column} from nodes limit 1").fetchone()
print("" if row is None or row[0] is None else row[0])
PY
}

# attachment_state reads WHERE PSP believes the client is on the node, as
# `state|email|applied_version`. `applied` is set only after a read-back confirms
# it, so this is the panel's own record that the client reached the node rather
# than an intention to send it. The version is what moves when the desired
# configuration changes: PSP mints a new one only when it does.
attachment_state() {
  python3 - "$WORKDIR/data/panel.db" <<'PY'
import sqlite3, sys
db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
row = db.execute("select state, applied_email, applied_version from psp_client_inbounds limit 1").fetchone()
print("none" if row is None else f"{row[0]}|{row[1]}|{row[2]}")
PY
}

# B02: A USER ADDED IN THE PANEL REACHES THE NODE, AND LEAVES IT WHEN DISABLED.
#
# Read out of the PANEL'S record of the attachment, not out of PSP's intent to
# send one: `psp_client_inbounds.state = applied` is written only after a
# read-back confirms the client is on the node, which is exactly the claim.
#
# The user can only be provisioned once the node has confirmed a configuration —
# a native panel learns its inbounds from the node's report, so provisioning
# before that fails with "native panel has no cached full report". That is why
# this runs after wait_synced rather than alongside the node's creation.
check_b02() {
  local token="$1" upn="$2" waited state

  local code
  code=$(curl -sS -o "$WORKDIR/b02.json" -w '%{http_code}' \
    -X POST -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    -d "{\"upn\":\"$upn\",\"group_id\":1,\"traffic_limit_gb\":10}" \
    "http://127.0.0.1:$OLD_PSP_PORT/api/admin/users" || true)
  [ "$code" = "201" ] ||
    fail "B02: the user was not created (HTTP $code: $(head -c 200 "$WORKDIR/b02.json" 2>/dev/null))"

  waited=0
  # Matched on the STATE, not on a full address. The client's email is derived
  # from the user's ID (`u2@psp.local`), so a comparison assembling the UPN into
  # an address never matches — and it fails by looping, which reads as "it never
  # arrived" when the record in front of it says otherwise.
  until attachment_state | grep -q '^applied|'; do
    if [ "$waited" -ge 120 ]; then
      fail "B02: the client never reached the node; the panel's attachment record says $(attachment_state)"
    fi
    sleep 5; waited=$((waited + 5))
  done
  log "B02: the panel recorded the client as applied to the node after ${waited}s ($(attachment_state))"

  # Captured BEFORE the disable: the assertion below is that this number moves,
  # so the value it moves FROM has to be the one in force before the change.
  local before_version
  before_version=$(attachment_state | awk -F'|' '{print $3}')

  # DISABLING MUST REACH IT TOO. A user the panel has switched off staying in the
  # node's configuration is the failure this half exists for: the panel would
  # report the user as disabled while the node kept serving them.
  #
  # `set-service-status` and not `PUT /users/:id`: the update route has no
  # `enabled` field at all, so `{"enabled":false}` there is IGNORED — it answers
  # 200 and changes nothing. That cost a run, and what it looked like was a panel
  # that would not push a disable to its node.
  local uid
  uid=$(user_id_by_upn "$token" "$upn")
  [ -n "$uid" ] || fail "B02: the panel does not list $upn after creating it"

  code=$(curl -sS -o "$WORKDIR/b02-disable.json" -w '%{http_code}' \
    -X POST -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    -d '{"enabled":false}' \
    "http://127.0.0.1:$OLD_PSP_PORT/api/admin/users/$uid/set-service-status" || true)
  case "$code" in
    2??) : ;;
    *) fail "B02: disabling $upn was refused (HTTP $code: $(head -c 200 "$WORKDIR/b02-disable.json" 2>/dev/null))" ;;
  esac

  # Confirmed on the panel before waiting on the node, so a request that was
  # accepted and ignored cannot read as a node that did not follow.
  #
  # THE SERVICE AXIS IS THE ONE THAT MOVES. `enabled` belongs to the ACCOUNT axis
  # and deliberately stays true: a suspended user can still sign in and
  # self-rescue, which is the model this panel documents. Asserting `enabled=0`
  # here asserts a model it does not have, and it fails against a working
  # disable — which is exactly what it did.
  local service_reason
  service_reason=$(python3 - "$WORKDIR/data/panel.db" "$uid" <<'PY'
import sqlite3, sys
db = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
row = db.execute("select service_disabled_reason from users where id=?", (int(sys.argv[2]),)).fetchone()
print("" if row is None or row[0] is None else row[0])
PY
)
  [ -n "$service_reason" ] ||
    fail "B02: the panel answered $code to the disable and the user's service axis is still unset"

  local after_state
  waited=0
  # THE VERSION IS WHAT MOVES, not the state. The attachment stays `applied` — the
  # client is still provisioned onto that node; what changes is the configuration
  # the node confirmed, and PSP mints a new version only when the desired one
  # changes. Asserting that the attachment stops reading `applied` would be
  # asserting a model this panel does not have, and it would fail against a
  # correctly-working disable.
  until [ "$(attachment_state | awk -F'|' '{print $3}')" != "$before_version" ]; do
    if [ "$waited" -ge 120 ]; then
      fail "B02: $upn was disabled in the panel and the node never confirmed a new configuration (still version $before_version)"
    fi
    sleep 5; waited=$((waited + 5))
  done
  after_state=$(attachment_state)
  log "B02: the node confirmed a new configuration after the disable (version $before_version -> ${after_state##*|}; $(node_field config_sync_state))"
}

# user_id_by_upn resolves the panel's own id for a user, which the update route
# is addressed by.
user_id_by_upn() {
  local token="$1" upn="$2"
  curl -fsS -H "Authorization: Bearer $token" "http://127.0.0.1:$OLD_PSP_PORT/api/admin/users" |
    python3 -c "
import json,sys
want=sys.argv[1]
for u in json.load(sys.stdin).get('items',[]):
    if u.get('upn')==want:
        print(u.get('id'))
        break
" "$upn"
}

# B05: AN UPGRADE TASK IS ADMITTED ONLY FOR A NODE THAT REPORTS THE CAPABILITY.
#
# THE SAME REQUEST, TWICE, AGAINST TWO NODES WHOSE ONLY DIFFERENCE IS WHAT THEY
# REPORT. A one-sided check cannot work here, and finding that out cost a run: a
# panel that refused EVERYTHING satisfies "the request for the incapable node was
# refused" exactly as well as a panel that gates on the capability, and the first
# version of this case passed for a reason it had not tested at all — the request
# had been rejected by ordinary request validation, before any admission decision
# was reached, and the response body is no help in telling those apart because
# every validation error is flattened into one string by the handler.
#
# So the other side is built rather than hoped for: a second node is given, by a
# forged report, the full capability set AgentUpgradeCapabilities names. If that
# node is admitted and the real candidate is not, the decision provably depends
# on what the node reports.
#
# WHAT THIS DOES NOT CLAIM. The eligible node's capability set is asserted by the
# harness, not by the candidate, so this measures the PANEL's gate — which is what
# "停止新升级任务准入" is about. Whether the candidate can actually serve an upgrade
# task needs a node with the helper installed, and is not reachable from here.
check_b05() {
  local token="$1" candidate_id="$2" candidate_agent="$3" eligible_id="$4" eligible_agent="$5"
  local code rows

  code=$(upgrade_attempt "$token" "$eligible_id")
  if [ "$code" != "202" ]; then
    fail "B05: a node reporting the full upgrade capability set was not admitted (HTTP $code: $(cat "$WORKDIR/b05.json" 2>/dev/null)), so the refusal of the real candidate proves nothing — a panel that refuses every request looks the same"
  fi
  rows=$(task_count "$eligible_agent" "agent.upgrade.v1")
  [ "$rows" = "1" ] ||
    fail "B05: the eligible node was answered 202 but has $rows agent.upgrade.v1 task row(s), so the answer and the recorded intent disagree"
  log "B05: the capable node was admitted and has its task row (HTTP $code)"

  code=$(upgrade_attempt "$token" "$candidate_id")
  [ "$code" != "202" ] ||
    fail "B05: an upgrade task was admitted for a node that reports no upgrade capability"
  rows=$(task_count "$candidate_agent" "agent.upgrade.v1")
  [ "$rows" = "0" ] ||
    fail "B05: $rows agent.upgrade.v1 task row(s) exist for a node without the capability"
  log "B05: the incapable node was refused (HTTP $code: $(cat "$WORKDIR/b05.json")) and wrote no task row"
}

# B08: A PROTOCOL GENERATION THE OLD PANEL DOES NOT KNOW IS REFUSED, BY NAME.
#
# The report sent below is OTHERWISE COMPLETE — every required field, all three
# required streams — so the protocol generation is the only thing left to refuse
# it for. That matters more than it looks: an earlier version of this case sent a
# truncated report and got its 400 from a missing `have.config`, which satisfies
# "it was refused" while saying nothing whatever about protocol handling.
#
# Measured response from v4.0.0-beta.19:
#   400 {"error":"validate node report: protocol_version 99 is unsupported"}
check_b08() {
  local token="$1" credential="$2" agent_id="$3" name="$4"
  local code body

  code=$(post_report "$credential" "$(report_body "$agent_id" 99 \
    "task.execution.v1" "task.expiry.v1" "task.agent.upgrade.v1")")
  body=$(cat "$WORKDIR/report.json" 2>/dev/null)

  case "$code" in
    2??) fail "B08: a report claiming protocol generation 99 was ACCEPTED (HTTP $code)" ;;
  esac

  # THE DIAGNOSTIC IS THE OTHER HALF OF THE REQUIREMENT. A 400 with an empty body
  # refuses without saying what it refused, which sends an operator hunting
  # through node logs for a cause the panel already knew.
  printf '%s' "$body" | grep -q 'protocol_version' ||
    fail "B08: the refusal does not name the protocol version: $body"
  printf '%s' "$body" | grep -q 'unsupported' ||
    fail "B08: the refusal does not say the generation is unsupported: $body"

  # AND NOTHING WAS HALF-APPLIED. A rejected report that had already written what
  # it carried would leave the node reading as observed, and the panel then
  # offering configuration for a generation it cannot produce — the loop this case
  # exists to rule out.
  local state rows
  state=$(node_state "$token" "$name" | awk '{print $1}')
  [ "$state" = "unknown" ] ||
    fail "B08: the node reads as '$state' after a report that was refused, so the refusal did not roll back what it had stored"
  rows=$(task_count "$agent_id")
  [ "$rows" = "0" ] ||
    fail "B08: $rows task row(s) exist for a node whose only report was refused"

  log "B08: the panel refused protocol generation 99 with a diagnostic, stored nothing and queued nothing (HTTP $code: $body)"
}

# B06 IS N/A AGAINST THIS VERSION, AND SAYING SO IS THE RESULT.
#
# The plan allows a missing optional feature to be N/A PROVIDED the panel is also
# shown not to dispatch it — what it forbids is letting the gap read as coverage.
#
# `node-diagnostics` was added on 2026-09-18 (PR #133); v4.0.0-beta.19 was
# published 2026-09-17. So the route is not there, and the request falls through
# to the SPA catch-all: HTTP 200 with an HTML page, which is exactly the shape
# that would fool a case asserting only "not 4xx".
#
# THE EXPIRY HALF CANNOT BE DRIVEN EITHER, and that is a property of THIS PAIR
# rather than of the harness. The only task kind this panel can mint is
# `agent.upgrade.v1`, and it refuses to mint one for the candidate, which reports
# no upgrade helper — proved by B05 in the same run. An expired task the agent
# could actually have accepted therefore cannot be constructed here at all.
check_b06() {
  local token="$1" panel_id="$2" agent_id="$3"

  local code
  code=$(curl -sS -o "$WORKDIR/b06.json" -w '%{http_code}' \
    -X POST -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    -d '{"sections":["system"]}' \
    "http://127.0.0.1:$OLD_PSP_PORT/api/admin/servers/$panel_id/node-diagnostics" || true)

  # Detected by the SPA marker rather than by the status code: an absent admin
  # route answers 200 here, so "not 404" would have been read as "the route
  # exists and did something".
  if ! grep -qi '<!doctype html' "$WORKDIR/b06.json" 2>/dev/null; then
    fail "B06: this panel ANSWERS the diagnostics route (HTTP $code), so the case is not N/A and must be implemented rather than waived: $(head -c 200 "$WORKDIR/b06.json" 2>/dev/null)"
  fi

  # The negative half the plan asks for: nothing of that kind was queued for the
  # node. An absent route that still left a task row would be a dispatch with no
  # way to collect it.
  local rows
  rows=$(task_count "$agent_id" "diagnostics.collect.v1")
  [ "$rows" = "0" ] ||
    fail "B06: $rows diagnostics.collect.v1 task row(s) exist although the route that would mint them is absent"

  log "B06: N/A — $OLD_PSP_VERSION has no node-diagnostics route (HTTP $code served the SPA), and no such task was queued. Task expiry is unreachable for this pair: the only kind the panel can mint is agent.upgrade.v1, which B05 shows it refuses for this candidate."
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

  local node agent_id credential panel_id
  node=$(create_node "$token" "compat-candidate")
  agent_id=$(printf '%s' "$node" | python3 -c 'import json,sys;print(json.load(sys.stdin)["agent_id"])')
  credential=$(printf '%s' "$node" | python3 -c 'import json,sys;print(json.load(sys.stdin)["credential"])')
  panel_id=$(node_id_by_name "$token" "compat-candidate")

  # THE INBOUND IS CREATED BEFORE THE AGENT STARTS, so the agent's first sync
  # carries it. Created afterwards, the panel has already attempted — and failed —
  # to provision existing users against a node with no cached report, and it does
  # not retry that.
  local inbound_code
  inbound_code=$(create_inbound "$token" "$panel_id")
  [ "$inbound_code" = "201" ] ||
    fail "the node's inbound was not created (HTTP $inbound_code: $(head -c 200 "$WORKDIR/b02-inbound.json" 2>/dev/null)); without it no user can reach this node"

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
  wait_synced || fail "the node never confirmed the configuration, so nothing about a user reaching it could be measured"
  check_b02 "$token" "compat-user-b02"

  # THE OTHER HALF OF B05'S COMPARISON, built here because no real node in this
  # harness has the upgrade helper installed. `compat-eligible` is given the full
  # capability set AgentUpgradeCapabilities names, by a forged report, so the only
  # difference between the two nodes below is what they say about themselves.
  local eligible eligible_agent eligible_cred eligible_id
  eligible=$(create_node "$token" "compat-eligible")
  eligible_agent=$(printf '%s' "$eligible" | python3 -c 'import json,sys;print(json.load(sys.stdin)["agent_id"])')
  eligible_cred=$(printf '%s' "$eligible" | python3 -c 'import json,sys;print(json.load(sys.stdin)["credential"])')
  eligible_id=$(node_id_by_name "$token" "compat-eligible")
  local report_code
  report_code=$(post_report "$eligible_cred" "$(report_body "$eligible_agent" 1 \
    "task.execution.v1" "task.expiry.v1" "task.agent.upgrade.v1")")
  [ "$report_code" = "200" ] ||
    fail "B05: the forged report that grants the upgrade capability was not accepted (HTTP $report_code: $(cat "$WORKDIR/report.json" 2>/dev/null)) — without it there is no capable node to compare against"

  check_b05 "$token" "$panel_id" "$agent_id" "$eligible_id" "$eligible_agent"
  check_b06 "$token" "$panel_id" "$agent_id"

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

  # B08 LAST, AND ON ITS OWN NODE. A report claiming an unknown protocol
  # generation is BY DESIGN an attempt to corrupt what the panel believes about a
  # node, so it must not be aimed at the node every other case just measured: one
  # forged report against `compat-candidate` would leave B03, B04 and B05 reading
  # a row this case had rewritten. `compat-probe` exists to be damaged.
  local probe
  probe=$(create_node "$token" "compat-probe")
  check_b08 "$token" \
    "$(printf '%s' "$probe" | python3 -c 'import json,sys;print(json.load(sys.stdin)["credential"])')" \
    "$(printf '%s' "$probe" | python3 -c 'import json,sys;print(json.load(sys.stdin)["agent_id"])')" \
    "compat-probe"

  log "PASS: $OLD_PSP_VERSION accepted the candidate agent (compatibility=$observed)"
}

main "$@"
