# Passwall-Node

A node backend driven by an external control plane. The production daemon runs
an audited Xray or sing-box version, applies only PSP-owned desired state, and
reports what the selected core actually applied and counted.

**Status: the Xray and sing-box production paths are implemented.** `cmd/node`
wires outbound HTTPS synchronization, SQLite schema v9, exact checksum-pinned core install,
full-config compilation, atomic process/config replacement with rollback,
offline expiry/quota enforcement, core-specific telemetry, durable issue
delivery, a durable capability-negotiated task journal, and graceful shutdown.
sing-box accounting uses its authenticated loopback daemon API and a crash-safe connection journal; a stream gap is
reported instead of silently under-counting. `cmd/contract-agent` remains the
deterministic coreless cross-repository contract harness.

## What this is

A control plane decides *who may use the network and how much*. This runs on the
machine that actually carries the traffic and does what it is told:

| | |
|---|---|
| **The control plane decides** | who the users are, their quota, their expiry, what the listeners should be |
| **This executes** | runs the core, admits or refuses connections, counts bytes, reports |

It never decides anything on its own. The strongest way to say that: the report
message has **no field in which it can state its own configuration** — see
`protocol.NodeReport`.

## Shape of the protocol

**The node dials out.** It connects to the control plane on the interval the
response supplies (30 seconds by default); the full enumeration defaults to 60
seconds. The
control plane never connects to it. So a node needs no public address, no
inbound management port and no certificate. The cost is that "this node did not
check in" cannot be the node's own admission — the control plane times it out
independently.

**One round trip carries everything.** The node reports; the response carries
three independently-versioned streams:

| stream | contents | changes |
|---|---|---|
| `config` | which listeners to serve | rarely |
| `roster` | which clients live here | often |
| `directives` | values that need summing across nodes | possibly every round |

They are separate so that disabling one user cannot invalidate the listener
configuration — if it could, one diff bug would mean a core reload per user
disabled.

**Content-addressed.** Each stream carries a version and an ETag that is a pure
digest of its content. Unchanged means no body. Minting is content-idempotent:
recomputing the same bytes mints no new version.

## Design record

The protocol was not designed here. It was derived from three years of a real
panel's failures, and the reasoning lives with that panel:

- [`psp-node-agent.md §8`](https://github.com/KazuhaHub/Passwall-Sub-Panel/blob/main/docs/psp-node-agent.md) — the protocol, and why each part is shaped the way it is
- [`ADR 0024`](https://github.com/KazuhaHub/Passwall-Sub-Panel/blob/main/docs/adr/0024-psp-native-node-backend.md) — why a native backend at all
- [`ADR 0025`](https://github.com/KazuhaHub/Passwall-Sub-Panel/blob/main/docs/adr/0025-push-pull-decision-rule.md) — how push-vs-pull is decided, and what a dial-direction flip costs

Every doc comment in `protocol/` names the decision it implements. If a type
looks over-specified, the comment says which failure it is holding shut.

## Using it from another control plane

`protocol` is the whole contract and depends on nothing. Import it, validate
untrusted reports with `protocol.ValidateNodeReport`, serve one endpoint, and
any Passwall-Node will talk to you.

That is the point of this repository being separate: the protocol is a public
contract rather than an internal detail. It carries a real obligation —
documented, versioned, with a deprecation cycle for breaking changes.

## Run the production daemon

Create a **PSP Node** on PSP's Servers page. PSP returns an agent ID, sync
endpoint and credential exactly once; it stores only the credential's SHA-256
digest. Save the credential as a private regular file, then start the daemon:

```bash
install -d -m 0700 /etc/passwall-node /var/lib/passwall-node
printf '%s\n' 'pspn_REPLACE_WITH_THE_ONE_TIME_VALUE' > /etc/passwall-node/credential
chmod 0600 /etc/passwall-node/credential

passwall-node \
  --endpoint https://panel.example/v1/node/sync \
  --agent-id agt_REPLACE_WITH_THE_ASSIGNED_ID \
  --credential-file /etc/passwall-node/credential \
  --data-dir /var/lib/passwall-node
```

Plain HTTP is rejected by default. `--allow-insecure-http` exists only for an
explicit local-development deployment. The data directory holds the SQLite
state, downloaded core versions, last confirmed runtime configuration, and a
generated private sing-box API secret; back it up and keep it private.

The daemon refuses symlink credentials and, on Unix, any credential readable
by group or others. On restart it launches a prior configuration only when its
bytes match the last durably confirmed digest. A stale, orphaned or modified
configuration degrades closed instead of being executed.

## Docker Compose

The container image is Linux `amd64` + `arm64`. Native release archives also
cover Linux, macOS and Windows on both architectures.

```bash
cp compose.example.yaml compose.yaml
install -d -m 0700 secrets
printf '%s\n' 'pspn_REPLACE_WITH_THE_ONE_TIME_VALUE' > secrets/node-credential
chmod 0600 secrets/node-credential
export PSP_NODE_ENDPOINT=https://panel.example/v1/node/sync
export PSP_NODE_AGENT_ID=agt_REPLACE_WITH_THE_ASSIGNED_ID
docker compose up -d
```

The example uses host networking because PSP can change the listener set and
ports dynamically; a fixed bridge-mode port list cannot represent that. The
entrypoint copies Docker's commonly mode-0444 secret into a private tmpfs file,
repairs only the persistent volume ownership, then drops permanently to UID/GID
10001. The root filesystem is read-only and the service keeps only the three
capabilities needed for that startup transition.

On Linux hosts where unprivileged processes cannot bind ports below 1024, use
listener ports at or above 1024 or deliberately configure the host's
`net.ipv4.ip_unprivileged_port_start`. The container does not retain root merely
to make port 443 convenient.

## Development and release gates

```bash
go test ./...
go test -race ./...
go vet ./...
```

CI repeats those checks, cross-compiles `cmd/node` for six targets, and builds
the container. A `v*` tag publishes archives plus `SHA256SUMS.txt` and a
multi-architecture GHCR image. `:latest` is stable-only; `:beta` follows the
newest release of either stability class.

## Contract harness

`cmd/contract-agent` deliberately uses a deterministic coreless runtime. It is
not the production daemon: it lets a control plane exercise the real agent
transport/state/apply/report stack without downloading or launching Xray.
The durable task/result protocol is implemented, but the harness advertises no
kind-specific task capability and therefore receives no tasks from a conforming
control plane. Production RealityProbe and AgentUpgrade handlers are likewise
intentionally absent until their input, deadline, recovery, and authorization
contracts are specified; silently dropping or guessing a future side effect is
not a compatibility strategy.

Deadline-aware infrastructure additionally requires `task.expiry.v1` alongside
execution and kind capabilities. `not_after_ms` is an immutable latest-start
deadline, not a completion timeout. The worker authorizes starts only from fresh
control-plane time bounds, checks again before handler entry, and never executes
an unknown expired replay or converts an already-running task into a new start.
Unknown unprovable requests produce a bounded deduplicated Issue, not a guessed
terminal result; existing terminal evidence remains replayable without a clock.

Linux/macOS have suspend-inclusive elapsed backends; Windows currently disables
expiry support without affecting proxy cores or synchronization. The daemon's
30-second anchor/RTT windows and one-second uncertainty allowance are operational
guard margins, not measured accuracy guarantees. Process restart requires a new
valid sync anchor. Database/VM restore safety, retention, and each kind's recovery
contract remain separate release gates; no production task handler is registered.
Schema v9 preserves v8 journals and outbox bytes, but older binaries cannot open
the upgraded database. Roll back the matching pre-upgrade database backup too.

```bash
go run ./cmd/contract-agent \
  -endpoint http://127.0.0.1:8788/v1/node/sync \
  -agent-id agt_example \
  -state ./data/contract.db \
  -rounds 2 \
  -allow-insecure-http
```

## Licence

TBD.
