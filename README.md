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

The build toolchain is pinned to `go1.26.8` in `go.mod` (`go 1.26.0` is the
minimum language/toolchain requirement). CI selects that preferred toolchain
without automatic switching and inspects all six release binaries. Source
container builds use the same compiler; both container paths use Alpine
`3.24.1`. `v0.0.1-beta1` remains testing-only because it was built with the
older Go/Alpine baselines; its published artifacts are not replaced.

Create a **PSP Node** on PSP's Servers page. PSP assigns a stable agent ID and a
long-lived credential for that logical server. Authentication uses its SHA-256
digest; the administrator can retrieve the same credential/private installer
later from an encrypted recovery copy. Save the credential as a private regular
file through a private channel (not a shell command containing the value), then
start the daemon:

```bash
install -d -m 0700 /etc/passwall-node /var/lib/passwall-node
install -m 0600 /private/path/to/credential /etc/passwall-node/credential

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
install -d -m 0700 config data upgrades
install -m 0600 /private/path/to/credential config/node-credential.txt
export PSP_NODE_ENDPOINT=https://panel.example/v1/node/sync
export PSP_NODE_AGENT_ID=agt_REPLACE_WITH_THE_ASSIGNED_ID
export NODE_VERSION=vREPLACE_WITH_AN_EXPLICIT_PUBLISHED_RELEASE
docker compose up -d
```

The example uses host networking because PSP can change the listener set and
ports dynamically; a fixed bridge-mode port list cannot represent that. The
entrypoint copies the read-only credential into a private tmpfs file, repairs
only the persistent data-directory ownership, then drops permanently to UID/GID
10001. The root filesystem is read-only and the service keeps only the three
capabilities needed for that startup transition. Keep the credential mount
read-only: the Agent never needs to modify it. The data mount must be writable.
The generated/default Compose consistently mounts explicit project directories:
`./config` read-only, `./data` read-write, and `./upgrades` for the optional
updater. The root entrypoint repairs the bind-directory owner before dropping
privileges; on storage that forbids ownership changes, set `PUID` and `PGID` to
the directory owner. Create the regular `./config/node-credential.txt` before
the first `docker compose up`. Mounting the directory instead of an individual
host file prevents NAS Compose implementations from turning a missing file bind
source into a directory.

Agent-owned log lines use a UTC timestamp, severity and component in the same
line-oriented shape Xray and the panel use, so a managed core and the Agent read
as one stream in the journal:

```
2026/09/17 08:15:36.091882 [Info] passwall-node: sync completed
```

Core subprocesses retain their upstream log format. The Compose example also
bounds Docker's `json-file` logs to three 10 MiB files.

The optional `passwall-node-updater` service enables PSP's authenticated remote
upgrade task for Docker deployments. The network-facing Agent never receives
the Docker socket. Only the isolated, network-disabled updater mounts it; Docker
socket access is nevertheless root-equivalent on the host, so deploy this helper
only on a trusted node host. It accepts official exact release tags, retains the
stopped previous container, and commits only after the replacement Agent has
authenticated to PSP and converged its core configuration. A failed or timed-out
replacement is removed and the retained container is restored automatically.
If the Docker Engine fails part-way through that rollback, the task ends
`indeterminate` for an operator to inspect, but the updater first starts one
container so the node keeps serving and can report; the task's error names it.
When that is the previous container still running under its
`passwall-node-agent-upgrade-…` backup name, rename it back to
`passwall-node-agent` before the next `docker compose up`. Otherwise Compose
starts a second Agent with the same identity beside it.

On Linux hosts where unprivileged processes cannot bind ports below 1024, use
listener ports at or above 1024 or deliberately configure the host's
`net.ipv4.ip_unprivileged_port_start`. The container does not retain root merely
to make port 443 convenient.

## Linux systemd installation

For a credential-free GitHub installation, run the public bootstrap on the
target Linux/systemd host. With no arguments it installs the newest Stable
release and opens `pn connect` to enter the endpoint, agent ID and credential
shown by PSP:

```bash
curl --disable --fail --silent --show-error --location --proto '=https' \
  https://raw.githubusercontent.com/KazuhaHub/Passwall-Node/main/install.sh | sudo sh
```

The credential is read from the terminal without echo and is never embedded in
that command. If setup is interrupted after the program is installed, resume
with `sudo pn connect`. The public installer never replaces an existing
installation or an unrelated `pn` command.

Prefer the explicit channel option in automation. Arguments after a shell pipe
must be passed after `sh -s --`:

```bash
curl --disable --fail --silent --show-error --location --proto '=https' \
  https://raw.githubusercontent.com/KazuhaHub/Passwall-Node/main/install.sh | \
  sudo sh -s -- --channel beta
```

Use `--channel stable` to state the default explicitly. With no channel
argument, both interactive and non-interactive runs use Stable. `PN_CHANNEL`
remains supported for compatibility, but the command-line option takes
precedence.

To install the program and `pn` command without configuring or starting the
Agent, pass `--install-only`; connect it later with `sudo pn connect`:

```bash
curl --disable --fail --silent --show-error --location --proto '=https' \
  https://raw.githubusercontent.com/KazuhaHub/Passwall-Node/main/install.sh | \
  sudo sh -s -- --install-only
```

For a host that cannot reach GitHub, download the exact Linux archive and
`SHA256SUMS.txt` on a connected administrator device, verify the archive there,
and transfer the archive to the target through a trusted channel. Extract it
without renaming the generated package directory, enter that directory, then
run the bundled public installer in offline mode:

```bash
sha256sum --check --ignore-missing SHA256SUMS.txt
tar -xzf passwall-node_vVERSION_linux_ARCH.tar.gz
cd passwall-node_vVERSION_linux_ARCH
sudo ./install.sh --offline
```

`--offline` reads only the binary, LICENSE and NOTICE beside the script and
does not contact GitHub. Combine it with `--install-only` when the PSP endpoint,
Agent ID or credential is not yet available. The PSP manual-install view lists
the exact archive/checksum links and all three connection values for the
selected server.

PSP also offers a private one-click path for an already registered identity.
That path remains version-pinned and preconfigured:

The public Go package `deployment` renders a **private** installer for an
already registered PSP identity and an explicitly selected, already published
Node release. PSP can generate it with `deployment.RenderLinux(Options{Endpoint,
AgentID, Credential, Version})`. The endpoint must use HTTPS; a PSP path prefix
before `/v1/node/sync` is supported. The version must be an explicit
`vMAJOR.MINOR.PATCH[-prerelease]`, never `latest` or an arbitrary download URL.
This does not mint an identity, redeem a bootstrap token or publish a release.

Save the rendered script as mode 0600, transfer it through a private channel,
and run `sudo sh /absolute/path/to/private-install.sh` on Linux amd64/arm64 with
systemd. The script itself contains the long-lived credential: never put its
contents in command arguments, shell history, tracing, shared logs or a public
URL. Remove that private file after use. The `deployment/install.sh` included
in release archives is an unrendered template, not a public bootstrap script.

The installer downloads only the exact release tag from this repository using
HTTPS with timeouts, selects one exact `SHA256SUMS.txt` entry, and verifies the
archive before reading only its regular binary, LICENSE and NOTICE members.
Checksums authenticate neither an independent publisher nor a compromised
GitHub release; that release and its HTTPS delivery remain trusted inputs.

Installation uses a dedicated non-login `passwall-node` account. Its credential
is mode 0600 under `/opt/passwall-node/config`; configuration and persistent
data directories are mode 0700. The systemd unit contains only the credential
file path, not its value, and gives the non-root daemon only
`CAP_NET_BIND_SERVICE` so PSP-owned listeners can use port 443 without changing
host sysctls. Existing 3X-UI/sing-box services, firewall and host networking
configuration are not taken over or modified; choose non-conflicting ports.

A same-identity/endpoint/credential/version rerun is offline and preserves state.
Any differing or incomplete installation, or unrelated systemd unit, requires
manual inspection; there is no automatic upgrade, credential rotation or
rebind. Stop the old machine before reinstalling a replacement with the same
credential; credentials bind a logical server, not a physical machine. Reusing
the same identity does not update a changed public proxy address in PSP.
Failed downloads do not publish a partial identity. A systemd failure
retains the complete installation and state so the same private script can be
retried. Back up the matching private config and data before any manually
planned upgrade or migration; never erase the database to work around a rebind.

### Local management with `pn`

Both installation paths create `/usr/local/bin/pn` as a managed link to the
installed Passwall Node binary, so the menu and daemon always upgrade together.
Run `pn` for the interactive menu or use direct commands in automation:

```text
pn status
pn start | stop | restart
pn logs --follow
pn doctor
pn connect
pn config
pn rebind
pn backup
pn repair
```

`pn connect` configures only an unconfigured installation. `pn rebind` is a
separate, explicit operation: it stops the service, retains the old identity
and runtime state in a private backup, starts with fresh runtime state, and
requires typing `REBIND`. Neither command prints the credential. If a different
program already owns the `pn` name, the installers and repair command fail
closed instead of replacing it.

`pn backup` briefly stops an active service, copies the private `config/` and
`data/` trees plus the installed service definition into a root-only snapshot
under `/opt/passwall-node/backups/`, and then restarts the service even when a
copy fails. It rejects symlinks and special files instead of following them.
Automatic restore is deliberately not offered: restoring identity and runtime
state is a maintenance operation that should be inspected and performed while
the service is stopped.

## Development and release gates

```bash
go test ./...
go test -race ./...
go vet ./...
```

CI runs the suite once, under the race detector, vets it, cross-compiles
`cmd/node` for six targets, and builds the container. A `v*` tag publishes
archives plus `SHA256SUMS.txt` and a multi-architecture GHCR image. `:latest`
is stable-only; `:beta` follows the newest release of either stability class.
The tagged commit must be on `main`, and its Test run there must have
succeeded; the release waits for that run and refuses any other conclusion, so
a cancelled or failed run is re-run first.
The image, and with it `:beta` or `:latest`, is pushed only after the approved,
signed release is published. If the image job fails, the release stays
published without an image, and the pointers stay where they were, until that
failed job is re-run.
The container and installation acceptances run by themselves on amd64 and
arm64 after every release, and `promote.yml` promotes a release to Stable only
once both have passed on it.

## Contract harness

`cmd/contract-agent` deliberately uses a deterministic coreless runtime. It is
not the production daemon: it lets a control plane exercise the real agent
transport/state/apply/report stack without downloading or launching Xray.
The durable task/result protocol is implemented, but the harness advertises no
kind-specific task capability and therefore receives no tasks from a conforming
control plane. Reality probing remains unimplemented. The production daemon
registers `agent.upgrade.v1` only for a managed Linux/systemd installation with
its separate root-owned upgrade helper explicitly enabled. The contract harness
does not perform upgrades.

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
valid sync anchor. Database/VM restore safety and general task-journal retention
are not provided by remote upgrading; do not infer them from lifecycle settings.
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

## Remote agent upgrades (Linux/systemd)

PSP administrators request an **exact newer published PN release**, with an
expected current release and an idempotency key. The existing authenticated
sync/task channel delivers it only to agents advertising execution, expiry and
`task.agent.upgrade.v1`. There is no SSH requirement, floating `latest`, arbitrary
download URL, shell command or additional public node endpoint.

The daemon stays non-root with its original filesystem sandbox. A separate
root-owned systemd path/oneshot controller downloads the official archive,
authenticates the release checksum manifest with the Ed25519 public key compiled
into the agent, checks the selected archive's SHA-256 and native build identity,
then stops the agent gracefully and atomically replaces its binary, version
metadata and bundled licence files. The signature is verified before the
archive is downloaded, extracted or executed; a replacement archive plus a
matching replacement checksum file is therefore rejected without the separate
release-signing key.

Agents predating signed-manifest verification cannot authenticate the first
signed release retroactively. Install that transition release through a
manually verified maintenance path; every later native upgrade then fails
closed unless the manifest has a valid release signature.

Credential, endpoint, identity, SQLite state and desired core selection are
retained. The helper confirms the new non-root MainPID/executable digest plus
fresh local activation evidence after authenticated sync and **strict** core
convergence; only then does the restarted agent return a successful task result.
PSP additionally requires a fresh matching reported version before showing
verified success. Activation evidence assumes a trusted daemon/service UID; it
is not remote attestation against an already-compromised node.

The start authorization is ten minutes, tied to same-boot suspend-inclusive time.
It is checked again after backup preparation, immediately before stopping the
daemon. Customized systemd drop-ins or an unverified current service process
require manual maintenance and are rejected before downloading or stopping it.
Download failures leave the running agent untouched. Startup/readiness failures
restore the retained previous managed files and restart them. If that restore
itself cannot run — a full disk, an I/O error — the outcome is indeterminate and
needs a person, but the daemon is still brought back first: what is installed at
that point is either the retained previous release or a target that already
passed the signed manifest, its exact digest and its own version self-report, and
one of those running beats the node sitting stopped. A binary matching neither is
not started. Interrupted tasks
read durable receipts rather than blindly download/execute again. **Only equal
state schemas and upgrade-contract versions support automatic upgrade/rollback.**
Changes to either require manual maintenance. No database/VM snapshot framework
is added. Persisted counters survive, but traffic not sampled before a core stop
has the existing restart metering gap; do not promise lossless byte accounting.

New installations of a supporting binary configure the helper automatically.
Existing `v0.0.1-beta2` installations cannot execute an upgrade task: first
perform one manual binary maintenance update after a supporting release is
published, preserving `/opt/passwall-node/config` and `data`, then run the
installed binary as root with `--enable-remote-upgrade` and restart the agent.
The private install script deliberately refuses cross-version replacement;
do not delete state or recreate PSP server/node rows to bypass that guard.
Generated Docker installations can use the separate updater sidecar described
above. Existing single-container Docker installs and other operating systems use
host-managed/manual updates until they are deliberately migrated; never add the
Docker socket to the Agent container itself.

The helper retains at most three completed managed-file backups; it never
prunes live, indeterminate or foreign evidence. General terminal journals and
small immutable receipts are not automatically garbage-collected.
Keep disk monitoring and ordinary backups; lifecycle retention settings alone
do not constitute a GC implementation or database-restore guarantee.

### Panel / Node compatibility policy

PSP and Passwall Node do not use a lockstep version requirement. Sync documents
remain additive, and optional work is offered only when the Agent advertises the
matching capability; upgrading PSP therefore does not itself replace or disable
older connected Agents. A future incompatible wire change must ship as a new
capability or parallel protocol before the old path is retired, with an explicit
maintenance release for existing nodes.

Automatic Agent upgrades are narrower: source and target must publish the same
state-schema and upgrade-contract numbers. A release that changes either number
is deliberately refused by both the systemd helper and Docker updater and must
be migrated manually. Floating `latest` / `beta` image tags select an installation
channel, but PSP always dispatches an audited exact release to the upgrade task.

## Licence

Passwall-Node's own code, including `protocol` and `corecatalog`, is licensed
under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for
project attribution. Passwall-Sub-Panel retains its existing AGPLv3 license.

Third-party dependencies and the separately installed proxy cores retain
their own licenses; this project's Apache license does not replace them:

- Xray-core: [MPL-2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE).
- sing-box: [GPL-3.0-or-later](https://github.com/SagerNet/sing-box/blob/testing/LICENSE),
  with its additional naming/association notice.

Native release archives include `LICENSE` and `NOTICE`; container images keep
them in `/usr/share/licenses/passwall-node/`. Those releases do not bundle
Xray or sing-box: the daemon downloads the exact selected core at runtime.
If you redistribute a populated data directory or an image containing those
cores, preserve their copyright/license notices and meet their respective
source-availability requirements. This attribution notice is not a complete
third-party license audit.
