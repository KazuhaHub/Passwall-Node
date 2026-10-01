# Disposable source upgrade acceptance

The `upgrade-systemd` jobs in `.github/workflows/test.yml` run natively on
GitHub-hosted Ubuntu 24.04 amd64 and arm64 machines. They require no real PSP
account, VPS, production credential, or newly published module.

`TestUpgradeSystemdProcInspection` independently runs the actual helper's
restricted systemd sandbox properties and confirms cross-UID `/proc/PID/exe`
inspection with its explicit capability allowlist.

`TestUpgradeSystemdRealNodeE2E` is opt-in (`PN_NODE_UPGRADE_E2E=1`) and refuses
mutation unless a guarded root test child runs on a disposable GitHub-hosted
Ubuntu machine with systemd PID 1, no existing installation/account, and all
three fixed units absent from every systemd search path. Do not run it on a
developer machine or existing server.

CI builds the current real daemon three times with synthetic versions
`v1.0.0`, `v1.1.0`, and `v1.2.0`; these names are test stamps, not releases.
The first version authenticates against a private local HTTPS fixture and
downloads a catalog-approved real Xray core through its normal installer.
Subsequent processes reuse the installed core and existing SQLite database.

The fixture negotiates capabilities and sends actual deadline/input-bound tasks.
The old daemon durably claims the task and writes the private request; the
privileged controller performs production validation, systemctl stop/start,
atomic activation, nonce/PID/UID/executable-digest checks, and rollback.
The new/restored real daemon recovers the original journal row, converges its
real core, authenticates, reports the terminal result, and acknowledges its
outbox. The test verifies fixed credential/environment bytes and unchanged
identity/data/database inodes. A root-owned test-only startup gate in the base
unit rejects only `v1.2.0`, causing real systemctl startup failure and a confirmed
return to `v1.1.0` without replacing data or credentials.

Boundaries: only the controller's fetch function is replaced by an exact
locally built real Candidate. The path watcher is intentionally not started,
so the production CLI helper cannot race to download synthetic version tags.
This E2E does not execute the published-archive→production-watcher combination;
official HTTPS/checksum/archive safety and actual helper sandbox permissions
have separate gates. The control plane uses empty streams, not the PSP app;
actual nonempty proxy traffic, quotas, and billing remain separate acceptance.
No database snapshots, schema downgrade, or VM restore detection is added.

The disposable fixture's CA is scoped with `SSL_CERT_FILE` in its own unit;
the host trust store is not modified. Private subprocess/journal output is
withheld, and no credential-bearing artifacts are uploaded. Cleanup checks
the run nonce, fixture credential, exact owned unit bytes, and allowed owners,
then removes individually validated entries bottom-up; foreign units or
changed provenance stop cleanup.

# Docker updater acceptance

`.github/workflows/docker-updater.yml` runs the Docker updater against a real
daemon on GitHub-hosted Ubuntu 24.04 amd64 and arm64 machines, for changes to
`internal/upgrade`, `cmd/node`, the Dockerfiles, the entrypoint or the example
compose, on dispatch, and weekly, because Docker moves under it. It needs no PSP,
registry account or published release, and pulls nothing.

It is deliberately not part of `test.yml`, whose every job a release waits for:
it answers questions about Docker and the runner image as much as about the
commit. **A release that changes the updater is tagged only after this workflow
is green on the release commit on both architectures.** That is a release
checklist item, not something `release.yml` enforces.

Both tests are opt-in (`PN_DOCKER_UPDATER_E2E=1`) and re-execute themselves as
root through `sudo` only on a disposable GitHub-hosted runner with no containers
of its own: they SIGKILL host processes and restart the Docker daemon. Do not run
them on a developer machine, a Lima VM or a server.

The `assumptions` job, `TestDockerEngineAssumptions`, probes the Docker
behaviour the updater's self-upgrade is built on, in containers built `FROM
scratch` around the test binary itself: a container finds its own ID through
`/proc/self/mountinfo` (A1); an `flock` on a bind-mounted directory excludes a
second container and dies with its holder (A2); a renamed container keeps its
restart policy across a daemon restart (A3); an Engine API create of an absent
image returns 404 and pulls nothing (A4); a host-PID SIGKILL is a crash the
restart policy recovers and counts, an API stop is not restarted even by a
daemon restart (A5); a created, never-started container stays so across a daemon
restart (A6); Compose leaves alone a clone that carries the original's labels and
removes it on `down` (A7); a clone without a hostname gets its own (A8); and a
container's image ID is its tag's (A9).

The `handover` job needs `assumptions`. It builds `Dockerfile.release` twice, at
the never-published versions `4.0.99.1` (the updater) and `4.0.99.2` (the
agent), tagged locally under the official repository, and runs
`TestDockerUpdaterFollowsAgentE2E`. Each scenario starts
`testdata/e2e/psp-compose.yaml` — the compose PSP generates for a Docker node with
remote upgrade on, unchanged — with `testdata/e2e/e2e-agent-override.yaml`, which
only names each service's local image, forbids pulling it, and makes the agent
sleep; the updater checks what the agent is, never what it runs. The evidence an
agent upgrade leaves in `receipts/` is written before the updater starts, so every
scenario is also the catch-up case. Throughout each one the agent's identity,
start time and restart count, the heartbeat's age (at most ten seconds outside a
window the scenario breaks on purpose) and the absence of image pulls are
sampled.

- E1: the happy path, on the panel's compose and on `compose.example.yaml`. One
  updater is left, under its own name, on the agent's image, the journal says
  `completed`; then `compose up -d` recreates nothing and `compose down` removes
  everything.
- E2: an agent Compose recreated after the evidence was written is never followed.
- E3: the predecessor SIGKILLed by host PID after creating its successor restarts,
  aborts, and does not try again inside its back-off.
- E4: the successor SIGKILLed in standby is restarted by Docker, so the handover
  aborts and the successor is removed.
- E5: `systemctl restart docker` mid-handover leaves one updater, heartbeating.
- E6: evidence recording a digest the successor cannot prove ends `aborted` at the
  predecessor's deadline, with no proof written.
- E7: an agent request written during standby pre-empts the handover without
  counting an attempt, and the predecessor writes its receipt.
- E8: `compose up --force-recreate` of the updater mid-handover leaves exactly one
  updater, the primary, and nothing the handover named. Compose's own handling of
  two containers of one service is not settled, so a Compose error there is
  logged and the command run once more, as an operator would.
- E9: `PSP_NODE_UPDATER_FOLLOW_AGENT=false` logs `handover: disabled (opt-out)`
  and creates nothing.
- E10: a plain `compose up -d` mid-handover, which reconciles the two containers
  carrying the updater service's labels to one, leaves exactly one updater under
  the service's name, the primary. Which container Compose keeps differs between
  its releases and both are accepted: the predecessor, with the handover aborted,
  or the successor, which the stopped predecessor left standing and which then
  took over. The runner's Compose may show only one of the two; the other is
  unit-tested against the fake engine.

Boundaries: the agent upgrade that would install the newer image is not run —
that needs a PSP authorization and a registry answering as `ghcr.io` — and the
Docker agent swap stays unit-tested against a fake engine. The
successor's post-commit reclaim is unit-tested only: its window cannot be hit
reliably from outside the process. Signed-digest verification of Docker images
does not exist yet, in the agent upgrade or here.
