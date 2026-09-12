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
