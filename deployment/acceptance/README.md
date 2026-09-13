# Published Linux installation acceptance

This opt-in tool is only for fresh **GitHub-hosted Ubuntu 24.04 VMs**. Do not run
it on a developer machine, production server or self-hosted runner. It checks
the root/GitHub-hosted environment and refuses any existing installation,
systemd unit, installation lock or `passwall-node` account before mutation.

Dispatch `.github/workflows/installation-acceptance.yml` after the exact public
release (default `v0.0.1-beta4`) has finished publishing. Both `ubuntu-24.04` and
`ubuntu-24.04-arm` execute the real installer and the **published binary**, not a
locally built agent. The acceptance tool itself is built from the checkout.
Before beta4 publication, dispatch the candidate checkout with an explicit
`version=v0.0.1-beta3` to test the new installer against the existing public binary.

The fixture generates an independent temporary AgentID and credential, listens
only on `127.0.0.1` with HTTPS beneath a PSP-shaped panel prefix, and requires the
real Bearer credential. Only the disposable runner temporarily trusts its
dedicated self-signed CA. Config, roster and directives are fixed empty streams;
the real daemon installs/runs its catalog-approved Xray core, but this test adds
no production proxy listeners or clients.

The gate checks:

- All six installer phases occur once and in order on fresh install, offline
  rerun and fresh reinstall. Download/skip feedback must match the actual path;
  startup-only notices remain distinct from the core/report checks below. Only
  safe assertion counts and booleans are printed, never captured private output.
- Real systemd `active/running`, MainPID and all process UIDs non-root, plus an
  authenticated fresh report followed by acknowledgement of all three streams.
- Exact published version verification by the unmodified installer; private
  script/files mode `0600` and config/data directories mode `0700`.
- No fixture credential in agent cmdline/environment, unit/environment file,
  journal, systemd properties or any captured installation-command output.
  Private evidence is never printed or uploaded, including on failure.
- Same-script offline rerun through `unshare --net`, without fake commands or
  installer/unit changes. The already active agent is briefly SIGSTOP-paused so
  SQLite DB/WAL/SHM bytes and inodes can be compared without heartbeat writes.
  The installer remains offline; this is **not** an offline-runtime test.
- Same PID and unchanged binary/config/credential/unit hashes after rerun,
  followed by SIGCONT and a new authenticated report.
- Stopping and removing only the run-owned node directory/unit, reinstalling
  with the same credential/AgentID, and observing a fresh report then the same
  three stream identities. Successful core telemetry must persist a new local
  counter epoch. This is probabilistic reinstall separation, not rollback
  detection or a proxy-traffic accounting proof.

Cleanup verifies a run-specific ownership marker and matching credential before
removing `/opt/passwall-node`. A unit must be a regular file matching this run's
own bundle before it can be removed; foreign units are never claimed. The tool
removes its own private temporary directory and dedicated CA, and refreshes the
runner trust store. The service account exists only on the disposable VM and is
discarded with that VM. No private scripts, proc data or raw journal artifacts
are retained by the workflow.

This is an **empty-stream authenticated TLS/systemd/repeat/offline/reinstall**
gate. It does not stand in for real PSP registration/UI/business acceptance,
proxy handshake/traffic/quota tests, credential rotation or PSP/VM restoration.
Local development should run only unit tests and Linux cross-compilation.

Primary operational references:

- [GitHub-hosted runner isolation, architectures and administrative privileges](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
- [Ubuntu root CA trust installation/removal](https://ubuntu.com/server/docs/how-to/security/install-a-root-ca-certificate-in-the-trust-store/).
- [systemctl machine-readable properties including MainPID](https://raw.githubusercontent.com/systemd/systemd/main/man/systemctl.xml).
- [util-linux unshare network namespaces](https://raw.githubusercontent.com/util-linux/util-linux/master/sys-utils/unshare.1.adoc).
