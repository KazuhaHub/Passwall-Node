# Executable core acceptance

The `real-core` job in `.github/workflows/test.yml` runs on native Linux amd64 and arm64
GitHub-hosted runners.
It downloads every selectable catalog Xray (**26.6.27**, **26.7.28**, and the
restricted **26.9.9** and **26.11.9**), plus the recommended sing-box **1.14.0**,
through the production core
installer, including catalog archive SHA256 checks and exact executable version
verification. The test-only Mihomo **1.19.30** client is pinned to an official
release asset SHA256; amd64 uses its v1 CPU-baseline asset. No moving release,
private credential, external proxy endpoint or production host is involved.

The fixture enables the existing gated tests and runs them with `-count=1`:

- Official Xray and sing-box installer integrations, including downloaded
  archive verification and real executable configuration checks.
- Xray 26.6.27, 26.7.28, 26.9.9 and 26.11.9 compiler and destination-policy artifacts
  accepted by the real binaries, and destination policy enforced end to end by
  each of them. The 26.6.27 binary is also the client of those harnesses.
- sing-box 1.14.0 compiler artifacts accepted by the real binary.
- sing-box daemon API authenticated subscribe/reset wire compatibility.
- A real sing-box VLESS/TCP/REALITY/XTLS-Vision server, local TLS decoy and local
  HTTP target, exercised through Xray, Mihomo and sing-box SOCKS clients. Each
  client must carry HTTP traffic with the expected response body and header.

A second job, `image-cores`, runs on the same two architectures INSIDE the
runtime image the `Dockerfile` builds (Alpine, musl), as the image's
unprivileged user with a read-only root: a static build of the installer tests
downloads, checks and executes the recommended Xray and sing-box there, with
`PSP_TEST_EXPECT_LIBC=musl` pinning what the installer must detect. The Ubuntu
runners above are glibc hosts and cannot see a core that only fails on musl —
sing-box's plain Linux build is linked against glibc and passed them while it
could not start in the Docker image. That job's evidence is checked with
`coreacceptance check --profile image`.

The JSON checker requires every executable leaf test, including one subtest per
Xray version, each parent test and all three packages to run and pass exactly
once. Any skip, failure, missing
test or pass without a preceding run fails acceptance. Exact source/digest/
version metadata and `go test -json` execution evidence are retained as CI
artifacts, including partial evidence on failure. Ordinary unit-test runs still
skip these optional downloads; those skips are **not** acceptance evidence.

This gate does not claim real end-to-end traffic metering, production firewall
or sysctl changes, systemd deployment acceptance, or Windows/macOS Linux parity.
The fixture also supports local Darwin arm64 runs; that is local macOS evidence
only. Updating any recommended version requires a deliberate fixture pin and
fresh executable evidence update. The Xray pins must equal the selectable
catalog releases in both directions: adding or retiring one in
`corecatalog/catalog.json` fails `prepare` until the pins, the exported
variable, the required subtests in `check.go`, and the version tables in
`internal/core/xray/compiler_test.go` and `policy_test.go` are updated together
(a version left in those tables without a binary skips, and `check` fails on any
skip). Pulling a release urgently therefore means one change across all of them.

sing-box releases other than the recommended one are not pinned here: the
fixture exports one sing-box binary, the recommended one. A verified sing-box
release (such as **1.14.4**) is reviewed by running this suite locally with
`PSP_TEST_SING_BOX_BIN` pointing at that release, on glibc and inside the
Alpine image for its musl build; its catalog evidence names the platform it
ran on.

For a local run, disable any parent workspace so the module's pinned toolchain
and dependencies are used, then prepare a private absolute directory and
environment file:

```sh
export GOWORK=off
go run ./deployment/coreacceptance prepare \
  --directory /absolute/private/core-acceptance \
  --env-file /absolute/private/core-acceptance.env
```

The environment file uses GitHub's `NAME=value` format, not shell quoting. Do
not source it as a shell script. Export its values explicitly or use the
same GitHub Actions steps, then run the three commands from the workflow and
pass their concatenated JSON stream to `coreacceptance check --results FILE`.
