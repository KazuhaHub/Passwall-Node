# Executable core acceptance

`core-acceptance.yml` runs on native Linux amd64 and arm64 GitHub-hosted runners.
It downloads all three catalog Xray versions (**26.6.27**, **26.7.28**, **26.9.9**)
and sing-box **1.14.0** through the production core
installer, including catalog archive SHA256 checks and exact executable version
verification. The test-only Mihomo **1.19.30** client is pinned to an official
release asset SHA256; amd64 uses its v1 CPU-baseline asset. No moving release,
private credential, external proxy endpoint or production host is involved.
The disposable fixture explicitly opts into restricted Xray 26.9.9; production
installation and REALITY client-compatibility consent remain unchanged.

The fixture enables the existing gated tests and runs them with `-count=1`:

- Official Xray and sing-box installer integrations, including downloaded
  archive verification and real executable configuration checks.
- All three Xray versions and sing-box 1.14.0 compiler artifacts accepted by real binaries.
- sing-box daemon API authenticated subscribe/reset wire compatibility.
- A real sing-box VLESS/TCP/REALITY/XTLS-Vision server, local TLS decoy and local
  HTTP target, exercised through Xray, Mihomo and sing-box SOCKS clients. Each
  client must carry HTTP traffic with the expected response body and header.
- Private usage traffic through the production Xray compiler, process output
  factory, filter and authenticated hit receiver on all three pinned versions.
  Direct, observe and trial requests reach a local HTTP target and each count
  one usage event; deny does not reach it or count usage. Observe/trial/deny
  also require their separate hit, with anonymous trial fields. Raw access
  lines and fixture account emails must not appear in forwarded daemon output.

The JSON checker requires every executable leaf, parent and all four packages
to run and pass exactly once. Any skip, failure, missing
test or pass without a preceding run fails acceptance. Exact source/digest/
version metadata and `go test -json` execution evidence are retained as CI
artifacts, including partial evidence on failure. Ordinary unit-test runs still
skip these optional downloads; those skips are **not** acceptance evidence.

This gate does not claim real end-to-end traffic metering, production firewall
or sysctl changes, systemd deployment acceptance, or Windows/macOS Linux parity.
The fixture also supports local Darwin arm64 runs; that is local macOS evidence
only. Updating any recommended version requires a deliberate fixture pin and
fresh executable evidence update.

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
not source it as a shell script. Export its eight values explicitly or use the
same GitHub Actions steps, then run the test commands from the workflow and
pass their concatenated JSON stream to `coreacceptance check --results FILE`.
