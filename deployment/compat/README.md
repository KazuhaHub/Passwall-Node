# Reverse-direction compatibility

`old-psp.sh` runs the **candidate agent in this repository** against a
**released** old PSP, and reads the result out of the OLD panel's own API.

```bash
PSP_CANDIDATE_AGENT=/path/to/passwall-node ./deployment/compat/old-psp.sh
```

## Why the old panel decides the result

It would be easy to run the agent, watch it start a core, and call the direction
verified. That proves the agent works; it does not prove the two implementations
agree. So the assertion is that the old panel's `node_compatibility` for that
node **leaves `unknown`** — which only happens if it authenticated the report,
parsed the protocol version and capabilities, and persisted them.

A **control node** is created and never given to the agent. Without it, a panel
that reported every node as observed would look like a pass.

## What it refuses to do

- It does not run this repository's binary wearing an old version string. The old
  panel is the released artifact, downloaded and **SHA-256 verified against the
  published sums** before anything runs, running its own dependencies.
- It does not patch the old panel's parsing, coordination or storage. If the
  candidate needs the old panel changed, that is the finding.

## Measured

Against `v4.0.0-beta.19` (commit `8f4b59f`), from an empty machine:

```
candidate node state: limited 1 4
control node state:   unknown None 0
PASS: v4.0.0-beta.19 accepted the candidate agent (compatibility=limited 1 4)
```

The candidate agent authenticated, pulled its configuration, started a real
Xray core, and reported protocol version 1 with four capabilities. `limited`
rather than `compatible` is correct: the upgrade helper is not enabled, which is
ADR 0033's stated behaviour for a node with base sync but no upgrade capability.

## Scope

This is the reverse direction's **base management profile, first case**. The full
B01–B08 set in the remediation plan — capability withdrawal, task expiry and
replay, control-plane loss, an incompatible protocol generation — is not here.
It needs a harness that drives those states, not just first contact.
