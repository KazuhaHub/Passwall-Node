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
B03: the older panel accepted a report carrying fields it predates, and carries none of them itself
B04: an absent capability stayed absent (state=limited ready=None)
B07: stopping v4.0.0-beta.19 with the agent still running
B07: the agent kept its last valid config across the outage (sha256 b35ebf2bd0b2)
B07: restarting the panel
B07: the node re-converged after the panel returned (compatibility=limited)
PASS: v4.0.0-beta.19 accepted the candidate agent (compatibility=limited 1 4)
```

The candidate agent authenticated, pulled its configuration, started a real
Xray core, and reported protocol version 1 with four capabilities. `limited`
rather than `compatible` is correct: the upgrade helper is not enabled, which is
ADR 0033's stated behaviour for a node with base sync but no upgrade capability.

**B07** takes the panel away underneath that running agent and restarts it. The
assertion is the applied config's **digest**, not the agent's liveness — "still
running" is also true of an agent that threw its configuration away and is
idling, and a node that dropped its config when its panel went away would take
the user's traffic down with it.

## The negative control

A green harness proves nothing until it is shown able to fail. Run the same case
with an agent that does not sync, and it must report the failure:

```bash
PSP_CANDIDATE_AGENT=/bin/true ./deployment/compat/old-psp.sh
```

```
candidate node state: unknown None 0
control node state:   unknown None 0
FAIL: the old panel still reports the candidate node as unknown; it never accepted a report
```

The **control node** is the other half of that: it is created and never given to
the agent, so a panel that reported every node as observed fails the run instead
of looking like a pass.

## Scope

The cases present are **B01** (first contact: authenticate, pull, apply, report,
read back out of the old panel's API), **B03**, **B04** and **B07** (control-plane
loss and return).

Still missing from the plan's B01–B08 set, and each needing the harness to drive a
state it does not yet drive: **B02** (user add, credential update, disable,
expiry, quota — the node-side config that follows), **B05** (capability withdrawal
or helper disabled, and the panel then admitting no new upgrade task), **B06**
(unknown task kind, expired task, replayed result) and **B08** (a protocol
generation the old panel does not understand, refused with a diagnostic rather
than looped).

