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
B02: the panel recorded the client as applied to the node after 60s (applied|u2@psp.local|2)
B02: the node confirmed a new configuration after the disable (version 2 -> 3; synced)
B05: the capable node was admitted and has its task row (HTTP 202)
B05: the incapable node was refused (HTTP 400) and wrote no task row
B06: N/A — v4.0.0-beta.19 has no node-diagnostics route (HTTP 200 served the SPA), and no such task was queued
B07: stopping v4.0.0-beta.19 with the agent still running
B07: the agent kept its last valid config across the outage (sha256 b35ebf2bd0b2)
B07: restarting the panel
B07: the node re-converged after the panel returned (compatibility=limited)
B08: the panel refused protocol generation 99 with a diagnostic, stored nothing and queued nothing (HTTP 400)
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

**B05** and **B08** are both *differential*, and in both cases the first version
of the case was one-sided and proved nothing:

- B05 asks the same upgrade request of two nodes whose only difference is the
  capability they report. The incapable one being refused says nothing on its own
  — a panel that refuses everything looks identical — so a second node is given
  the full capability set by a forged report, and must be admitted.
- B08 sends a report whose protocol generation the panel does not know. It is
  otherwise complete, because a 400 produced by a malformed field would satisfy
  "it was refused" while saying nothing about protocol handling. An earlier
  version did exactly that and passed for the wrong reason.

Neither can see the *reason* the panel refused the upgrade: every validation
error on that route is flattened into one string by the handler, so an ineligible
node and a malformed request are indistinguishable from the response. The case
asserts what is observable and says so rather than implying it checked more.

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

Present: **B01** (first contact: authenticate, pull, apply, report, read back out
of the old panel's API), **B02** (a user reaches the node, and the node confirms a
new configuration when the user's service is suspended), **B03**, **B04**, **B05**
(upgrade admission gated on the reported capability), **B07** (control-plane loss
and return) and **B08** (an unknown protocol generation refused by name).

**B06 — N/A, and the reason is a version fact.** `node-diagnostics` was added on
2026-09-18 (PR #133); `v4.0.0-beta.19` was published 2026-09-17. The route is
absent, so the request falls through to the SPA catch-all and comes back **200
with an HTML page** — which is why the case is written to detect the SPA marker
rather than a 404. The plan allows a missing optional feature to be N/A provided
the panel is also shown not to dispatch it, and the case asserts exactly that:
no `diagnostics.collect.v1` row exists.

The expiry half is unreachable for this **pair** as well, and that is a property
of the versions rather than of the harness: the only kind this panel can mint is
`agent.upgrade.v1`, and B05 shows in the same run that it refuses to mint one for
this candidate, which reports no upgrade helper. There is therefore no task the
agent could have accepted, expired or not.

## B02 cost four runs, and three of them were this harness

It was recorded here as NOT COVERED once, on the reading that a native panel
would not provision a client onto a node. That reading was wrong, and the way it
was wrong is worth keeping.

- **The node could not bind its port.** R07's launcher publishes 3X-UI's node
  range (24443–24450) on the host, and the harness had told the native node to
  listen on 24443. Xray failed with `bind: address already in use`, the agent
  rolled the configuration back, and it never reported the inbound. Everything
  downstream followed: `config_sync_state` stayed `pending` forever, the panel
  logged `native panel has no cached full report`, and provisioning a user failed
  with `shared client u2@psp.local absent after create`. Three different-looking
  failures, one port, and none of them said so. The node now uses 25443.
- **`PUT /users/:id` with `{"enabled":false}` does nothing.** The update route has
  no `enabled` field, so the field is ignored and it answers 200. It looked like a
  panel that would not push a disable to its node.
- **The service axis is the one that moves.** `POST /users/:id/set-service-status`
  suspends the service and leaves `enabled` true on purpose — a suspended user can
  still sign in and self-rescue. And the attachment stays `applied`; the client is
  still provisioned onto that node. The number that moves is the **applied
  version**, which PSP mints only when the desired configuration changes.

What the case actually asserts, all of it read from the panel's own store: the
attachment reaches `state = applied` with the client's email; and after the
service is suspended the applied version advances while `config_sync_state`
returns to `synced`.



