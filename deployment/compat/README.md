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
of the old panel's API), **B03**, **B04**, **B05** (upgrade admission gated on
the reported capability), **B07** (control-plane loss and return) and **B08** (an
unknown protocol generation refused by name).

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

**B02 — NOT COVERED.** A user added in the panel must reach the node, and the
harness cannot currently make that happen. What was established by trying:

- A native panel learns its inbounds from the node's report, so the inbound must
  be recorded *after* the node has reported. Recorded alongside the node, the
  panel answers `sync existing users (background) node_id=1 err="inspect inbound:
  native panel has no cached full report: not found"` and the node's
  `config_sync_state` stays `pending` for the rest of the run.
- Recorded after the first report, the error becomes `inspect inbound: not
  found`, and the panel's own task queue records the failure:
  `user_resync ... last_error="shared provision: shared client u2@psp.local absent
  after create"`, retrying. The `psp_clients` row and its attachment **are**
  created; what never happens is the node receiving the inbound.
- The node's applied configuration then contains `inbounds: []`.

It is not yet known whether that is a defect in the released panel or an artifact
of the harness creating the node through `POST /api/admin/servers` and
`POST /api/admin/nodes` instead of the install flow an operator would use. Until
that is settled, B02 is recorded as a gap rather than asserted at whatever
strength the harness happens to reach — an earlier version of this file called
B05 covered on that kind of reasoning and it was wrong.



