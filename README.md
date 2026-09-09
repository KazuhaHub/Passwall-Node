# Passwall-Node

A node backend driven by an external control plane: it runs xray / sing-box,
applies the configuration it is given, and reports what it observes.

**Status: protocol only.** `protocol/` is the wire contract and it compiles and
is tested. There is no agent binary yet.

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

**The node dials out.** It connects to the control plane every 60–120s; the
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

`protocol` is the whole contract and depends on nothing. Import it, serve one
endpoint, and any Passwall-Node will talk to you.

That is the point of this repository being separate: the protocol is a public
contract rather than an internal detail. It carries a real obligation —
documented, versioned, with a deprecation cycle for breaking changes.

## Licence

TBD.
