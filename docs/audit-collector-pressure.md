# Collector and frozen pending pressure

The `collector-pressure` job in the Test workflow measures the production audit
collector on the hosted Linux runner with Node's exact preferred Go compiler.

The running daemon can additionally opt into `--audit-metrics`. It emits one
`audit_pressure` journal record per second with four fixed kinds, current aggregate
keys/limits/hour buckets, separate frozen pending row/canonical byte counts,
retained dropped/unmatched counters, and the agent process's actual Go heap and
goroutine counts. It exports no accounts, destinations, rules, revision or batch
IDs. These retained counters disappear when their batch is acknowledged; they
are not lifetime loss totals. The observer is disabled by default.

Pressure reads lock only the bounded state and use the wire size already computed
at freeze time; they never clone/serialize private rows or expire/acknowledge state.
The heap observer does not force GC. Its samples describe the whole running agent
and do not establish a continuous peak or collector-only retained heap. Opt-in
sampling has a cost and must be recorded with the workload. The strict journal
reader discards other lines and rejects unknown/private fields or changed limits.
This enables subsequent same-run integration; it is not itself proof that the
four classes, PSP queue, SQL and control/poll pressure have been exercised together.
It keeps the wall clock and every production capacity unchanged.

Observer schema 2 additionally includes `access_log`: availability, private
input lines, usage/denied/unmatched/queue-dropped/stale event counters, parse
queue occupancy/limit, and unflushed dropped/unmatched counts. These are
process-lifetime numeric observations; no raw line or identity is exported.
Unavailable filtering is explicit, rather than a zero-traffic assertion.
Reads do not flush losses or consume input. Concurrent atomic loads may straddle
a writer, so exact category reconciliation requires a quiescent snapshot.

The bounded filter's overflow path now distinguishes recognized denied lines
from usage. A full parser queue must not turn a denied connection into a usage
drop. Malformed or truncated overflow input contributes unmatched counts in
its original receive hour, using separate bounded counters; valid allowed
overflow contributes dropped counts. The original 4096-entry queue, revision
fences, nonblocking producer and private-output suppression remain in place.

The first actual PSP mixed run at `2616824e` delivered all four traffic classes,
preserved all four canonical retries and drained both retained states, but
usage storage plus observed loss counters did not explain 29046 allowed events.
Its failed originals remain retained; this is not a successful mixed proof.
Pinned Xray 26.6.27's `common/log/logger.go` uses a 128-message queue whose
full path discards messages without a counter. The new filter observations
locate received versus missing input; they cannot measure inside that upstream
queue or turn upstream omissions into fabricated persisted Node loss counts.
An acceptance fixture with independently counted real connections must keep
that before-filter difference separate from the Node-observed/persisted ledger.
The observer change still needs hosted runtime verification and a new mixed run.

| Kind | Aggregate key limit | Separate frozen pending bound | Slots per cycle |
|---|---:|---:|---:|
| block | 20000 | 4096 rows and 1 MiB | 4 |
| observe | 10000 | 4096 rows and 1 MiB | 1 |
| trial | 10000 | 4096 rows and 1 MiB | 1 |
| usage | 50000 | 8192 rows and 1 MiB | 1 |

One complete benchmark iteration interleaves input until every collector is
full and rejects one new key. It creates all four pending subtrees through the
real seven-slot scheduler, refills the freed aggregate space while retaining
those subtrees, and rejects one further new key per kind. All 90000 aggregate
keys and four bounded pending subtrees coexist. Retries must preserve their
entire canonical serialized content; the comparator retains only hashes and
lengths, rather than extra copies of the bodies. Trial pending rows remain
anonymous with zero ports; usage retains sites rather than original subdomains.

The report records each kind's actual keys, pending row/wire counts, two known
overflow events, zero unmatched events, and exact sending opportunities.
It also records GC-retained heap and the maximum heap sampled throughout
ingress, refill and final GC. A sampled maximum is not a continuous-time peak.
The artifact contains only fixed names and numbers, with a separate unique
test RUN/PASS and package PASS; destinations, subjects, batch IDs and hashes
are not retained. Negative verifier tests reject missing, duplicate, skipped,
failed, unknown and private evidence, changed capacities, and false accounting.

The first actual hosted run passed at source
`c28a0cbbb011813eb6771acac27b5579be6b2f91`, PR merge
`e7d6c2598f74106e3d8a890c5c87908619d67b71`:
[collector pressure job](https://github.com/KazuhaHub/Passwall-Node/actions/runs/38222606789/job/114722250229).
Both original artifact files were retained with their nonexpired, exact-source
metadata. The immutable source verifier and a separate checker both confirmed
the complete unique execution, closed fields, original limits and accounting.

| Kind | Aggregate keys | Pending rows | Pending wire bytes |
|---|---:|---:|---:|
| block | 20000 | 2674 | 1048347 |
| observe | 10000 | 2647 | 1048353 |
| trial | 10000 | 4096 | 868491 |
| usage | 50000 | 8192 | 1024140 |

The four frozen subtrees totaled 3989331 bytes while all 90000 aggregate keys
remained full. GC-retained heap was 47438944 bytes and sampled maximum heap was
79324136 bytes. Each kind recorded exactly two overflow events, zero unmatched
events, and its original 4/1/1/1 scheduling opportunities; all 4096 trial rows
were anonymous. These are measurements from one complete benchmark iteration,
not long-running memory guarantees. The run exercises production collector
retention and scheduling, not live Xray, a running Node daemon, PSP ingestion,
SQL waits, control latency, or long-running cleanup. Those remain separate
requirements of the full mixed-pressure acceptance.
