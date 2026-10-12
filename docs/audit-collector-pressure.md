# Collector and frozen pending pressure

The `collector-pressure` job in the Test workflow measures the production audit
collector on the hosted Linux runner with Node's exact preferred Go compiler.
It keeps the wall clock and every production capacity unchanged.

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

This component is awaiting its first actual hosted evidence. It exercises
production collector retention and scheduling, not live Xray, a running Node
daemon, PSP ingestion, SQL waits, control latency, or long-running cleanup.
Those remain separate requirements of the full mixed-pressure acceptance.
