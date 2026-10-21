# OpenCTI ingestion benchmarks

These benchmarks measure what it costs to get STIX objects from a connector queue into the database, and
where that time goes. They answer four questions:

1. How long does one object take on the worker path, and how is that time split between the platform's
   write, the HTTP requests and the queue loop?
2. Inside the platform, which steps of a relationship write cost the most?
3. How does throughput change with concurrency, and when many relationships share one entity?
4. Would writing relationships in batches help, and by how much?

Everything runs on your machine, against a separate benchmark platform that lives next to your development
platform without touching its data.

## Quick start

```bash
# 1. Start the development stack (Elasticsearch, Redis, RabbitMQ, MinIO)
cd opencti-platform/opencti-dev
docker compose up -d opencti-dev-elasticsearch opencti-dev-redis opencti-dev-rabbitmq opencti-dev-minio

# 2. Install the platform's dependencies, as for running the platform from source
cd ../opencti-graphql
yarn install
yarn install:python            # Python requirements of the platform (indicator pattern validation)

# 3. A Python environment with the client library, for the worker-path and queue-loop scenarios
cd ../..
python3 -m venv .venv
.venv/bin/pip install -e ./client-python    # installs pycti and pika

# 4. Run
.venv/bin/python benchmarks/ingestion/run.py run all --quick   # every scenario, small sizes, ~5 minutes
.venv/bin/python benchmarks/ingestion/run.py run relationships  # one scenario, full size
```

The first `run` creates the benchmark platform if it does not exist. Results are written to
`benchmarks/ingestion/results/` (ignored by git), one JSON file and one log per scenario.

## Commands

| Command | What it does |
|---|---|
| `run.py list` | Lists the scenarios and their default sizes |
| `run.py init` | Creates the benchmark platform, or wipes and recreates it |
| `run.py run <scenario>... \| all` | Runs scenarios and prints a summary. Options: `--quick`, `--n`, `--concurrency`, `--chunk`, `--messages`, `--phases` |
| `run.py show <result.json>...` | Prints the summary of earlier results. `--phases` adds the platform phase timings |
| `run.py data-shape --target opencti` | Read-only report of what an existing platform stores: counts by type, relationships per entity, most connected entities |

Global options: `--prefix` (default `bench`, see [Isolation](#isolation)), `--es-url` (default
`http://127.0.0.1:9200`), `--python` (the interpreter for the Python scenarios, default the one running
`run.py`).

## Scenarios

| Scenario | Question | Default size | Duration* |
|---|---|---|---|
| `relationships` | Today's relationship write path against the batch prototype, with each relationship on its own endpoints (*spread*) and with all of them on one shared malware (*hub*), one at a time and 8 at a time | 2,000 relationships per case | ~4 min |
| `batch-variants` | Batch prototype with chunks of 100, 500 and 1,000, and with 4 or 8 writers on the same hub | 2,000 per case | ~1.5 min |
| `reingest` | The same relationships sent again, unchanged and with a new description (upsert path) | 500 per case | ~1.5 min |
| `feed-shaped` | Data shaped like a connector feed: indicators with created-by, a marking and 3 labels, 12 `indicates` each to 40 shared attack patterns, and reports with 100 to 1,000 objects | 300 indicators, 3,600 relationships per case | ~4 min |
| `worker-path` | What the worker does per message, through pycti over HTTP, with each GraphQL request timed | 500 objects per case | ~2 min |
| `queue-loop` | The worker's RabbitMQ consumer loop alone, with a handler that sleeps a fixed time | 200 messages per case | ~1 min |
| `lockfree` | Lock-free prototype against today's path and the batch prototype: entities and relationships with refs, one per call, 8 at a time and in chunks, on spread ends, a hub and a hub that already lists 20,000 relationships, and re-ingestion | 2,000 per case (500 on the big hub) | ~6 min |
| `lockfree-batch` | Lock-free prototype in chunks against the batch prototype: hub and spread, with and without refs, 1, 4 and 8 parallel chunk writers, chunks of 100 to 2,000, and bundles carrying entities with their relationships; per-step timing of each chunk | 8,000 per case | ~2 min |
| `lockfree-behaviours` | Correctness of the lock-free prototype: 42 checks over duplicates, alias matches and races, out-of-order arrival, merges, delete, rename, parity with today's documents | 50 per case | ~1 min |

\* On a recent laptop, including the ~15 s platform start of each scenario.

## Methodology

### Isolation

The scenarios run inside a test platform started by Vitest from the platform's sources, with
`config/test.json` (API on port 4010). `run.py` gives it its own prefix everywhere:

| Store | Name |
|---|---|
| Elasticsearch indices | `bench_*` |
| Redis keys | `bench:*` |
| RabbitMQ queues and exchanges | `bench*` |
| MinIO bucket | `bench-bucket` |

`init` deletes everything under that prefix and recreates the platform. `run.py` refuses the prefixes `opencti`
and the empty prefix, so it cannot wipe a development platform by mistake. A development platform on port 4000
can keep running during the benchmarks. It shares the same Elasticsearch, Redis and RabbitMQ, so for quiet
numbers stop its connectors and its worker: a worker draining a connector backlog writes to Elasticsearch the
whole time. The reference results below were measured that way.

### What is measured, and where

| Layer | How | Scenarios |
|---|---|---|
| Platform write path | The scenario calls the platform's own functions (`createRelation`, `addIndicator`, `addReport`) inside the test platform. This is the code a GraphQL resolver runs, without HTTP and GraphQL. | `relationships`, `reingest`, `feed-shaped` |
| Steps of a write | Phase timers in `createRelationRaw` (`src/database/middleware.ts`) and `elIndexElements` (`src/database/engine.ts`). They do nothing unless `OPENCTI_BENCH_TIMING=true`, which `run.py` sets. | same |
| Worker path | `tools/worker_path.py` calls `import_bundle_from_json` with one-object bundles, as `push_handler.py` does, one pycti client per thread, and times every HTTP request by GraphQL operation. The platform serves it from the Vitest global setup, in another process, so this scenario has no phase timings. | `worker-path` |
| Queue loop | `tools/queue_loop.py` runs the real `MessageQueueConsumer` from `opencti-worker/src` on a temporary durable queue. The handler sleeps 0, 10, 25 or 33 ms; anything above that per message is the loop's cost. A variant that waits on `done()` every 1 ms instead of `running()` every 50 ms shows whether that wait matters. | `queue-loop` |
| Batch prototype | `tests/bench/batch-writer.ts`, see below. | `relationships`, `batch-variants`, `feed-shaped` |
| Lock-free prototype | `tests/bench/lockfree/`, see below. Called like the batch prototype, inside the test platform. | `lockfree`, `lockfree-behaviours` |

### Data

- Every run uses names unique to the run, so it creates new objects instead of updating old ones. The
  `reingest` scenario sends its relationships again on purpose.
- Entities created to set up a case (sources, targets, hubs) are created 8 at a time and are not measured,
  except the indicators of `feed-shaped`, which are the subject of two cases.
- *Spread* means every relationship has its own source and target. *Hub* means every relationship points at
  the same malware, which is the pattern of a feed that links thousands of objects to a few well-known ones.
- In `feed-shaped`, an indicator's 12 relationships follow each other, as they do in a split bundle whose
  connector emits an indicator with its relationships.
- The benchmark platform grows with each run. For numbers you want to compare, run `init` first and repeat
  each run twice: runs repeated on the same machine differed by up to about 20%.

### Metrics

| Field | Meaning |
|---|---|
| `throughput_per_s` | Items processed divided by the wall time of the case |
| `latency_ms` | Time of each call (mean, p50, p95, p99, max). With concurrency, it includes time spent waiting for locks |
| `latency_mean_by_decile_ms` | Mean latency of each tenth of the run, in order. A rising series means a cost that grows with the data already written |
| `errors` | Failed calls, by error code. Every case is expected to have none |
| `phases_ms` | Mean and p95 of each platform phase over the case (see the glossary) |
| `per_chunk_mean_ms` | Batch prototype: mean time of each step per chunk |
| `write_throughput_per_s` | Lock-free prototype: items divided by the time until every write call returned |
| `settled_throughput_per_s` | Lock-free prototype: items divided by the time until the settler finished and the indices were refreshed, so every endpoint lists its relationships and searches see everything |
| `writer`, `settler` | Lock-free prototype: what happened (created, merged, unchanged, optimistic retries, lost key races, re-pointed, reconciled...) |
| `checks` | Correctness checks, see below |

### Phase glossary

Relationship creation, `createRelationRaw`, in order:

| Phase | What happens |
|---|---|
| `relation.prepare` | Confidence and custom-field handling, entity settings from cache |
| `relation.resolve_refs` | One search resolving `from`, `to` and every other ref |
| `relation.checks` | Access, consistency and single-ref checks, lock ids |
| `relation.lock_wait` | Acquiring the Redis lock on the relationship ids and on each impacted endpoint |
| `relation.existing_search` | Search for an existing duplicate (ids, or same endpoints in a ±30-day window) |
| `relation.defaults` | Default values and second resolution, or loading the existing relationship for an upsert |
| `relation.validate` | Schema validation |
| `relation.build` | Building the documents |
| `relation.index` | `elIndexElements`, see below |
| `relation.stream_event` | Writing the event to the Redis stream |
| `relation.unlock` | Releasing the lock |
| `relation.lock_held` | From lock acquired to lock released |
| `relation.total` | The whole call |

Indexing, `elIndexElements`, for entities and relationships alike:

| Phase | What happens |
|---|---|
| `index.prepare` | Transforming documents for indexing |
| `index.bulk_refresh` | Bulk indexing of the documents, with `refresh: true` |
| `index.build_impacts` | Grouping the endpoint updates by entity |
| `index.endpoints_refresh` | Bulk painless update appending the new ids to each impacted endpoint (`rel_<type>.internal_id`), with `refresh: true` |

### The batch prototype

`tests/bench/batch-writer.ts` writes new relationships one chunk at a time, to show what a batch write path
could gain. For each chunk it:

1. resolves every ref of the chunk in one search, producing the same input shape as `inputResolveRefs`;
2. builds the documents with the platform's `buildRelationData`;
3. takes one lock over the chunk, with the same lock ids the platform computes for each relationship;
4. checks for duplicates by id in one search;
5. indexes the whole chunk with one `elIndexElements` call, which groups endpoint updates by entity, so 500
   relationships to one malware become one update and one refresh of that malware;
6. writes one stream event per relationship, 16 at a time, so stream consumers see the same events as today.

It does not handle: updates of existing relationships, the ±30-day duplicate window, per-item access,
confidence and consistency checks, container sharing tasks, and the security-coverage hook. Treat its numbers
as an upper bound for a real implementation with those added.

### The lock-free prototype

`tests/bench/lockfree/` replaces the Redis locks, the searches for existing copies and the forced refreshes by
identity that Elasticsearch enforces itself:

| File | Role |
|---|---|
| `identity.ts` | Identity index (`lockfree_identities_<prefix>`): one document per identity key (standard id, STIX ids, alias ids, hashes, internal id), whose `_id` is UUIDv5 of the key and which names the owner. Claiming a key is a `create`, which Elasticsearch accepts once; looking one up is a realtime get, which needs no refresh. Deleted objects leave tombstones. |
| `writer.ts` | Write path per chunk: resolve references and keys with two realtime multi-gets, `create` new objects without refresh (`internal_id` = UUIDv5 of the `standard_id`; relationships UUIDv5 of type, from id and to id), claim their keys, merge existing ones with `if_seq_no`, emit the stream events. An unknown end gets a provisional id derived from its STIX id. |
| `settler.ts` | Work done after the write, grouped per endpoint, every `settle_ms`: merge duplicates found by lost key races, re-point relationships whose provisional end is now known, delete those whose end was deleted, update every endpoint's `rel_*` list once, fill the names of ends that were provisional. |
| `store.ts` | Realtime reads, meta relationships with derived ids, merges with optimistic concurrency and update events in the platform's change format. |
| `run.ts` | Runs a write with background settlers; delete and rename through the platform with their identity updates. |

Documents are built with the platform's own `buildEntityData`, `buildRelationData` and `prepareIndexingElement`
(exported for this purpose), so they are stored in the same shape as today; `lockfree-behaviours` checks it.
The time range of a relationship is not part of its identity: copies widen it. Merge rules are simplified: a
copy with a confidence at least as high replaces description and confidence, lists are unions, markings keep
the highest per type. Not covered: the rest of `upsertElement`'s rules, access checks and organization
sharing (it writes as admin), drafts, inferences, sightings, observables matched by hashes, and a durable
settler queue (work is kept in memory).

### Correctness checks

Each scenario fails if its checks fail, so a fast but wrong result never reads as a success:

- **Denormalized counts.** Every hub lists all its relationships in `rel_<type>.internal_id`, whichever path
  wrote them.
- **Bulk resolution.** For one input, the prototype's bulk resolution holds the same ids under every key as
  the platform's `inputResolveRefs`.
- **Lock-free behaviours.** `lockfree-behaviours` runs 42 checks: derived ids; refs loaded back by the
  platform; same stored fields as today's path for an entity, a relationship and its meta relationships;
  today's path finding a lock-free relationship instead of creating a duplicate; the platform loading and
  listing lock-free relationships; a hub written 8 at a time and by 4 settlers at once; the same relationship
  or entity sent twice at the same moment; alias matches, in sequence and racing (with relationships sent to
  the duplicate before it is merged); references by a STIX id that is not the standard id; relationships
  before their ends, by standard id and by another STIX id; time ranges widening; merges by confidence, with
  markings keeping the highest and update events emitted; delete refusing later references and removing
  relationships the platform's delete did not see; re-creation after delete; rename; `indicates` leaving its
  target's list alone.
- **Refs.** In `feed-shaped`, a relationship loaded back has its created-by, marking and 3 labels, the
  indicator lists its 24 `indicates`, and the attack pattern lists none (that side is not impacted).

## Reference results

Measured on 2026-10-20 at default sizes, on a 15-core Apple Silicon laptop (macOS 26.4) with the development
stack in containers (Elasticsearch 8.19.23, single node), Node.js 22.23.3 and OpenCTI 7.261014.0 (`master` at
`aa73e1ff77` plus this branch). No connector or worker was running. Expect different absolute numbers on
your machine; the ratios are what matter.

### Relationship write path (`relationships`)

| Relationships | 1 at a time | 8 at a time | Batch of 500 |
|---|---|---|---|
| Each on its own endpoints (spread) | 55/s | 173/s | 1,978/s |
| All on one shared malware (hub) | 43/s | 43/s, p95 1.3 s | 2,236/s |

Where the time goes in one spread relationship, one at a time (16.7 ms in the platform process):

| Phase | Mean |
|---|---|
| `relation.index`: `index.bulk_refresh` 4.6 ms + `index.endpoints_refresh` 5.0 ms | 9.8 ms |
| `relation.resolve_refs` | 3.0 ms |
| `relation.existing_search` | 1.7 ms |
| `relation.lock_wait` + `relation.unlock` | 1.4 ms |
| `relation.stream_event` | 0.5 ms |
| Everything else | 0.3 ms |

- The two refreshing bulk requests are 59% of the write and 77% of the 12.6 ms the lock is held.
- On the hub, `index.endpoints_refresh` doubles to 10.2 ms, and latency one at a time rises from 18.3 ms in the
  first tenth of the run to 29.7 ms in the last, as the hub document grows. Spread latency stays at 17–20 ms.
- On the hub with 8 at a time, 163 ms of the 184 ms per call is `relation.lock_wait`.

### Batch prototype (`batch-variants`)

| Case | Per second |
|---|---|
| Hub, chunks of 100, 1 writer | 1,661 |
| Hub, chunks of 500, 1 writer | 2,323 |
| Hub, chunks of 1,000, 1 writer | 2,624 |
| Hub, chunks of 250, 4 writers | 1,503 |
| Hub, chunks of 100, 8 writers | 1,382 |
| Spread, chunks of 500, 1 writer | 2,072 |

In a 500 chunk on the hub (224 ms), indexing takes 119 ms and the stream events 51 ms.

### Re-ingestion (`reingest`)

| Case | Per second | Mean | p95 |
|---|---|---|---|
| Spread, first time | 52 | 19.3 ms | 23.3 ms |
| Spread, resent unchanged | 71 | 14.1 ms | 21.3 ms |
| Spread, resent with a change | 46 | 21.8 ms | 29.3 ms |
| Hub, first time | 50 | 20.1 ms | 23.5 ms |
| Hub, resent unchanged | 77 | 12.9 ms | 14.2 ms |
| Hub, resent unchanged, 8 at a time | 74 | 104 ms | 735 ms |
| Hub, resent with a change, 8 at a time | 53 | 147 ms | 798 ms |

### Feed-shaped data (`feed-shaped`)

| Case | Per second | Mean |
|---|---|---|
| Indicator, no refs | 42 | 23.7 ms |
| Indicator with created-by, marking and 3 labels | 36 | 28.1 ms |
| STIX pattern check alone | 10,300 | 0.1 ms |
| `indicates`, no refs | 54 | 18.4 ms |
| `indicates` with refs | 49 | 20.4 ms |
| `indicates` with refs, 8 at a time | 65 | 122 ms, of which 98 ms lock wait |
| `indicates` with refs, batch of 500 | 1,166 | 5.4 documents indexed per relationship |
| Report with 100 / 500 / 1,000 objects | – | 72 / 157 / 237 ms |

The 8-at-a-time case waits on the indicator's lock: an indicator's relationships follow each other, and the
attack pattern side is not locked.

### Worker path (`worker-path`)

| Case | Per second | Mean per message |
|---|---|---|
| Relationships, spread, 1 at a time | 33 | 30.2 ms |
| Relationships, hub, 1 at a time | 30 | 32.9 ms |
| Relationships, hub, 8 at a time | 34 | 231 ms, p95 1.1 s |
| Entities, 8 at a time | 180 | 44.4 ms |

A spread relationship message is `stixCoreRelationshipAdd` (21.4 ms) followed by `workEdit` for
`reportExpectation` (8.7 ms, 29% of the message). With 8 entities at a time, `workEdit` takes 19.3 ms.

### Queue loop (`queue-loop`)

| Handler time | Loop overhead, current loop | Loop overhead, 1 ms wait |
|---|---|---|
| 0 ms | 0.6 ms | 1.1 ms |
| 10 ms | 5.0 ms | 3.2 ms |
| 25 ms | 8.7 ms | 5.1 ms |
| 33 ms | 6.6 ms | 5.3 ms |

An earlier run on the same machine, with a connector backlog being drained in the background, measured 1.1 to
4.6 ms for both loops. The difference between the two loops is a few milliseconds at most and moves between
runs; run this scenario several times before drawing a conclusion from it.

### Lock-free prototype (`lockfree`)

2,000 items per case (500 on the big hub), every object with an author, a marking and 3 labels, on the same
platform run as the today and batch rows. *Settled* = every endpoint lists its relationships and a refresh
was done, so searches see everything.

| Workload | Today | Batch prototype | Lock-free, written | Lock-free, settled |
|---|---|---|---|---|
| Entities, 1 at a time | 51/s | - | 225/s | 221/s |
| Entities, 8 at a time | - | - | 776/s | 723/s |
| Entities, chunks of 500 | - | - | 1,564/s | 1,399/s |
| Relationships, spread, 1 at a time | 50/s | - | 287/s | 283/s |
| Relationships, spread, 8 at a time | - | - | 906/s | 783/s |
| Relationships, hub, 8 at a time | 41/s | - | 895/s | 845/s |
| Relationships, hub, chunks of 500 | - | 997/s | 1,612/s | 1,147/s |
| Relationships, hub listing 20,000, 8 at a time | 10.8/s | - | 719/s | 591/s |
| Re-ingestion of the hub, changed, 8 at a time | 45/s | - | 701/s | 666/s |
| Re-ingestion of the hub, unchanged, 8 at a time | - | - | 2,039/s | 1,995/s |

`lockfree-behaviours`: 42 of 42 checks pass at 50 items per case; in the alias race, 49 of 50 pairs lost
a key race and were reconciled, with 39 relationships re-pointed.

### Lock-free in chunks (`lockfree-batch`)

8,000 relationships per case, chunks of 500, on the same platform run as the batch prototype rows.

| Case | Batch prototype | Lock-free, 1 writer | Lock-free, 4 writers | Lock-free, 8 writers |
|---|---|---|---|---|
| Hub, without refs | 2,152/s | 2,856/s (3,582 written) | 3,152/s (4,731 written) | 2,985/s (4,886 written) |
| Hub, with refs | 936/s (889 with 4 writers) | 1,418/s | 1,759/s (2,091 written) | 1,695/s (2,237 written) |
| Spread, without refs | - | 2,275/s (2,970 written) | 2,275/s (4,458 written) | - |
| Bundles of 250 entities and their 250 relationships, with refs | - | 1,378/s | 1,866/s | - |

Settled throughput, with written throughput in brackets where they differ by more than 10%. During these
cases the Node process ran at 100-170% CPU (`ps`, one event loop plus GC threads) and Elasticsearch at 17-35%
of its 5 cores (`_nodes/stats`, `process.cpu.percent`): the writers share one Node process, which is the
ceiling, so more writers in it add 30-50%. Per chunk without refs, the bulk create takes 24-44% of the time,
stream events 18-36%, reference resolution 16-32%; with refs, the 5 ref relationships per relationship take
about half. One settler falls behind above about 3,000/s: up to 1.7 s of endpoint updates remain after the
last write.

### What the numbers say

- On the worker path, a relationship costs about 30 ms of HTTP plus about 5 ms of queue loop. The separate
  `reportExpectation` request is close to 30% of the HTTP time.
- Inside the platform, the two bulk requests with `refresh: true` are most of a write, and they run while the
  endpoints are locked.
- Relationships that share an entity are written one after another: 8 writers give no more throughput than 1.
- Writing relationships in chunks was 24 to 52 times faster than one at a time in these runs, on spread, hub
  and feed-shaped data.
- Without locks, forced refreshes and searches for existing copies, one object per call is 4 to 6 times faster,
  concurrency scales again (8 writers on one hub: 21 times today), and a hub that already lists 20,000
  relationships no longer slows writes down (55 times today).

## Limits

- One machine, a single-node Elasticsearch with no replicas, and small indices. A production cluster with
  replicas usually pays more for each refresh.
- Stream consumers (rules engine, history, notifications) run in the benchmark platform, but their load is
  not representative of production.
- Observables, external references, sightings and containers other than reports are not covered.
- The worker-path scenario times the client side only; its platform phases are not recorded.

## Adding a scenario

1. Add `opencti-platform/opencti-graphql/tests/bench/scenarios/<name>.scenario.ts`. Use the helpers in
   `tests/bench/bench-utils.ts`: `benchParam` for sizes, `measure` to time a case, `writeResults` at the end.
   Fail the test when a correctness check fails.
2. Register it in `SCENARIOS` in `run.py`, with its default and `--quick` sizes.
3. Run it with `run.py run <name> --quick`, then at full size.

The scenarios are excluded from the platform's test suites: they only match `vitest.config.bench.ts`.

## Files

| Path | Role |
|---|---|
| `benchmarks/ingestion/run.py` | Entry point |
| `benchmarks/ingestion/tools/worker_path.py` | pycti client of the `worker-path` scenario |
| `benchmarks/ingestion/tools/queue_loop.py` | The `queue-loop` scenario |
| `benchmarks/ingestion/tools/data_shape.py` | The `data-shape` report |
| `opencti-platform/opencti-graphql/vitest.config.bench.ts` | Vitest configuration of the scenarios |
| `opencti-platform/opencti-graphql/tests/bench/scenarios/` | The scenarios run inside the benchmark platform |
| `opencti-platform/opencti-graphql/tests/bench/bench-utils.ts` | Measurement helpers |
| `opencti-platform/opencti-graphql/tests/bench/batch-writer.ts` | The batch prototype |
| `opencti-platform/opencti-graphql/tests/bench/lockfree/` | The lock-free prototype |
| `opencti-platform/opencti-graphql/src/utils/bench-timing.ts` | Phase timers, off unless `OPENCTI_BENCH_TIMING=true` |
