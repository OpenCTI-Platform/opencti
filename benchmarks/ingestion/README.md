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
| `lockfree` | Lock-free write path against today's path and the batch prototype: entities and relationships with refs, one per call, 8 at a time and in chunks, on spread ends, a hub and a hub that already lists 20,000 relationships, and re-ingestion | 2,000 per case (500 on the big hub) | ~6 min |
| `lockfree-batch` | Lock-free write path in chunks against the batch prototype: hub and spread, with and without refs, 1, 4 and 8 parallel chunk writers, chunks of 100 to 2,000, and bundles carrying entities with their relationships; per-step timing of each chunk | 8,000 per case | ~2 min |
| `lockfree-profile` | CPU profile of lock-free chunks (relationships with and without refs, entities with refs), one `.cpuprofile` per case in `results/`; summarize with `tools/cpu_profile.py` | 8,000 per case | ~40 s |
| `lockfree-behaviours` | Correctness of the lock-free path: parity with today's path (stored documents, meta relationships and stream events of the same steps written both ways) and 28 checks over concurrency, races, out-of-order arrival, deletes, renames, access, restarts, drafts, backfill | 50 per case | ~1.5 min |

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
| `write_throughput_per_s` | Lock-free path: items divided by the time until every write call returned |
| `settled_throughput_per_s` | Lock-free path: items divided by the time until the settler finished and the indices were refreshed, so every endpoint lists its relationships and searches see everything |
| `writer`, `settler` | Lock-free path: what happened (created, merged, unchanged, optimistic retries, lost key races, re-pointed, reconciled...) |
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

### The lock-free write path

`tests/bench/lockfree/` writes entities and relationships without Redis locks, forced refreshes or searches for
existing copies, with today's behaviour. It takes the same inputs as `createEntity` and `createRelation` and
runs the platform's own code for every rule: input preparation (confidence, access, custom fields, restricted
members), `inputResolveRefs` (given a finder that reads by id), defaults, validation, `buildEntityData` /
`buildRelationData`, the multiple-match rules of `internalCreateEntityRaw` (merges with `mergeEntities`), the
upsert rules (`buildUpdatePatchForUpsert`, `generateInputsForUpsert`, `updateAttributeRaw`, the ref handling and
`i_attributes` of `updateAttributeMetaResolved`), stream events, enrichment and workflow triggers. Only the
writes differ.

| File | Role |
|---|---|
| `identity.ts` | Identity index (`lockfree_identities_<prefix>`): one document per identity key (internal and standard id, STIX ids, alias ids, hashes), with an `_id` derived from the key, naming the owner. Claiming a key is a `create`, which Elasticsearch accepts once; a lookup is a realtime get, which needs no refresh. Deleted objects leave tombstones. |
| `load.ts` | Realtime reads in the platform's store shape (`elConvertHits`), refs resolved as `storeLoadByIdWithRefs` does, and the finder handed to `inputResolveRefs` (same contract as `internalFindByIds`, access filter included). |
| `pairs.ts` | Relationship duplicates: one document per (type, from, to) lists the pair's relationships; candidates are matched with today's `buildRelationDeduplicationFilters` (window, per-type overrides, created-by), evaluated in memory. Entries of relationships deleted since (by today's path, from the interface) are dropped, so the relationship is created again, as today. |
| `writer.ts` | Write path per chunk (steps timed as `lf_entity.*` / `lf_relation.*`): prepare and resolve as today, match, then create in bulk. New entities claim their keys before being created, so two writers never both create one object: the one that loses a key waits for the holder and merges into it. New relationships get an id from type, ends and time; a duplicate created at the same moment by another writer is caught when it is recorded in its pair. Relationships whose ends do not exist yet go to the pending store. Drafts, file uploads, explicit ref relationships and single-ref replacements go to today's path, unchanged. |
| `upsert.ts` | Merges: today's rules on the object read by id, written back with `if_seq_no` and recomputed when someone wrote in between; meta relationships with ids derived from their ends; update events in today's format. |
| `queue.ts` | Durable settler queue: Redis streams split by entity id, read through a consumer group; tasks are acknowledged once applied, and tasks a stopped settler left are taken over after `claimIdleMs`. |
| `settler.ts` | Applies the queued work: one update per entity for its `rel_*` lists (one entry per relationship, as today, recorded per relationship so a redelivered task is not applied twice), today's `mergeEntities` for duplicates found after creation, merges of relationship duplicates, removal of relationships whose end was deleted, and the pending relationships whose ends now exist. |
| `pending.ts` | Relationships waiting for an end, in their own index, invisible to reads; written through the normal path when the ends exist, refused when an end was deleted (as today), dropped after their time to live. |
| `reconcile.ts` | Merges two entities found to be one, with today's `mergeEntities`, and moves the identity keys. |
| `backfill.ts` | One-time backfill of the identity index and pair documents for data written before, run before lock-free writes are enabled; idempotent. A key still held by an object that no longer exists is given to the object that has it now. |
| `run.ts` | Runs writes in chunks with background settlers (`writeEntities`, `writeRelations`, `writeBundles`); delete and rename through today's path with their identity updates; `waitForSearch` makes each write searchable when it returns, as today; `resetLockFreeState` drops the lock-free state of a wiped platform (`run.py init` calls it). |

### Profiling

`lockfree-profile` starts the V8 profiler (through `node:inspector`) only around the measured writes, in the
process that does them, and saves `results/<case>.cpuprofile`. Open one in Chrome DevTools, or summarize it:

```bash
python tools/cpu_profile.py results/relations_refs.cpuprofile --top 25
```

It prints the CPU time on and off CPU (idle = waiting on Elasticsearch or Redis), self time by area (a
platform file, a dependency, garbage collection) and by function, and the inclusive time of platform functions.
The profiler's own output (`node inspector`) shows up in the profile and can be ignored.

### Correctness checks

Each scenario fails if its checks fail, so a fast but wrong result never reads as a success:

- **Denormalized counts.** Every hub lists all its relationships in `rel_<type>.internal_id`, whichever path
  wrote them.
- **Bulk resolution.** For one input, the batch prototype's bulk resolution holds the same ids under every key as
  the platform's `inputResolveRefs`.
- **Lock-free behaviours.** `lockfree-behaviours` first runs the same steps through today's path (one by one)
  and through the lock-free path (in chunks), in two worlds told apart by a name prefix: entities with every kind
  of ref, aliases, observables, files merged by hashes, attack patterns with kill chain phases, relationships with
  dates, sightings, copies with higher and lower confidence, new aliases, labels, a marking upgrade, an alias
  match, two existing objects matched by one input, relationship copies inside and outside the duplicate window,
  and a report with its objects. The stored documents, the meta relationships and the stream events must be the
  same, ids replaced by names. Then 28 checks cover what parity cannot show: the same relationship or entity sent
  twice at the same moment, an alias race (no duplicate visible, even before settling), relationships before
  their ends (waiting invisibly, then written), pending expiry, deletes (later references refused, relationships
  the platform's delete missed removed), re-creation of a deleted entity and of a relationship deleted by today's
  path, rename, marking access and confidence capping as today, a
  settler stopping mid-run (another one finishes its work), partitioned settlers, `waitForSearch` visibility,
  drafts (today's path), backfill of existing data and of keys left by vanished objects, and platform reads of
  lock-free objects. It runs on a freshly initialized platform, where only the backfill knows the markings.
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

### Lock-free write path (`lockfree`)

Final code, on a freshly initialized benchmark platform. 2,000 items per case (500 on the big hub), every object
with an author, a marking and 3 labels. *Settled* = every endpoint lists its relationships and a refresh was
done, so searches see everything.

| Workload | Today | Batch prototype | Lock-free, written | Lock-free, settled |
|---|---|---|---|---|
| Entities, 1 at a time | 59/s | - | 152/s | 152/s |
| Entities, 8 at a time | - | - | 572/s | 569/s |
| Entities, chunks of 500 | - | - | 760/s | 753/s |
| Relationships, spread, 1 at a time | 47/s | - | 170/s | 170/s |
| Relationships, spread, 8 at a time | - | - | 576/s | 561/s |
| Relationships, hub, 8 at a time | 41/s | - | 572/s | 563/s |
| Relationships, hub, chunks of 500 | - | 1,337/s | 1,508/s | 1,361/s |
| Relationships, hub listing 20,000, 8 at a time | 10.6/s | - | 448/s | 391/s |
| Re-ingestion of the hub, changed, 8 at a time | 46/s | - | 483/s | 481/s |
| Re-ingestion of the hub, unchanged, 8 at a time | - | - | 762/s | 761/s |

Entities in chunks vary between runs (760 to 1,180/s across the last three); the other rows move by less than
10%. `lockfree-behaviours`: parity on 22 objects, 98 meta relationships and 33 stream events, and 28 of 28
checks; in the alias race, 49 of 50 pairs met at the same moment and were merged before either was visible twice.

### Lock-free in chunks (`lockfree-batch`)

Final code, freshly initialized benchmark platform, 8,000 relationships per case, chunks of 500. Settled
throughput, written in brackets where it differs by more than 10%.

| Case | Batch prototype | Lock-free, 1 writer | Lock-free, 4 writers | Lock-free, 8 writers |
|---|---|---|---|---|
| Hub, without refs | 2,890/s | 2,444/s | 3,385/s (4,120 written) | 3,672/s (4,665 written) |
| Hub, with refs | 1,314/s (1,254 with 4 writers) | 1,247/s | 1,879/s (2,098 written) | 2,137/s (2,495 written) |
| Spread, without refs | - | 1,858/s (2,346 written) | 2,575/s (3,535 written) | - |
| Bundles of 250 entities and their 250 relationships, with refs | - | 1,044/s | 1,778/s | - |

Settler bulks sent at once, on the spread case with 4 writers: 1 gives 2,388/s, 4 gives 2,575/s, 8 gives
2,815/s; 4 is the default.

### Optimization steps

Each step was measured with the scenarios above; the progression on the hardest realistic case, relationships
with refs all on one entity, settled:

| Step | Change | Throughput |
|---|---|---|
| Today | One object per call, locks and forced refreshes, 8 writers | 41/s |
| 1 | Batches of 500 (`batch-writer.ts`), still locked | 997/s |
| 2 | Lock-free, one object per call, 8 writers | 845/s |
| 3 | Lock-free in chunks of 500, 4 writers | 1,737/s |
| 4 | Cheaper per-object work: `isNotEmptyField` fast path, one copy in `prepareRelation`, `doYield` only when due | 2,379/s |
| 5 | Stream events of a chunk in one Redis round trip, stream size check without copy, TLP ids by lookup, faster id field filter | 2,328/s |
| 6 | Settler: one read per round, relationships indexed by end, parallel update bulks | 3,133/s |
| 7 | Today's behaviour in full: upsert rules, duplicate window, access checks, enrichment and workflow, durable settler queue, pending store, backfill; 8 writers | 2,137/s |

Step 3 showed the limit had moved into the Node process (100-170% CPU while Elasticsearch used 17-35% of its
cores); `lockfree-profile` and `tools/cpu_profile.py` found the hot spots fixed in steps 4 and 5. Step 5 raised
written throughput (8 writers without refs: 8,182 to 11,768/s) while the settled rate waited for step 6.
Steps 4 and 5 are platform changes that also speed up today's batch path (2,018 to 2,979/s without refs).
Steps 2 to 6 skipped part of today's rules; step 7 runs all of them, through the platform's own functions, and
gives up about a third of step 6 for it, mostly in the per-object work those rules do (the entity workflow
lookup, the upsert patch, access filtering), which today's path pays too.

### What the numbers say

- On the worker path, a relationship costs about 30 ms of HTTP plus about 5 ms of queue loop. The separate
  `reportExpectation` request is close to 30% of the HTTP time.
- Inside the platform, the two bulk requests with `refresh: true` are most of a write, and they run while the
  endpoints are locked.
- Relationships that share an entity are written one after another: 8 writers give no more throughput than 1.
- Writing relationships in chunks was 24 to 52 times faster than one at a time in these runs, on spread, hub
  and feed-shaped data.
- Without locks, forced refreshes and searches for existing copies, and with today's rules in full, one object
  per call is 2.5 to 3.5 times faster, concurrency scales again (8 writers on one hub: 14 times today), and a hub
  that already lists 20,000 relationships no longer slows writes down (37 times today).
- In chunks, relationships with refs on one entity reach about 2,100/s settled with 8 writers, 52 times today,
  with the same stored documents, meta relationships and stream events as today's path.

## Limits

- One machine, a single-node Elasticsearch with no replicas, and small indices. A production cluster with
  replicas usually pays more for each refresh.
- Stream consumers (rules engine, history, notifications) run in the benchmark platform, but their load is
  not representative of production.
- Throughput scenarios use intrusion sets, malware and `uses` relationships; observables, sightings, files,
  attack patterns and reports are checked for parity in `lockfree-behaviours`, not timed.
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
| `benchmarks/ingestion/tools/cpu_profile.py` | Summary of a `.cpuprofile`: CPU by area and by function, inclusive time of platform functions |
| `opencti-platform/opencti-graphql/vitest.config.bench.ts` | Vitest configuration of the scenarios |
| `opencti-platform/opencti-graphql/tests/bench/scenarios/` | The scenarios run inside the benchmark platform |
| `opencti-platform/opencti-graphql/tests/bench/bench-utils.ts` | Measurement helpers |
| `opencti-platform/opencti-graphql/tests/bench/batch-writer.ts` | The batch prototype |
| `opencti-platform/opencti-graphql/tests/bench/lockfree/` | The lock-free write path |
| `opencti-platform/opencti-graphql/src/utils/bench-timing.ts` | Phase timers, off unless `OPENCTI_BENCH_TIMING=true` |
