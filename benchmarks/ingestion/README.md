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
| `batch-import` | The `lockfreeImport` mutation over HTTP: chunks of 1, 100 and 500 objects per request, 1 and 4 clients, entities with refs then relationships with refs on one hub; waits until the platform lists them all | 4,000 per case | ~1.5 min |
| `lockfree-processes` | The lock-free path from 1, 2 and 4 platform processes at once, as the nodes of a cluster: entities with refs, then relationships with refs from all of them to one hub; `--processes 1,2` picks the counts | 16,000 per case | ~2 min |
| `full-flow` | A connector-shaped bundle (author, marking, labels, attack patterns with kill chain phases and external references, intrusion sets on one malware, observables, one report containing everything) pushed to a connector queue and imported by a real worker started by the scenario, lock-free; then pycti one object per request against batch mode; checks the stored data is the same | 2,403 objects per run | ~1 min |
| `full-flow-today` | The same bundle through the queue and the worker, today's flow (lock-free off) | 2,403 objects | ~1.5 min |
| `feeds` | Feed-shaped bundles (`tools/feeds.py`: AlienVault pulses, Recorded Future risk list chunks, MISP events) pushed to a connector queue one work per bundle, as the connectors send them, and imported by 4 real workers; each feed is sent fresh, then twice again once stored; times each pass until every work is complete, and reports errors and what was stored; lock-free | 10,000 objects per feed | ~2.5 min |
| `feeds-today` | The same feeds through the queue and 4 workers, today's flow | 10,000 objects per feed | ~20 min |
| `lockfree-behaviours` | Correctness of the lock-free path: parity with today's path (stored documents, meta relationships and stream events of the same steps written both ways) and 30 checks over concurrency, races, out-of-order arrival, deletes, renames, access, restarts, drafts, backfill, known no-op merges | 50 per case | ~1.5 min |

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
| Lock-free write path | `src/database/lockfree/`, see below. Called inside the benchmark platform by the scenarios, over HTTP by `batch-import`, and through queue and worker by `full-flow`. | `lockfree*`, `batch-import`, `full-flow` |

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

`src/database/lockfree/` writes entities and relationships without Redis locks, forced refreshes or searches for
existing copies, with today's behaviour (`tests/bench/lockfree/run.ts` drives it in the scenarios). It takes the
same inputs as `createEntity` and `createRelation` and runs the platform's own code for every rule: input preparation (confidence, access, custom fields, restricted
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
| `upsert.ts` | Merges: today's rules on the object read by id, written back with `if_seq_no` and recomputed when someone wrote in between; meta relationships with ids derived from their ends; update events in today's format. The objects a chunk merges into, and their refs, are read once per chunk (`ChunkReads` in `load.ts`). |
| `unchanged.ts` | Known no-op merges: a merge that left an object as it was is remembered in the identity index with the object's version (`_seq_no`, `_primary_term`) and a fingerprint of the prepared input, the user, the request's synchro flags and the platform (version, Enterprise Edition, platform organization, marking definitions, workflow statuses, entity settings). The same merge on the same version is answered "unchanged" without being computed; any write to the object gives it a new version. Merges that read other objects (alias owners, individuals linked to users), move files or carry `upsertOperations` are not remembered. |
| `queue.ts` | Durable settler queue: Redis streams split by entity id, read through a consumer group; tasks are acknowledged once applied, and tasks a stopped settler left are taken over after `claimIdleMs`. |
| `settler.ts` | Applies the queued work: one update per entity for its `rel_*` lists (one entry per relationship, as today, recorded per relationship so a redelivered task is not applied twice), today's `mergeEntities` for duplicates found after creation, merges of relationship duplicates, removal of relationships whose end was deleted, and the pending relationships whose ends now exist. |
| `pending.ts` | Relationships waiting for an end, in their own index, invisible to reads; written through the normal path when the ends exist, refused when an end was deleted (as today), dropped after their time to live. |
| `reconcile.ts` | Merges two entities found to be one, with today's `mergeEntities`, and moves the identity keys. |
| `backfill.ts` | One-time backfill of the identity index and pair documents for data written before, run before lock-free writes are enabled; idempotent. A key still held by an object that no longer exists is given to the object that has it now. |
| `ingestion.ts` | The path inside the platform, behind `app:lockfree_ingestion:enabled`: worker imports and batch imports go through it (`createEntity` / `createRelation` hand them over), the identity index follows what today's path writes (creates, updates, merges, deletes, from where the platform stores their stream events), `lockfreeImport`. |
| `batch.ts` | `lockfreeImport` operations: each create mutation as pycti sends it, run through its resolver in dependency order with placeholders replaced by real ids; a collector holds their creates and writes them as lock-free chunks (up to 4 at once). |
| `context.ts` | The path's own context and a small concurrency pool. |
| `run.ts` (in `tests/bench/lockfree/`) | Runs writes in chunks with background settlers (`writeEntities`, `writeRelations`, `writeBundles`); delete and rename through today's path with their identity updates; `waitForSearch` makes each write searchable when it returns, as today; `resetLockFreeState` drops the lock-free state of a wiped platform (`run.py init` calls it). |

### The full flow

From a connector to stored data, with `app:lockfree_ingestion:enabled`:

1. The connector helper (pycti) splits a bundle in dependency order, as today, but sends `CONNECTOR_PUSH_CHUNK_SIZE`
   (500) split objects per message instead of one, when the platform takes batch imports; the platform does the
   same for bundles pushed through its API (`app:lockfree_ingestion:push_chunk_size`). The work still expects
   one report per object.
2. The worker takes up to `WORKER_BATCH_SIZE` (500) messages at a time from a queue; consecutive messages with
   the same context (user, work, update flag, no draft) are imported as one bundle, capped at 2,000 objects, and a
   message alone too, even with a single object. Each message is still acknowledged, retried or sent to the dead
   letter queue on its own.
3. pycti converts each object as today, inside a batch: every create it sends (STIX objects, relationships,
   sightings, external references) is kept and answered with a placeholder, its STIX id; any other request first
   sends what was kept. Kept creates go 1,000 per `lockfreeImport` request.
4. The platform runs each create through its own resolver, in dependency order, the placeholders replaced by
   the real ids, and writes their objects as lock-free chunks. An object whose create failed is imported again on
   its own by pycti, with today's retries and error reporting; success is reported per object once confirmed.
5. An object whose create failed only because what it references does not exist yet (another worker may still be
   importing it) is not retried in the worker: pycti leaves it to the worker (`defer_missing_references`,
   `stix2.last_batch_deferred`) without reporting it, and the worker sends those objects to the end of its queue as
   one message, imported again no sooner than 1, 2, 4, 8 and 16 s later. After the fifth time, today's retries and
   error report apply. The work's counts stay exact: the object is reported once, when it is finally imported.

Each step falls back to today's: a platform without the switch answers the probe with an error, and the helper
sends one object per message, the worker one message at a time, pycti one create per request. Objects written
lock-free are found by id at once (also by the filters that resolve ids) and by searches after the next refresh.

### Several processes

`lockfree-processes` is the one scenario `run.py` starts several times at once: each copy is a whole platform
process (its own HTTP and liveness ports, its own managers), writes its share of the objects with 2 chunk writers,
and waits for the others at barriers kept in Redis, so that every case starts together. The first process creates
the shared refs and the hub. `run.py` then adds the shares up: all items over the time from the first start to the
last write returned (written) or to the shared settler queue being empty (settled). Settlers of every process read
the same queue through the same consumer group.

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
  same, ids replaced by names. Then 30 checks cover what parity cannot show: the same relationship or entity sent
  twice at the same moment, an alias race (no duplicate visible, even before settling), relationships before
  their ends (waiting invisibly, then written), pending expiry, deletes (later references refused, relationships
  the platform's delete missed removed), re-creation of a deleted entity and of a relationship deleted by today's
  path, rename, marking access and confidence capping as today, a
  settler stopping mid-run (another one finishes its work), partitioned settlers, `waitForSearch` visibility,
  drafts (today's path), backfill of existing data and of keys left by vanished objects, platform reads of
  lock-free objects, a third identical send answered from known no-op merges, and an edit by hand between two
  sends giving the same result as today's path. It runs on a freshly initialized platform, where only the backfill knows the markings.
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

Each case runs twice: reporting each imported object to its work with its own `reportExpectation` request, as
pycti did before, and with the success reports batched (`ExpectationBatcher` in `pycti/api/opencti_api_work.py`:
counted per work, sent with a count from a background thread every second or every 500). Each way imports into
its own work, which expects every object; both works counted 3,502 of 3,502 and completed. Two runs, per second:

| Case | Report each | Batched | Mean per message, batched |
|---|---|---|---|
| Entities, 8 at a time | 230 / 270 | 315 / 315 | 25.2 ms |
| Relationships, spread, 1 at a time | 42.7 / 45.0 | 47.9 / 45.4 | 21.4 ms |
| Relationships, hub, 1 at a time | 41.5 / 39.2 | 44.0 / 43.6 | 22.7 ms |
| Relationships, hub, 8 at a time | 43.0 / 41.2 | 43.0 / 43.8 | 179 ms, p95 1.1 s |

Batching sends 154 report requests instead of 3,503. A report cost 2.6 ms per object sent one at a time and
5 ms with 8 entities at a time (`workEdit`), now off the message's path. The hub at 8 at a time does not move:
it waits on the hub's lock. On a real deployment the worker and the platform are further apart than on this
laptop, so each request saved is worth more.

An earlier version of this scenario created its work without expected objects. Every report then completed the
work again and updated it in Elasticsearch, which made a report look like 8.7 ms (29% of a message). A real
import sets its expectations, as the scenario now does.

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

Final code, on a freshly initialized benchmark platform, 22 October 2026. 2,000 items per case (500 on the big
hub), every object with an author, a marking and 3 labels. *Settled* = every endpoint lists its relationships and
a refresh was done, so searches see everything. The machine ran about 8% slower that day than the day before, on
today's path too (entities one at a time: 51/s against 59/s).

| Workload | Today | Batch prototype | Lock-free, written | Lock-free, settled |
|---|---|---|---|---|
| Entities, 1 at a time | 51/s | - | 122/s | 122/s |
| Entities, 8 at a time | - | - | 512/s | 510/s |
| Entities, chunks of 500 | - | - | 2,244/s | 1,870/s |
| Relationships, spread, 1 at a time | 47/s | - | 197/s | 196/s |
| Relationships, spread, 8 at a time | - | - | 448/s | 443/s |
| Relationships, hub, 8 at a time | 38/s | - | 584/s | 576/s |
| Relationships, hub, chunks of 500 | - | 1,317/s | 1,516/s | 1,371/s |
| Relationships, hub listing 20,000, 8 at a time | 10.2/s | - | 412/s | 371/s |
| Re-ingestion of the hub, changed, 8 at a time | 43/s | - | 404/s | 403/s |
| Re-ingestion of the hub, unchanged, 8 at a time | - | - | 702/s | 701/s |

One object at a time moves by up to 20% between runs: those cases wait on Elasticsearch. `lockfree-behaviours`:
parity on 22 objects, 98 meta relationships and 33 stream events, and 28 of 28 checks; in the alias race, 48 of
50 pairs met at the same moment and were merged before either was visible twice.

### Lock-free in chunks (`lockfree-batch`)

Final code, freshly initialized benchmark platform, 8,000 relationships per case, chunks of 500. Settled
throughput, written in brackets where it differs by more than 10%. The last column is the code before step 8, run
the same day, 1 and 8 writers.

| Case | Batch prototype | Lock-free, 1 writer | Lock-free, 4 writers | Lock-free, 8 writers | Before step 8 |
|---|---|---|---|---|---|
| Hub, without refs | 2,755/s | 2,483/s | 3,307/s (3,914 written) | 3,168/s (4,590 written) | 2,243/s, 3,318/s |
| Hub, with refs | 1,265/s (1,273 with 4 writers) | 1,486/s | 1,683/s (2,010 written) | 1,736/s (2,077 written) | 1,026/s, 1,850/s |
| Spread, without refs | - | 1,614/s | 2,745/s (3,822 written) | - | - |
| Bundles of 250 entities and their 250 relationships, with refs | - | 1,495/s | 2,269/s | - | 957/s, 1,337/s (4 writers) |

With one writer, or with bundles, step 8 adds 29 to 70%; with 8 writers in one process it changes nothing (within
the 10% runs vary by), because that process's event loop is then busy all the time. More processes are the way
past it (next section).

### Batch import over HTTP (`batch-import`)

`lockfreeImport` takes a chunk of inputs (entities as `{type, input}`, then relationships, each as the matching
`*Add` mutation takes it) and writes it with the lock-free path in one request; it needs
`app:lockfree_ingestion:enabled`. The client sends the chunks over HTTP, as a worker would. Two runs, 22 October
2026, every object with an author, TLP:GREEN and 3 labels:

| Case | 1 per request, 8 clients | Chunks of 100, 1 client | Chunks of 500, 1 client | Chunks of 500, 4 clients |
|---|---|---|---|---|
| Entities | 225 to 394/s | 1,494 to 1,590/s | 2,047 to 2,229/s | 2,949 to 3,048/s |
| Relationships, all on one hub | 277 to 463/s | 1,282 to 1,297/s | 1,518 to 1,610/s | 2,030 to 2,240/s |

No errors; the platform listed all 13,000 relationships of the hub at most 1.1 s after the last write. Over HTTP,
chunks reach the rates measured inside the platform: the per-request cost is paid once per chunk. The worker does
not use it yet: pycti converts STIX to inputs object by object and sends each one.

### Full flow (`full-flow`, `full-flow-today`)

A connector-shaped bundle of 2,403 objects, through the connector queue and a real worker, until the work is
complete, on a freshly initialized benchmark platform, 22 October 2026:

| Flow | Time | Throughput |
|---|---|---|
| Today (lock-free off, one object per message) | 62.9 s | 38.2/s |
| Lock-free, messages imported together | 3.3 s | 729/s |

The two store the same data: 1,000 intrusion sets with author, marking and 2 labels, 100 attack patterns with 100
kill chain phases and 200 external references, 1,200 relationships on the malware, a report with 2,401 objects,
every object counted, no error. On the demo platform the same flow ran at 790 to 801/s three times in a row, and
today's at 41.5/s. pycti alone, without the queue: 1,034/s in batch mode against 98/s one object per request.

Building it found, and fixed: a pushed bundle published one RabbitMQ message per object (2.65 s of 4.72 s before
chunked messages); a message holding several objects was imported one by one when it came alone; external
references took today's path, two forced refreshes each, 200 at a time; and labels created by pycti were unknown
to the identity index, so every import first failed on a missing reference and was retried.

### Feeds end to end (`feeds`, `feeds-today`)

Feed-shaped bundles through the connector queue and 4 real workers, until every work is complete, on the
benchmark platform (managers on), 23 October 2026. Objects per second over the whole pass, objects sent (the
connector splitter drops duplicate ids within a bundle); two lock-free runs:

| Feed (bundles, objects) | Pass | Today | Lock-free |
|---|---|---|---|
| AlienVault-like (19 pulses, 9,861) | fresh | 39/s, 49 relationships lost | 679 to 825/s |
| | sent again | 103/s | 1,028 to 1,231/s |
| Recorded Future-like (9 chunks, 10,467) | fresh | 78/s, 7 lost | 602 to 727/s |
| | sent again | 122/s | 1,061 to 1,165/s |
| MISP-like (73 events, 10,001) | fresh | 24/s, 98 lost | 445/s |
| | sent again | 81/s | 637 to 745/s |

Today's flow loses relationships whose end another worker is still importing (`MISSING_REFERENCE_ERROR` after its
retries); the lock-free flow sends them back through the queue and lost none. Every work completed in every run.

Known no-op merges (`unchanged.ts`), the second re-send, one run each:

| Feed | Without | With |
|---|---|---|
| AlienVault-like | 1,250/s | 2,294/s |
| Recorded Future-like | 1,206/s | 1,784/s |
| MISP-like | 657/s | 1,115/s |

The first re-send is what records them (1,044 to 1,314/s either way). Fresh passes vary by up to 40% between runs
on this laptop.

### Live connectors (demo platform)

Real connectors deployed through the integration manager on a platform with the switch on, one platform process
and 4 workers, 22 October 2026. Not a benchmark scenario: the feeds, the laptop's load and the restarts made along
the way are not repeatable.

**AlienVault**, pulses since 1 May 2026, 1.84 million objects (5.9 million records with their labels, markings and
authors). On the first run Elasticsearch had 5 CPUs and was the limit (about 315% CPU, thousands of rejected
searches a minute):

| Workers | Objects stored per second | Limit |
|---|---|---|
| 1 | 1,300 | the worker waits for each batch; the platform's main thread is idle 42% of the time |
| 3 | 1,610 | Elasticsearch's search pool (8 threads, 1,000 queued) turns requests away |
| 4 | 1,100 to 2,500 | the same, at all the CPU Elasticsearch had |

With 10 CPUs for the container VM (Elasticsearch's search pool sizes itself: 16 threads) and
`thread_pool.search.queue_size: 5000`, a fresh import of the same feed stored 1,836,700 objects in about 24 minutes,
about 1,300/s on average including two restarts, 2,898/s at the best minute, with no rejected search. The limit is
now the platform process: its main thread is busy 82% of the time, spread over many functions (garbage collection
11%), while Elasticsearch uses about 1 of its 10 CPUs.

**Recorded Future** sends one object per message (its connector image has the released pycti) and each indicator
brings an observable, a relationship, labels and markings: 300 to 430 messages a second from one platform process.

What these runs found and fixed:

- A report with tens of thousands of objects held the platform's event loop for minutes: writing its refs rebuilt
  the whole ref list for every ref. Now one set per field (`fc5629c270`).
- The Elasticsearch client opened a tracing span for every request even with tracing off, 4% of the platform's
  CPU (`ca05b8f46a`).
- 21 relationships were dropped on the first AlienVault import: they came while their end was still in another
  worker's batch, and today's 8 s of retries in the worker ran out; their ends arrived 0 to 4 s later. Step 5 of
  the full flow above sends them through the queue again (`6fff9d90ad`). A forced race on the demo (a relationship
  12 s ahead of its ends) lands after 4 deferrals with no error; on Recorded Future, thousands of objects were
  deferred and none failed for a missing reference.

### Several processes (`lockfree-processes`)

Same day and platform, 16,000 objects per case, each process with 2 chunk writers of 500. Settled throughput of
all processes together; two runs on 22 October.

| Case | 1 process | 2 processes | 4 processes |
|---|---|---|---|
| Entities with refs | 2,507 to 2,864/s | 4,049 to 4,103/s | 4,139 to 4,317/s |
| Relationships with refs, all on one hub | 1,771 to 1,864/s | 2,478 to 3,088/s | 2,968 to 3,046/s |

A second process adds 40 to 65%; the next two add up to 20% more. Every hub listed all 16,000 relationships. With 4
processes the Node processes used up to 5.6 of the laptop's 15 cores and Elasticsearch (one node, 5 cores) peaked
at 84%, so the single Elasticsearch node is the likely limit here; a cluster with more data nodes was not tried.

### Optimization steps

Each step was measured with the scenarios above; the progression on the hardest realistic case, relationships
with refs all on one entity, settled, best configuration of each step:

| Step | Change | Throughput |
|---|---|---|
| Today | One object per call, locks and forced refreshes, 8 writers | 41/s |
| 1 | Batches of 500 (`batch-writer.ts`), still locked | 997/s |
| 2 | Lock-free, one object per call, 8 writers | 845/s |
| 3 | Lock-free in chunks of 500, 4 writers | 1,737/s |
| 4 | Cheaper per-object work: `isNotEmptyField` fast path, one copy in `prepareRelation`, `doYield` only when due | 2,379/s |
| 5 | Stream events of a chunk in one Redis round trip, stream size check without copy, TLP ids by lookup, faster id field filter | 2,328/s |
| 6 | Settler: one read per round, relationships indexed by end, parallel update bulks | 3,133/s |
| 7 | Today's behaviour in full: upsert rules, duplicate window, access checks, enrichment and workflow, durable settler queue, pending store, backfill; 8 writers | 2,137/s (1,850/s on 22 Oct) |
| 8 | Less waiting per chunk: workflow configuration read once per type and chunk instead of once per entity, keys, pair entries and meta relationships written at once, large bulks sent as parallel slices; 1 process, 2 writers | 1,864/s |
| 9 | Two platform processes, 2 writers each | 3,088/s |
| 10 | `lockfreeImport` over HTTP, chunks of 500, 4 clients | 2,030 to 2,240/s |
| 11 | The full flow, a mixed connector bundle through queue and worker (all object kinds, not only relationships on one entity) | 729 to 801/s (today 38 to 41/s) |
| 12 | Merge targets and their refs read once per chunk; light notifications (ids of the user only, no raw document or `rel_*` lists); deferred messages not yet due no longer hold their batch | re-sends 490 to 1,000/s (in process); feeds, 4 workers: 445 to 825/s fresh |
| 13 | Known no-op merges answered without computing them | feeds sent a third time: 1,115 to 2,294/s |

Step 3 showed the limit had moved into the Node process (100-170% CPU while Elasticsearch used 17-35% of its
cores); `lockfree-profile` and `tools/cpu_profile.py` found the hot spots fixed in steps 4 and 5. Step 5 raised
written throughput (8 writers without refs: 8,182 to 11,768/s) while the settled rate waited for step 6.
Steps 4 and 5 are platform changes that also speed up today's batch path (2,018 to 2,979/s without refs).
Steps 2 to 6 skipped part of today's rules; step 7 runs all of them, through the platform's own functions, and
gives up about a third of step 6 for it. Step 8 came from timing each part of a chunk: the per-entity workflow
lookup (an Elasticsearch search each, which `createEntity` also pays) was 43% of an entity chunk, and the meta
relationships about half of a chunk with refs. With one writer, entities in chunks went from 1,059 to 1,912/s and
relationships with refs from 1,254 to 1,481/s.

### What the numbers say

- On the worker path, a relationship costs about 20 ms of HTTP plus about 5 ms of queue loop. The separate
  `reportExpectation` request was 2.6 ms of it (5 ms with 8 at a time); batching takes it off the path and
  sends 96% fewer of them.
- Inside the platform, the two bulk requests with `refresh: true` are most of a write, and they run while the
  endpoints are locked.
- Relationships that share an entity are written one after another: 8 writers give no more throughput than 1.
- Writing relationships in chunks was 24 to 52 times faster than one at a time in these runs, on spread, hub
  and feed-shaped data.
- Without locks, forced refreshes and searches for existing copies, and with today's rules in full, one object
  per call is 2.5 to 4 times faster, concurrency scales again (8 writers on one hub: 15 times today), and a hub
  that already lists 20,000 relationships no longer slows writes down (36 times today).
- In chunks, relationships with refs on one entity reach about 1,850/s settled from one process and about 3,000/s
  from two or four, 45 to 75 times today, with the same stored documents, meta relationships and stream events
  as today's path.
- End to end, from a connector's bundle through the queue and the worker to stored data, a mixed bundle goes
  19 times faster than today (729/s against 38/s), storing the same data. What remains is mostly the platform's
  own work per create (resolvers, ref resolution, chunk writes), 1,000 creates in about 0.65 s.
- On a live feed with several workers, the limit moves to Elasticsearch's search pool and CPU first, then, once
  Elasticsearch has the CPU and queue for it, back to the platform process: about 1,300 objects/s per process,
  sustained, on AlienVault data. More throughput then means more platform processes, not more workers.

## Limits

- One machine, a single-node Elasticsearch with no replicas, and small indices. A production cluster with
  replicas usually pays more for each refresh.
- Stream consumers (rules engine, history, notifications) run in the benchmark platform, but their load is
  not representative of production.
- The lock-free throughput scenarios use intrusion sets, malware and `uses` relationships; `full-flow` times a
  mixed bundle (observables, attack patterns, external references, a report); sightings and files are checked
  for parity in `lockfree-behaviours`, not timed.
- The feeds are synthetic, shaped after what three connectors stored on the demo platform; real feeds differ in
  their mix and in how their bundles arrive over time.
- Known no-op merges are never cleaned up: one small document per object and input stays in the identity index.
  An object written to all the time (a malware many relationships point to) changes version too often to benefit.
- Elasticsearch's defaults size its search pool from its CPUs and queue 1,000 searches: on a small node, lock-free
  imports from several workers fill that queue in bursts. The live runs used 10 CPUs and a queue of 5,000.
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
| `benchmarks/ingestion/tools/batch_import.py` | Client of the `batch-import` scenario |
| `benchmarks/ingestion/tools/full_flow.py` | The connector-shaped bundle, the queue flow and pycti's two modes (`full-flow`) |
| `opencti-platform/opencti-graphql/src/database/lockfree/` | The lock-free write path, its platform integration and `lockfreeImport` |
| `client-python/pycti/api/opencti_api_batch.py` | pycti's batch import (creates kept and sent together) |
| `opencti-worker/src/push_handler.py`, `message_queue_consumer.py` | The worker's batches of messages |
| `benchmarks/ingestion/tools/queue_loop.py` | The `queue-loop` scenario |
| `benchmarks/ingestion/tools/data_shape.py` | The `data-shape` report |
| `benchmarks/ingestion/tools/cpu_profile.py` | Summary of a `.cpuprofile`: CPU by area and by function, inclusive time of platform functions |
| `opencti-platform/opencti-graphql/vitest.config.bench.ts` | Vitest configuration of the scenarios |
| `opencti-platform/opencti-graphql/tests/bench/scenarios/` | The scenarios run inside the benchmark platform |
| `opencti-platform/opencti-graphql/tests/bench/bench-utils.ts` | Measurement helpers |
| `opencti-platform/opencti-graphql/tests/bench/batch-writer.ts` | The batch prototype |
| `opencti-platform/opencti-graphql/tests/bench/lockfree/run.ts` | The scenarios' driver of the lock-free write path |
| `opencti-platform/opencti-graphql/src/utils/bench-timing.ts` | Phase timers, off unless `OPENCTI_BENCH_TIMING=true` |
