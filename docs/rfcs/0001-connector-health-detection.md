# RFC 0001 — Platform-side connector health detection

| | |
|---|---|
| **Status** | Draft |
| **Author** | Julien Richard |
| **Date** | 2026-09-12 |
| **Scope** | `opencti-platform/opencti-graphql`, `opencti-platform/opencti-front` |
| **Hard constraint** | No change to connectors, to `client-python` (pycti) or to the connector protocol |
| **Reviewers** | Platform team, Connectors team, Product, Design (named owners still open, §12) |
| **Target release** | Phases 0–1 in the next minor release, phases 2–3 in the following one (decided 2026-09-15) |
| **Edition** | Community Edition for everything except the audit events of phase 4 (decided 2026-09-15) |
| **Code baseline** | `core-engine` commit `a8c0e5a009` (master), connectors repository checkout of 2026-09-12 |

**Contents** — 1 Summary · 2 Problem · 3 Goals and non-goals · 4 Background (4.0 Terminology, 4.1 Ping, 4.2 `active`, 4.3 Registration, 4.4 Works, 4.5 RabbitMQ, 4.6 Composer, 4.7 Alerting primitives) · 5 Why work cadence is not the primary signal · 6 Failure modes and detectability · 7 Design (7.1 Overview, 7.2 Observability fields, 7.3 Health model, 7.4 Rule map, 7.5 Evaluation pipeline, 7.6 Overrides, 7.7 Storage and exposure, 7.8 Alerting, 7.9 UI, 7.10 Configuration, 7.11 Permissions, 7.12 Cost and self-observability, 7.13 Related fixes, 7.14 Ingestion pipeline health, 7.15 Data freshness) · 8 Limitations · 9 Alternatives · 10 Rollout · 11 Testing · 12 Decisions log and open points · A Connector survey · B Code references

---

## 1. Summary

**Problem.** OpenCTI cannot tell an operator that a connector has stopped doing its job. The only signal, `Connector.active`, means "pinged in the last 5 minutes" and is faked by any administrative write on the entity. A connector that keeps pinging while failing every run, or whose bundles are all rejected, is shown green.

**Proposal.** A new Community Edition scheduled manager, `connectorHealthManager`, evaluates every connector once per tick (60 s by default) from signals the platform already receives (ping, registration, works, RabbitMQ) and stores a status in `{OK, DEGRADED, KO, PAUSED, UNKNOWN}` with reason codes and operator hints. Alerts fire only on status transitions, through the existing notification pipeline. The status is shown in Integrations > Deployed and on the connector page. For import connectors the design rests on two co-primary axes: progress signals carried by the ping (`connector_info`, `connector_state` changes) and the **content** of works (errors, expectations). Work **cadence** is only a fallback estimator of a connector's expected period and a veto against false alarms. A third axis, **ingested volume against a per-connector baseline** (§7.5 stage 4b), detects the partial degradation that binary rules miss. Two platform-level complements are in scope: an **ingestion pipeline health** indicator (workers, backlog, lost bundles, §7.14) so that worker-side problems are reported once instead of being blamed on every connector, and a **data-freshness** rule (§7.15) that counts objects actually created or modified per connector, because volume alone is not novelty.

**What changes for existing behaviour.** Nothing for connectors, pycti or the protocol. One platform-side semantic change: `active` is computed from a new `last_ping_at` instead of `updated_at`, so administrative writes stop faking liveness (§7.2, phase 0). Two independent correctness fixes on works are recommended (§7.13).

**Rollout.** Phase 0 observability fields → phase 1 shadow manager with read-only status, alerting off → phase 2 alerting → phase 3 full UI and overrides → phase 4 Enterprise audit events (§10).

**Decisions taken on 2026-09-15** (§12): everything ships in Community Edition; recipients are the `MODULES` users; storage is Redis; one health chip replaces the Active/Inactive chip; thresholds `3P` / `5P`; run-and-terminate connectors are handled minimally (a registration counts as a heartbeat); the pipeline health indicator and the data-freshness rule are in scope; the companion pycti RFC is deferred. Target: phases 0–1 in the next minor release, in a single first pull request, phases 2–3 in the following one. Still open: named owners per team.

Statements about platform, pycti and worker behaviour carry a `file:line` reference to the code baseline above; connector-repository counts come from the survey in Appendix A and are approximate where marked (~).

---

## 2. Problem statement

Operators discover broken connectors late, typically when an analyst notices stale data. Cases reported from the field:

- the container died and nobody restarted it;
- the container restarts in a loop (crash at startup, bad configuration);
- the process is alive but its main loop is stuck (API retry without timeout, deadlock);
- the process is alive, runs every period, and fails every time with an exception the connector swallows and logs (expired credentials, moved endpoint, TLS change);
- the connector runs and sends bundles, but the platform rejects every object (connector user lost rights, confidence level, organisation segregation);
- the connector is deployed with `CONNECTOR_SEND_TO_QUEUE=false` by mistake and ingests nothing;
- an internal (enrichment or import-file) connector cannot connect to RabbitMQ and silently never serves a request.

In all these cases the connector row in the UI is green, or red without a cause, and nothing notifies anybody.

---

## 3. Goals and non-goals

### Goals

1. Compute and store a per-connector health status with explicit reasons, re-evaluated on a fixed tick (60 s by default).
2. Detect the failure modes of §6 to the extent the platform can observe them, with an explicit list of what cannot be detected.
3. Keep false alarms low enough that alerts are actionable: per-connector expectations, hysteresis, suppression of platform-wide incidents, and an operator hint per reason code.
4. Alert on status transitions through the existing notification chain, on Community Edition as well as Enterprise Edition.
5. Surface the status where connectors are already monitored: Integrations > Deployed and the connector detail page.
6. No change to connectors, pycti or the protocol (header constraint). Everything is derived from what connectors already send.
7. Detect partial degradation of the ingested volume against a per-connector baseline learnt by the platform, with an explicit operator override for critical feeds.
8. Report worker-side problems once, at platform level (ingestion pipeline health), rather than on every connector row, and detect connectors that keep sending data without anything new landing (data freshness).

### Non-goals

- Replacing the XTM Composer health reporting for managed connectors (it is consumed as an input).
- Detecting a stream connector whose downstream target is broken while the connector swallows errors (§8).
- A general-purpose anomaly detection or learning system. Rules are explicit and reviewable; the volume baseline of §7.5 is a single robust-statistics rule with a documented reference window, not a model.
- Changing the works lifecycle (force completion, 7-day purge). Two small correctness fixes are recommended separately (§7.13).

---

## 4. Background: what the platform already knows

### 4.0 Terminology

- **ping (heartbeat)**: the `pingConnector` mutation pycti issues every 40 s; the two words are used interchangeably below.
- **registration**: the `registerConnector` mutation made at every connector process start.
- **work**: a unit of ingestion tracked in the history index (`Work`), created by the connector or by the platform.
- **`listen_<id>` / `push_<id>`**: the two RabbitMQ queues of a connector; `listen_<id>` carries requests *to* the connector (enrichment, import, export), `push_<id>` carries bundles *from* the connector to the workers.
- **worker**: the `opencti-worker` process that consumes `push_<id>` queues and writes objects into the platform, reporting progress on works.
- **`connectorManager`**: the existing platform module that force-completes and purges works. Not this RFC.
- **`ConnectorManager` / Composer / managed connector**: the XTM Composer entity, and the connectors it deploys.
- **`connectorHealthManager`**: the module proposed here.
- **Integrations > Deployed**: the UI page listing connectors (`/dashboard/integrations/deployed`), the single name used for it in this document.

### 4.1 The 40-second ping

Every long-running pycti connector starts a `PingAlive` daemon thread that calls `pingConnector` every 40 s (`client-python/pycti/connector/opencti_connector_helper.py:1081`). The thread is independent from the connector's main loop and has its own `try/except`, so **pings continue while the main loop is stuck or failing**.

The mutation (`opencti-graphql/src/domain/connector.ts:112-155`) writes on the Connector entity:

| Field | Written by | Semantics | Caveat |
|---|---|---|---|
| `updated_at` | platform, `now()` | server-side heartbeat | also bumped by **any** patch on the entity (§4.2) |
| `connector_state` | connector, free JSON string | cursor / progress of the connector | schema is connector-specific; about 130 connectors use a `last_run` key with three different formats (epoch int, ISO, naive local string) |
| `connector_info.last_run_datetime` | pycti scheduler | timestamp after the scheduled callback **returned without raising** (`helper.py:3118-3120`) | advances even when the callback caught and logged an exception, which virtually all connectors do; `null` for non-scheduler connectors |
| `connector_info.next_run_datetime` | pycti scheduler | `end of run + duration_period`, set in `finally` (`helper.py:3132-3133`) | stale during a run; still advances during buffering; `null` for hand-rolled loops, listen and stream connectors |
| `connector_info.buffering` | pycti | run skipped because the connector queue exceeds `queue_threshold` (`helper.py:3004-3013`) | also set to `true` in the infinite publish retry loop (`helper.py:3899-3906`) |
| `connector_info.queue_messages_size`, `queue_threshold` | pycti | sampled at the last scheduler tick | snapshot, not live |
| `connector_info.run_and_terminate` | pycti | `true` only when set inside `schedule_process` (`helper.py:3160`), followed by a `force_ping` | hand-rolled run-and-terminate connectors never set it |

Who populates `next_run_datetime` / `last_run_datetime` (connectors repository, Appendix A):

| Family | Count | Scheduler | `next/last_run` populated |
|---|---|---|---|
| external-import, pycti `schedule_iso/process/unit` | 115 / 175 | helper | yes |
| external-import, connectors-sdk | 10 / 175 | helper via SDK | yes |
| external-import, hand-rolled `while True` loop (mitre, cve, opencti…) | 49 / 175 (+1 with no loop at all) | none | **no** |
| internal-enrichment, import-file, export-file | 75 + 13 | `helper.listen()` | no |
| stream | 40 | `helper.listen_stream()` | no |

### 4.2 `active` is a heuristic, and a fragile one

`completeConnector` computes `active = built_in ? (active ?? true) : sinceNowInMinutes(updated_at) < 5` (`src/database/repository.js:59`). Connector is a dated internal object, so the middleware appends `updated_at = now` to **any** patch with impacted inputs that does not already carry it (`src/database/middleware.ts:2446-2449`). Consequences:

- `registerConnector` (`connector.ts:353`), `resetStateConnector` (`connector.ts:157`), composer status updates, trigger-filter edits and migrations all make a dead connector look active for 5 minutes;
- there is no in-middleware way to write on the entity without bumping `updated_at` (an explicit identical `updated_at` is discarded as a no-op, then the bump applies);
- run-and-terminate connectors legitimately show inactive between runs because `PingAlive` is not started for them (`helper.py:2522-2549`); they only `force_ping` once at the end (`helper.py:3168-3171`).

### 4.3 Registration

`OpenCTIConnectorHelper.__init__` calls `registerConnector` unconditionally on every process start (`helper.py:2443`). The platform patches the entity (`connector.ts:338-372`) but keeps no history. An uncaught exception in a scheduled callback is routed to `sys.excepthook`, replaced by `killProgramHook` which sends `SIGTERM` to the process (`helper.py:68-82, 2050`); with a container restart policy this becomes a crash loop visible only as repeated registrations.

### 4.4 Works

Works live in the history index (`src/domain/work.js:215-267`). Facts that matter for health:

- created **connector-side** by 170 / 175 external-import connectors (168 call `initiate_work`, 2 more rely on the SDK work manager), but not one per run: the connectors-sdk creates a work lazily on the first non-empty `send()` and **deletes** works that sent nothing (`connectors-sdk/.../_work_manager.py:212-218`); upstream-version-gated connectors save state only when the upstream version changed (cisa KEV, malpedia), and malpedia additionally opens no work in that case; mitre, cve and the opencti-datasets connector are *interval*-gated on `state.last_run` (`mitre/src/__main__.py:370-381`, `cve/src/connector/cve_connector.py:276`, `opencti/src/connector/connector.py:88-93`) and open a work on every elapsed interval whatever upstream did; 5 connectors never create works; 0 / 40 stream connectors do;
- created **platform-side** on demand for enrichment, import-file, export-file and analysis connectors (`enrichment.js`, `file-storage.ts`, `stixCoreObject.js`); idle is normal for them;
- `status` is `wait` at creation, `progress` on `toReceived`, `complete` when `processed >= expected` (`isWorkFinished`, `work.js:301`) via `reportExpectation` (worker) or `toProcessed`; `connectorManager` **force-completes** older `wait/progress` works of a connector as soon as a newer work of that connector receives a `reportExpectation` (`src/manager/connectorManager.js:22-56`), writing `completed_number < import_expected_number` and no error; it **deletes** complete works after `connector_manager.works_day_range` = 7 days (`connectorManager.js:18, 75-100`);
- about a third of external-import connectors ever call `to_processed(in_error=True)` (Appendix A); template connectors catch exceptions and leave works open or mark them processed without error;
- **errors have two origins**: worker-rejected items are appended by `reportExpectation` **with** a `source` field (`work.js:358-363`, produced by `opencti_stix2.py:3575-3586`); connector-reported failures come from `to_processed(in_error=True)` **without** `source` (`work.js:487`). The two are separable;
- `Work.updated_at` is set at creation (`work.js:229`), **not** touched by `toReceived` (`work.js:444-459`), `toProcessed` or `reportExpectation`; it is refreshed only by `pingWork` (`work.js:152-158`), which pycti calls every 5 minutes while an AMQP listen callback is running (`helper.py:576-586`), never on the HTTP callback path;
- `updateProcessedTime` completes a work with `expected = 0, total = 0` and writes **both** `completed_number = 1` and `import_expected_number = 1` (`work.js:474-479`), so an empty run closed by `to_processed` is stored as *one expected, one processed* and is indistinguishable in Elasticsearch from a genuine one-object run; only the absence of Redis work figures tells them apart;
- Redis holds a hash per work (`import_expected_number`, `import_processed_number`, `import_last_processed`) and `work:<connectorId>` = last work of the connector that received a `reportExpectation` (`src/database/redis.ts:520-534`); `import_last_processed` on a work hash is a second-granularity "last object processed" marker of that work.

### 4.5 RabbitMQ

`metrics()` performs one `GET /api/overview` and one `GET /api/queues` with a 5 s timeout and returns every platform queue with `messages`, `messages_ready`, `messages_unacknowledged`, `consumers`, `idle_since` (`src/database/rabbitmq.js:482-491`); it throws when the management API is unavailable. The front already issues this call every 5 s per open Integrations tab. `getConnectorQueueDetails` returns only message counts and collapses errors to `0/0` (`rabbitmq.js:372-403`).

`consumers` on `listen_<id>` counts the connector's AMQP consumers **only** for AMQP listen-type connectors; it is 0 by design for external-import and stream connectors, and belongs to the worker for connectors registered with `listen_callback_uri`. pycti acks before processing (`helper.py:570`) with `prefetch_count = 1`, so a hung callback keeps `consumers = 1` and lets `listen_<id>` grow.

### 4.6 Composer-managed connectors

XTM Composer writes `manager_requested_status` / `manager_current_status` on the entity and `connector-<id>-health` `{restart_count, started_at, last_update, is_in_reboot_loop}` in Redis with a 300 s TTL (`redis.ts:870-878`). `ConnectorManager.last_sync_execution` is the composer's own heartbeat. Nothing consumes these for alerting today; the UI shows only uptime.

### 4.7 Alerting primitives

`storeNotificationEvent` appends to the notification stream (`src/database/stream/stream-handler.ts:179-181`). `publisherManager` resolves a synthetic per-user trigger `platform-notification-<userId>` with the user's `personal_notifiers` (default UI + email) without any stored Trigger (`src/manager/notificationManager.ts:142-154`). Request-access already uses this path (`requestAccess-domain.ts:476-490`). There is **no** deduplication: events are merged per `data.id` inside a 60 s buffer (`publisherManager.ts:493-501`, `publisher_manager.buffering_seconds`) and grouped per recipient into one notification, but never suppressed. The audit path (`publishUserAction`) is Enterprise Edition only (`activityListener.ts:130`).

---

## 5. Why work cadence is not the primary signal

The initial idea that motivated this work was to analyse the **pattern of works**: creation cadence and completion rhythm. The investigation shows that this is a poor *primary* signal, for four reasons all documented in §4.4:

1. **Coverage.** No works for stream connectors, on-demand works only for internal connectors, none for 5 external-import connectors and for SDK connectors on empty runs, none at all with `CONNECTOR_SEND_TO_QUEUE=false` (`initiate_work` returns `None`, `opencti_api_work.py:182-235`).
2. **Irregularity by design.** Version-gated connectors (malpedia) legitimately go weeks without a work; configured periods span PT3M to P7D (Appendix A); several connectors open one work per importer or per page. No global threshold exists, and per-connector cadence baselines cannot be learnt from the works index beyond the 7-day purge (the volume baseline of §7.5 is therefore accumulated in Redis as objects are processed, §7.2). Admins can also "Clear all works".
3. **Completion is not success.** Force completion, `in_error` used by a minority, swallowed exceptions and the `= 1` defaults on empty runs make the completion rhythm reflect platform housekeeping as much as connector behaviour.
4. **Completion measures the worker.** Progress comes from `reportExpectation` sent by workers; a worker backlog makes healthy connectors look stalled.

However, for the class *"connector succeeds, nothing lands"* (§6, cases 5–8) the works are the **only** platform-visible evidence, through their content. Hence the two-axis design, extended by a volume axis that reads work *figures* (objects processed per day), never cadence.

---

## 6. Failure modes and detectability

Legend: ✔ decisive signal · ◐ corroborating signal · ✘ signal absent · ⚠ signal present but misleading, must be ignored · blank: not relevant to this mode. Code references are in the footnotes.

| # | Failure mode | Ping / registration | `connector_info` | `connector_state` | Works | Queues | Result |
|---|---|---|---|---|---|---|---|
| 1 | Process dead, not restarted | ✔ pings stop | | | | | KO `no_heartbeat` |
| 2 | Crash loop (restart policy) | ✔ repeated registrations, few or no pings | | | | | KO `crash_loop` if the connector has pinged at least once in its life; UNKNOWN `insufficient_history` if it never has (§7.5 stage 1) |
| 3 | Main loop stuck (retry without timeout, deadlock), pings continue | ⚠ pings continue | ✔ `next_run` overdue (scheduler connectors) | ◐ state frozen (hand-rolled loops) | ◐ no new work, no processed object | | KO `scheduler_stalled` (scheduler connectors) / DEGRADED→KO `no_progress` (hand-rolled loops) |
| 4 | Every run raises, exception caught by the connector (expired token, moved endpoint) | ⚠ pings continue | ⚠ `last_run` advances | ✔ state never saved | ◐ works absent or open | | DEGRADED→KO `silent_failure` |
| 4b | Same, connector reports it with `to_processed(in_error=True)` | ⚠ | ⚠ | ✔ | ✔ errors without `source` | | KO `connector_reported_error` |
| 5 | Source unreachable but fetch error swallowed, connector still saves state and closes an empty work¹ | ⚠ | ⚠ | ⚠ state changes | ✔ works closed by `toProcessed` without any `reportExpectation` | | DEGRADED `empty_runs` |
| 6 | Platform rejects every object (rights, confidence, segregation)² | ⚠ | ⚠ | ⚠ | ✔ works complete with `import_rejected_number = import_processed_number` (Redis counter, §7.2); the Elasticsearch `errors[]` array shows at most 100 of them | | KO `ingestion_rejected` |
| 7 | Worker nack without report³ | ⚠ | ⚠ | ⚠ | ✔ works stay `wait` with `processed_time` set and `processed < expected`, later force-closed with `completed_number < expected` | ◐ push queue empty | KO `bundles_lost`, attributed to pipeline |
| 8 | `CONNECTOR_SEND_TO_QUEUE=false` | ⚠ | ⚠ | ⚠ | ✔ works disappear versus persisted counter | | DEGRADED `no_works` |
| 9 | Infinite publish retry⁴ | ⚠ | ✔ `last_run` frozen, `buffering = true` with a small queue | | | ✔ | KO `publish_failing` |
| 10 | AMQP listen connector cannot reach RabbitMQ⁵ | ⚠ | | | | ✔ `consumers = 0` on `listen_<id>` | KO `not_consuming` |
| 11 | Listen callback hung | ⚠ | | | ◐ work `progress` with old `received_time` (its `updated_at` is refreshed every 5 min, misleading) | ✔ `listen_<id>` backlog grows with `consumers ≥ 1` | KO `hung_callback` |
| 12 | Stream connector, downstream broken, errors swallowed⁶ | ⚠ | | ⚠ `start_from` advances on every SSE heartbeat | | | **undetectable** |
| 13 | Stream connector killed by `StreamAlive` (45 s without SSE heartbeat)⁷ and restarted | ⚠ registrations, state advancing | | | | | — no alert (legitimate restart) |
| 14 | Platform unreachable from connectors (network incident) | all connectors flip together | | | | | UNKNOWN `platform_incident` — no alert |
| 15 | Worker backlog (workers down or slow) | | | | ◐ works stalled | ✔ `push_<id>` deep | DEGRADED `worker_backlog` on the connector, not alerted while the pipeline status (§7.14) is not OK |
| 16 | Partial degradation: the connector runs and ingests a fraction of its usual volume (pagination bug, over-strict filter, partial source outage, rejections under `error_ratio_degraded`) | ⚠ | ⚠ | ⚠ state changes | ✔ volume per bucket far below the connector's baseline | | DEGRADED `volume_drop`; KO `volume_below_expected` when an operator declared a minimum |
| 17 | Connector runs and lands its usual volume, but every object is an unchanged re-send (source frozen, cursor stuck, stale mirror) | ⚠ | ⚠ | ⚠ | ⚠ volume normal, zero created or modified objects | | DEGRADED `no_new_data` (§7.15) |
| 18 | Workers down or saturated (platform side) | | | | ◐ all import works stalled | ✔ push backlog growing, zero consumers or zero ack rate | Pipeline KO `no_workers` / `throughput_stalled`, DEGRADED `backlog_growing` (§7.14); per-connector `worker_backlog` not alerted |

¹ mitre `__main__.py:139-142, 400-401`; `work.js:474-479`. ² `opencti_stix2.py:3575-3586` → `reportExpectation` with `source`. ³ `opencti-worker/src/push_handler.py:270-274`; `connectorManager.js:22-56`; `redis.ts:520-534`. ⁴ `helper.py:3899-3906`. ⁵ `helper.py:917-929`. ⁶ `helper.py:1765-1787`. ⁷ `helper.py:1140-1147`.

Cases 5–8 are the reason works content is a **co-primary** axis for import connectors.

---

## 7. Proposed design

### 7.1 Overview

```
                 pycti (unchanged)                          platform
 ┌──────────────┐  pingConnector (40 s)    ┌────────────────────────────────────┐
 │  connector   │ ───────────────────────► │ updateConnectorWithConnectorInfo   │
 │  process     │  registerConnector       │  + last_ping_at                    │
 │              │ ───────────────────────► │  + connector_state_changed_at      │
 └──────────────┘                          │  + Redis ring buffers (state,      │
                                           │    registrations, runs)            │
 worker ── reportExpectation/toProcessed ─►│ works + volume buckets (§7.2)      │
                                           └───────────────┬────────────────────┘
                                                           │ every 60 s
                                           ┌───────────────▼────────────────────┐
                                           │ connectorHealthManager             │
                                           │  snapshot → context → exclusions   │
                                           │  → liveness → progress per type    │
                                           │  → works content → volume baseline │
                                           │  → hysteresis → Redis status       │
                                           │  → transition event                │
                                           └───────────────┬────────────────────┘
                                                           │
                        GraphQL Connector.health ◄─────────┘──► publisher (UI / email / webhook)
```

Three building blocks:

1. **Observability fields** added by the platform in the two mutations connectors already call, and volume counters in the per-object reporting path the worker already uses (§7.2). They cost no extra Elasticsearch write.
2. **A scheduled manager** built on `registerManager` (`src/manager/managerModule.ts:211`) with a `ManagerDefinition` (`:39-50`), Community Edition, one node at a time through the Redis lock, evaluating a pure rule function on a per-connector snapshot (§7.3–7.5).
3. **Storage outside the Connector document** (§7.7), GraphQL exposure, transition-only alerting (§7.8) and UI (§7.9).

### 7.2 Observability fields written by existing mutations

Registered as Connector attributes in `internalObject-registrationAttributes.ts` (the strict Elasticsearch mapping requires it; `refreshMappingsAndIndices` runs at boot, `initialization.ts:98`, so no data migration is needed) and exposed in `type Connector`:

| Field | Type | Written in | Rule |
|---|---|---|---|
| `last_ping_at` | date | `updateConnectorWithConnectorInfo` | `now()` on every ping, in both the normal and the reset branch (`connector.ts:122-125`; today the reset branch's `updated_at` is bumped only by the middleware, §4.2) |
| `connector_state_changed_at` | date | same | `now()` when the incoming `state` string differs from the stored one, **after normalising** `''`, `null`, `'null'`, `'{}'` to empty, and **skipped** while `connector_state_reset` is pending (`connector.ts:122-124`), otherwise an admin reset counts as two fake successes. Distinct from the existing `connector_state_timestamp` (`opencti.graphql:2233`), written only by `resetStateConnector` (`connector.ts:157`) to mark an admin reset; that field is left untouched |
| `active` (existing, derived) | boolean | `completeConnector` | becomes `sinceNowInMinutes(last_ping_at ?? updated_at) < 5`, so the legacy chip and the health status agree and administrative patches stop faking liveness |

Redis ring buffers (LPUSH + LTRIM, pattern already used at `redis.ts:834-835`, bounded to `ring_buffer_size` entries, keys under the platform prefix):

| Key | Appended when | Entry | Used for |
|---|---|---|---|
| `connector-health-status:<id>:state-changes` | `connector_state_changed_at` moves | `{at}` | expected period estimation, `silent_failure` arming |
| `connector-health-status:<id>:registrations` | `registerConnector` on a non built-in connector | `{at}` | crash-loop detection, run-and-terminate liveness |
| `connector-health-status:<id>:runs` | `connector_info.last_run_datetime` changes | `{last_run: incoming.last_run_datetime, scheduled_start: stored.connector_info.next_run_datetime, at: now()}` | observed run duration `D_k = last_run − scheduled_start`; `scheduled_start` must be captured from the **previously stored** `connector_info`, since the ping carrying `last_run_k` already carries `next_run_k` |

Cost: the comparison uses the connector already loaded by `pingConnector` (`connector.ts:145`); the dates ride on the same document replace as today's patch; one Redis `LPUSH/LTRIM` per actual change.

**Volume accounting.** Volume is counted per object, not per work, in the three platform calls the worker and connectors already make: `reportExpectation` (`work.js:330`), right after `redisUpdateWorkFigures`, issues `HINCRBY connector-health-status:<connector_id>:volume <YYYY-MM-DD>:landed 1`, or `…:rejected 1` when `errorData` is present; `updateExpectationsNumber` (`work.js:393`) issues `…:sent <expectations>`; `createWork` issues `…:works 1`. `<connector_id>` is `currentWork.connector_id`; `<YYYY-MM-DD>` is the UTC day of the platform `now()` at reporting time (`format.js:94`), never `Work.timestamp` nor a connector-side clock. Each command is followed by `EXPIRE volume_history_days` (idempotent), so the bound holds even when the manager is disabled. The increment is gated on `currentWork.event_type === 'EXTERNAL_IMPORT'` and on the connector being a real, non built-in Connector present in the entity cache (`getEntitiesMapFromCache(ENTITY_TYPE_CONNECTOR)`, `cache.ts:193`): built-in feeds and forms carry `built_in = true`, background-task and draft-validation pseudo connectors are absent from the cache, so none of them writes a volume hash. The commands are issued standalone, not inside the existing `redisTx` on the work hash, because a Redis Cluster `MULTI` must address a single slot (`SET work:<connectorId>` is kept outside the transaction for the same reason, `redis.ts:525`).

The once-per-work completion hook `countIngestionObjectsProcessed` (`work.js:317-329`) is deliberately **not** used: it fires at a work's *first* completion, and pycti calls `add_expectations` once per `send_stix2_bundle` (`helper.py:3771`) with `is_multipart` defaulting to `false` (`opencti_api_work.py:186`, set by 5 of 175 connectors), so a multi-bundle work "completes" as soon as the worker drains the bundles sent so far and the hook records a run prefix whose size depends on worker speed; it also never runs for works force-closed by `connectorManager`. The platform telemetry counter it feeds has the same undercount (§7.13).

A per-work counter `import_rejected_number` is added to the work hash by `redisUpdateWorkFigures(workId, isRejected)` (`redis.ts:520-531`, called from `reportExpectation` with `!!errorData`; `redisGetWorkCompletionState` and `redisGetWork` expose it), because the Elasticsearch `errors[]` array is capped at 100 (`work.js:360`) and cannot count rejections. Every `reportExpectation`, with or without error, increments `import_processed_number` before the error is examined (`work.js:332`, `redis.ts:528`), so rejected items are a subset of processed items and the *landed objects of a work* are `import_processed_number − import_rejected_number`. `import_processed_number` may exceed `import_expected_number`: incompatible elements are reported as rejections (`opencti_stix2.py:3766-3777`) but were excluded from the expectations by the splitter (`opencti_stix2_splitter.py:221-236, 300-307`). `landed` also includes items the worker skipped on purpose (scope filtering, inferred objects), because the worker reports an expectation for every item. The stream-event hook of §7.15 adds `<d>:created` and `<d>:updated` to the same bucket; the manager owns `<d>:unhealthy` and `<d>:unhealthy_by` (§7.5) and trims the hash (§7.7). Cost: one `HINCRBY` and one `EXPIRE` per processed object, added to a request that already performs one `SET`, one `MULTI`, one `HGETALL`, one Elasticsearch GET and one UPDATE; one pair per expectations batch; one pair per work creation.

### 7.3 Health model

```graphql
enum ConnectorHealthStatus { OK DEGRADED KO PAUSED UNKNOWN }
enum ConnectorHealthPeriodSource { CONNECTOR_INFO STATE_CHANGES WORKS REGISTRATIONS OVERRIDE NONE }

type ConnectorHealthReason {
  code: String!          # see table below
  message: String!       # English fallback rendered server-side (emails, API); the front translates from code
  observed_at: DateTime!
  details: JSON          # thresholds and values that fired (§7.11)
}

type ConnectorHealth {
  status: ConnectorHealthStatus!
  reasons: [ConnectorHealthReason!]!
  since: DateTime                 # when the current status was entered
  evaluated_at: DateTime!
  expected_period_seconds: Int    # P, when it could be derived
  period_source: ConnectorHealthPeriodSource!
  registrations: [DateTime!]!     # §7.2 ring buffers, newest first
  state_changes: [DateTime!]!
  runs: [ConnectorHealthRun!]!
  volume: ConnectorHealthVolume   # EXTERNAL_IMPORT connectors; null only while no volume hash exists yet
}

type ConnectorHealthRun { last_run: DateTime!, scheduled_start: DateTime, at: DateTime! }
type ConnectorHealthVolumeBucket { start: DateTime!, landed: Int!, rejected: Int!, sent: Int!, works: Int!, created: Int!, updated: Int!, unhealthy: Boolean!, unhealthy_by: [String!]! }
type ConnectorHealthVolume {
  granularity_days: Int!          # 1 or 7 (§7.5); buckets are g-buckets aligned on UTC days or ISO weeks
  buckets: [ConnectorHealthVolumeBucket!]!   # last volume_history_days / granularity_days buckets, oldest first
  armed: Boolean!                 # baseline conditions of §7.5 met
  pending_reason: String          # insufficient_history | below_min_objects | baseline_unstable | class_unarmed, when not armed
  reference_days: Int!
  baseline_p25: Int               # the tested statistic (unsplit R), null until armed; per-class values in reason details
  baseline_median: Int            # display only
  expected_minimum: Int           # operator override min_objects, when set
  expected_minimum_per: ConnectorHealthVolumePeriod   # granularity of the override, may differ from granularity_days
  freshness_armed: Boolean!       # §7.15 baseline on created + updated
  freshness_baseline_p25: Int
}

type IngestionPipelineHealth { status: ConnectorHealthStatus!, reasons: [ConnectorHealthReason!]!, workers_connected: Int!, queued_bundles: Int!, ack_rate: Float, evaluated_at: DateTime! }   # §7.14
input ConnectorHealthExpectedVolumeInput { min_objects: Int!, per: ConnectorHealthVolumePeriod! }
enum ConnectorHealthVolumePeriod { DAY WEEK }
type ConnectorHealthTransition { at: DateTime!, from: ConnectorHealthStatus!, to: ConnectorHealthStatus!, reasons: [ConnectorHealthReason!]! }
type ConnectorHealthCount { status: ConnectorHealthStatus!, count: Int! }
input ConnectorHealthConfigureInput { health_check_enabled: Boolean, health_externally_scheduled: Boolean, health_expected_period: String, health_expected_volume: ConnectorHealthExpectedVolumeInput, accept_volume_baseline: Boolean }

extend type Connector { health: ConnectorHealth }
extend type Query {
  connectorsHealthSummary: [ConnectorHealthCount!]! @auth(for: [MODULES])
  connectorHealthTransitions(id: ID!, first: Int): [ConnectorHealthTransition!]! @auth(for: [MODULES])
  ingestionPipelineHealth: IngestionPipelineHealth! @auth(for: [MODULES])   # §7.14
}
extend type Mutation {
  connectorHealthConfigure(id: ID!, input: ConnectorHealthConfigureInput!): Connector @auth(for: [MODULES_MODMANAGE])
}
```

Not to be confused with the existing `Connector.manager_health_metrics: ConnectorHealthMetrics` (`opencti.graphql:2253`), the container-level restart and uptime data written by XTM Composer and consumed here as an input (§4.6).

| Status | Meaning | Alerting |
|---|---|---|
| `OK` | liveness and progress rules pass | on recovery from KO / DEGRADED |
| `DEGRADED` | works but something is off, or a rule needs more periods to conclude | on entry |
| `KO` | not doing its job, with a reason | on entry |
| `PAUSED` | intentionally idle, within a time bound: managed connector requested stopped, legitimate buffering | never |
| `UNKNOWN` | not enough data, or the platform cannot observe (management API down, platform-wide incident, first minutes after boot) | never |

**Hysteresis.** A candidate status must be observed on `hysteresis_ticks` consecutive evaluations before it is committed and can alert; recovery to `OK` also requires it. With the default 60 s tick, 2 ticks are strictly longer than the publisher's 60 s buffer; lowering `interval` below 30 s requires raising `hysteresis_ticks`, and the manager logs a warning at start if `interval × hysteresis_ticks ≤ publisher_manager.buffering_seconds`.

**Reason codes.** The operator hint becomes the `message` fallback and the documentation content. Pipeline-level codes (`no_workers`, `throughput_stalled`, `backlog_growing`, `bundles_lost_widespread`) are listed in §7.14; `management_api_unavailable` is shared by both levels with the hint below.

| Code | Status | Meaning | Operator hint |
|---|---|---|---|
| `no_heartbeat` | KO | no ping for more than `heartbeat_timeout_minutes` | check that the container is running; read its logs |
| `crash_loop` | KO | repeated registrations without any successful activity between them | check startup logs and configuration |
| `reboot_loop` | KO | composer reports `is_in_reboot_loop` | check the container logs in the Composer view |
| `composer_health_missing` | DEGRADED | container reported started but no health report for `queue_confirm_ticks` ticks | check the Composer deployment |
| `composer_start_timeout` | DEGRADED | requested `starting` for more than `composer_start_timeout_minutes` | check image pull and container events |
| `publish_failing` | KO | `buffering` reported while the queue is far below threshold | check RabbitMQ exchange/queue routing and alarms |
| `scheduler_stalled` | KO | scheduled run overdue with no sign of activity | connector main loop stuck: restart it, check API timeouts |
| `silent_failure` | DEGRADED→KO | runs complete but state never changes | check credentials and upstream endpoint in connector logs |
| `no_progress` | DEGRADED→KO | no state change and no work for several periods (hand-rolled or run-and-terminate connectors) | check connector logs and external scheduler |
| `empty_runs` | DEGRADED | consecutive works closed without a single object | check the upstream source and connector logs |
| `ingestion_rejected` | DEGRADED→KO | worker-rejected ratio above `error_ratio_degraded`, then every object of the last `rejected_works_count` works rejected by the platform | check connector user rights, confidence level, organisation |
| `connector_reported_error` | DEGRADED→KO | connector marked its recent works in error | read the work error message |
| `bundles_lost` | KO (pipeline) | bundles acked by the worker but never reported | check worker logs |
| `no_works` | DEGRADED | connector runs but no longer opens works | check `CONNECTOR_SEND_TO_QUEUE` and output configuration |
| `volume_drop` | DEGRADED | ingested volume over the test window below `volume_drop_ratio` of the connector's baseline P25 | compare recent works with older ones; check source pagination, filters and partial rejections; accept the new level if the source changed |
| `volume_below_expected` | KO | ingested volume below the minimum declared by an operator | check the source; adjust the declared minimum if the expectation changed |
| `volume_rebaselined` | OK (informational) | the reference level was reset to the current volume, automatically or by an operator | confirm the lower level is expected; otherwise investigate the source |
| `no_new_data` | DEGRADED | volume is normal but created or modified objects collapsed against the connector's freshness baseline (§7.15) | the connector sends data but nothing new lands: check the source cursor or the upstream feed |
| `worker_backlog` | DEGRADED | push queue deep, works progressing slowly | check worker capacity; not a connector problem |
| `not_consuming` | KO | no consumer on `listen_<id>` while the process pings | check RabbitMQ credentials and network from the connector |
| `hung_callback` | KO (DEGRADED for `listen_callback_uri` connectors) | a request has been processing far beyond the connector's usual duration and requests pile up | restart the connector; check external API timeouts |
| `management_api_unavailable` | UNKNOWN | RabbitMQ management API unreachable | check `rabbitmq:management_*` configuration |
| `platform_incident` | UNKNOWN | most connectors lost their heartbeat at once | check network and API availability |
| `insufficient_history` | UNKNOWN | at least `crash_loop_count` registrations and no ping ever recorded (externally scheduled connector, or crash before the first ping) | mark as externally scheduled (§7.6) or check the container startup logs |

### 7.4 Rule map per connector type

| Type | Exclusions and liveness (§7.5 stages 1–2) | Progress (stage 3) | Works content and requests (stages 4–5) | Queues |
|---|---|---|---|---|
| EXTERNAL_IMPORT, pycti scheduler or SDK | heartbeat, crash loop, publish failing | `scheduler_stalled`, `silent_failure` | rejected, connector-reported, empty runs, bundles lost, no works, worker backlog, volume drop / below expected (stage 4b) | push depth for attribution |
| EXTERNAL_IMPORT, hand-rolled loop | same | `no_progress` | same | same |
| EXTERNAL_IMPORT, run-and-terminate (rare: scheduled outside the platform) | registration counts as heartbeat | `no_progress` with `P` from registrations | same | same |
| INTERNAL_ENRICHMENT / IMPORT_FILE / EXPORT_FILE / ANALYSIS, AMQP listen | heartbeat, crash loop | — | `hung_callback` | `not_consuming`, listen backlog |
| same, HTTP callback (`listen_callback_uri`) | heartbeat, crash loop | — | `hung_callback` as DEGRADED only | — |
| STREAM | heartbeat, crash loop (6 h window, state unchanged) | — | — | — |
| Any other type (`INTERNAL_NOTIFICATION`, `INTERNAL_INGESTION`, future) | heartbeat, crash loop | — | — | — |
| Managed (any type) | + `reboot_loop`, `composer_health_missing`, `composer_start_timeout`; requested stopped → `PAUSED` | as per type | as per type | as per type |

### 7.5 Evaluation pipeline

**Population.** Every real `ENTITY_TYPE_CONNECTOR` except `built_in` connectors and the internal pseudo-connectors, listed with `fullEntitiesList` (`middleware-loader.ts:360`) rather than `connectors()`, which is capped at `ES_DEFAULT_PAGINATION` = 500 (`engine.ts:219`).

**Snapshot per connector** (all reads pipelined, §7.12): the Connector document (`last_ping_at`, `connector_state_changed_at`, `connector_info`, `connector_type`, `listen_callback_uri`, `manager_*`, `connector_state_reset`, `connector_state_timestamp`, overrides); the health hash, the three ring buffers and, for import connectors, the volume hash (§7.7); from the single works aggregation of the tick, the last `works_window` works of the connector (`status`, `timestamp`, `received_time`, `processed_time`, `completed_time`, `import_expected_number`, `completed_number`, `errors[].source`); `lastReportedWorkId = GET work:<connectorId>` and `HGET <lastReportedWorkId> import_last_processed` (absent when the work was purged, treated as "no movement"); for every work in the window, complete or not, `expected` / `processed` / `import_last_processed` from its Redis hash (`redisGetWork`; the hash is created with the work and deleted only with it, `work.js:258, 132`, so it survives completion until the 7-day purge; a purged hash is treated as `expected = 0` with `import_last_processed` absent), because the Elasticsearch document carries `completed_number = 0` until completion and, before the §7.13 fix, `import_expected_number = 1` for empty runs; per-queue `consumers`, `messages`, `messages_ready` for `listen_<id>` and `push_<id>` from the tick's `metrics()` call; composer health key and `ConnectorManager.last_sync_execution` for managed connectors.

**Definitions.**
- *Empty work*: `expected = 0` in Redis (before the §7.13 fix, an empty work closed by `toProcessed` shows `import_expected_number = completed_number = 1` in Elasticsearch and no Redis `import_last_processed`).
- *Successful work*: `status = complete`, received at least one `reportExpectation` (`import_last_processed` set), `completed_number ≥ expected`, and `import_rejected_number = 0` (no worker-rejected item).
- *Worker-rejected item*: an error with `source`. *Connector-reported error*: an error without `source`.
- *Successful activity* (for crash-loop and stall rules): a successful work, or a `last_run_datetime` advance **with** a state change.
- *Expected period `P`*, in order of preference: admin override (`OVERRIDE`); `next_run_datetime − last_run_datetime` when both present, `buffering = false` and `last_run_datetime` advanced since the previous runs entry (`CONNECTOR_INFO`; during buffering pycti advances `next_run` without `last_run`, `helper.py:3114-3133`, so the previously stored `expected_period_seconds` is kept); median interval of the state-change buffer with ≥ `min_period_samples` samples (`STATE_CHANGES`); median of work-creation intervals with ≥ `min_period_samples` works in the 7-day window (`WORKS`); median registration interval for run-and-terminate connectors (`REGISTRATIONS`); otherwise `null` (`NONE`).
- *Observed run duration `D_max`*: maximum of the last `runs_considered` `D_k` from the runs buffer (0 when unknown).
- *Volume bucket*: a UTC calendar day `d` with `landed(d)` = objects reported by the worker without error on `d` for the connector's `EXTERNAL_IMPORT` works, `rejected(d)`, `sent(d)` = expectations added on `d`, `works(d)` = works created on `d` (§7.2; works force-closed by `connectorManager` add nothing and surface as `bundles_lost`). Volume is *objects the worker processed without rejection*, which includes unchanged objects re-sent every run; it is not "new knowledge" (§8). `unhealthy(d)` is set by the manager when the connector's stored status was `KO` or `DEGRADED` at any tick of `d`, when it was `UNKNOWN platform_incident` or `PAUSED` for a managed stop or a pending state reset for a cumulative `volume_unhealthy_min_minutes` within `d`, or when `d` belongs to the test window of a stage-4b rule that fired; `unhealthy_by(d)` records the set of reasons. Buffering `PAUSED` ticks are healthy for volume purposes.
- *Evaluation granularity `g`*: 1 day when `P ≤ 36 h` or `P` is unknown, 7 days otherwise, aligned on UTC days and ISO weeks (Monday 00:00 UTC); daily buckets are summed per `g`. `g` is sticky (recomputed only when `P` moves by more than 50 % from the value that fixed it) and stored in the status hash.
- *Test window `T`*: the last `volume_test_buckets` (`volume_test_buckets_daily` when `g = 1`) complete `g`-buckets not flagged unhealthy by a reason other than a stage-4b rule; the current partial bucket is never tested. If fewer such buckets exist within the reference window, stage 4b is skipped for the tick and the previous volume verdict is kept.
- *Reference set `R`*: the complete `g`-buckets of the `volume_reference_days` days (`volume_history_days` when `g = 7`) immediately preceding `T`, excluding buckets with `unhealthy = true` and buckets that end before `volume_reset_at` (the last admin state reset, `connector_state_timestamp`: pre-reset behaviour is not the reference for post-reset behaviour). When `g = 1` and each day class (weekday, weekend) has at least `volume_min_reference_buckets` buckets in `R`, each tested bucket is compared to its own class; otherwise the unsplit `R` is used. A tested bucket whose class is unarmed is dropped from `T`.
- *Baseline*: `P25(R)` is the tested statistic, `median(R)` is kept for display; `expected(T)` = Σ over the tested buckets of the P25 of their reference set. The baseline is **armed** only if `|R| ≥ volume_min_reference_buckets`, `P25(R) ≥ volume_min_objects_per_bucket` (a feed with more than a quarter of empty buckets never arms) and, on the tick where these first hold, `Σ landed(T) ≥ volume_drop_ratio × expected(T)` (never arm into a drop: a backfill that just ended cannot alert, its buckets age out and the rule arms cleanly, `pending_reason = baseline_unstable` meanwhile). Arming changes only after its condition has held or failed on 7 consecutive daily evaluations. When not armed, `volume_drop` is skipped but `volume_below_expected` still applies and the buckets stay exposed on `Connector.health.volume`.

Rules are applied in stage order. The first matching stage decides the candidate status; later stages add reasons but cannot downgrade `PAUSED` / `UNKNOWN` **while the exclusion's time bound holds**.

**Stage 0 — platform context.**
- If `metrics()` throws, queue-based rules are disabled for the tick and their would-be findings become `UNKNOWN management_api_unavailable`.
- Incident test, stateless and sliding: `recent = {c : last_ping_at > now − incident_window_minutes}`, `lost = {c ∈ recent : last_ping_at ≤ now − heartbeat_timeout_minutes}`. If `|lost| / |recent| > incident_ratio`, every connector in `lost` is stored as `UNKNOWN platform_incident` for the tick (`since` unchanged; `UNKNOWN` never alerts, §7.8) and its stage 2 rules are skipped; once the ratio falls back under `incident_ratio` the connectors are re-evaluated with the normal hysteresis. Because it only reads `last_ping_at`, an incident that straddles two ticks is still caught.
- Boot grace: the first tick that finds no `connector-health-status:started_at` key writes it (`SET` with the current timestamp, `EX 3 × interval`); every later tick refreshes the TTL without changing the value. For `boot_grace_minutes` after the stored timestamp no transition is committed. The key is platform-wide and kept alive by whichever node ticks, so a rolling restart of one node does not re-arm it, while a full platform stop lets it expire and re-arms it at the next start.
- Worker outage: while the ingestion pipeline status (§7.14) is `KO` or `DEGRADED`, per-connector `worker_backlog` and `bundles_lost` reasons are recorded but not alerted; the root cause is reported once, at pipeline level.

**Stage 1 — exclusions (→ `PAUSED`) and the run-and-terminate liveness mode, each bounded in time; once the bound is exceeded the connector falls through to stage 2.**
- managed connector with `manager_requested_status ∈ {stopped, stopping}`; `starting` only while requested for ≤ `composer_start_timeout_minutes`, afterwards `DEGRADED composer_start_timeout`;
- `connector_state_reset` pending, only while `now − connector_state_timestamp ≤ heartbeat_timeout_minutes` (a dead connector can never clear the flag, `connector.ts:122-124`);
- `buffering = true` **and** `queue_messages_size ≥ queue_threshold` (the legitimate condition, `helper.py:3004-3013`);
- run-and-terminate connector (rare in customer deployments: the schedule lives outside the platform, so only the next run is unknown), recognised by `connector_info.run_and_terminate = true` on its last ping (set in memory at `helper.py:3160` and transmitted only by the `force_ping` at `:3170`, after the callback returned) or by the admin override `health_externally_scheduled`. Every run registers (`helper.py:2443`); a run that **completes** pings once, but a run whose callback raises reaches `sys.excepthook` → `killProgramHook` and exits **without** pinging (`:3198-3204`, `:68-82`), so a run-and-terminate connector failing every run shows registrations with no ping between them. Hence a **registration counts as a heartbeat**: liveness is `now − max(last_ping_at, last_registration_at) ≤ max(heartbeat_timeout_minutes, 2 × median registration interval)`, beyond that `KO no_heartbeat` with `details.mode = 'run_and_terminate'`; `crash_loop` is evaluated with a specific criterion, `crash_loop_count` consecutive registrations without a ping between them → `KO crash_loop`, `details.mode = 'run_and_terminate'` (the end-of-run ping is the successful activity that separates a cron from a crash loop); stage 3 `no_progress` applies with `P` from `REGISTRATIONS`. No `PAUSED` state is involved.

Registration-pattern inference is deliberately **not** used to recognise this mode: Kubernetes `CrashLoopBackOff` plateaus at 5 minutes and is indistinguishable from a 5-minute cron by cadence alone. A non built-in connector with ≥ `crash_loop_count` registrations and **no ping ever recorded** is reported `UNKNOWN insufficient_history` with a hint (externally scheduled connector without the flag, or crash before the first ping), so it neither alerts nor hides.

**Stage 2 — liveness (all types).**
- `no_heartbeat`: the connector has pinged before and `now − last_ping_at > heartbeat_timeout_minutes` → `KO`. Not evaluated for connectors recognised as run-and-terminate, whose liveness bound is the stage 1 rule (registration counts as a heartbeat).
- `crash_loop`: the connector has pinged before, and at least `crash_loop_count` registrations within `crash_loop_window_minutes` with **no successful activity between them**; evenly spaced registrations with a successful work between each are a cron, not a crash loop. For connectors recognised as run-and-terminate the "no successful activity" criterion is "no ping between the registrations" (stage 1). For stream connectors the window is `crash_loop_window_minutes_stream` and the rule additionally requires `connector_state` unchanged across the registrations, because `StreamAlive` kills the process after 45 s without heartbeat and slow callbacks trigger legitimate restarts (case 13).
- managed connectors: `is_in_reboot_loop = true` → `KO reboot_loop`; `manager_current_status = started` but no health key while the composer heartbeat is fresh, for `queue_confirm_ticks` → `DEGRADED composer_health_missing`.
- `publish_failing`: `buffering = true` with `queue_messages_size < publish_failing_queue_ratio × queue_threshold` for `queue_confirm_ticks` → `KO` (case 9).

**Stage 3 — progress, `EXTERNAL_IMPORT` only.**
- `scheduler_stalled` (case 3): `next_run_datetime` present, `now > next_run_datetime + max(2P, stall_floor_minutes, 2 × D_max)`, `last_run_datetime` unchanged, **and** no work created and no `import_last_processed` movement since `next_run_datetime`. The corroboration is mandatory: `next_run` is stale during a run (§4.1), so a MISP or Mandiant run longer than its documented default period (PT5M, `misp/docker-compose.yml:12`, `mandiant/docker-compose.yml:13`) would otherwise be reported as stalled while it is actively sending bundles.
- `silent_failure` (case 4): `P` known, `now − connector_state_changed_at > silent_failure_degraded_periods × P` while `last_run_datetime` keeps advancing → `DEGRADED`; beyond `silent_failure_ko_periods × P` → `KO`. **Armed only if** the state-change buffer contains at least one entry: three helper-scheduled connectors (opencti-stream, socradar, vxvault) never call `set_state` and would otherwise be permanently KO. **Vetoed** when a *successful work* completed inside the window: cisa KEV opens a work *before* comparing the catalogue version and closes it when nothing changed (`cisa/src/main.py:288, 306-313`), so the veto protects it. malpedia does **not**: `initiate_work_id` is only called inside its `check_version` branch (`malpedia/src/malpedia_connector/connector.py:104-111`), so with an unchanged upstream it produces neither a state change nor a work while `last_run_datetime` keeps advancing; it is the primary candidate for a shipped `health_expected_period` default (§7.6).
- `no_progress` (hand-rolled loops and run-and-terminate connectors, no `next_run`): `P` known, `now − max(connector_state_changed_at, last_work_created_at) > silent_failure_degraded_periods × P` → `DEGRADED`, beyond the KO multiple → `KO`. When `P` is unknown but the connector historically changed state or created works, `DEGRADED` after `no_progress_fallback_days` of silence.

**Stage 4 — works content, `EXTERNAL_IMPORT` (cases 5–8, 15).** Uses the last `works_window` works plus a **persisted per-connector counter** `{work_count, last_work_created_at}` maintained by the manager so the 7-day purge and "Clear all works" do not erase history.
- `ingestion_rejected`: the last `rejected_works_count` completed works with `import_processed_number > 0` each have `import_processed_number − import_rejected_number = 0` (no landed object; Redis counters of §7.2, since the Elasticsearch `errors[]` array is capped at 100) → `KO`. Worker-rejected ratio `Σ import_rejected_number / Σ import_processed_number` over the window above `error_ratio_degraded` → `DEGRADED`.
- `connector_reported_error` (case 4b): the last `rejected_works_count` completed works each carry a *connector-reported error* → `KO`; ratio above `error_ratio_degraded` → `DEGRADED`. This is the explicit failure signal of the connectors that call `to_processed(in_error=True)`.
- `empty_runs`: `empty_runs_count` consecutive *empty works* for a connector whose history contains works with expectations **and** whose share of empty works over the last `volume_reference_days` is below 25 % (cisa KEV closes an empty work on every release-free day and must not fire over a long weekend) → `DEGRADED`.
- `bundles_lost`: a work in `wait` or `progress` with `processed_time` set and `processed < expected` for more than `max(stuck_work_floor_minutes, stuck_work_p95_factor × p95 of past work durations)` with `push_<id>` empty, **or** a `complete` work in the window with `completed_number < import_expected_number` and no `source` error (force-closed by `connectorManager`) → `KO`, `details.attribution = 'pipeline'`. If `push_<id>` is deep instead → `DEGRADED worker_backlog`.
- `no_works`: the persisted counter shows works in the past, none created for more than `silent_failure_degraded_periods × P` while `last_run_datetime` or the state keep advancing → `DEGRADED`. This is the one place where work *cadence* is a primary rule, because nothing else sees `CONNECTOR_SEND_TO_QUEUE=false`.

**Stage 4b — ingested volume against a baseline, `EXTERNAL_IMPORT` (case 16).** The binary rules of stage 4 see "nothing lands"; this stage sees "much less than usual lands". It detects drops of roughly 75 % or more, sustained over the whole test window, against the preceding reference window; slow drifts and single bad days are out of its reach by design (§8).
- `volume_drop`: baseline armed, `Σ works(T) ≥ 1`, `Σ landed(T) > 0` (total absence is stage 4's job) and `Σ landed(T) < volume_drop_ratio × expected(T)` → `DEGRADED`. A learnt baseline never produces `KO`. The test window is the natural hysteresis (three complete days for daily-granularity connectors, two complete weeks for weekly ones); `hysteresis_ticks` applies on top. When it fires, every bucket of `T` is flagged `unhealthy_by += volume_drop` (the tested days, not the detection day).
- `volume_below_expected`: the operator override `health_expected_volume = {min_objects, per: DAY | WEEK}` is set and `landed` of each of the last `volume_test_buckets` complete buckets **at the override's granularity** is `< min_objects` → `KO`. Independent of the learnt baseline: it runs whether or not `armed` is true. The operator declared the expectation, so violating it is what they asked to be told.
- Notifications for `volume_drop` have their own switch, `volume_alerting_enabled` (§7.10): the status is shown in the UI from phase 1, notifications start only when the shadow-mode counters of this rule are under the agreed rate.
- **Re-baselining.** Freezing learning while the connector is degraded has a corollary: a legitimate, permanent drop (the source reduced its output) would keep `volume_drop` on forever, because the tested buckets are `unhealthy` and excluded from `R`. Two escapes. Automatically, when `volume_drop` has been the connector's **only** reason for `⌈volume_relearn_days / g⌉` consecutive complete buckets (21 days, 3 weeks for weekly connectors; the invariant `relearn buckets > (reference buckets − test buckets) / 2` keeps the rule from re-firing right after), the buckets flagged by `volume_drop` alone re-enter the reference set and a distinct committed transition `rebaselined` is emitted (§7.8, label "Baseline reset", never "Recovered": nothing recovered, the lower level was accepted), with the informational reason `volume_rebaselined` carrying the old and new P25 in `details` for the following reference window. Explicitly, through `connectorHealthConfigure(accept_volume_baseline: true)`, which clears the `volume_drop`-only flags immediately and records the accepting user in the transition. Buckets flagged by any other reason (`KO`, managed stop, incident) stay excluded.

*Why a baseline with a reference set rather than a rolling median of recent runs.* A rolling median over the last N runs has three failure modes that the reference-set construction avoids. (1) **Contamination**: once the window fills with degraded runs, the median follows and the drop becomes the new normal; excluding the test window and the buckets flagged when a rule fired freezes learning while the connector is degraded, and the never-arm-into-a-drop condition keeps deployment backfills and post-reset re-imports out of the reference. (2) **Seasonality**: many feeds publish on weekdays only (NVD, vendor advisories) or in weekly cycles; comparing a Monday to a median that includes weekends over- or under-states the drop, hence the day-class split and the weekly granularity for long-period connectors. Public holidays are not modelled (§8). (3) **Zero-inflated and bimodal feeds**: version-gated connectors bring nothing on most runs and a whole catalogue occasionally (cisa KEV re-sends about 1 400 entries on each release day and nothing otherwise); a median arms such a feed on most days and fires on any two release-free weekdays, whereas P25 with the quarter-empty arming rule and the `landed > 0` precondition keeps the rule silent for them. A **fixed** baseline calibrated once would avoid contamination but would go stale as feeds grow or shrink; the reference set therefore slides, slowly (42 days, 90 for weekly connectors), and the explicit `health_expected_volume` override is the fixed baseline for operators who know what they expect.

**Stage 5 — listen-type connectors** (`INTERNAL_ENRICHMENT`, `INTERNAL_IMPORT_FILE`, `INTERNAL_EXPORT_FILE`, `INTERNAL_ANALYSIS`). Idle is `OK`.
- `not_consuming`: AMQP protocol (no `listen_callback_uri`), heartbeat OK, `consumers = 0` on `listen_<id>` for `queue_confirm_ticks` → `KO` (case 10). The reconnect loop retries every 10 s, so two ticks avoid flapping on broker hiccups.
- `hung_callback` (case 11): a work in `progress` whose `received_time` is older than `max(stuck_work_floor_minutes, stuck_work_p95_factor × p95 of this connector's past received→completed durations)` **and** `listen_<id>.messages_ready` growing versus the previous tick with `consumers ≥ 1` → `KO`. `Work.updated_at` is deliberately not used: it is refreshed every 5 minutes for as long as the hung thread lives, so a rule on its staleness never fires on a real hang and fires on any work that waited in the queue. Connectors with `listen_callback_uri` have no keepalive at all (`helper.py:829-836`), so for them the rule emits `DEGRADED` only.

**Stage 6 — `STREAM`.** Liveness and crash loop only (stream window). Downstream breakage is documented as undetectable (§8).

**Any other `connector_type`** (`INTERNAL_NOTIFICATION`, `INTERNAL_INGESTION`, `schema/general.js:52-53`, future types): stage 2 only, `period_source = NONE`.

### 7.6 Per-connector overrides

Four admin-editable attributes on the Connector entity, set through `connectorHealthConfigure` (§7.3):

- `health_check_enabled: Boolean` (default `true`) — opt a connector out (test connectors, decommissioned sources);
- `health_externally_scheduled: Boolean` (default `false`) — declare a hand-rolled run-and-terminate connector (about 40 in total, including mitre, cve and opencti datasets; Appendix A) so stage 1 treats it as run-and-terminate;
- `health_expected_period: String` (ISO 8601 duration, PT1M to P90D) — force `P` for connectors whose behaviour cannot be inferred (version-gated state such as malpedia, custom cursors);
- `health_expected_volume: {min_objects, per: DAY | WEEK}` — declare the minimum ingested volume of a critical feed; drives `volume_below_expected` (§7.5 stage 4b) and is shown as the expected minimum on the Health card.

The same mutation accepts the action `accept_volume_baseline: true` (an action, not an attribute: it is never written on the Connector document): it clears, in the Redis volume hash, the `unhealthy` flags set by `volume_drop` alone so the current volume becomes the reference, and records the acceptance in the transitions buffer (§7.5 stage 4b, re-baselining). A request carrying only that flag performs no entity patch.

These are rare, user-triggered writes, but they are exposed to the lost-update race described in §7.7 (load before lock, full-field replace): a ping that loaded the document before the override commits would revert it. `connectorHealthConfigure` therefore takes the connector lock **before** loading and patches from the loaded instance (`patchAttributeFromLoadedWithRefs`, `middleware.ts:3031`). `pingConnector` gets the same lock-first treatment (platform-only change), which also closes the existing register-or-reset-versus-ping race of §4.2. With `active` recomputed from `last_ping_at` (§7.2) the `updated_at` bump caused by these writes is harmless. Shipping defaults for known version-gated connectors is a follow-up on the connectors catalogue side.

### 7.7 Storage and exposure

**Health must not be written on the Connector document by the manager.** `updateAttribute` loads the entity before taking the lock (`middleware.ts:3001, 2629`) and `elUpdateElement` replaces the whole prepared document (`engine.ts:5163-5168`). A manager write on every connector every 60 s racing with the 40-second ping would either revert the ping's fields (making the connector look dead) or be reverted by the ping (making the status flap and re-alert). Raw `elUpdate` has the same race and adds an index refresh per write. The race is tolerable for rare admin writes protected by the lock-first pattern of §7.6, not for a periodic write.

Therefore, per connector, under the platform Redis prefix:

- hash `connector-health-status:<id>` = `{status, reasons, since, evaluated_at, previous_status, candidate_status, candidate_ticks, expected_period_seconds, period_source, work_count, last_work_created_at, last_listen_messages_ready, last_push_messages, rule_counters}`;
- the three ring buffers of §7.2 and a fourth, `connector-health-status:<id>:transitions` = `{at, from, to, reasons}`, written on every committed transition;
- the volume hash `connector-health-status:<id>:volume` (§7.2, §7.15), fields `<YYYY-MM-DD>:landed|rejected|sent|works|created|updated|unhealthy|unhealthy_by`, trimmed by the manager once per UTC day (first tick after midnight) with one `HDEL` of the expired fields; the status hash additionally keeps `volume_granularity_days`, `volume_armed`, `volume_pending_reason`, `volume_baseline_p25`, `volume_baseline_median`, `volume_reset_at`, `freshness_armed`, `freshness_baseline_p25` for exposure;
- a Redis SET `connector-health-status:index` of connector ids, maintained by the hook and the manager on every write (`SADD`), used for cleanup instead of `SCAN`: ioredis `keyPrefix` applies neither to `SCAN` patterns nor to returned keys, and cluster mode would need a per-master scan;
- `EXPIRE 7d` on every `connector-health-status:<id>*` key except the volume hash, refreshed by the manager each tick; the volume hash carries `EXPIRE volume_history_days`, set by the hook on every write, so the bound holds even with the manager disabled and a week-long manager outage does not erase the baseline; absence of the status hash = `UNKNOWN`.

The prefix `connector-health-status:` is distinct from Composer's `connector-<id>-health` (`redis.ts:873`).

**Cleanup.** `connectorDelete` (`connector.ts:410-412`) removes the status hash, the four buffers, the volume hash and the index entry in the same call. Once per hour the manager iterates the index SET and deletes the keys of ids that are not in the health population of §7.5 (real, non built-in connectors), then removes them from the index; this covers orphans left by deletions performed while the manager was disabled. The platform-wide `connector-health-status:started_at` and `connector-health-status:pipeline` (§7.14) keys are not indexed; the pipeline hash carries the same `EXPIRE 7d`, refreshed each tick.

**Exposure.** `Connector.health` is resolved from Redis exactly like `manager_health_metrics` (`src/resolvers/connector.js:117`); `Query.connectorsHealthSummary` feeds the status facet and the Integrations header; `Query.connectorHealthTransitions` feeds the Health card timeline; telemetry gauge `connectors_health_count{status}` in `telemetryManager`.

**Compatibility.** All schema changes are additive (new fields, types, enums, one mutation, three queries); no existing field changes type or nullability. The only semantic change is `Connector.active` (§7.2), visible to API clients that poll it. pycti's `ConnectorInfoInput` is unchanged.

A Redis flush shows every connector as `UNKNOWN` until statuses are recomputed and re-committed after `hysteresis_ticks` ticks; buffer history is lost, so `P` falls back to `connector_info` or works. This is consistent with how work counters and composer health already behave.

### 7.8 Alerting

Alerts are emitted **only on committed transitions**: `→ KO`, `→ DEGRADED`, `KO|DEGRADED → OK`, and the `rebaselined` transition of §7.5 stage 4b. Never on `PAUSED` or `UNKNOWN`.

- **Channel (Community and Enterprise).** One event per transitioning connector: `storeNotificationEvent` with an `ActionNotificationEvent` addressed to `platformNotification(recipient)` for each recipient. `ActionNotificationEvent.data` (`notificationManager.ts:98-103`, today `{ id: StixId | null; representative }`) gains `entity_type: 'Connector'`, propagated into `NotificationContentEvent.entity_type` by the publisher (`publisherManager.ts:69-74`) so the front can route on it; `data.id` carries the connector `internal_id` (the route expects it), so the `id` type is widened to `string | null`, unlike request-access which passes a `standard_id` (`requestAccess-domain.ts:480`). `representative.main = "<connector name>: <status> — <reason message>"`; `targets[].type = 'to_ko' | 'to_degraded' | 'recovered' | 'rebaselined'`, shown by the UI as the operation chip with labels "KO", "Degraded", "Recovered", "Baseline reset".
- **Recipients (decided, §12 #1).** Active, non-service-account, non-internal users holding `MODULES` ("Access connectors", the capability that gates `connectors` and Integrations > Deployed), built with `convertToNotificationUser(user, user.personal_notifiers)` (`notificationManager.ts:258`). Service accounts must be filtered, otherwise the publisher throws for each of them (`publisherManager.ts:249-251`). Connectors are platform-level objects with no organisation scoping; recipients are resolved platform-wide and the alert content carries no knowledge data, so organisation segregation does not apply. A settings-level recipient list or a dedicated notifier (webhook towards a monitoring tool) is an option for a later phase.
- **Storm control.** Hysteresis (§7.3) keeps two transitions of one connector out of one publisher buffer. The publisher's 60 s buffer already groups the events of several connectors per recipient into one notification, so a controlled restart yields one digest, not N emails. Only above `storm_threshold` transitions in a single tick are the per-connector events replaced by one summary event with `data.id = 'connector-health'`, `data.entity_type = 'ConnectorHealthSummary'`, `representative.main = '<n> connectors changed health status'`.
- **Enterprise Edition audit (phase 4).** `publishUserAction` with `event_type: 'mutation'`, `event_scope: 'health'`, `event_access: 'administration'`, emitted as `SYSTEM_USER` (origin socket `internal` passes the guard at `activityListener.ts:127-129`). This needs an explicit branch in `activityListener` (it only logs a whitelist of scopes, `:205-252`) and a new entry in `EVENT_SCOPE_VALUES` (`activityListener.ts:35`) so activity triggers can filter on it.
- **Not used.** `Settings.platform_critical_alerts`: it renders as a blocking modal on every page load for admins and supports a single alert; unsuitable for an operational status.

### 7.9 UI

Nothing is automatic on the front: the status model is a closed union and `computeConnectorStatus` (`opencti-front/src/utils/Connector.tsx:66-115`) derives everything from `active` and `manager_*`. Work items:

1. Add `health { status reasons { code observed_at details } since }` to `ConnectorsStateQuery` (polled every 5 s, `ConnectorsState.tsx:6-32`) and to the connector detail fragment.
2. Extend `DeployedIntegrationStatus` (`useDeployedIntegrations.ts:15`) and the status facet with `ko`, `degraded`, `paused`, `unknown` (health `OK` maps to the existing `active`); make `computeConnectorStatus` **prefer** `health` when present, so one chip is shown, not two contradicting ones (decided, §12 #4).
3. A severity chip (OK green, DEGRADED orange, KO red, PAUSED grey, UNKNOWN neutral) replacing `ItemBoolean` for connectors; the Filigran Design System component takes precedence if it ships one. Phase 1 ships this chip read-only so operators can review shadow results.
4. Detail page: a "Health" card with status, reasons and thresholds, expected period and its source, a volume sparkline (`Connector.health.volume.buckets`, labelled as UTC days or ISO weeks, against `baseline_p25` and, when `expected_minimum_per` matches `granularity_days`, `expected_minimum`, with `created + updated` as a second series on its own scale against `freshness_baseline_p25`, §7.15), plus a timeline from `connectorHealthTransitions` and the ring buffers exposed on `Connector.health` (`registrations`, `state_changes`, `runs`). `manager_health_metrics`, already fetched and never rendered, belongs there too.
5. Notification routing: in `Alerts.tsx` (`:244-252`) and `DigestNotification.tsx`, `entity_type === 'Connector'` → `/dashboard/integrations/connectors/<id>` (route `/connectors/:connectorId/*` under `/integrations/*`, `integrations/Root.tsx:25-28`, `Index.tsx:154`); `'ConnectorHealthSummary'` → `/dashboard/integrations/deployed?status=ko,degraded`; `'IngestionPipeline'` (§7.14) → `/dashboard/integrations/deployed`. Today a Connector `instance_id` is routed to `/dashboard/id/<id>`, which cannot resolve an internal object.
6. Built-in feed twin connectors are folded into their feed card (`useDeployedIntegrations.ts:105-126`); they are excluded from the manager (`built_in`) and the feeds keep their own `last_execution_status`.
7. i18n: the reason `code` maps to keys `Connector health reason: <code>` in `lang/front/*.json` (9 locales) with `details` values interpolated; status labels are translated; notification emails stay English, as request-access notifications do today.

### 7.10 Configuration

Under `connector_health_manager` in `default.json`, all overridable by environment. This table is the single source of defaults; §7.5 refers to keys by name.

| Key | Default | Purpose |
|---|---|---|
| `enabled` | `true` | manager switch |
| `interval` | `60000` | tick (ms) |
| `lock_key` | `connector_health_manager_lock` | cluster lock |
| `alerting_enabled` | `false` in phase 1, `true` from phase 2 | emit notifications on transitions |
| `hysteresis_ticks` | `2` | consecutive ticks before committing |
| `heartbeat_timeout_minutes` | `5` | aligned with `active` |
| `crash_loop_count` / `crash_loop_window_minutes` / `crash_loop_window_minutes_stream` | `3` / `15` / `360` | |
| `composer_start_timeout_minutes` | `10` | `starting` bound before `composer_start_timeout` |
| `publish_failing_queue_ratio` | `0.5` | `queue_messages_size / queue_threshold` below which `buffering` is suspicious |
| `queue_confirm_ticks` | `2` | `not_consuming`, `publish_failing`, `composer_health_missing` |
| `silent_failure_degraded_periods` / `silent_failure_ko_periods` | `3` / `5` | multiples of `P`, also used by `no_progress` and `no_works` |
| `stall_floor_minutes` | `15` | floor for `scheduler_stalled` |
| `runs_considered` | `10` | for `D_max` |
| `min_period_samples` | `3` | samples required before `P` is derived from a ring buffer or from works |
| `no_progress_fallback_days` | `7` | when `P` is unknown |
| `works_window` | `10` | works inspected for content rules |
| `rejected_works_count` | `3` | `ingestion_rejected`, `connector_reported_error` |
| `error_ratio_degraded` | `0.5` | |
| `empty_runs_count` | `5` | |
| `stuck_work_floor_minutes` / `stuck_work_p95_factor` | `30` / `3` | `bundles_lost`, `hung_callback` |
| `volume_history_days` | `90` | daily buckets kept per connector; reference window for weekly connectors |
| `volume_reference_days` | `42` | reference window for daily-granularity connectors (at most 12 weekend and 30 weekday buckets) |
| `volume_test_buckets` / `volume_test_buckets_daily` | `2` / `3` | complete buckets compared against the baseline (weekly / daily granularity) |
| `volume_drop_ratio` | `0.25` | `Σ landed(T) / expected(T)` below which `volume_drop` fires |
| `volume_min_reference_buckets` / `volume_min_objects_per_bucket` | `7` / `20` | arming conditions of the baseline, evaluated on `P25(R)` |
| `volume_unhealthy_min_minutes` | `360` | cumulative `PAUSED` (managed stop, reset) or `UNKNOWN` time in a day before the bucket is flagged unhealthy |
| `volume_relearn_days` | `21` | applied as `⌈21 / g⌉` buckets; `volume_drop`-only buckets after which the new level is accepted |
| `volume_alerting_enabled` | `false` until the shadow-mode counters of `volume_drop` pass | notifications for `volume_drop` and `no_new_data` transitions |
| `no_new_data_ratio` | `0.25` | `Σ changed(T) / expected_changed(T)` below which `no_new_data` fires (§7.15) |
| `pipeline_confirm_ticks` | `5` | consecutive ticks a pipeline condition must hold before its reason fires; `hysteresis_ticks` then applies on top, as for connectors (§7.14) |
| `pipeline_backlog_min_messages` | `1000` | queued bundles below which `backlog_growing` and `throughput_stalled` are not evaluated |
| `pipeline_alerting_enabled` | `false` until shadow mode validates the thresholds | notifications for pipeline transitions |
| `incident_ratio` / `incident_window_minutes` | `0.5` / `10` | platform-wide suppression; `incident_ratio` is also the `bundles_lost_widespread` threshold (§7.14) |
| `boot_grace_minutes` | `10` | |
| `storm_threshold` | `10` | transitions per tick above which one summary event is sent |
| `ring_buffer_size` | `50` | |

### 7.11 Permissions and security

- `Connector.health`, `Query.connectorsHealthSummary`, `Query.connectorHealthTransitions`, `Query.ingestionPipelineHealth` (§7.14): `@auth(for: [MODULES])` ("Access connectors", `data-initialization.js:164-168`), the capability that already gates `connectors` / `connector` (`opencti.graphql:14623-14624`) and Integrations > Deployed (`IntegrationsDeployed.tsx:274`).
- `connectorHealthConfigure`: `@auth(for: [MODULES_MODMANAGE])` ("Manage connector state"), like `resetStateConnector` and `updateConnectorTrigger`. `health_expected_period` must parse as an ISO 8601 duration between PT1M and P90D, and `health_expected_volume.min_objects` must be a positive integer; anything else raises `FunctionalError`. `accept_volume_baseline` is gated by the same capability; it writes only the Redis volume hash (`HDEL` of the `volume_drop`-only flags) and the transitions buffer (`details.rebaselined = true, details.accepted_by = <user id>`), and a request carrying only that flag performs no entity patch.
- `ConnectorHealthReason.details` carries thresholds, counters and queue names only, data already visible to `MODULES` users through `connector_queue_details`; never host names, tokens or configuration values.
- Recipients are resolved server-side from capabilities (§7.8); service accounts, internal users and disabled users are excluded; no user can subscribe another user.
- The manager runs as `SYSTEM_USER`; Enterprise audit events carry `SYSTEM_USER` as origin.

### 7.12 Cost per tick and self-observability

Per tick, for N connectors: one `fullEntitiesList` scroll on connectors; one `metrics()` call (2 HTTP requests); **one** aggregated works query (`terms` on `connector_id`, `top_hits(size = works_window, sort timestamp desc)` restricted to `entity_type = Work AND timestamp > now − works_day_range`, with the fields listed in §7.5) instead of N queries, on top of the two `elList` per connector per minute that `connectorManager` already issues; at most `works_window + 7` Redis reads (volume hash included) and, per connector, one status-hash write plus one `EXPIRE` per live key, plus for import connectors whose status is not `OK` one `HSET` of the current bucket's `unhealthy` flags (at most 8 commands; `LPUSH`/`LTRIM` on the transitions buffer only on a committed transition; the daily `HDEL` trim once per connector per day), pipelined. Volume accounting adds one `HINCRBY` and one `EXPIRE` per processed object (to a request that already runs five commands), one pair per expectations batch and one pair per work creation, all outside the tick; the tick computes P25 and medians over at most 40 values per connector in memory. Freshness (§7.15) adds one `HINCRBY` per emitted create, update or merge event; the pipeline status (§7.14) costs nothing beyond the `metrics()` call already made. Budget: tick under 2 s for N = 300 on the reference deployment. If a tick is still running when the next is due, the next tick is skipped and `connector_health_tick_overrun_total` is incremented. `registerManager` catches and logs handler exceptions and releases the lock in `finally` (`managerModule.ts:64-107`), so a throwing tick cannot kill the manager.

Telemetry: `connector_health_tick_duration_ms` (histogram), `connector_health_tick_errors_total`, `connector_health_last_success_timestamp`, `connectors_health_count{status}`, `connectors_health_rule_total{rule, outcome}` with `outcome ∈ {fired, committed, contradicted}` (§11). `warning()` (`managerModule.ts:49`) returns true when the last successful tick is older than 5 × `interval`, or when `alerting_enabled = true` while `notification_manager` or `publisher_manager` is disabled, so Settings > Managers shows it. The stored status remains the source of truth for the UI even when alerts cannot be delivered.

### 7.13 Related correctness fixes (independent of the manager)

- `updateReceivedTime` should also bump `Work.updated_at` (`work.js:444-459`), so work activity timestamps mean something.
- `updateProcessedTime` must persist `import_expected_number = expected` and `completed_number = total` (both 0 on an empty run) instead of forcing both to 1 (`work.js:474-479`), which currently shows a fake "1 processed" for empty runs and blinds the `empty_runs` rule on Elasticsearch data alone.
- Follow-up outside this RFC: the platform telemetry counter fed by `countIngestionObjectsProcessed` (`work.js:317-329`) counts a work's first completion only and undercounts multi-bundle works (§7.2); the per-object volume buckets are the correct source for it.

### 7.14 Ingestion pipeline health

Worker-side problems (workers down, saturated, nacking) show up on every import connector at once. They are reported **once, at platform level**, and mute the per-connector `worker_backlog` / `bundles_lost` alerts while they last (§7.5 stage 0).

- **Inputs**, all from the single `metrics()` call of the tick (`rabbitmq.js:482-491`): `metrics().consumers`, the consumer count of the first `push_*` queue that has consumers, 0 when none has (`rabbitmq.js:487-489`); since every worker consumes every push queue this is the number of connected workers, the figure the Integrations header already shows (`IntegrationsStatsStrip.tsx:240, 283`), `overview.queue_totals.messages` (queued bundles), `overview.message_stats.ack_details.rate` (bundles processed per second), plus the number of import connectors currently carrying `bundles_lost`.
- **Status** `{OK, DEGRADED, KO, UNKNOWN}` with its own reason codes:

| Code | Status | Rule | Operator hint |
|---|---|---|---|
| `no_workers` | KO | `push_*` consumers = 0 while queued bundles > 0 for `pipeline_confirm_ticks` | start or check the workers |
| `throughput_stalled` | KO | queued bundles ≥ `pipeline_backlog_min_messages`, ack rate ≈ 0 and consumers > 0 for `pipeline_confirm_ticks` | workers connected but not acking: check worker logs and platform API latency |
| `backlog_growing` | DEGRADED | queued bundles ≥ `pipeline_backlog_min_messages` and growing on each of the last `pipeline_confirm_ticks` ticks | scale workers, or wait for a bulk import to drain |
| `bundles_lost_widespread` | DEGRADED | more than `incident_ratio` of import connectors carry `bundles_lost` | check worker nack logs |
| `management_api_unavailable` | UNKNOWN | `metrics()` throws | check the RabbitMQ management configuration |

- **Storage and exposure.** Redis hash `connector-health-status:pipeline` (`status, reasons, since, evaluated_at, last_queued, last_ack_rate, last_consumers`), same hysteresis as connectors; `Query.ingestionPipelineHealth: IngestionPipelineHealth! @auth(for: [MODULES])` returning `{ status, reasons, workers_connected, queued_bundles, ack_rate, evaluated_at }`; telemetry gauge `ingestion_push_backlog_messages`.
- **UI.** A status chip in the Integrations header strip (`private/components/integrations/deployed/IntegrationsStatsStrip.tsx:239-241`, values read at `:283-285` from the same `rabbitMQMetrics` fields) next to the existing "Connected workers", "Queued bundles" and "Bundles processed" (per second) figures, reasons as tooltip (phase 3).
- **Alerting.** Transitions only, same recipients and hysteresis as connectors, `data.id = 'ingestion-pipeline'`, `data.entity_type = 'IngestionPipeline'`, routed to `/dashboard/integrations/deployed`. Bulk imports legitimately grow the backlog for hours: `backlog_growing` is `DEGRADED`, never `KO`, and pipeline notifications are gated by `pipeline_alerting_enabled` until shadow mode validates the thresholds.

### 7.15 Data freshness: `no_new_data`

Volume counts objects the worker processed without rejection; a connector that re-sends the same 10 000 unchanged objects every run has a perfect volume and brings nothing (§8). The platform can tell the difference **exactly, per write, without Elasticsearch aggregation and without `creator_id`**:

- every write performed by a worker carries the work id in the request header, exposed as `context.workId` (`http/httpAuthenticatedContext.js:71`);
- the middleware emits a create or update stream event only when something actually changed: `updateAttributeMetaResolved` calls `storeUpdateEvent` only when `updatedInputs.length > 0` and otherwise returns `event: null` (`middleware.ts:2899-2921, 2942`); `upsertElement` returns `event: null` when `generateInputsForUpsert` produced no input (`:3334`); merges, decided in `createEntityRaw` (`:3880-3921`), emit a distinct `storeMergeEvent` (`mergeEntities`, `:2035`).

**Hook.** In `storeCreateEntityEvent`, `storeCreateRelationEvent`, `storeUpdateEvent` and `storeMergeEvent` (`database/stream/stream-handler.ts:71-143`), inside the `isStixExportableInStreamData` branch where the event is actually built (the functions return `undefined` for non-exportable instances, and in a draft they still build the event while `pushToStream`, `:49-52`, skips the stream), when `context.workId` is set, the context is not a draft (`getDraftContext(context, user)`, `utils/draftContext.ts:3`) and the work's connector is a real non built-in `EXTERNAL_IMPORT` connector (same gate as §7.2), issue `HINCRBY connector-health-status:<connector_id>:volume <d>:created 1` for a create event or `…:updated 1` for an update or merge event, followed by the same `EXPIRE`. The connector id is derived from the work id as `redisUpdateWorkFigures` does. Cost: one `HINCRBY` per emitted create, update or merge event. The unit is the stream event, not the expectation item: one imported item may emit several events (meta objects pycti creates first, `opencti_stix2.py:715, 865, 3481`; one update event per `update_field` and per ref add or remove, `middleware.ts:3568, 4223`), so `changed(d)` is not bounded by `landed(d)` and the two series are plotted on separate scales. Unchanged upserts cost nothing: `upsertElement` returns `event: null` without calling any store function.

**Definition.** `changed(d) = created(d) + updated(d)`. Attribution is by the work that performed the write, so shared connector users, `creator_id` fixed at creation, and unchanged upserts that do not touch `updated_at` are all irrelevant.

**Rule `no_new_data`** (stage 4b, `EXTERNAL_IMPORT`): the reference-set machinery of `volume_drop` applied to `changed` (P25 of the reference set, day classes, never arm into a drop, re-baselining and `accept_volume_baseline`), with two preconditions: `volume_drop` is not firing (the drop is in novelty, not in volume) and the freshness baseline is armed (`P25(changed over R) ≥ volume_min_objects_per_bucket`). `Σ changed(T) < no_new_data_ratio × expected_changed(T)` → `DEGRADED no_new_data`. Connectors that legitimately re-import unchanged catalogues (mitre, opencti datasets, urlhaus `csv_recent`, abuseipdb) have a normal `changed` close to zero, so their freshness baseline never arms and the rule is silent for them by construction; it arms on feeds that normally bring new or modified objects every bucket (NVD, OTX, MISP, vendor alerts) and fires when they stop doing so while still sending.

**Exposure.** `created` and `updated` fields on `ConnectorHealthVolumeBucket`, `freshness_armed` and `freshness_baseline_p25` on `ConnectorHealthVolume`, a second series on the sparkline (§7.9). Reason `no_new_data` (`DEGRADED`), hint: "the connector sends data but nothing new lands: check the source cursor or the upstream feed". Notifications follow `volume_alerting_enabled`.

---

## 8. Known limitations

- **Stream connectors with a broken downstream** that swallow errors are invisible: `start_from` is rewritten on every SSE heartbeat (`helper.py:1765-1787`). Only a connector-side change can fix this (out of scope; the companion pycti RFC is deferred, §12 #6). The UI states it: stream health means "connected to the platform".
- **State that advances on failure.** A few connectors move their cursor even when items fail (alienvault advances `latest_pulse_timestamp` per batch regardless of per-pulse failures, `importer.py:161-178`; mandiant writes state before fetching in `_init_state`, `base.py:314-343`). For them `silent_failure` does not fire; `ingestion_rejected`, `connector_reported_error` and `empty_runs` remain.
- **Version-gated connectors without a work per run** (malpedia) need the `health_expected_period` override until catalogue defaults ship.
- **Connectors scheduled outside the platform** without the pycti flag are `UNKNOWN` until an admin marks them externally scheduled (§7.6); rare in customer deployments.
- **Crash before the first ping.** A connector that never pinged in its life (bad configuration at first deployment) is `UNKNOWN insufficient_history` with a hint, not `KO crash_loop`: its registrations are indistinguishable from an externally scheduled cron.
- **Hung AMQP callback without queue growth** (no further requests arrive) is reported only when a second request queues up. Acceptable: with no demand there is no user impact yet.
- **Clock skew.** `next_run` / `last_run` are computed on the connector host with `utcnow()`. Rules compare deltas between two connector timestamps wherever possible; the absolute comparison in `scheduler_stalled` tolerates skew up to `stall_floor_minutes`.
- **Scaled deployments** (N replicas sharing one connector id) are seen as one connector; one replica dying is invisible.
- **Volume is not novelty.** `landed` counts objects the worker processed without rejection, including unchanged objects a connector re-sends every run; a connector that re-imports the same catalogue daily has a healthy volume with no new knowledge. The data-freshness rule of §7.15 closes this for feeds that normally bring new or modified objects every bucket; connectors that legitimately re-import unchanged catalogues stay indistinguishable from a frozen source, by construction.
- **Volume baselines need history.** Daily-granularity connectors need at least `volume_min_reference_buckets + volume_test_buckets_daily` complete healthy UTC days (ten with the defaults) after the last backfill or reset before the rule arms, weekly connectors nine complete weeks; feeds whose P25 is below `volume_min_objects_per_bucket` (bimodal, zero-inflated, small) never arm and rely on the binary rules and on the operator override.
- **Volume detection floor.** The rule detects a drop of roughly 75 % or more sustained over the whole test window and occurring faster than the reference window slides; a decline slower than about 45 % per week is absorbed as feed evolution, and a one-day outage followed by a normal day is not a volume event. For periods between 1.5 and 7 days a weekly bucket holds two or three runs, so only drops of about 80 % sustained over two weeks are detected. Only the operator override catches slow erosion.
- **Holidays.** Two consecutive weekday buckets at weekend level (Christmas, Thanksgiving, New Year) can fire `volume_drop` on weekday-only feeds; no calendar is shipped. The day-class P25 absorbs part of it, and the alarm clears itself once the next test window is normal.
- **Redis is the store.** History is bounded (`ring_buffer_size`, `volume_history_days`) and lost on flush; statuses recover within `hysteresis_ticks` ticks, volume baselines only after new history accumulates.

---

## 9. Alternatives considered

| Alternative | Why not (or not now) |
|---|---|
| **Works cadence as the sole signal** (the initial idea) | See §5. Kept as a fallback estimator of `P`, as the `no_works` rule and as a veto. |
| **Extend the connector protocol** (`connector_info.last_run_status`, explicit health in the ping) | The right long-term move and fully compatible with this design (it would replace the `silent_failure` heuristics). Excluded by the constraint of this RFC; a companion RFC on the pycti side is deferred until shadow mode shows what the heuristics miss (§12 #6). |
| **Rely on XTM Composer health** | Covers only managed connectors and reports container state (restarts), not ingestion; consumed here as an input. |
| **Scrape connector Prometheus metrics** | Pull-based, disabled by default, not reachable from the platform in most deployments. |
| **Parse `connector_state.last_run`** | Three formats, several key names (`last_run` present in only 128 / 175), and 7 connectors keep no state at all; the string-equality change detector avoids parsing entirely. |
| **Derive everything from RabbitMQ** | `push_<id>` describes the worker, `listen_<id>` consumers are meaningful only for AMQP listen connectors; useful as corroboration only. |
| **Rolling median of the last N runs for volume** | Contaminated by the degradation it should detect, blind to weekday / weekend cycles, undefined for zero-inflated feeds (§7.5 stage 4b). Replaced by a reference set that excludes the test window and unhealthy days, with a day-class split and an operator override. |
| **Fixed volume baseline calibrated once** | Avoids contamination but goes stale as feeds grow or shrink; kept only as the explicit operator override `health_expected_volume`. |

---

## 10. Rollout plan

| Phase | Content | Docs | Exit criterion |
|---|---|---|---|
| **0 — Observability** | `last_ping_at`, `connector_state_changed_at`, ring buffers, `active` from `last_ping_at`, lock-first `pingConnector`, volume buckets and `import_rejected_number` counter in the per-object reporting path (§7.2), freshness counters in the stream-event hook (§7.15), §7.13 fixes | note on `active` semantics in the connectors page | No behaviour change visible except a more truthful `active` and correct empty-work counters; volume hashes populate for import connectors |
| **1 — Shadow manager** | `connectorHealthManager` computing and storing statuses, `Connector.health`, `connectorHealthTransitions` and `ingestionPipelineHealth` in GraphQL, read-only status chip, pipeline status and `no_new_data` in shadow, `alerting_enabled = false`, rule counters and telemetry | `connector_health_manager` keys in the configuration reference; new page Deployment > Connectors > Connector health (statuses, reason codes, operator hints) | Per rule, once ≥ `silent_failure_ko_periods × P` of history exists for that rule's target population (minimum 6 weeks for daily connectors), `contradicted / committed` below an agreed rate on Filigran internal platforms and volunteer customers; thresholds tuned. For `volume_drop`, at least `volume_min_reference_buckets + volume_test_buckets` complete healthy buckets since phase 0 (ten days for daily connectors, nine weeks for weekly ones) and the stage-4b contradiction metric of §11 |
| **2 — Alerting** | transition notifications, recipient resolution, summary events, front routing for Connector and pipeline notifications; `volume_alerting_enabled` and `pipeline_alerting_enabled` stay off until their own counters pass | notifications page: platform notifications for connectors, recipient rule | Alerts judged actionable by operators; one digest, not a storm, during a controlled platform restart |
| **3 — UI and overrides** | status facet and sort, Health card with timeline and volume / freshness sparkline, pipeline chip in the Integrations header, `connectorHealthConfigure` and its form | screenshots of chip, facet and Health card; override guidance | Design review against the Filigran Design System |
| **4 — Enterprise** | audit events with `event_scope: 'health'`, activity-trigger filtering, webhook notifier presets | activity/audit page: `health` scope | Optional |

The first implementation pull request carries phases 0 and 1 together (§12 #9); documentation ships in the same pull request as the code it describes. Phases 1–4 are independently shippable and can each be disabled through configuration. Phase 0 adds mapped attributes and changes the semantics of `active`; it is shipped once and not reverted. Target (decided 2026-09-15): phases 0 and 1 in the next minor release, so that history accumulates early; phases 2 and 3 in the following one; phase 4 unscheduled.

| Feature | Community | Enterprise |
|---|---|---|
| Status computation, `Connector.health`, UI chip and card | ✔ | ✔ |
| Transition notifications via personal notifiers (UI, email) | ✔ | ✔ |
| Audit events `event_scope: 'health'`, activity-trigger filtering | — | ✔ |
| Webhook notifier presets | ✔ (the webhook notifier connector is built-in and not Enterprise-gated, `modules/notifier/notifier-statics.ts:138`) | ✔ |

---

## 11. Testing strategy

- **Rule engine as a pure function** `evaluate(snapshot, previous, config) → {status, reasons}`, unit-tested with one fixture per line of §6, plus one fixture per false-positive scenario found during the design review: cisa KEV with unchanged upstream (work but no state), malpedia with unchanged upstream (neither work nor state), a MISP run longer than its PT5M period, a hand-rolled run-and-terminate connector on a 5-minute cron (mitre) with and without the override, a stream connector restarted by `StreamAlive`, an enrichment connector with a 20-minute backlog, a connector under legitimate buffering, a connector wedged in the publish retry loop, an admin state reset on a live and on a dead connector, an empty run closed by `toProcessed` before and after the §7.13 fix, a work force-closed by `connectorManager`. Volume fixtures: a weekday-only feed evaluated on a Monday and on a Saturday; the cisa KEV pattern (full catalogue on release days, empty works otherwise; two release-free weekdays after a release day must not fire, a four-day weekend must not raise `empty_runs`); a zero-inflated version-gated feed (must not arm); a step drop to 20 % sustained for three daily buckets (must fire on the tick after the third closes) and the same drop for one bucket followed by a normal day (must not fire); a slow drift of 10 % per week over eight weeks (must **not** fire, the reference slides with it); a two-day total outage followed by recovery (`no_heartbeat` flags the days, no `volume_drop` on recovery); a managed connector requested stopped for three days then started (no `volume_drop`); a three-week backfill at first deployment then steady state (must not fire, arms cleanly later); an admin state reset on a 30-day-lookback connector (must not fire in the following weeks); a weekday-only feed over Thanksgiving Thursday and Friday (outcome documented under the defaults); a weekly connector with six weeks of history (must not arm) and with twelve (must arm); a weekly connector with a permanent 80 % drop (rebaselined after three weekly buckets, transition type `rebaselined`); an operator minimum violated for one bucket then two. Pipeline fixtures (§7.14): workers stopped with a non-empty backlog (KO `no_workers` after `pipeline_confirm_ticks`); a bulk import growing the backlog with a normal ack rate (DEGRADED `backlog_growing`, never KO); management API down (UNKNOWN, connectors' queue rules skipped); a pipeline KO muting per-connector `worker_backlog` alerts. Freshness fixtures (§7.15): a mitre-style full re-import with zero changes (freshness never arms, no `no_new_data`); an NVD-style feed whose cursor gets stuck while re-sending the same page (normal volume, `changed` collapses, `no_new_data` fires); writes inside a draft context (not counted); a merge counted as one update.
- **Integration tests** on `pingConnector` / `registerConnector` for the new fields, ring buffers and lock-first behaviour, extending `tests/01-unit/domain/connector-ping-state-consistency-test.ts` and the manager tests under `tests/03-integration/04-manager`.
- **Replay tests**: recorded sequences of pings, registrations and work events from real connectors (anonymised), asserting the committed status timeline.
- **Alerting tests**: transition → one event per recipient, publisher grouping, summary event above `storm_threshold`, no event for `PAUSED` / `UNKNOWN`, service accounts excluded, routing on `entity_type`.
- **Shadow-mode metrics** (phase 1): per rule, counters `fired`, `committed`, `contradicted` kept in the health hash and exported as `connectors_health_rule_total{rule, outcome}`; `contradicted` = a *successful work* or a `last_run_datetime` advance **with** a state change observed within one `P` after the firing. For stage 4b the generic test does not apply (a partial degradation keeps succeeding): `contradicted` = the first complete bucket after the firing has `landed ≥ volume_drop_ratio × its reference P25` without re-baselining (`volume_drop`), `landed ≥ min_objects` (`volume_below_expected`), or `changed ≥ no_new_data_ratio × its reference P25` without re-baselining (`no_new_data`).

---

## 12. Decisions log and open points

Decisions taken by the author on 2026-09-15; reviewers may reopen any of them in the pull request.

| # | Question | Decision | Where applied |
|---|---|---|---|
| 0 | Edition: which parts are Community and which are Enterprise? | Everything in Community Edition; only the audit events of phase 4 are Enterprise | header, §10 matrix |
| 1 | Recipients: capability-based, settings list, or dedicated notifier? | `MODULES` users through their personal notifiers; settings list and dedicated notifier remain later options | §7.8 |
| 2 | Phase 1 thresholds for `silent_failure` / `no_progress`? | `3P` DEGRADED / `5P` KO; alerting is off in phase 1, shadow-mode counters decide the tuning | §7.10 |
| 3 | Storage: Redis or a dedicated Elasticsearch object? | Redis; an Elasticsearch object is reconsidered only if filtering lists by health is requested | §7.7 |
| 4 | One status chip or two in Integrations > Deployed? | One health chip replaces Active/Inactive in the list; `active` stays in the API | §7.9 |
| 5 | Run-and-terminate connectors? | Rare in customer deployments (schedule outside the platform, only the next run is unknown): a registration counts as a heartbeat, `health_externally_scheduled` for connectors without the pycti flag, no inference from registration cadence, no catalogue work | §7.5 stage 1, §7.6 |
| 6 | Companion RFC on pycti (`last_run_status`, `last_run_error`, objects per run)? | Deferred: not in scope, revisited after shadow mode shows what the heuristics miss | §9 |
| 7 | Platform-level ingestion pipeline health? | In scope | §7.14 |
| 8 | Data-freshness rule? | In scope, implemented per write through `context.workId` and stream events, not through `creator_id` aggregation | §7.15 |
| 9 | First implementation pull request? | Phases 0 and 1 together (observability fields, counters, shadow manager, read-only chip) | §10 |
| 10 | Target release? | Phases 0–1 next minor, phases 2–3 the following one | header, §10 |
| 11 | Location and language? | `docs/rfcs/`, English; the folder is not published on docs.opencti.io, an accepted RFC gets a derived page under `docs/docs/development/` | README |

Still open: named owners per team for the review (Platform, Connectors, Product, Design).

---

## Appendix A — Connectors repository survey (checkout of 2026-09-12)

Method: `grep -rlE '<pattern>' <family> --include='*.py' | cut -d/ -f2 | sort -u`, counted per connector directory.

| Measure | Value |
|---|---|
| external-import connectors | 175 |
| referencing pycti `schedule_iso` / `schedule_process` / `schedule_unit` | 78 / 49 / 3 pattern hits (130) over 117 distinct connectors; 13 reference two helpers; 2 of the 117 are SDK-based, leaving **115** pycti-helper-scheduled |
| using connectors-sdk `ExternalImportConnector` | 10 |
| hand-rolled `while True` loops, neither helper nor SDK | 49 (+ 1, restore-files, with no loop at all); 115 + 10 + 49 + 1 = 175 |
| referencing `run_and_terminate` without a helper scheduler | ~41 (35 call `force_ping`, 6 never ping) |
| calling `set_state` directly | 165 (10 never; 3 of them are SDK connectors whose state is saved by `connectors_sdk/states/_base_state.py:59`, so 7 are truly stateless: echocti, matrix, opencti-stream, portspoof, s3, socradar, vxvault) |
| creating works (`initiate_work`) | 168 (7 never call it: cape, cuckoo, malwarebazaar-recent-additions, sentinelone-threats, urlhaus-recent-payloads, and 2 SDK connectors whose works are created by the SDK work manager, which deletes empty works) |
| ever calling `to_processed` in error | ≈ 53 (50 with `in_error=True`, 3 positional), about a third |
| `last_run` key in `connector_state` | 128 |
| `CONNECTOR_DURATION_PERIOD` present in docker-compose (active or commented default) | 106, of which 91 parseable ISO durations: ≥ P1D 27, ≤ PT15M 17, range PT3M–P7D |
| internal-enrichment / import-file + export-file | 75 / 13 (6 + 7), all `helper.listen()`; works are platform-created except 3 enrichment connectors that also call `initiate_work` (attribution-tools, proofpoint-et-intelligence, reversinglabs-spectra-analyze) |
| stream | 40, none create works, 39 `listen_stream()` |

## Appendix B — Code references used in this RFC

Platform (`opencti-platform/opencti-graphql/src`): `database/repository.js:59` (`active`), `database/middleware.ts:2446-2449` (`updated_at` auto-bump), `:3001, :2629` (load before lock), `:3031` (`patchAttributeFromLoadedWithRefs`), `database/engine.ts:219` (`ES_DEFAULT_PAGINATION`), `:5163-5168` (full document replace), `database/middleware-loader.ts:360` (`fullEntitiesList`), `domain/connector.ts:112-155` (ping), `:157` (reset), `:338-372` (register), `:410-412` (delete), `domain/work.js:152-158, 229, 301, 317-329, 330-383, 360, 393, 444-459, 461-495`, `database/cache.ts:193`, `manager/cacheManager.ts:374`, `utils/format.js:94`, `manager/connectorManager.js:18, 22-56, 75-100`, `manager/managerModule.ts:39-50, 49, 64-107, 211`, `database/redis.ts:201-203, 520-534, 554-558, 834-835, 870-878`, `database/rabbitmq.js:372-403, 482-491`, `database/stream/stream-handler.ts:179-181` and `storeCreateEntityEvent` / `storeCreateRelationEvent` / `storeUpdateEvent` (freshness hook, §7.15), `database/middleware.ts:2939-2942, 3334` (`event: null` when nothing changed), `http/httpAuthenticatedContext.js:71` (`context.workId`), `manager/notificationManager.ts:98-103, 142-154, 258`, `manager/publisherManager.ts:69-74, 249-251, 493-501`, `manager/activityListener.ts:35, 127-130, 205-252`, `modules/requestAccess/requestAccess-domain.ts:476-490`, `modules/attributes/internalObject-registrationAttributes.ts:439-467`, `database/data-initialization.js:164-168`, `schema/general.js:52-53`, `initialization.ts:98`. Schema `opencti-platform/opencti-graphql/config/schema/opencti.graphql:2233, 2253, 14623-14624` (Connector types and queries), `:299-338` (`AckDetails`, `QueueTotals`, `OverviewMetrics`, `RabbitMQMetrics`, §7.14), `:14488` (`rabbitMQMetrics`); `config/default.json` (`publisher_manager.buffering_seconds`, `connector_manager.works_day_range`).

Front (`opencti-platform/opencti-front/src`): `utils/Connector.tsx:66-115`, `private/components/data/connectors/ConnectorsState.tsx:6-32`, `private/components/integrations/deployed/useDeployedIntegrations.ts:15, 105-142`, `private/components/integrations/deployed/IntegrationsDeployed.tsx:274`, `private/components/profile/Alerts.tsx:244-252`, `private/components/profile/notifications/DigestNotification.tsx`, `private/components/integrations/Root.tsx:25-28`, `private/Index.tsx:154`, `private/components/integrations/deployed/IntegrationsStatsStrip.tsx:31-43, 239-241, 283-285`.

pycti (`client-python/pycti`): `connector/opencti_connector_helper.py:68-82, 2050` (`killProgramHook`), `570-586` (ack before process, 5-minute work ping), `829-836` (HTTP callback path), `917-929` (AMQP reconnect), `1081` (40 s ping), `1140-1147` (`StreamAlive`), `1765-1787` (`start_from`), `2443` (register on start), `2522-2549` (`PingAlive` start condition), `3004-3013` (buffering), `3114-3133` (`_schedule_process`), `3155-3171` (run-and-terminate), `3771` (`add_expectations` per bundle), `3899-3906` (publish retry); `api/opencti_api_work.py:33, 58, 182-235, 186`; `utils/opencti_stix2.py:3575-3586, 3766-3777`; `utils/opencti_stix2_splitter.py:221-236, 300-307`.

Connectors: `connectors-sdk/connectors_sdk/connectors/external_import/_work_manager.py:212-218`, `external_import_connector.py:145-167`, `connectors-sdk/connectors_sdk/states/_base_state.py:59`, `external-import/cisa-known-exploited-vulnerabilities/src/main.py:288, 306-313`, `external-import/malpedia/src/malpedia_connector/connector.py:104-111, 133-143`, `external-import/mitre/src/__main__.py:139-142, 370-381, 400-424`, `external-import/cve/src/connector/cve_connector.py:276`, `external-import/opencti/src/connector/connector.py:88-93`, `external-import/alienvault/src/alienvault/importer.py:161-178`, `external-import/mandiant/src/connector/base.py:314-343`, `external-import/misp/docker-compose.yml:12`, `external-import/mandiant/docker-compose.yml:13`.

Worker (`opencti-worker/src`): `push_handler.py:270-274` (nack without report).
