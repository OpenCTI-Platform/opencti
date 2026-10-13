# Ingestion Health — Chunk 1 Brainstorm (and what moves to chunk 2)

> Status: **brainstorm**, no code. Revised on 2026-10-13: new architecture (Redis fed by a PubSub listener, Elasticsearch written by the manager), new storage and API formats, and a smaller chunk 1 (the structure, with one check, and the UI chip). Aligned on the implemented scope: connectors, feeds and syncs. The previous implementation plan was deleted.
> Summary: `2026-10-08-ingestion-health-chunk-1-summary.md`.
> Sources: Notion TAS-1415 › « Brainstorm chunk 1: Health check minimal version », RFC 0001 (`filigran-private` PR #229), issue #18305, PO decisions of 2026-10-07, 2026-10-08 and 2026-10-13.

## 1. Goal

**Chunk 1 ships the structure, with as few checks as possible, for connectors, feeds and syncs:**
- the **health manager**;
- **one check**: `USER_MISSING`;
- the **Elasticsearch fields**;
- the **GraphQL types**;
- the **UI chip** and its tooltip (§8 bis).

**Chunk 2** adds the rest: the PubSub listener, the runtime check `NO_HEARTBEAT`, the check `USER_NOT_SERVICE_ACCOUNT`, the `stopped` status and the activity event (§10).

Everything is behind the `INGESTION_HEALTH` feature flag. Chunk 1 is a single PR for #18305.

Why this shape: the later chunks only add sources, checks and outputs to a structure that already works.

## 2. Scope of chunk 1

**In:**
- every **deployed connector**, whatever its type: import, enrichment, file import/export, analysis, notification, stream. Managed by the composer or self-hosted;
- every **feed** (RSS, CSV, JSON, TAXII, TAXII collection) and every **sync**;
- the health manager, its cycle and its Elasticsearch write (§4);
- the `USER_MISSING` check (§6);
- the stored fields (§7) and the GraphQL types (§8), with every status and the check registry;
- the UI chip and its tooltip (§8 bis).

**Out of chunk 1:**
- **chunk 2:** the PubSub channel and the listener, `NO_HEARTBEAT`, `USER_NOT_SERVICE_ACCOUNT`, `NOT_EVALUATED`, the `stopped` status, the `ingestion_health` activity event;
- **later chunks:**
  - the runtime sources of feeds and syncs (ingestion manager, stream manager);
  - the composer health source;
  - notifications;
  - `TOKEN_EXPIRED`;
- **never:**
  - the platform's built-in connectors (CSV mapper import, draft validation, internal queues, the hidden connectors behind feeds). No process deploys them and they never ping;
  - any change to the authentication path.

The status model, the stored fields, the check format and the chip are not connector-specific: the same ones serve connectors, feeds and syncs.

## 3. Target architecture

Two stores, each with one writer. Chunk 1 builds the bottom half: manager, Elasticsearch, API and UI.

```
 sources ──PubSub──► listener ──► Redis (raw check data)        ← chunk 2
                                     │
                                     ▼  each period
                     health manager (+ configuration data)      ← chunk 1
                                     │  only on change
                                     ▼
                  Elasticsearch (status, since, health_checks)  ← chunk 1
                                     │
                                     ▼
                             GraphQL API ──► UI                 ← chunk 1
```

- **Redis** holds raw check data (last ping date, a 404 when fetching a feed, logs sent by the connector…), written by the listener. Never a verdict. See chunk 2 (§10).
- **Elasticsearch** holds the verdict, written by the health manager only.
- **Redis is never called from the read path.** The Deployed list is polled every 5 s per open tab, and a single GraphQL error would break the whole page. The API only reads Elasticsearch.

## 4. The health manager (chunk 1)

At each period (**60 s by default**, `ingestion_health_manager:interval`), with its own lock, for each deployed connector, feed and sync, the manager:
1. computes the configuration check data itself (the user of the connector, feed or sync);
2. *(chunk 2)* reads the runtime check data from Redis;
3. computes from those checks the final **status** and the final **`health_checks` list**, with a **pure function**, with no I/O;
4. **only if the status or the checks changed**:
   - writes them in Elasticsearch;
   - invalidates the connector cache (connectors only: feeds and syncs are not cached);
   - *(chunk 2)* if the **status** changed, publishes an `ingestion_health` activity event.

The Elasticsearch write:
- `health_status_since` moves only when the status changes;
- must not touch `updated_at` (an entity update would also emit a stream event);
- must not emit a stream event.

In chunk 1 the manager does not use Redis. It reads connectors and users from the cache, feeds and syncs from Elasticsearch (they are not cached).

The manager is registered only when the flag is on. It is disabled in `config/test.json`.

## 5. Statuses

Priority: `stopped` > `critical` > `degraded` > `unknown`.

| Status     | When                                                                                                             | Produced from |
|------------|------------------------------------------------------------------------------------------------------------------|---------------|
| `stopped`  | A managed connector switched off by a person: its **requested** status is `stopping` or `stopped`. A crashed container (requested `starting`, current `stopped`) is **not** stopped. | Chunk 2 |
| `critical` | A runtime check fails.                                                                                           | Chunk 2 (`NO_HEARTBEAT`) |
| `degraded` | A `blocking` configuration check fires, and no runtime check fails.                                              | **Chunk 1** (`USER_MISSING`) |
| `unknown`  | Nothing proves the connector works or fails.                                                                     | **Chunk 1**   |
| `healthy`  | Proven to bring data in.                                                                                         | Not before a check proves data comes in: a ping only proves the connector is alive. |

The API exposes these five values from chunk 1, so the list never changes later. `idle` is dropped.

## 6. The chunk 1 check: `USER_MISSING`

- Configuration check, severity `blocking`.
- Fires when the connector has no user: `connector_user_id` is empty, or the user it points to no longer exists (deleted).
- Message « User is missing », **with no user id or name**, neither in the message nor in the stored metadata. Reading a connector only needs the `MODULES` capability, while the name of its user is reserved to `SETTINGS_SETACCESSES`.
- Effect: the status becomes `degraded` (unless it is `stopped` or `critical`, from chunk 2).
- `connector_user_id` is set again at every registration, so a running connector always has one. An empty value only exists on an old record of a connector that has not restarted since.
- **Feeds and syncs:** `USER_MISSING` fires only when their `user_id` points to a user that no longer exists. An empty `user_id` (or SYSTEM) is a supported setup: they then run as the system user, so no check fires.

## 7. Elasticsearch storage format (chunk 1)

Stored on connectors, feeds (RSS, CSV, JSON, TAXII, TAXII collection) and syncs, written by the manager only:

```
health_status:        critical | unknown | stopped | healthy | degraded
health_status_since:  Datetime                    # null until the manager first evaluates the connector
health_checks: [                                   # nested
  {
    health_check_code:     string                  # USER_MISSING; later NO_HEARTBEAT, USER_NOT_SERVICE_ACCOUNT, NOT_EVALUATED, LAST_RUN_FAIL…
    health_check_metadata: {                       # raw object, depends on the code
      reason?:   string                            # NOT_EVALUATED (chunk 2)
      log?:      string                            # sent by the connector
      entityId?: string                            # when the issue concerns one entity
      …
    }
  }
]
```

- `health_checks` is **nested**; `health_check_metadata` is **raw**.
- Every attribute and every nested mapping carries `featureFlag: INGESTION_HEALTH_FEATURE_FLAG`.
- **Kind and severity are not stored**: they are derived from the code, through one registry (code → kind, severity, message). They describe the check type, not one occurrence; changing a severity must not require rewriting Elasticsearch.
- No stored human message, no stored summary: the message is computed by the API from the code and the metadata.
- The metadata never holds a value that changes with every ping (for example the last ping date), so the manager only writes on a real change.

## 8. GraphQL API (chunk 1)

On `Connector`, `IngestionRss`, `IngestionCsv`, `IngestionJson`, `IngestionTaxii`, `IngestionTaxiiCollection` and `Synchronizer`:

```graphql
health_status: IngestionHealthStatus!
health_status_since: DateTime                    # nullable
healthChecks: [IngestionHealthCheck!]! @auth(for: [MODULES])   # INGESTION on feeds and syncs

type IngestionHealthCheck {
  health_check_code: String!                     # from Elasticsearch
  health_check_message: String                   # from the code and the metadata
  health_check_kind: runtime | configuration     # derived from the code
  health_check_severity: blocking | advisory     # derived from the code
}
```

- A connector the manager has not evaluated yet: `unknown`, `health_status_since` null, no check.
- The raw metadata is not exposed: only what the UI uses.
- `healthChecks` requires the capability that already reads the entity: `MODULES` for connectors, `INGESTION` for feeds and syncs. A stricter one would make the field fail, and break the page, for a user who can read the list.
- No resolver calls Redis.

## 8 bis. What the user sees (chunk 1)

| Where | Chip | Tooltip |
|---|---|---|
| Data › Connectors list, rows | Status | « since », then check messages |
| Connector detail page, next to the existing status chip | Status | « since », then check messages |
| Integrations › Deployed, cards and lines (connectors, feeds, syncs; not forms) | Status | « since », then check messages |
| Feed and sync detail page, next to the Active/Inactive chip | Status | « since », then check messages |

- Design system chip (`@filigran/design-system`), label = the status with a capital first letter, translated.
- Colors, from the design system feedback tones: `critical` red, `degraded` orange, `healthy` green, `stopped` and `unknown` grey.
- The check messages come from the server, in English, shown as is. With no check: « No health issue detected », or « Not evaluated yet » when the manager has not looked yet.
- Hidden when the flag is off.

## 9. Chunk 1: flag off and accepted risks

**With the flag off**, nothing differs from `master`:
- no manager;
- no stored field;
- the API fields return empty, without error;
- no chip.

**Accepted risks:**
- **No manager, no fresh status.** If no node runs the manager, the stored status gets old, and nothing says so. `health_status_since` is when the status last changed, not when the manager last looked. Whether the manager runs is visible in Settings › Parameters.
- **Lag.** A fixed user stays `degraded` up to one period.
- **Leftovers.** Turning the flag on, then off, leaves the stored fields behind. Nothing reads them, and nothing cleans them up.

## 10. Chunk 2

### 10.1 Redis, fed by the listener

- **Sources** send their issues on a new PubSub channel: the connector **ping** in chunk 2; the composer health, the ingestion manager (feeds) and the stream manager (syncs) in later chunks.
- **The listener** subscribes to that channel and writes the data in Redis. It only records what it sees: it never evaluates anything.
- **Pings:** the last ping date is the existing `connector_heartbeats` value (#18851), written on every ping and registration, the same source as Active/Inactive. This may change or be improved later.
- With the flag off: no listener, no message published, no Redis key of the feature read, written or deleted.

### 10.2 The runtime check: `NO_HEARTBEAT`

**Rule:** no ping for **5 minutes or more** → `critical`.
- It is the same threshold as Active/Inactive, so the two always agree. The POC's 10 min is rejected.
- The ping date is read from `connector_heartbeats`, by the manager, once per cycle. If that read fails, the cycle fails and is retried.

**Only for connectors that ping every 40 s.** A long-running pycti connector has a thread that pings every 40 s.
Many legacy run-and-terminate connectors (about 30, e.g. `cape`) behave differently:
- they do not declare `run_and_terminate`;
- they do not start that thread;
- they register at start and ping once or twice at exit, then are silent for hours.

Without a guard, they would turn red between every run.

So the **manager** checks a connector only once it has seen **3 pings in a row, each at most 2 manager periods after the previous one, and never less than 120 s** (120 s with the default 60 s period). The listener only records the pings; this logic lives in the manager.
- With the default period, a live pycti connector shows a new ping 40 to 80 s after the previous one at each cycle, so it qualifies after about 4 minutes.
- The bound follows the period: with a 5 min period, the manager sees a new ping up to about 5 min 40 s after the previous one, so the bound becomes 10 min.
- A legacy run shows at most 2 pings, so it never qualifies, whatever its length and whatever the period.

**Never checked:**
- connectors that declare `run_and_terminate`;
- connectors never seen running;
- connectors the manager has not yet seen pinging every 40 s, for example just after the flag is turned on. This means no burst of false alarms at activation or after a restart.

**Back to normal:** a dead connector that restarts pings long after its last ping, so the count starts again from zero. It shows `unknown` again at the next cycle.

**When the manager itself was not looking.** A platform restart or a lost lock can leave the manager without a cycle for a while. Then the gap between two pings it sees is wide because *it* did not look, not because the connector stopped.
- A **full cycle** is one pass of the manager over every deployed connector. It counts as full as soon as the connector list could be read, even if some connectors failed to evaluate.
- After each full cycle, the manager records **the time that cycle started** in a single Redis key, `ingestion-health-manager-last-run`.
- At the start of the next cycle, it reads that key. If the previous full cycle started more than 2 periods ago (and at least 120 s ago), the manager knows it was blind.
- It then keeps the count of the connectors **already seen pinging every 40 s** (count at 3), instead of restarting it. A connector that was pinging every 40 s and dies right after the outage is therefore still caught.
- Every other count restarts as usual. Outages can never add up, run after run, into a false proof: a legacy connector's count stays at 2 or less.

The same key also tells an operator whether the manager is alive.

### 10.3 `NOT_EVALUATED`

Runtime check, severity `advisory`. It explains an `unknown` status when the heartbeat is not checked. Its message is the sentence stored in `health_check_metadata.reason`:
- « No ping every 40 seconds observed, heartbeat not evaluated »: a legacy or newly started connector;
- « Pinging every 40 seconds, data intake not evaluated yet »: alive, but not `healthy`, on purpose;
- « Heartbeat not evaluated for run-and-terminate connectors »;
- « Never seen running ».

### 10.4 `USER_NOT_SERVICE_ACCOUNT`

- Configuration check, severity `advisory`: no effect on the status.
- Fires when the connector user is not a service account.
- Message « User is not a service account », with no user name, for the same reason as `USER_MISSING`.
- A connector gets either `USER_MISSING` or `USER_NOT_SERVICE_ACCOUNT`, never both.

### 10.5 The `stopped` status

A managed connector whose **requested** status is `stopping` or `stopped`. It wins over everything: a source stopped on purpose is never red. A crashed container (requested `starting`, current `stopped`) goes through the heartbeat check and turns `critical`.

### 10.6 The activity event

When the status changes, the manager publishes an `ingestion_health` activity event.

### 10.7 Chunk 2 accepted risks

- **A connector already dead when the flag is turned on is never flagged.** The manager never sees it ping, so it stays `unknown` until it restarts. Nothing tells it apart from a legacy connector between two runs.
- **Run-and-terminate jobs scheduled at least as often as the close-pings bound** (every 2 minutes or less with the default period) look like connectors pinging every 40 s, and turn red when their schedule pauses. Rare. A longer period widens this risk.
- **Lag.** The chip turns red up to one period after Active/Inactive turns « Inactive », plus the 5 s poll. A longer period means a longer lag, and a longer wait (about 3 periods) before a new connector is checked.
- **A connector deleted during a manager cycle.** The cycle can write its Redis key again right after the deletion removed it, leaving a key with no expiry. A later chunk makes sure the key of a deleted connector is gone for good.
- **Leftovers.** Turning the flag on, then off, also leaves the Redis keys behind.

## 11. How we will know it works

Deferred: the acceptance criteria and tests will be written once the design is settled.

## 12. Follow-ups

- Update RFC 0001 with the gaps:
  - connectors, feeds and syncs, with only `USER_MISSING` in chunk 1;
  - `unknown` instead of `healthy`, explained by `NOT_EVALUATED`;
  - two configuration checks (service account, missing user), `TOKEN_EXPIRED` not shipped;
  - the 5 min threshold;
  - the 40 s rule;
  - the Redis / listener / manager / Elasticsearch pipeline.
- Open follow-up issues:
  - `TOKEN_EXPIRED` without touching authentication;
  - the suspected composer token revocation between connectors sharing a user;
  - `health_status` stays readable by users with only the `KNOWLEDGE` capability (through `connectorsForImport`/`Export`/`Analysis`); `healthChecks` is protected by `@auth`;
  - deleting a connector deletes its Redis key for good, even during a manager cycle.
- Tick the chunk items in Notion.

## 13. Open questions

1. **Listener on several nodes (chunk 2):** every node subscribed to the PubSub channel would write the same data. Accept idempotent writes, or have a single node listen? To discuss later.

## 14. Decisions log

| Date | Decision |
|---|---|
| 2026-10-07 | Start from `master`, one PR for backend and front, #18305. The draft and POC branches are reference only. |
| 2026-10-07 | 5 min threshold, aligned on Active/Inactive. Never `healthy`. `TOKEN_EXPIRED` dropped. Authentication untouched. |
| 2026-10-08 | Every deployed connector, whatever its type. Built-ins excluded. |
| 2026-10-08 | `NO_HEARTBEAT` only for connectors pinging every 40 s. |
| 2026-10-08 | No Redis on the read path. |
| 2026-10-08 | The ingestion health manager is disabled in `config/test.json`. |
| 2026-10-08 | After a manager outage of more than 2 periods (at least 120 s), only the counts already at 3 are kept (`ingestion-health-manager-last-run`, start time of the last full cycle). A connector already dead at activation stays undetected (accepted). |
| 2026-10-08 | The service account warning says « User is not a service account », with no user name (reserved to `SETTINGS_SETACCESSES`). |
| 2026-10-08 | Manager period: 60 s by default, configurable (`ingestion_health_manager:interval`). The close-pings bound and the blind threshold follow it: 2 periods, never less than 120 s. |
| 2026-10-08 | `USER_MISSING` added (PO): empty `connector_user_id` or deleted user, « User is missing », severity `blocking`, exclusive with `USER_NOT_SERVICE_ACCOUNT`. |
| 2026-10-08 | `stopped` = requested status `stopping`/`stopped` only, so a crashed managed container turns `critical`. |
| 2026-10-08 | Accepted: no fresh status without the manager, leftovers after the flag is turned off, run-and-terminate jobs scheduled every ≤ 2 min. PR title free. |
| 2026-10-13 | New pipeline: sources (ping; later composer health, ingestion manager, stream manager) publish on a new PubSub channel; a listener records the raw check data in Redis; the manager reads it each period, adds the configuration data, computes status and `health_checks`, and writes Elasticsearch only on change. |
| 2026-10-13 | Configuration checks move from the resolver to the manager and are stored with the runtime checks (reverses 2026-10-08). |
| 2026-10-13 | On change: write Elasticsearch, invalidate the connector cache; on a status change, publish an `ingestion_health` activity event. |
| 2026-10-13 | Stored fields: `health_status` (critical, unknown, stopped, healthy, degraded), `health_status_since`, `health_checks` (nested: code + raw metadata). No stored summary; the message is computed by the API. `idle` dropped. |
| 2026-10-13 | Kind and severity derived from the code (registry), not stored. |
| 2026-10-13 | A `blocking` configuration check makes the status `degraded`. Priority: `stopped` > `critical` > `degraded` > `unknown`. |
| 2026-10-13 | The listener only records the pings; the 3-close-pings logic stays in the manager. The ping date is read from `connector_heartbeats` (may change later). |
| 2026-10-13 | Composer health is not in chunks 1 and 2. |
| 2026-10-13 | The old `unknown` summaries become a `NOT_EVALUATED` advisory check, with the sentence in `health_check_metadata.reason`. |
| 2026-10-13 | The service account check keeps the code `USER_NOT_SERVICE_ACCOUNT`. |
| 2026-10-13 | GraphQL: `health_status`, `health_status_since` (nullable), `healthChecks` (code, message, kind, severity) under `@auth`: `MODULES` on connectors, `INGESTION` on feeds and syncs. Raw metadata not exposed. |
| 2026-10-13 | **Chunk 1 = the structure**: the manager with the single check `USER_MISSING`, the Elasticsearch fields, the GraphQL types. Everything else (listener, `NO_HEARTBEAT`, `NOT_EVALUATED`, `USER_NOT_SERVICE_ACCOUNT`, `stopped`, activity event) moves to chunk 2. |
| 2026-10-13 | Chunk 1 also ships, as implemented: the UI chip and its tooltip (connector list and detail, deployed cards and lines, feed and sync detail), and feeds (RSS, CSV, JSON, TAXII, TAXII collection) and syncs, with the same fields, GraphQL types and `USER_MISSING` (empty or SYSTEM user allowed for them). |
| 2026-10-13 | Tests and acceptance criteria deferred until the design is settled. |
