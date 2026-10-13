# Ingestion Health — Chunk 1 Summary

> Summary of `2026-10-08-ingestion-health-chunk-1-brainstorm.md` (revised on 2026-10-13).
> Issue #18305, Notion TAS-1415, RFC 0001.

## In one sentence

Behind the `INGESTION_HEALTH` flag, chunk 1 ships the **structure** of connector health: the **health manager**, **one check** (`USER_MISSING`), the **Elasticsearch fields** and the **GraphQL types**. Chunk 2 adds the runtime check, the other checks, the listener, the activity event and the UI.

## Split

| Chunk 1                                                                      | Chunk 2                                             | Later                                               |
|------------------------------------------------------------------------------|-----------------------------------------------------|-----------------------------------------------------|
| Health manager (cycle, pure evaluation, write on change, cache invalidation) | PubSub channel + listener writing Redis             | Feeds and syncs (ingestion manager, stream manager) |
| `USER_MISSING`                                                               | `NO_HEARTBEAT` (40 s rule, blind-manager logic)     | Composer health                                     |
| ES fields: `health_status`, `health_status_since`, `health_checks`           | `NOT_EVALUATED`, `USER_NOT_SERVICE_ACCOUNT`         | Notifications                                       |
| GraphQL types + check registry                                               | `stopped` status, `ingestion_health` activity event | `TOKEN_EXPIRED`                                     |
|                                                                              | UI chip and tooltip                                 |                                                     |

**Never:** built-in connectors (CSV import, draft validation, internal queues, feed twins), and any change to authentication.

## Chunk 1 scope

Every deployed connector, whatever its type, managed by the composer or self-hosted.

## The health manager

Every period (**60 s by default**, `ingestion_health_manager:interval`), with its own lock, for each deployed connector:
1. computes the configuration data (the connector user);
2. computes the status and the `health_checks` list with a pure function;
3. **only if the status or the checks changed**: writes Elasticsearch, without touching `updated_at` and without a stream event, then invalidates the connector cache. `health_status_since` moves only when the status changes.

In chunk 1 the manager does not use Redis. It is registered only when the flag is on, and disabled in `config/test.json`.

## The check: `USER_MISSING`

- Configuration check, severity `blocking`: the status becomes `degraded`.
- Fires on an empty `connector_user_id`, or a user that no longer exists.
- Message « User is missing ». **No user id or name**, neither in the message nor in the metadata: reading a connector only needs `MODULES`, the user name is reserved to `SETTINGS_SETACCESSES`.

## Statuses

Priority: `stopped` > `critical` > `degraded` > `unknown`. All five values (`critical`, `unknown`, `stopped`, `healthy`, `degraded`) exist from chunk 1; `idle` is dropped.

- Chunk 1 produces **`degraded`** (`USER_MISSING`) and **`unknown`** (every other case).
- Chunk 2 adds `critical` (`NO_HEARTBEAT`) and `stopped`.
- `healthy` comes only with a check that proves data comes in.

## Storage (Elasticsearch)

```
health_status:        critical | unknown | stopped | healthy | degraded
health_status_since:  Datetime          # null until first evaluated
health_checks: [ { health_check_code, health_check_metadata (raw) } ]   # nested
```

Kind and severity are **not stored**: they are derived from the code through one registry (code → kind, severity, message). No stored message or summary.

## API (GraphQL)

```graphql
health_status: IngestionHealthStatus!
health_status_since: DateTime            # nullable
healthChecks: [IngestionHealthCheck!]! @auth(for: [MODULES])
# IngestionHealthCheck: health_check_code, health_check_message, health_check_kind, health_check_severity
```

- The API only reads Elasticsearch, **never Redis**.
- A connector not evaluated yet: `unknown`, no date, no check.
- The raw metadata is not exposed.

## Flag off

Nothing changes compared with `master`: no manager, no stored field, the API fields return empty without error.

## Chunk 1 accepted risks

- **Manager stopped:** the stored status gets old and nothing says so.
- **Lag:** a fixed user stays `degraded` up to one period.
- **Leftovers after turning the flag off:** the stored fields stay.

## Chunk 2 in short

- **Listener:** sources publish on a new PubSub channel; the listener only records the raw data in Redis. Ping date: `connector_heartbeats` (#18851), may change later.
- **`NO_HEARTBEAT`:** no ping for 5 min or more → `critical`, only for connectors the manager has seen pinging every 40 s (3 pings in a row, each at most 2 periods apart, never less than 120 s), because about 30 legacy run-and-terminate connectors ping once per run. After a manager outage, only the counts already at 3 are kept (`ingestion-health-manager-last-run`).
- **`NOT_EVALUATED`** (advisory): explains `unknown`, sentence in `metadata.reason`.
- **`USER_NOT_SERVICE_ACCOUNT`** (advisory): « User is not a service account », no effect on the status, exclusive with `USER_MISSING`.
- **`stopped`:** requested status `stopping`/`stopped`; a crashed container turns `critical`.
- **Activity event** `ingestion_health` on status change.
- **UI:** FDS chip and tooltip in the Deployed list and on the detail page; `critical` red, `degraded` orange, `stopped` and `unknown` neutral.
- **Open question:** listener on several nodes, to discuss later.

## Follow-ups

- Update RFC 0001.
- Open follow-up issues:
  - `TOKEN_EXPIRED` without touching authentication;
  - the suspected composer token revocation between connectors sharing a user;
  - `health_status` readable by `KNOWLEDGE`-only users (`healthChecks` is protected);
  - deleting the Redis key of a deleted connector for good, even during a manager cycle.
- Tick the chunks in Notion.

Tests and acceptance criteria are deferred until the design is settled.
