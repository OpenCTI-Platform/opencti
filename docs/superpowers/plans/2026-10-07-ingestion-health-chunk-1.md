# Ingestion Health — Chunk 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Behind the `INGESTION_HEALTH` feature flag, every deployed connector exposes:
- a **runtime status**, evaluated by a manager:
  - `critical` when a connector that pings every 40 s has sent no ping for 5 min (same threshold as Active/Inactive);
  - `stopped` when a person switched it off;
  - `unknown` otherwise;
- a separate **configuration warning**: the connector user is not a service account.

The manager caches the status on the connector. The status is shown as an FDS chip in Integrations › Deployed (lines and cards) and on the connector detail page.

**Architecture:**
- A new `ingestionHealth` module holds a **pure evaluator** with no I/O. Only the manager calls it. The UI reads what the manager cached, so the UI and future alerts can never disagree (RFC 0001 §4.4).
- Runtime checks decide the status. Configuration warnings are a second axis: they never change the status, are never cached and are never notified (RFC 0001 §4.1, §5.1).
- `ingestionHealthManager` is a cron with its own lock, every 60 s by default (`ingestion_health_manager:interval`), registered only when the flag is on. **It is the only code that reads or writes Redis for this feature.** On each cycle it does two things:
  - It updates a **heartbeat observation** per connector in Redis (`ingestion-health-observation:<id>`, no TTL). The observation counts the pings seen in a row, each close to the previous one: at most 2 manager periods, never less than 120 s (the **close-pings bound**, 120 s with the default period). A connector **pings every 40 s** (the pycti ping thread) once that count reaches 3. Only such a connector can become `critical`.
  - After each full cycle (one pass that listed every connector, even if some evaluations failed), it records **the time that cycle started** in one platform-wide Redis key, `ingestion-health-manager-last-run`. If the previous full cycle started more than the close-pings bound before the current one, the manager was **blind** (platform restart, lost lock…). A wide gap between two pings then says nothing about the connector: the count of a connector **already seen pinging every 40 s** is kept instead of being restarted. Any other count restarts as usual, so outages can never add up into a false proof for a legacy connector.
  - When the status, the summary or the checks change, it caches them with `elReplace`: `ingestion_health_status`, `ingestion_health_since`, `ingestion_health_summary`, `ingestion_health_checks`. That write never touches `updated_at`, which is the heartbeat being measured.
- `Connector.ingestion_health` **reads that cache**, with no Redis and no evaluation. `Connector.ingestion_warnings` is computed at read time from the user cache. Both are gated by `@ff(..., softFail: true)`.
- On the front:
  - the deployed list reads the status from `ConnectorsStateQuery`, which is already polled every 5 s;
  - the detail page reads it from the `Connector_connector` fragment, refetched every 5 s.

**Tech Stack:** Node/TypeScript + Apollo GraphQL (`opencti-platform/opencti-graphql`), Elasticsearch via `database/engine`, Redis via `database/redis`, React + Relay (`opencti-platform/opencti-front`), Filigran Design System (`@filigran/design-system`), Vitest on both sides.

**Spec:**
- RFC 0001: `RFC/0001-ingestion-health-monitoring.md`, `OpenCTI-Platform/filigran-private` PR #229 (final design).
- Notion TAS-1415 « Ability to notify when an ingestion source is not working properly », *Chunks › CHUNK 1*.
- The scope decisions below were taken with the PO on 2026-10-07. Where they differ from the RFC, the decisions win.
- Reference only, **never a base**: the local branch `issue/health-draft` and the POC branch `origin/issue/18305`.

## Scope decisions (PO, 2026-10-07)

| Topic | Decision |
|---|---|
| Base / delivery | From `master`, branch `issue/health`. **One PR, backend + front**, issue **#18305**. The PR title starts with « preparation of » so it stays out of the changelog. |
| Sources | **Every deployed connector, whatever its type** (import, enrichment, file import/export, analysis, notification, stream), managed or self-hosted. Built-in connectors are excluded: CSV mapper import, draft validation, internal queues and the technical twins of feeds. No process deploys them and they never ping. Feeds and syncs come later. |
| Runtime check | `NO_HEARTBEAT`: no ping (`updated_at`) for **≥ 300 s** → `critical`. This is **exactly the threshold of `isConnectorActive`** (`Math.floor(minutes) < 5`). The RFC gives no number. The POC's 10 min is not used. The chip turns `critical` at the first manager cycle after Active/Inactive turns « Inactive »: at most one period later (60 s by default), plus the 5 s poll. |
| Only connectors pinging every 40 s | `NO_HEARTBEAT` only fires for a connector seen pinging every 40 s, like the pycti ping thread. The manager must have seen **3 pings in a row, each within the close-pings bound of the previous one**: 2 periods, never less than 120 s. With a 40 s ping and the default 60 s period, a live connector shows a new ping 40 to 80 s after the previous one, so it qualifies after about 4 min. With a 5 min period, it shows one up to about 5 min 40 s later, hence a 10 min bound.<br>Legacy run-and-terminate connectors (about 30, e.g. `cape`) do not declare `run_and_terminate` and do not start the ping thread. They register at start and call `force_ping()` at exit, which sends one or two pings milliseconds apart. That is at most 2 pings seen per run, so they never qualify and stay `unknown`, whatever the run length. The check is also skipped for connectors that declare `run_and_terminate`, and for connectors never seen running. |
| Read path | **The UI reads the cache written by the manager.** No resolver calls Redis or evaluates anything. The deployed list is polled every 5 s per open tab, and a Redis error there would break the whole page: `react-relay-network-modern` throws on any GraphQL error. |
| Statuses produced | `stopped` (a managed connector switched off by a person; wins over everything) > `critical` > `unknown`. **Never `healthy` in chunk 1**: a ping proves liveness, not that data comes in. The GraphQL enum exposes all 6 RFC values. |
| Configuration warning | `USER_NOT_SERVICE_ACCOUNT` (advisory) only, when the connector user has `user_service_account !== true`. A missing user → no warning (`USER_MISSING` is deferred). The message is « User is not a service account », **with no user name**, in the message or the params: reading a connector only needs `MODULES`, while the name of its user is reserved to `SETTINGS_SETACCESSES` (`connectorUser`, `src/domain/connector.ts:811-817`). `TOKEN_EXPIRED` is **out of chunk 1**. |
| Authentication | **The authentication path is not modified.** |
| API | `ingestion_health { status summary since checks }` (runtime only) **and** a separate field `ingestion_warnings: [IngestionCheck!]`. |
| Manager | Kept in chunk 1, and the only evaluator. It holds the heartbeat observation in Redis (no TTL, deleted with the connector) and the cached verdict in the connector document. Its period is **60 s by default, configurable** with `ingestion_health_manager:interval` (ms). The close-pings bound and the blind threshold follow it (2 periods, never less than 120 s), otherwise a longer period would leave no connector able to qualify. No events, no hysteresis, no dedicated user: all of that is chunk 2. |
| UI — list and cards | FDS chip for **every** status: `critical` in red, `stopped`/`unknown` neutral. Tooltip = the server `summary`, in English, as is. No warning shown. |
| UI — detail page | The same chip, next to the existing status chip. Tooltip = summary, `since`, runtime checks, then the warning if it applies. |
| RFC | Updated **at the end** (Task 7). |
| PR title | Free form. |

## Addendum after the final review (2026-10-08)

The branch was rebased onto a master that includes #18851 (`1682a9d903`): connector liveness now comes from the Redis sorted set `connector_heartbeats`, written by every ping and every registration, and `pingConnector` no longer moves `updated_at`. Two changes follow, and they override the task code below where it differs:

- **Heartbeat source (C1).** `collectIngestionSources` reads `redisGetConnectorsHeartbeats()` once per cycle and uses the heartbeat of each connector (by `internal_id`) instead of `updated_at`, for the observation and for `last_seen_at`. The health chip and Active/Inactive use the same source again. Redis stays manager-only. If that read fails, the cycle fails and is not recorded (retried at the next period), instead of evaluating every connector without a heartbeat.
- **Stopped by a person (I1, PO decision).** A managed connector is `stopped` only when its *requested* status is `stopping` or `stopped`. The composer reports current `stopped` for a crashed, exited or restarting container while the requested status stays `starting`: such a connector goes through the heartbeat check and turns `critical`. This departs from `isConnectorActive` on purpose.
- Also in the same fix: the Redis delete in `connectorDelete` is best effort (a warning, never a blocked deletion), and the manager test pins the last-run value (the cycle start, recorded even when one evaluation fails).
- The accepted risk « `updated_at` is not only the ping » below no longer applies, and its follow-up issue (a dedicated ping timestamp) is dropped. A new follow-up: the health fields are readable by users with only the `KNOWLEDGE` capability, through `connectorsForImport` / `Export` / `Analysis` (no user name).

## Accepted risks (PO, 2026-10-08, adversarial review)

> *No longer applies since #18851, see the addendum above.* ~~⚠ **`updated_at` is not only the ping.**~~ Any update of a connector document moves it: a composer status report (`updateConnectorCurrentStatus`), a state reset, an admin edit. The manager counts each of these as a ping. So an edit or a composer report during a legacy run-and-terminate run can complete the 3-ping proof, and the connector then turns `critical` 5 min after the run ends. Accepted for chunk 1. A dedicated ping timestamp would fix it, but changes the ping path.

- **No manager running → no fresh status.** If no node runs `ingestionHealthManager`, or it is disabled by `ingestion_health_manager:enabled`, the cache is not refreshed. A connector never evaluated shows `unknown` / « Not evaluated yet ». One evaluated before keeps its last status, and nothing in the UI says that status is out of date. `since` is when the health status last changed, not when the manager last looked. Example: a connector cached `critical` that comes back while the manager is down stays red next to « Active ». Whether the manager is running is visible in Settings › Parameters. Accepted for chunk 1.
- **A connector already dead when the flag is turned on is never flagged.** Its last ping is older than the activation, so the manager never sees 3 close pings, and it stays `unknown` until it restarts. Nothing in the existing data tells it apart from a legacy run-and-terminate connector between two runs. Accepted for chunk 1. A connector that dies *after* a manager outage is handled: the count is kept while the manager was blind.
- **Run-and-terminate jobs scheduled at least as often as the close-pings bound** (every 2 minutes or less with the default period). Their pings fall within the bound, so they look like connectors pinging every 40 s, and they turn `critical` when their schedule pauses. Rare. Accepted for chunk 1. A longer manager period widens this risk.
- **A longer period, a slower feature.** With a period P, the chip turns red up to P after « Inactive », and a new connector is checked after about 3 P. Accepted: 60 s by default.
- **A connector deleted during a manager cycle.** The cycle can write its Redis observation again right after `connectorDelete` removed it: an orphan key with no TTL, and one warning in the logs. Accepted for chunk 1, follow-up issue in Task 7.
- **Leftovers after the flag is turned off.** Turning the flag on, then off, leaves the `ingestion-health-observation:*` keys in Redis and the `ingestion_health_*` fields in the connector documents. Nothing reads them while the flag is off, and nothing cleans them up: with the flag off, nothing differs from `master`. Accepted.

## Global Constraints

- Feature flag `INGESTION_HEALTH`, off by default (`app:enabled_dev_features`). It is read at module load, so changing it needs a restart. With the flag off:
  - no manager is registered and no cached attribute is registered;
  - nothing is read from or written to Redis, and nothing is deleted;
  - `ingestion_health` and `ingestion_warnings` resolve to `null` without error;
  - no chip is rendered;
  - ingestion and authentication behave exactly as on `master`.
- **Redis is only called by the manager.** The resolvers read the cached `ingestion_health_*` fields of the connector document, which is already loaded. They do no Redis call and no evaluation.
- No write made by the manager may touch `updated_at`: `isConnectorActive` (`src/database/repository.js:46-60`) and `NO_HEARTBEAT` both read it as the heartbeat.
- Heartbeat timeout: **300 s**. A connector is lost when the elapsed time is ≥ 300 s, identical to `isConnectorActive` (`sinceNowInMinutes` uses `Math.floor`, `src/utils/format.js:96-100`). « Pings every 40 s » means 3 pings in a row seen by the manager, each within the close-pings bound of the previous one: max(120 s, 2 × the manager period).
- The summaries of a status that holds carry no timestamp that moves on every ping, so the manager writes only on a real change. « No ping received since <date> » is stable while the connector is silent.
- No event, no live-stream message, nothing on `/health`, nothing on the platform banner (RFC §3).
- Server messages and summaries are English sentences displayed as is (decided). The statuses are translated.
- UI: `Chip` and `Tooltip` come from `@filigran/design-system`. MUI `Chip`/`Tooltip` are **enforced** as forbidden in new code (`node fds-migration/scripts/check-mui-regression.mjs --explain`).
- Translations: every new backend `label: '…'` must exist in `opencti-front/lang/back/en.json`, and every new literal front `t_i18n('…')` in `opencti-front/lang/front/en.json`. CI runs `yarn verify-translation`. Add all 9 languages.
- Commits: `type(scope): description (#18305)`, signed (`-S`). Run backend tests only through the yarn scripts (`.github/instructions/backend/patterns/testing.md`).

## Review Focus

1. **A connector at 299 s vs 300 s without ping.** The evaluator must return `critical` exactly when Active/Inactive turns « Inactive », not before. The chip follows at the next manager cycle. Tests in Task 1.
2. **A legacy run-and-terminate connector.** It does not declare `run_and_terminate` and registers at start, then calls `force_ping()` (one or two pings) at exit. It must never be `critical`, whether its run lasts 30 s, 90 s or 10 min. Tests in Tasks 1-2.
3. **The flag just turned on, or the manager down for a while.** With no observation yet, no connector may be `critical`: no burst of false alarms at activation. After a manager outage, a connector already seen pinging every 40 s keeps its count, so its death is still caught, while a legacy run-and-terminate connector never gains a ping from the outage. Tests in Tasks 1, 2 and 4.
4. **The cache write moving `updated_at`.** It would refresh the heartbeat being measured, and `NO_HEARTBEAT` would never fire again. The write must go through `elReplace` with only the four `ingestion_health_*` keys. Test in Task 4.
5. **One broken connector document stopping the manager cycle.** The other connectors must still be evaluated, and the error must be logged with the id. Test in Task 4.
6. **Redis on the read path.** Neither `ingestion_health` nor `ingestion_warnings` may call Redis: the deployed list is polled every 5 s per open tab. Test in Task 2.

---

## File map

**Backend** (`opencti-platform/opencti-graphql/`)
- Create:
  - `src/modules/ingestionHealth/ingestionHealth-types.ts`
  - `src/modules/ingestionHealth/ingestionHealth-checks.ts`: pure evaluator and heartbeat observation
  - `src/modules/ingestionHealth/ingestionHealth-redis.ts`: observation get/set/delete
  - `src/modules/ingestionHealth/ingestionHealth-domain.ts`: connector → input, cached resolution, collection
  - `src/modules/ingestionHealth/ingestionHealth-attributes.ts`
  - `src/modules/ingestionHealth/ingestionHealth.graphql`
  - `src/modules/ingestionHealth/ingestionHealth-resolver.ts`
  - `src/modules/ingestionHealth/ingestionHealth-graphql.ts`
  - `src/manager/ingestionHealthManager.ts`
  - `tests/01-unit/modules/ingestionHealth/ingestionHealth-checks-test.ts`
  - `tests/01-unit/modules/ingestionHealth/ingestionHealth-domain-test.ts`
  - `tests/01-unit/manager/ingestionHealthManager-test.ts`
- Modify:
  - `src/config/conf.js`
  - `config/schema/opencti.graphql` (`type Connector`)
  - `src/modules/index.ts`
  - `src/modules/attributes/internalObject-registrationAttributes.ts`
  - `src/manager/index.ts`
  - `src/domain/connector.ts` (`connectorDelete`)
  - `config/default.json`
  - `config/test.json`
  - `tests/03-integration/02-resolvers/connector-test.ts`
- Generated, never edited by hand: `src/generated/graphql.ts`, `../opencti-front/src/schema/relay.schema.graphql`

**Front** (`opencti-platform/opencti-front/`)
- Create:
  - `src/private/components/data/connectors/IngestionHealthChip.tsx`
  - `src/private/components/data/connectors/IngestionHealthChip.test.tsx`
- Modify:
  - `src/private/components/data/connectors/ConnectorsState.tsx`
  - `src/private/components/integrations/deployed/useDeployedIntegrations.ts` (+ `.test.ts`)
  - `src/private/components/integrations/deployed/DeployedIntegrationLine.tsx` (+ `.test.tsx`)
  - `src/private/components/integrations/deployed/DeployedIntegrationCard.tsx`
  - `src/private/components/data/connectors/Connector.tsx` (+ `Connector.test.tsx`)
  - `src/private/components/settings/settings_managers/settingsManagersUtils.ts` (+ `.test.ts`)
  - `lang/back/*.json`, `lang/front/*.json` (9 languages each)

---

### Task 1: Feature flag and pure evaluator

**Files:**
- Modify: `opencti-platform/opencti-graphql/src/config/conf.js` (after `ENTITIES_WORKFLOW_FEATURE_FLAG`, ~line 605)
- Create: `opencti-platform/opencti-graphql/src/modules/ingestionHealth/ingestionHealth-types.ts`
- Create: `opencti-platform/opencti-graphql/src/modules/ingestionHealth/ingestionHealth-checks.ts`
- Test: `opencti-platform/opencti-graphql/tests/01-unit/modules/ingestionHealth/ingestionHealth-checks-test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `INGESTION_HEALTH_FEATURE_FLAG = 'INGESTION_HEALTH'` (conf.js)
  - Types:
    - `INGESTION_HEALTH_STATUSES`, `IngestionHealthStatus`
    - `IngestionCheckCode = 'NO_HEARTBEAT' | 'USER_NOT_SERVICE_ACCOUNT'`, `IngestionCheck`, `IngestionHealth`
    - `IngestionActingUser { service_account: boolean }`: no name on purpose, see `computeIngestionWarnings`
    - `HeartbeatObservation { last_seen_at: string | null; close_pings: number }`
    - `IngestionHealthInput { running: boolean; run_and_terminate: boolean; last_seen_at: Date | null; pings_regularly: boolean }`
  - `HEARTBEAT_TIMEOUT_SECONDS = 300`, `MIN_CLOSE_PINGS_BOUND_SECONDS = 120`, `REGULAR_PING_MIN_STREAK = 3`
  - `closePingsBoundSeconds(managerPeriodSeconds: number): number`: `max(120, 2 × period)`
  - `ObservationOptions { boundSeconds?: number; managerWasBlind?: boolean }` (defaults: 120, false)
  - `nextHeartbeatObservation(previous: HeartbeatObservation | null, lastSeenAt: Date | null, options?: ObservationOptions): HeartbeatObservation`
  - `isPingingRegularly(observation: HeartbeatObservation | null): boolean`
  - `computeNoHeartbeatCheck(input, now): IngestionCheck | undefined`
  - `computeIngestionHealth(input, now): IngestionHealth`. It leaves `since` unset; the manager fills it when it caches the verdict.
  - `computeIngestionWarnings(actingUser: IngestionActingUser | undefined): IngestionCheck[]`

- [ ] **Step 1: Flag constant**

In `src/config/conf.js`, right after `export const ENTITIES_WORKFLOW_FEATURE_FLAG = 'ENTITIES_WORKFLOW';`:

```js
// Ingestion health monitoring (RFC 0001)
export const INGESTION_HEALTH_FEATURE_FLAG = 'INGESTION_HEALTH';
```

- [ ] **Step 2: Types**

`src/modules/ingestionHealth/ingestionHealth-types.ts`:

```ts
// Ingestion health evaluator types (RFC 0001). No platform import here:
// the evaluator is a pure function, called by the manager only.

// The six runtime states of RFC 0001 §4.1. Chunk 1 only produces unknown, critical and stopped,
// the full set is exposed now so the GraphQL enum does not change in later chunks.
export const INGESTION_HEALTH_STATUSES = ['healthy', 'idle', 'degraded', 'critical', 'stopped', 'unknown'] as const;
export type IngestionHealthStatus = typeof INGESTION_HEALTH_STATUSES[number];

// runtime checks decide the status, configuration warnings never do (RFC 0001 §4.1, §5.1)
export type IngestionCheckKind = 'runtime' | 'configuration';
export type IngestionCheckSeverity = 'advisory' | 'blocking';
export type IngestionCheckCode = 'NO_HEARTBEAT' | 'USER_NOT_SERVICE_ACCOUNT';

export interface IngestionCheck {
  kind: IngestionCheckKind;
  code: IngestionCheckCode;
  severity: IngestionCheckSeverity;
  // Values of the message placeholders, so a surface can render the check in its own locale later
  params: Record<string, string>;
  // English sentence, for logs, API clients and the UI tooltips
  message: string;
}

export interface IngestionHealth {
  status: IngestionHealthStatus;
  // The most diagnostic check as one sentence, or what is known about the source when nothing failed
  summary: string;
  // Runtime checks only, most diagnostic first
  checks: IngestionCheck[];
  // Since when the source is in this status, when known
  since?: Date | null;
}

// The user the source acts as. No name: the warning must not leak it (see computeIngestionWarnings)
export interface IngestionActingUser {
  service_account: boolean;
}

// What the manager remembers of a connector heartbeat between two cycles (Redis, RFC 0001 §4.4)
export interface HeartbeatObservation {
  last_seen_at: string | null; // last ping observed, ISO date
  close_pings: number; // pings observed in a row, each within the close-pings bound of the previous one
}

// Everything the runtime evaluation needs, extracted from the source, its observation and the platform caches
export interface IngestionHealthInput {
  running: boolean; // false when switched off by a person
  run_and_terminate: boolean; // declared as absent between its runs
  last_seen_at: Date | null; // last ping, null when never seen or unreadable
  pings_regularly: boolean; // seen pinging every 40 seconds, false for a connector pinging only at start and exit
}
```

- [ ] **Step 3: Write the failing tests**

`tests/01-unit/modules/ingestionHealth/ingestionHealth-checks-test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import {
  computeIngestionHealth,
  computeIngestionWarnings,
  closePingsBoundSeconds,
  computeNoHeartbeatCheck,
  isPingingRegularly,
  nextHeartbeatObservation,
} from '../../../../src/modules/ingestionHealth/ingestionHealth-checks';
import type { HeartbeatObservation, IngestionHealthInput } from '../../../../src/modules/ingestionHealth/ingestionHealth-types';

const NOW = new Date('2026-10-07T12:00:00.000Z');
const secondsAgo = (seconds: number) => new Date(NOW.getTime() - seconds * 1000);

const input = (overrides: Partial<IngestionHealthInput> = {}): IngestionHealthInput => ({
  running: true,
  run_and_terminate: false,
  last_seen_at: secondsAgo(30),
  pings_regularly: true,
  ...overrides,
});

describe('Ingestion health evaluator - heartbeat', () => {
  it('should not fire before 5 minutes without ping, like Active/Inactive', () => {
    expect(computeNoHeartbeatCheck(input({ last_seen_at: secondsAgo(299) }), NOW)).toBeUndefined();
  });

  it('should fire from 5 minutes without ping, exactly when Active/Inactive turns inactive', () => {
    const lastSeen = secondsAgo(300);
    expect(computeNoHeartbeatCheck(input({ last_seen_at: lastSeen }), NOW)).toEqual({
      kind: 'runtime',
      code: 'NO_HEARTBEAT',
      severity: 'blocking',
      params: { last_seen: lastSeen.toISOString() },
      message: `No ping received since ${lastSeen.toISOString()}`,
    });
  });

  it('should never fire for a connector not seen pinging every 40 seconds, like a legacy run-and-terminate one', () => {
    expect(computeNoHeartbeatCheck(input({ pings_regularly: false, last_seen_at: secondsAgo(3 * 24 * 3600) }), NOW)).toBeUndefined();
  });

  it('should never fire for a connector declaring run-and-terminate', () => {
    expect(computeNoHeartbeatCheck(input({ run_and_terminate: true, last_seen_at: secondsAgo(3 * 24 * 3600) }), NOW)).toBeUndefined();
  });

  it('should not fire for a connector never seen running, there is no baseline', () => {
    expect(computeNoHeartbeatCheck(input({ last_seen_at: null }), NOW)).toBeUndefined();
  });
});

// The observations the manager makes, one cycle after the other, of a connector pinging at these times
const observe = (pingsSecondsAgo: number[]): HeartbeatObservation | null => {
  return pingsSecondsAgo.reduce<HeartbeatObservation | null>((previous, seconds) => nextHeartbeatObservation(previous, secondsAgo(seconds)), null);
};

describe('Ingestion health evaluator - heartbeat observation', () => {
  it('should not consider a connector observed for the first time as pinging regularly', () => {
    expect(nextHeartbeatObservation(null, secondsAgo(30))).toEqual({ last_seen_at: secondsAgo(30).toISOString(), close_pings: 0 });
    expect(isPingingRegularly(null)).toBe(false);
  });

  it('should consider a connector pinging every 40 seconds as regular after 3 close pings, the manager looking every 60 seconds', () => {
    // A new ping is seen 40 or 80 seconds after the previous one
    expect(isPingingRegularly(observe([240, 200, 120]))).toBe(false); // 2 close pings
    expect(isPingingRegularly(observe([240, 200, 120, 80]))).toBe(true); // 3 close pings
  });

  it('should never consider a legacy run-and-terminate connector as regular, whatever its run length', () => {
    // Registration at start, then force_ping at exit, which can send a second ping milliseconds later
    expect(isPingingRegularly(observe([400, 310, 309.99]))).toBe(false); // a 90 seconds run, both final pings seen
    expect(isPingingRegularly(observe([400, 370]))).toBe(false); // a 30 seconds run
    expect(isPingingRegularly(observe([1000, 400]))).toBe(false); // a 10 minutes run
  });

  it('should restart the count when two pings are more than 120 seconds apart, with the default period', () => {
    const regular = { last_seen_at: secondsAgo(400).toISOString(), close_pings: 3 };
    expect(nextHeartbeatObservation(regular, secondsAgo(200))).toEqual({ last_seen_at: secondsAgo(200).toISOString(), close_pings: 0 });
    // A run hours later, or a manager down for a while
    expect(nextHeartbeatObservation(regular, secondsAgo(10)).close_pings).toBe(0);
  });

  it('should keep the observation when no new ping arrived, so a dead regular connector stays judged', () => {
    const previous = { last_seen_at: secondsAgo(900).toISOString(), close_pings: 3 };
    expect(nextHeartbeatObservation(previous, secondsAgo(900))).toBe(previous);
    expect(nextHeartbeatObservation(previous, null)).toBe(previous);
  });

  it('should cap the count, so a live connector does not grow its observation forever', () => {
    const previous = { last_seen_at: secondsAgo(80).toISOString(), close_pings: 3 };
    expect(nextHeartbeatObservation(previous, secondsAgo(40)).close_pings).toBe(3);
  });

  it('should keep the count when the gap comes from the manager not looking, not from the connector', () => {
    // Pinging every 40 seconds before a 5 minutes manager outage, and during it
    const regular = { last_seen_at: secondsAgo(400).toISOString(), close_pings: 3 };
    expect(nextHeartbeatObservation(regular, secondsAgo(10), { managerWasBlind: true })).toEqual({ last_seen_at: secondsAgo(10).toISOString(), close_pings: 3 });
  });

  it('should never let manager outages build up the count of a legacy run-and-terminate connector, run after run', () => {
    const blind = { managerWasBlind: true };
    // Run 1: registration, then force_ping doubled at exit
    let observation = nextHeartbeatObservation(null, secondsAgo(3000));
    observation = nextHeartbeatObservation(observation, secondsAgo(2910));
    observation = nextHeartbeatObservation(observation, secondsAgo(2909.99));
    expect(observation.close_pings).toBe(2);
    // Run 2 starts during a manager outage, then ends with the same exit pings
    observation = nextHeartbeatObservation(observation, secondsAgo(1000), blind);
    observation = nextHeartbeatObservation(observation, secondsAgo(910));
    observation = nextHeartbeatObservation(observation, secondsAgo(909.99));
    expect(observation.close_pings).toBe(2);
    expect(isPingingRegularly(observation)).toBe(false);
  });

  it('should restart from zero a connector not yet seen pinging every 40 seconds, after a manager outage', () => {
    const starting = { last_seen_at: secondsAgo(400).toISOString(), close_pings: 2 };
    expect(nextHeartbeatObservation(starting, secondsAgo(10), { managerWasBlind: true }).close_pings).toBe(0);
  });

  it('should derive the close-pings bound from the manager period, never below 120 seconds', () => {
    expect(closePingsBoundSeconds(60)).toBe(120); // the default period
    expect(closePingsBoundSeconds(30)).toBe(120);
    expect(closePingsBoundSeconds(300)).toBe(600);
  });

  it('should still recognize a connector pinging every 40 seconds with a 5 minutes manager period', () => {
    // The manager sees one ping every 5 minutes, up to 5 minutes 40 seconds apart
    const options = { boundSeconds: closePingsBoundSeconds(300) };
    const observation = [1400, 1080, 720, 380].reduce<HeartbeatObservation | null>((previous, seconds) => nextHeartbeatObservation(previous, secondsAgo(seconds), options), null);
    expect(isPingingRegularly(observation)).toBe(true);
    // A legacy run is still 2 pings at most
    expect(isPingingRegularly([1400, 1310, 1309.99].reduce<HeartbeatObservation | null>((previous, seconds) => nextHeartbeatObservation(previous, secondsAgo(seconds), options), null))).toBe(false);
  });

  it('should restart the count on an unreadable previous observation', () => {
    expect(nextHeartbeatObservation({ last_seen_at: 'not a date', close_pings: 3 }, secondsAgo(10)).close_pings).toBe(0);
    expect(nextHeartbeatObservation({ last_seen_at: secondsAgo(50).toISOString() } as any, secondsAgo(10)).close_pings).toBe(1);
  });
});

describe('Ingestion health evaluator - status', () => {
  it('should be unknown, never healthy, for a connector pinging every 40 seconds', () => {
    expect(computeIngestionHealth(input(), NOW)).toEqual({
      status: 'unknown',
      summary: 'Pinging every 40 seconds, data intake not evaluated yet',
      checks: [],
    });
  });

  it('should give a summary that does not move with every ping, so the manager writes on change only', () => {
    expect(computeIngestionHealth(input({ last_seen_at: secondsAgo(10) }), NOW)).toEqual(computeIngestionHealth(input({ last_seen_at: secondsAgo(50) }), NOW));
  });

  it('should be critical with the heartbeat check as summary when the ping is lost', () => {
    const lastSeen = secondsAgo(3600);
    const health = computeIngestionHealth(input({ last_seen_at: lastSeen }), NOW);
    expect(health.status).toBe('critical');
    expect(health.summary).toBe(`No ping received since ${lastSeen.toISOString()}`);
    expect(health.checks.map((check) => check.code)).toEqual(['NO_HEARTBEAT']);
  });

  it('should stay unknown for a connector not seen pinging every 40 seconds, between two runs', () => {
    expect(computeIngestionHealth(input({ last_seen_at: secondsAgo(3600), pings_regularly: false }), NOW)).toEqual({
      status: 'unknown',
      summary: 'No ping every 40 seconds observed, heartbeat not evaluated',
      checks: [],
    });
  });

  it('should explain an unknown status for a run-and-terminate connector and a never seen one', () => {
    expect(computeIngestionHealth(input({ run_and_terminate: true }), NOW).summary).toBe('Heartbeat not evaluated for run-and-terminate connectors');
    expect(computeIngestionHealth(input({ last_seen_at: null }), NOW)).toEqual({ status: 'unknown', summary: 'Never seen running', checks: [] });
  });

  it('should be stopped when switched off by a person, whatever fails, keeping the checks', () => {
    const health = computeIngestionHealth(input({ running: false, last_seen_at: secondsAgo(3600) }), NOW);
    expect(health.status).toBe('stopped');
    expect(health.summary).toBe('Stopped by a user');
    expect(health.checks.map((check) => check.code)).toEqual(['NO_HEARTBEAT']);
  });
});

describe('Ingestion health evaluator - configuration warnings', () => {
  it('should warn when the connector user is not a service account', () => {
    // No user name, neither in the message nor in the params: reading a connector only needs MODULES,
    // while the name of its user is reserved to SETTINGS_SETACCESSES (connectorUser, domain/connector.ts)
    expect(computeIngestionWarnings({ service_account: false })).toEqual([{
      kind: 'configuration',
      code: 'USER_NOT_SERVICE_ACCOUNT',
      severity: 'advisory',
      params: {},
      message: 'User is not a service account',
    }]);
  });

  it('should not warn for a service account', () => {
    expect(computeIngestionWarnings({ service_account: true })).toEqual([]);
  });

  it('should not warn when the connector user is missing, that is another check', () => {
    expect(computeIngestionWarnings(undefined)).toEqual([]);
  });
});
```

- [ ] **Step 4: Run them and check they fail**

Run: `cd opencti-platform/opencti-graphql && yarn test:ci-unit tests/01-unit/modules/ingestionHealth/ingestionHealth-checks-test.ts`
Expected: FAIL (`Failed to resolve import ".../ingestionHealth-checks"`)

- [ ] **Step 5: Implement the evaluator**

`src/modules/ingestionHealth/ingestionHealth-checks.ts`:

```ts
import type { HeartbeatObservation, IngestionActingUser, IngestionCheck, IngestionHealth, IngestionHealthInput } from './ingestionHealth-types';

// Same timeout as isConnectorActive (database/repository.js: Math.floor(minutes) < 5)
export const HEARTBEAT_TIMEOUT_SECONDS = 300;
// pycti pings every 40 seconds. With the default 60 seconds manager period, a live connector shows
// a new ping 40 to 80 seconds after the previous one; with a period P, up to P + 40 seconds after it.
// Hence a bound of 2 periods, never below 120 seconds.
export const MIN_CLOSE_PINGS_BOUND_SECONDS = 120;
export const closePingsBoundSeconds = (managerPeriodSeconds: number) => Math.max(MIN_CLOSE_PINGS_BOUND_SECONDS, 2 * managerPeriodSeconds);
// A legacy run-and-terminate connector shows at most two pings per run: its registration,
// then force_ping at exit (sometimes doubled). Three close pings in a row cannot come from it.
export const REGULAR_PING_MIN_STREAK = 3;

const secondsBetween = (from: Date, to: Date) => (to.getTime() - from.getTime()) / 1000;

// The manager memory of a connector heartbeat: how many pings in a row came close to each other.
export interface ObservationOptions {
  // Max gap between two close pings, from closePingsBoundSeconds
  boundSeconds?: number;
  // The manager itself did not look for longer than the bound (platform restart, lost lock...).
  // A wide gap then says nothing about the connector: the count of a connector already seen
  // pinging every 40 seconds is kept as is; any other count restarts as usual.
  managerWasBlind?: boolean;
}

export const nextHeartbeatObservation = (previous: HeartbeatObservation | null, lastSeenAt: Date | null, options: ObservationOptions = {}): HeartbeatObservation => {
  const { boundSeconds = MIN_CLOSE_PINGS_BOUND_SECONDS, managerWasBlind = false } = options;
  if (!lastSeenAt) {
    return previous ?? { last_seen_at: null, close_pings: 0 };
  }
  const lastSeen = lastSeenAt.toISOString();
  if (previous?.last_seen_at === lastSeen) {
    return previous; // No new ping since the last observation
  }
  if (!previous?.last_seen_at) {
    return { last_seen_at: lastSeen, close_pings: 0 };
  }
  const gapSeconds = secondsBetween(new Date(previous.last_seen_at), lastSeenAt);
  // NaN (unreadable previous date) and negative gaps restart the count too
  const isClose = gapSeconds > 0 && gapSeconds <= boundSeconds;
  const previousCount = Number.isInteger(previous.close_pings) ? previous.close_pings : 0;
  if (isClose) {
    return { last_seen_at: lastSeen, close_pings: Math.min(previousCount + 1, REGULAR_PING_MIN_STREAK) };
  }
  // An outage only spares a connector already seen pinging every 40 seconds. A count still being built
  // (a new connector, or a legacy run-and-terminate one) restarts, so outages can never add up into a false proof
  const isAlreadyRegular = previousCount >= REGULAR_PING_MIN_STREAK;
  return { last_seen_at: lastSeen, close_pings: managerWasBlind && isAlreadyRegular ? previousCount : 0 };
};

// Seen pinging every 40 seconds: only such a connector can be said to have stopped pinging
export const isPingingRegularly = (observation: HeartbeatObservation | null) => {
  return (observation?.close_pings ?? 0) >= REGULAR_PING_MIN_STREAK;
};

export const computeNoHeartbeatCheck = (input: IngestionHealthInput, now: Date): IngestionCheck | undefined => {
  // A run-and-terminate connector is supposed to be absent between its runs (RFC 0001 §4.2),
  // a connector not seen pinging every 40 seconds cannot be said to have stopped pinging,
  // and a connector never seen running has no baseline to judge a missing ping against.
  if (input.run_and_terminate || !input.pings_regularly || !input.last_seen_at) {
    return undefined;
  }
  if (secondsBetween(input.last_seen_at, now) < HEARTBEAT_TIMEOUT_SECONDS) {
    return undefined;
  }
  const lastSeen = input.last_seen_at.toISOString();
  return {
    kind: 'runtime',
    code: 'NO_HEARTBEAT',
    severity: 'blocking',
    params: { last_seen: lastSeen },
    message: `No ping received since ${lastSeen}`,
  };
};

// No timestamp moving with every ping here: the manager caches the summary and writes on change only
const unknownSummary = (input: IngestionHealthInput) => {
  if (input.run_and_terminate) {
    return 'Heartbeat not evaluated for run-and-terminate connectors';
  }
  if (!input.last_seen_at) {
    return 'Never seen running';
  }
  return input.pings_regularly ? 'Pinging every 40 seconds, data intake not evaluated yet' : 'No ping every 40 seconds observed, heartbeat not evaluated';
};

// Pure evaluator, called by the manager only. The UI reads what the manager cached,
// so a status shown in the UI and a status sent by a future alert can never disagree (RFC 0001 §4.4).
export const computeIngestionHealth = (input: IngestionHealthInput, now: Date): IngestionHealth => {
  const checks = [computeNoHeartbeatCheck(input, now)].filter((check): check is IngestionCheck => check !== undefined);
  // Stopped short-circuits every check: a source switched off on purpose is never painted red
  if (!input.running) {
    return { status: 'stopped', summary: 'Stopped by a user', checks };
  }
  const [headline] = checks;
  if (headline && headline.severity === 'blocking') {
    return { status: 'critical', summary: headline.message, checks };
  }
  // Never healthy in chunk 1: a ping proves the connector is alive, not that it brings data in
  return { status: 'unknown', summary: unknownSummary(input), checks };
};

// Configuration warnings (RFC 0001 §4.1): a second axis, shown on the source detail page only.
// They never change the runtime status, are never cached and never notified.
export const computeIngestionWarnings = (actingUser: IngestionActingUser | undefined): IngestionCheck[] => {
  // A missing user is USER_MISSING, deferred by the RFC: saying "not a service account" would be wrong
  if (!actingUser || actingUser.service_account) {
    return [];
  }
  // Never the user name: reading a connector only needs MODULES, while the name of its user
  // is reserved to SETTINGS_SETACCESSES (connectorUser, domain/connector.ts)
  return [{
    kind: 'configuration',
    code: 'USER_NOT_SERVICE_ACCOUNT',
    severity: 'advisory',
    params: {},
    message: 'User is not a service account',
  }];
};
```

- [ ] **Step 6: Run them and check they pass**

Run: `cd opencti-platform/opencti-graphql && yarn test:ci-unit tests/01-unit/modules/ingestionHealth/ingestionHealth-checks-test.ts`
Expected: PASS (26 tests)

- [ ] **Step 7: Commit**

```bash
git add opencti-platform/opencti-graphql/src/config/conf.js opencti-platform/opencti-graphql/src/modules/ingestionHealth/ingestionHealth-types.ts opencti-platform/opencti-graphql/src/modules/ingestionHealth/ingestionHealth-checks.ts opencti-platform/opencti-graphql/tests/01-unit/modules/ingestionHealth/ingestionHealth-checks-test.ts
git commit -S -m "feat(ingestion-health): add the INGESTION_HEALTH flag and the connector health evaluator (#18305)"
```

---

### Task 2: Domain — Redis observation, connector input, cached resolution

**Files:**
- Create: `opencti-platform/opencti-graphql/src/modules/ingestionHealth/ingestionHealth-redis.ts`
- Create: `opencti-platform/opencti-graphql/src/modules/ingestionHealth/ingestionHealth-domain.ts`
- Test: `opencti-platform/opencti-graphql/tests/01-unit/modules/ingestionHealth/ingestionHealth-domain-test.ts`

**Interfaces:**
- Consumes (Task 1): `nextHeartbeatObservation`, `ObservationOptions`, `isPingingRegularly`, `computeIngestionWarnings`, `HeartbeatObservation`, `IngestionActingUser`, `IngestionHealthInput`, `IngestionHealth`, `IngestionCheck`, `IngestionHealthStatus`.
- Produces:
  - `redisGetIngestionHealthObservation(sourceId: string): Promise<HeartbeatObservation | null>`
  - `redisSetIngestionHealthObservation(sourceId: string, observation: HeartbeatObservation): Promise<void>`
  - `redisDeleteIngestionHealthObservation(sourceId: string): Promise<void>`
  - `redisGetIngestionHealthLastRun(): Promise<Date | null>` / `redisSetIngestionHealthLastRun(at: Date): Promise<void>`: one platform-wide key, `ingestion-health-manager-last-run`, the start time of the manager's last full cycle
  - `type IngestionHealthConnector`: the stored connector fields read by the feature, including the cached `ingestion_health_status?`, `ingestion_health_since?`, `ingestion_health_summary?` and `ingestion_health_checks?` (a JSON string)
  - `isIngestionConnector(connector): boolean`
  - `buildActingUser(connector, usersById: Map<string, AuthUser>): IngestionActingUser | undefined`
  - `buildIngestionHealthInput(connector, heartbeat: HeartbeatObservation): IngestionHealthInput`
  - `resolveIngestionHealth(connector): IngestionHealth | null`: reads the cache only, with no I/O
  - `resolveIngestionWarnings(context, connector): Promise<IngestionCheck[] | null>`: reads the user cache, never Redis
  - `interface IngestionSourceSnapshot { connector; input; previous_heartbeat: HeartbeatObservation | null; heartbeat: HeartbeatObservation }`
  - `collectIngestionSources(context, options: ObservationOptions): Promise<IngestionSourceSnapshot[]>`

- [ ] **Step 1: Write the failing tests**

`tests/01-unit/modules/ingestionHealth/ingestionHealth-domain-test.ts`:

```ts
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getEntitiesMapFromCache } from '../../../../src/database/cache';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import {
  buildActingUser,
  buildIngestionHealthInput,
  collectIngestionSources,
  isIngestionConnector,
  resolveIngestionHealth,
  resolveIngestionWarnings,
} from '../../../../src/modules/ingestionHealth/ingestionHealth-domain';
import { redisGetIngestionHealthObservation } from '../../../../src/modules/ingestionHealth/ingestionHealth-redis';

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  getEntitiesMapFromCache: vi.fn(),
}));
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  fullEntitiesList: vi.fn(),
}));
vi.mock('../../../../src/modules/ingestionHealth/ingestionHealth-redis', () => ({
  redisGetIngestionHealthObservation: vi.fn(),
}));

const RECENT = '2026-10-07T11:59:30.000Z';
const OLD = '2026-10-07T10:00:00.000Z';
const users = new Map<string, any>([
  ['service-user', { id: 'service-user', name: 'Service', user_service_account: true }],
  ['personal-user', { id: 'personal-user', name: 'John' }],
]);
const connector = (overrides: Record<string, unknown> = {}): any => ({
  internal_id: 'connector-id',
  name: 'My connector',
  _index: 'opencti_internal_objects-000001',
  connector_type: 'EXTERNAL_IMPORT',
  connector_user_id: 'service-user',
  updated_at: RECENT,
  ...overrides,
});
const regular = (lastSeen: string) => ({ last_seen_at: lastSeen, close_pings: 3 });

describe('Ingestion health domain', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (getEntitiesMapFromCache as any).mockResolvedValue(users);
    (redisGetIngestionHealthObservation as any).mockResolvedValue(null);
  });

  it('should evaluate every deployed connector whatever its type, managed or self-hosted', () => {
    expect(isIngestionConnector({ connector_type: 'EXTERNAL_IMPORT' })).toBe(true);
    expect(isIngestionConnector({ connector_type: 'INTERNAL_ENRICHMENT', built_in: false })).toBe(true);
    expect(isIngestionConnector({ connector_type: 'INTERNAL_EXPORT_FILE' })).toBe(true);
    expect(isIngestionConnector({ connector_type: 'STREAM' })).toBe(true);
    expect(isIngestionConnector({ connector_type: 'EXTERNAL_IMPORT', built_in: true })).toBe(false); // platform plumbing or feed twin
    expect(isIngestionConnector({ connector_type: 'internal' })).toBe(false); // queue-backed internal connector
  });

  it('should build the input from the connector, its last ping and its heartbeat observation', () => {
    expect(buildIngestionHealthInput(connector({ connector_info: { run_and_terminate: true } }), regular(RECENT))).toEqual({
      running: true,
      run_and_terminate: true,
      last_seen_at: new Date(RECENT),
      pings_regularly: true,
    });
  });

  it('should read a missing or unparseable ping date as never seen', () => {
    expect(buildIngestionHealthInput(connector({ updated_at: undefined }), regular(RECENT)).last_seen_at).toBeNull();
    expect(buildIngestionHealthInput(connector({ updated_at: 'not a date' }), regular(RECENT)).last_seen_at).toBeNull();
  });

  it('should consider a managed connector stopped exactly like isConnectorActive does', () => {
    const managed = { catalog_id: 'catalog-id' };
    const runningOf = (overrides: Record<string, unknown>) => buildIngestionHealthInput(connector({ ...managed, ...overrides }), regular(RECENT)).running;
    expect(runningOf({ manager_requested_status: 'stopping' })).toBe(false);
    expect(runningOf({ manager_requested_status: 'stopped' })).toBe(false);
    expect(runningOf({ manager_current_status: 'stopped' })).toBe(false);
    expect(runningOf({ manager_requested_status: 'starting' })).toBe(true);
    // A self-hosted connector cannot be switched off from the platform
    expect(buildIngestionHealthInput(connector({ manager_requested_status: 'stopped' }), regular(RECENT)).running).toBe(true);
  });

  it('should build the acting user without its name, a user without the service account flag being a personal account', () => {
    expect(buildActingUser(connector(), users)).toEqual({ service_account: true });
    expect(buildActingUser(connector({ connector_user_id: 'personal-user' }), users)).toEqual({ service_account: false });
    expect(buildActingUser(connector({ connector_user_id: 'deleted-user' }), users)).toBeUndefined();
    expect(buildActingUser(connector({ connector_user_id: null }), users)).toBeUndefined();
  });

  describe('resolution at read time, from the manager cache only', () => {
    const noHeartbeat = [{ kind: 'runtime', code: 'NO_HEARTBEAT', severity: 'blocking', params: { last_seen: OLD }, message: `No ping received since ${OLD}` }];

    it('should return the cached status, summary, checks and since', () => {
      const cachedCritical = connector({
        updated_at: OLD,
        ingestion_health_status: 'critical',
        ingestion_health_since: RECENT,
        ingestion_health_summary: `No ping received since ${OLD}`,
        ingestion_health_checks: JSON.stringify(noHeartbeat),
      });
      expect(resolveIngestionHealth(cachedCritical)).toEqual({
        status: 'critical',
        summary: `No ping received since ${OLD}`,
        checks: noHeartbeat,
        since: new Date(RECENT),
      });
    });

    it('should be unknown, never critical, before the manager evaluated the connector, at activation for instance', () => {
      expect(resolveIngestionHealth(connector({ updated_at: OLD }))).toEqual({ status: 'unknown', summary: 'Not evaluated yet', checks: [], since: null });
    });

    it('should read unreadable cached checks as no check', () => {
      expect(resolveIngestionHealth(connector({ ingestion_health_status: 'unknown', ingestion_health_checks: 'not json' }))?.checks).toEqual([]);
    });

    it('should never call Redis: the deployed list polls this field every 5 seconds', async () => {
      resolveIngestionHealth(connector({ updated_at: OLD, ingestion_health_status: 'critical' }));
      await resolveIngestionWarnings({} as any, connector());
      expect(redisGetIngestionHealthObservation).not.toHaveBeenCalled();
    });

    it('should resolve the configuration warnings separately from the status', async () => {
      const personal = connector({ connector_user_id: 'personal-user', ingestion_health_status: 'unknown' });
      expect(resolveIngestionHealth(personal)?.status).toBe('unknown');
      expect((await resolveIngestionWarnings({} as any, personal))?.map((warning) => warning.code)).toEqual(['USER_NOT_SERVICE_ACCOUNT']);
    });

    it('should resolve nothing for a connector that is not an ingestion source', async () => {
      const builtIn = connector({ connector_type: 'internal' });
      expect(resolveIngestionHealth(builtIn)).toBeNull();
      expect(await resolveIngestionWarnings({} as any, builtIn)).toBeNull();
    });
  });

  it('should collect every ingestion connector with its previous and next heartbeat observation', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      connector({ internal_id: 'a' }),
      connector({ internal_id: 'b', built_in: true }),
    ]);
    const previous = { last_seen_at: '2026-10-07T11:58:40.000Z', close_pings: 2 };
    (redisGetIngestionHealthObservation as any).mockResolvedValue(previous);
    const sources = await collectIngestionSources({} as any, { boundSeconds: 120, managerWasBlind: false });
    expect(sources.map((source) => source.connector.internal_id)).toEqual(['a']);
    expect(sources[0].previous_heartbeat).toEqual(previous);
    expect(sources[0].heartbeat).toEqual(regular(RECENT)); // a third close ping, 50 seconds after the previous one
    expect(sources[0].input.pings_regularly).toBe(true);
  });

  it('should keep the count of a regular connector after a manager outage, so its death is still caught', async () => {
    (fullEntitiesList as any).mockResolvedValue([connector({ internal_id: 'a' })]);
    // Last seen by the manager long before its outage, pinging during it
    (redisGetIngestionHealthObservation as any).mockResolvedValue(regular(OLD));
    const [afterOutage] = await collectIngestionSources({} as any, { boundSeconds: 120, managerWasBlind: true });
    expect(afterOutage.heartbeat).toEqual(regular(RECENT));
    const [withoutOutage] = await collectIngestionSources({} as any, { boundSeconds: 120, managerWasBlind: false });
    expect(withoutOutage.heartbeat.close_pings).toBe(0);
  });
});
```

- [ ] **Step 2: Run them and check they fail**

Run: `cd opencti-platform/opencti-graphql && yarn test:ci-unit tests/01-unit/modules/ingestionHealth/ingestionHealth-domain-test.ts`
Expected: FAIL (`Failed to resolve import ".../ingestionHealth-domain"`)

- [ ] **Step 3: Redis observation**

`src/modules/ingestionHealth/ingestionHealth-redis.ts` (same pattern as `src/modules/connector/connector-redis.ts`):

```ts
import { getClientBase } from '../../database/redis';
import type { HeartbeatObservation } from './ingestionHealth-types';

// The ingestion health manager memory between two cycles (RFC 0001 §4.4).
// No TTL on purpose: it must outlive a dead connector. It is removed with the connector.
const observationKey = (sourceId: string) => `ingestion-health-observation:${sourceId}`;

export const redisGetIngestionHealthObservation = async (sourceId: string): Promise<HeartbeatObservation | null> => {
  const rawObservation = await getClientBase().get(observationKey(sourceId));
  if (!rawObservation) {
    return null;
  }
  try {
    return JSON.parse(rawObservation) as HeartbeatObservation;
  } catch {
    return null;
  }
};

export const redisSetIngestionHealthObservation = async (sourceId: string, observation: HeartbeatObservation) => {
  await getClientBase().set(observationKey(sourceId), JSON.stringify(observation));
};

export const redisDeleteIngestionHealthObservation = async (sourceId: string) => {
  await getClientBase().del(observationKey(sourceId));
};

// Start time of the manager's last full cycle (a pass that listed every connector), one key for the platform.
// It tells the manager whether
// it was blind for a while (restart, lost lock), so a wide gap between two pings is not blamed
// on the connector. It also answers « is the ingestion health manager alive » for an operator.
const LAST_RUN_KEY = 'ingestion-health-manager-last-run';

export const redisGetIngestionHealthLastRun = async (): Promise<Date | null> => {
  const rawDate = await getClientBase().get(LAST_RUN_KEY);
  const date = rawDate ? new Date(rawDate) : null;
  return date && !Number.isNaN(date.getTime()) ? date : null;
};

export const redisSetIngestionHealthLastRun = async (at: Date) => {
  await getClientBase().set(LAST_RUN_KEY, at.toISOString());
};
```

- [ ] **Step 4: Implement the domain**

`src/modules/ingestionHealth/ingestionHealth-domain.ts`:

```ts
import { getEntitiesMapFromCache } from '../../database/cache';
import { fullEntitiesList } from '../../database/middleware-loader';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import type { BasicStoreEntity } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_USER } from '../user/user-types';
import { computeIngestionWarnings, isPingingRegularly, nextHeartbeatObservation, type ObservationOptions } from './ingestionHealth-checks';
import { redisGetIngestionHealthObservation } from './ingestionHealth-redis';
import type {
  HeartbeatObservation,
  IngestionActingUser,
  IngestionCheck,
  IngestionHealth,
  IngestionHealthInput,
  IngestionHealthStatus,
} from './ingestionHealth-types';

// Stored connector fields read by the health evaluation
export interface IngestionHealthConnector {
  internal_id: string;
  name: string;
  _index: string;
  built_in?: boolean;
  connector_type?: string;
  connector_user_id?: string | null;
  catalog_id?: string | null;
  manager_requested_status?: string | null;
  manager_current_status?: string | null;
  // Refreshed by every ping: the connector heartbeat
  updated_at?: string | Date | null;
  connector_info?: { run_and_terminate?: boolean } | null;
  // Cached health, written by the ingestion health manager on change only
  ingestion_health_status?: IngestionHealthStatus;
  ingestion_health_since?: string;
  ingestion_health_summary?: string;
  ingestion_health_checks?: string; // JSON array of IngestionCheck
}

export interface IngestionSourceSnapshot {
  connector: IngestionHealthConnector;
  input: IngestionHealthInput;
  previous_heartbeat: HeartbeatObservation | null;
  heartbeat: HeartbeatObservation;
}

// Every deployed connector, whatever its type, managed by the composer or self-hosted.
// Built-in ones are platform plumbing (draft validation, csv import, internal queues) or the technical twin of a feed:
// no process deploys them and they never ping.
export const isIngestionConnector = (connector: Pick<IngestionHealthConnector, 'built_in' | 'connector_type'>) => {
  return connector.built_in !== true && connector.connector_type !== 'internal';
};

// Switched off by a person: same rule as isConnectorActive (database/repository.js).
// A self-hosted connector cannot be switched off from the platform.
const isStoppedByUser = (connector: IngestionHealthConnector) => {
  if (!connector.catalog_id) {
    return false;
  }
  return connector.manager_requested_status === 'stopping'
    || connector.manager_requested_status === 'stopped'
    || connector.manager_current_status === 'stopped';
};

const toDate = (value: string | Date | null | undefined): Date | null => {
  if (!value) {
    return null;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
};

const observeHeartbeat = (connector: IngestionHealthConnector, previous: HeartbeatObservation | null, options: ObservationOptions) => {
  return nextHeartbeatObservation(previous, toDate(connector.updated_at), options);
};

export const buildIngestionHealthInput = (connector: IngestionHealthConnector, heartbeat: HeartbeatObservation): IngestionHealthInput => ({
  running: !isStoppedByUser(connector),
  run_and_terminate: connector.connector_info?.run_and_terminate === true,
  last_seen_at: toDate(connector.updated_at),
  pings_regularly: isPingingRegularly(heartbeat),
});

export const buildActingUser = (connector: IngestionHealthConnector, usersById: Map<string, AuthUser>): IngestionActingUser | undefined => {
  const user = connector.connector_user_id ? usersById.get(connector.connector_user_id) : undefined;
  return user ? { service_account: user.user_service_account === true } : undefined;
};

const getUsersById = (context: AuthContext) => getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);

const parseCachedChecks = (rawChecks: string | undefined): IngestionCheck[] => {
  if (!rawChecks) {
    return [];
  }
  try {
    const checks = JSON.parse(rawChecks);
    return Array.isArray(checks) ? checks : [];
  } catch {
    return [];
  }
};

// Read from the cache written by the ingestion health manager, the only evaluator (RFC 0001 §4.4).
// No Redis and no evaluation here: the deployed list polls this field every 5 seconds per open tab,
// and any GraphQL error would break the whole page.
export const resolveIngestionHealth = (connector: IngestionHealthConnector): IngestionHealth | null => {
  if (!isIngestionConnector(connector)) {
    return null;
  }
  if (!connector.ingestion_health_status) {
    // Not evaluated by the manager yet, at activation for instance: never painted red
    return { status: 'unknown', summary: 'Not evaluated yet', checks: [], since: null };
  }
  return {
    status: connector.ingestion_health_status,
    summary: connector.ingestion_health_summary ?? 'Not evaluated yet',
    checks: parseCachedChecks(connector.ingestion_health_checks),
    since: toDate(connector.ingestion_health_since),
  };
};

// Configuration warnings: a direct uncached read, never part of the health verdict (RFC 0001 §4.1)
export const resolveIngestionWarnings = async (context: AuthContext, connector: IngestionHealthConnector): Promise<IngestionCheck[] | null> => {
  if (!isIngestionConnector(connector)) {
    return null;
  }
  return computeIngestionWarnings(buildActingUser(connector, await getUsersById(context)));
};

// Every ingestion connector with its evaluation input, assembled once per manager cycle.
// options: the close-pings bound of the manager period, and whether the manager was blind since its last cycle
export const collectIngestionSources = async (context: AuthContext, options: ObservationOptions): Promise<IngestionSourceSnapshot[]> => {
  const connectors = await fullEntitiesList<BasicStoreEntity & IngestionHealthConnector>(context, SYSTEM_USER, [ENTITY_TYPE_CONNECTOR]);
  const ingestionConnectors = connectors.filter((connector) => isIngestionConnector(connector));
  return Promise.all(ingestionConnectors.map(async (connector) => {
    const previousHeartbeat = await redisGetIngestionHealthObservation(connector.internal_id);
    const heartbeat = observeHeartbeat(connector, previousHeartbeat, options);
    return { connector, input: buildIngestionHealthInput(connector, heartbeat), previous_heartbeat: previousHeartbeat, heartbeat };
  }));
};
```

If `tsc` rejects `BasicStoreEntity & IngestionHealthConnector` (for example `updated_at` typed `Date` on one side), type the list as `fullEntitiesList<BasicStoreEntity>(...)` and cast each element with `as unknown as IngestionHealthConnector`.

- [ ] **Step 5: Run the tests and check they pass**

Run: `cd opencti-platform/opencti-graphql && yarn test:ci-unit tests/01-unit/modules/ingestionHealth/ingestionHealth-domain-test.ts`
Expected: PASS (13 tests)

- [ ] **Step 6: Type-check**

Run: `cd opencti-platform/opencti-graphql && yarn check-ts`
Expected: no error

- [ ] **Step 7: Commit**

```bash
git add opencti-platform/opencti-graphql/src/modules/ingestionHealth/ingestionHealth-redis.ts opencti-platform/opencti-graphql/src/modules/ingestionHealth/ingestionHealth-domain.ts opencti-platform/opencti-graphql/tests/01-unit/modules/ingestionHealth/ingestionHealth-domain-test.ts
git commit -S -m "feat(ingestion-health): resolve the health of ingestion connectors and read it from the manager cache (#18305)"
```

---

### Task 3: GraphQL — `Connector.ingestion_health` and `Connector.ingestion_warnings`

**Files:**
- Create: `opencti-platform/opencti-graphql/src/modules/ingestionHealth/ingestionHealth.graphql`
- Create: `opencti-platform/opencti-graphql/src/modules/ingestionHealth/ingestionHealth-resolver.ts`
- Create: `opencti-platform/opencti-graphql/src/modules/ingestionHealth/ingestionHealth-graphql.ts`
- Modify: `opencti-platform/opencti-graphql/config/schema/opencti.graphql` (`type Connector`, after `jwks: String!`, ~line 2056)
- Modify: `opencti-platform/opencti-graphql/src/modules/index.ts` (after `import './dataSanity/dataSanity-graphql';`)
- Regenerate: `src/generated/graphql.ts`, `opencti-front/src/schema/relay.schema.graphql`
- Test: `opencti-platform/opencti-graphql/tests/03-integration/02-resolvers/connector-test.ts`

**Interfaces:**
- Consumes (Task 2): `resolveIngestionHealth`, `resolveIngestionWarnings`, `IngestionHealthConnector`.
- Produces (the contract for Tasks 5-6):
  - `Connector.ingestion_health: IngestionHealth`, shaped `{ status: IngestionHealthStatus!, summary: String!, checks: [IngestionCheck!]!, since: DateTime }`
  - `Connector.ingestion_warnings: [IngestionCheck!]`, each item shaped `{ kind, code, severity, params: JSON, message: String! }`
  - Both are nullable: `null` when the flag is off or the connector is built-in. A deployed connector the manager has not evaluated yet gets `unknown` / « Not evaluated yet ».

- [ ] **Step 1: Write the failing integration tests**

In `tests/03-integration/02-resolvers/connector-test.ts`, add next to the other queries:

```ts
const READ_CONNECTOR_HEALTH_QUERY = gql`
  query GetConnectorHealth($id: String!) {
    connector(id: $id) {
      id
      ingestion_health {
        status
        summary
        since
        checks {
          code
        }
      }
      ingestion_warnings {
        kind
        code
        severity
        message
      }
    }
  }
`;
```

and in `describe('Connector resolver standard behaviour', ...)`, after `'should get connector details'`:

```ts
  it('should read the ingestion health of a connector, never healthy in chunk 1', async () => {
    // The ingestion health manager is disabled in config/test.json: nothing is ever evaluated here
    const queryResult = await queryAsAdminWithSuccess({ query: READ_CONNECTOR_HEALTH_QUERY, variables: { id: TEST_CN_ID } });
    const health = queryResult.data?.connector.ingestion_health;
    expect(health.status).toEqual('unknown');
    expect(health.summary).toEqual('Not evaluated yet');
    expect(health.since).toBeNull();
    expect(health.checks).toEqual([]);
  });

  it('should warn that the connector user is not a service account, apart from the status', async () => {
    // USER_CONNECTOR, who registered TestConnector, is not a service account
    const queryResult = await queryAsAdminWithSuccess({ query: READ_CONNECTOR_HEALTH_QUERY, variables: { id: TEST_CN_ID } });
    expect(queryResult.data?.connector.ingestion_warnings).toEqual([
      // No user name: the admin running this query could see it, a MODULES-only user could not
      { kind: 'configuration', code: 'USER_NOT_SERVICE_ACCOUNT', severity: 'advisory', message: 'User is not a service account' },
    ]);
  });

  it('should not compute any ingestion health for a built-in connector', async () => {
    const queryResult = await queryAsAdminWithSuccess({ query: READ_CONNECTOR_HEALTH_QUERY, variables: { id: IMPORT_CSV_CONNECTOR.id } });
    expect(queryResult.data?.connector.ingestion_health).toBeNull();
    expect(queryResult.data?.connector.ingestion_warnings).toBeNull();
  });
```

(`config/test.json` enables every flag with `"*"`, so `@ff` lets both fields through.)

- [ ] **Step 2: Declare the types**

`src/modules/ingestionHealth/ingestionHealth.graphql`:

```graphql
# Ingestion health (RFC 0001), evaluated by the ingestion health manager every minute
# and read from its cache on the source.

enum IngestionHealthStatus {
  healthy
  idle
  degraded
  critical
  stopped
  unknown
}

enum IngestionCheckKind {
  runtime
  configuration
}

enum IngestionCheckSeverity {
  advisory
  blocking
}

enum IngestionCheckCode {
  NO_HEARTBEAT
  USER_NOT_SERVICE_ACCOUNT
}

type IngestionCheck {
  kind: IngestionCheckKind!
  code: IngestionCheckCode!
  severity: IngestionCheckSeverity!
  # Values of the message placeholders, so each surface can render the check in its own locale
  params: JSON
  # English sentence
  message: String!
}

type IngestionHealth {
  status: IngestionHealthStatus!
  # The most diagnostic check as one sentence, or what is known when nothing failed
  summary: String!
  # Runtime checks only, most diagnostic first
  checks: [IngestionCheck!]!
  # Since when the source is in this status, null when not known yet
  since: DateTime
}
```

In `config/schema/opencti.graphql`, inside `type Connector implements BasicObject & InternalObject { ... }`, after `jwks: String!`:

```graphql
  ingestion_health: IngestionHealth @ff(flags: ["INGESTION_HEALTH"], softFail: true)
  ingestion_warnings: [IngestionCheck!] @ff(flags: ["INGESTION_HEALTH"], softFail: true)
```

- [ ] **Step 3: Write the resolver and register it**

`src/modules/ingestionHealth/ingestionHealth-resolver.ts`:

```ts
import type { IngestionCheck as GqlIngestionCheck, IngestionHealth as GqlIngestionHealth, Resolvers } from '../../generated/graphql';
import { type IngestionHealthConnector, resolveIngestionHealth, resolveIngestionWarnings } from './ingestionHealth-domain';

// Both fields carry @ff(flags: ["INGESTION_HEALTH"], softFail: true):
// with the flag off they resolve to null and these resolvers never run.
// The evaluator uses string unions where codegen emits TS enums with the same runtime values.
const ingestionHealthResolvers: Resolvers = {
  Connector: {
    // The manager cache only: no Redis on this field, polled by the deployed list
    ingestion_health: (connector) => {
      return resolveIngestionHealth(connector as unknown as IngestionHealthConnector) as unknown as GqlIngestionHealth | null;
    },
    ingestion_warnings: async (connector, _, context) => {
      return (await resolveIngestionWarnings(context, connector as unknown as IngestionHealthConnector)) as unknown as GqlIngestionCheck[] | null;
    },
  },
};

export default ingestionHealthResolvers;
```

`src/modules/ingestionHealth/ingestionHealth-graphql.ts`:

```ts
import { registerGraphqlSchema } from '../../graphql/schema';
import ingestionHealthTypeDefs from './ingestionHealth.graphql';
import ingestionHealthResolvers from './ingestionHealth-resolver';

registerGraphqlSchema({
  schema: ingestionHealthTypeDefs,
  resolver: ingestionHealthResolvers,
});
```

In `src/modules/index.ts`, after `import './dataSanity/dataSanity-graphql';`:

```ts
import './ingestionHealth/ingestionHealth-graphql';
```

- [ ] **Step 4: Regenerate the typings and the relay schema**

Run: `cd opencti-platform/opencti-graphql && yarn build:schema`
Expected: `src/generated/graphql.ts` and `../opencti-front/src/schema/relay.schema.graphql` now contain `IngestionHealth`, `IngestionCheck`, and the two fields on `Connector`.

- [ ] **Step 5: Type-check and lint**

Run: `cd opencti-platform/opencti-graphql && yarn check-ts && yarn lint`
Expected: no error

- [ ] **Step 6: Integration tests (local stack)**

Run with ES, Redis, RabbitMQ and MinIO started: `cd opencti-platform/opencti-graphql && yarn test:dev tests/03-integration/02-resolvers/connector-test.ts`
Expected: PASS, including the 3 new tests. With no local stack available, rely on the CI `test:ci-integration` job and say so in the PR.

- [ ] **Step 7: Commit**

```bash
git add opencti-platform/opencti-graphql/src/modules/ingestionHealth/ingestionHealth.graphql opencti-platform/opencti-graphql/src/modules/ingestionHealth/ingestionHealth-resolver.ts opencti-platform/opencti-graphql/src/modules/ingestionHealth/ingestionHealth-graphql.ts opencti-platform/opencti-graphql/src/modules/index.ts opencti-platform/opencti-graphql/config/schema/opencti.graphql opencti-platform/opencti-graphql/src/generated/graphql.ts opencti-platform/opencti-front/src/schema/relay.schema.graphql opencti-platform/opencti-graphql/tests/03-integration/02-resolvers/connector-test.ts
git commit -S -m "feat(ingestion-health): expose the connector health and configuration warnings in GraphQL (#18305)"
```

---

### Task 4: Cached attributes, `ingestionHealthManager`, observation cleanup

**Files:**
- Create: `opencti-platform/opencti-graphql/src/modules/ingestionHealth/ingestionHealth-attributes.ts`
- Create: `opencti-platform/opencti-graphql/src/manager/ingestionHealthManager.ts`
- Modify: `opencti-platform/opencti-graphql/src/modules/attributes/internalObject-registrationAttributes.ts` (`[ENTITY_TYPE_CONNECTOR]`, after `manager_upgrade_strategy`, ~line 363)
- Modify: `opencti-platform/opencti-graphql/src/manager/index.ts`
- Modify: `opencti-platform/opencti-graphql/src/domain/connector.ts` (`connectorDelete`, ~line 433)
- Modify: `opencti-platform/opencti-graphql/config/default.json` (after the `data_sanity_manager` block)
- Modify: `opencti-platform/opencti-graphql/config/test.json` (after the `ingestion_manager` block)
- Modify: `opencti-platform/opencti-front/lang/back/*.json` (9 files)
- Test: `opencti-platform/opencti-graphql/tests/01-unit/manager/ingestionHealthManager-test.ts`
- Test: `opencti-platform/opencti-graphql/tests/03-integration/02-resolvers/connector-test.ts` (`afterAll`, ~line 598)

**Interfaces:**
- Consumes (Tasks 1-2): `computeIngestionHealth`, `closePingsBoundSeconds`, `collectIngestionSources`, `IngestionSourceSnapshot`, `redisSetIngestionHealthObservation`, `redisDeleteIngestionHealthObservation`, `redisGetIngestionHealthObservation`, `redisGetIngestionHealthLastRun`, `redisSetIngestionHealthLastRun`, `INGESTION_HEALTH_STATUSES`, `INGESTION_HEALTH_FEATURE_FLAG`.
- Produces:
  - ES attributes on `Connector`, registered only when the flag is on:
    - `ingestion_health_status` (enum)
    - `ingestion_health_since` (date)
    - `ingestion_health_summary` (string)
    - `ingestion_health_checks` (JSON string)
  - `evaluateIngestionSource(context, source, now): Promise<boolean>`: saves the heartbeat observation when it changed, and returns `true` when the cache was written
  - `ingestionHealthHandler(): Promise<void>`
  - Manager id `INGESTION_HEALTH_MANAGER`, used by Task 6. Chunk 2 will hook its transition emission into `evaluateIngestionSource`.

- [ ] **Step 1: Write the failing unit tests**

`tests/01-unit/manager/ingestionHealthManager-test.ts`:

```ts
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../src/config/conf';
import { elReplace } from '../../../src/database/engine';
import { evaluateIngestionSource, ingestionHealthHandler } from '../../../src/manager/ingestionHealthManager';
import { collectIngestionSources } from '../../../src/modules/ingestionHealth/ingestionHealth-domain';
import {
  redisGetIngestionHealthLastRun,
  redisSetIngestionHealthLastRun,
  redisSetIngestionHealthObservation,
} from '../../../src/modules/ingestionHealth/ingestionHealth-redis';

vi.mock('../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  elReplace: vi.fn(),
}));
vi.mock('../../../src/modules/ingestionHealth/ingestionHealth-domain', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  collectIngestionSources: vi.fn(),
}));
vi.mock('../../../src/modules/ingestionHealth/ingestionHealth-redis', () => ({
  redisGetIngestionHealthObservation: vi.fn(),
  redisSetIngestionHealthObservation: vi.fn(),
  redisDeleteIngestionHealthObservation: vi.fn(),
  redisGetIngestionHealthLastRun: vi.fn(),
  redisSetIngestionHealthLastRun: vi.fn(),
}));

const NOW = new Date('2026-10-07T12:00:00.000Z');
const SINCE = '2026-10-07T10:05:00.000Z';
const LAST_SEEN = '2026-10-07T10:00:00.000Z';
const SUMMARY = `No ping received since ${LAST_SEEN}`;
const CHECKS = JSON.stringify([{ kind: 'runtime', code: 'NO_HEARTBEAT', severity: 'blocking', params: { last_seen: LAST_SEEN }, message: SUMMARY }]);
const heartbeat = { last_seen_at: LAST_SEEN, close_pings: 3 };
// A connector that pinged every 40 seconds and has been silent for 2 hours
const source = (id: string, cached: Record<string, unknown> = {}, previousHeartbeat: any = heartbeat, running = true) => ({
  connector: { _index: 'opencti_internal_objects-000001', internal_id: id, name: `Connector ${id}`, ...cached } as any,
  input: { running, run_and_terminate: false, last_seen_at: new Date(LAST_SEEN), pings_regularly: true },
  previous_heartbeat: previousHeartbeat,
  heartbeat,
});
const cachedCritical = { ingestion_health_status: 'critical', ingestion_health_since: SINCE, ingestion_health_summary: SUMMARY, ingestion_health_checks: CHECKS };

describe('Ingestion health manager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should cache the new verdict with only the ingestion health fields when the status changes', async () => {
    expect(await evaluateIngestionSource({} as any, source('a', { ingestion_health_status: 'unknown', ingestion_health_since: SINCE }), NOW)).toBe(true);
    // Only these four keys: updated_at is the heartbeat this manager measures, it must never move here
    expect(elReplace).toHaveBeenCalledWith(expect.anything(), 'opencti_internal_objects-000001', 'a', {
      doc: { ingestion_health_status: 'critical', ingestion_health_since: NOW.toISOString(), ingestion_health_summary: SUMMARY, ingestion_health_checks: CHECKS },
    });
  });

  it('should cache the verdict of a connector never evaluated before', async () => {
    expect(await evaluateIngestionSource({} as any, source('a'), NOW)).toBe(true);
  });

  it('should write nothing in the index when the status, the summary and the checks did not change', async () => {
    expect(await evaluateIngestionSource({} as any, source('a', cachedCritical), NOW)).toBe(false);
    expect(elReplace).not.toHaveBeenCalled();
  });

  it('should keep since when only the summary or the checks changed', async () => {
    // Stopped by a person while already stopped, the heartbeat being lost meanwhile
    const cachedStopped = { ingestion_health_status: 'stopped', ingestion_health_since: SINCE, ingestion_health_summary: 'Stopped by a user', ingestion_health_checks: '[]' };
    expect(await evaluateIngestionSource({} as any, source('a', cachedStopped, heartbeat, false), NOW)).toBe(true);
    expect(elReplace).toHaveBeenCalledWith(expect.anything(), 'opencti_internal_objects-000001', 'a', {
      doc: { ingestion_health_status: 'stopped', ingestion_health_since: SINCE, ingestion_health_summary: 'Stopped by a user', ingestion_health_checks: CHECKS },
    });
  });

  it('should save the heartbeat observation only when it changed', async () => {
    await evaluateIngestionSource({} as any, source('a', cachedCritical), NOW);
    expect(redisSetIngestionHealthObservation).not.toHaveBeenCalled();
    await evaluateIngestionSource({} as any, source('b', cachedCritical, null), NOW);
    expect(redisSetIngestionHealthObservation).toHaveBeenCalledWith('b', heartbeat);
  });

  it('should keep evaluating the other connectors when one fails', async () => {
    (collectIngestionSources as any).mockResolvedValue([source('a'), source('b')]);
    (elReplace as any).mockRejectedValueOnce(new Error('version conflict'));
    const warnSpy = vi.spyOn(logApp, 'warn');
    await ingestionHealthHandler();
    expect(elReplace).toHaveBeenCalledTimes(2);
    expect(warnSpy).toHaveBeenCalledWith('[OPENCTI-MODULE] Ingestion health evaluation error', expect.objectContaining({ id: 'a' }));
  });

  describe('blind periods of the manager itself', () => {
    beforeEach(() => {
      (collectIngestionSources as any).mockResolvedValue([]);
    });

    // The default period (config/default.json): 60 seconds, so a 120 seconds close-pings bound
    it('should not consider itself blind when its last full cycle started less than 120 seconds ago', async () => {
      (redisGetIngestionHealthLastRun as any).mockResolvedValue(new Date(Date.now() - 60 * 1000));
      await ingestionHealthHandler();
      expect(collectIngestionSources).toHaveBeenCalledWith(expect.anything(), { boundSeconds: 120, managerWasBlind: false });
    });

    it('should consider itself blind after more than 120 seconds without a full cycle, or with no trace of one', async () => {
      (redisGetIngestionHealthLastRun as any).mockResolvedValue(new Date(Date.now() - 5 * 60 * 1000));
      await ingestionHealthHandler();
      expect(collectIngestionSources).toHaveBeenLastCalledWith(expect.anything(), { boundSeconds: 120, managerWasBlind: true });
      (redisGetIngestionHealthLastRun as any).mockResolvedValue(null);
      await ingestionHealthHandler();
      expect(collectIngestionSources).toHaveBeenLastCalledWith(expect.anything(), { boundSeconds: 120, managerWasBlind: true });
    });

    it('should record the start time of a full cycle, and nothing for a cycle that could not list the connectors', async () => {
      await ingestionHealthHandler();
      expect(redisSetIngestionHealthLastRun).toHaveBeenCalledTimes(1);
      (collectIngestionSources as any).mockRejectedValueOnce(new Error('index unavailable'));
      await expect(ingestionHealthHandler()).rejects.toThrow('index unavailable');
      expect(redisSetIngestionHealthLastRun).toHaveBeenCalledTimes(1);
    });
  });
});
```

In `tests/03-integration/02-resolvers/connector-test.ts`:
- add the import: `import { redisGetIngestionHealthObservation, redisSetIngestionHealthObservation } from '../../../src/modules/ingestionHealth/ingestionHealth-redis';`
- in `afterAll`, before `// Delete the connector`:

```ts
  // The heartbeat observation of a connector must not outlive it
  await redisSetIngestionHealthObservation(TEST_CN_ID, { last_seen_at: null, close_pings: 0 });
```

- and at the end of `afterAll`:

```ts
  expect(await redisGetIngestionHealthObservation(TEST_CN_ID)).toBeNull();
```

- [ ] **Step 2: Run the unit tests and check they fail**

Run: `cd opencti-platform/opencti-graphql && yarn test:ci-unit tests/01-unit/manager/ingestionHealthManager-test.ts`
Expected: FAIL (`Failed to resolve import ".../ingestionHealthManager"`)

- [ ] **Step 3: Flagged cached attributes**

`src/modules/ingestionHealth/ingestionHealth-attributes.ts`:

```ts
import { INGESTION_HEALTH_FEATURE_FLAG } from '../../config/conf';
import type { AttributeDefinition } from '../../schema/attribute-definition';
import { INGESTION_HEALTH_STATUSES } from './ingestionHealth-types';

// Health cache, written by the ingestion health manager on change only (RFC 0001 §4.4).
// This is what the UI reads: the manager is the only evaluator.
// Not registered at all when the INGESTION_HEALTH feature flag is off.
export const ingestionHealthAttributes: AttributeDefinition[] = [
  {
    name: 'ingestion_health_status',
    label: 'Ingestion health status',
    type: 'string',
    format: 'enum',
    values: [...INGESTION_HEALTH_STATUSES],
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
    featureFlag: INGESTION_HEALTH_FEATURE_FLAG,
  },
  {
    name: 'ingestion_health_since',
    label: 'Ingestion health since',
    type: 'date',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: true,
    featureFlag: INGESTION_HEALTH_FEATURE_FLAG,
  },
  {
    name: 'ingestion_health_summary',
    label: 'Ingestion health summary',
    type: 'string',
    format: 'text',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: false,
    featureFlag: INGESTION_HEALTH_FEATURE_FLAG,
  },
  {
    // JSON array of IngestionCheck, like connector_state
    name: 'ingestion_health_checks',
    label: 'Ingestion health checks',
    type: 'string',
    format: 'json',
    mandatoryType: 'no',
    editDefault: false,
    multiple: false,
    upsert: false,
    isFilterable: false,
    featureFlag: INGESTION_HEALTH_FEATURE_FLAG,
  },
];
```

In `src/modules/attributes/internalObject-registrationAttributes.ts`:
- add the import with the others: `import { ingestionHealthAttributes } from '../ingestionHealth/ingestionHealth-attributes';`
- in `[ENTITY_TYPE_CONNECTOR]`, right after the `manager_upgrade_strategy` line and before `// endregion`:

```ts
    ...ingestionHealthAttributes,
```

- [ ] **Step 4: The manager**

`src/manager/ingestionHealthManager.ts`:

```ts
import conf, { booleanConf, INGESTION_HEALTH_FEATURE_FLAG, isFeatureEnabled, logApp } from '../config/conf';
import { elReplace } from '../database/engine';
import { closePingsBoundSeconds, computeIngestionHealth } from '../modules/ingestionHealth/ingestionHealth-checks';
import { collectIngestionSources, type IngestionSourceSnapshot } from '../modules/ingestionHealth/ingestionHealth-domain';
import {
  redisGetIngestionHealthLastRun,
  redisSetIngestionHealthLastRun,
  redisSetIngestionHealthObservation,
} from '../modules/ingestionHealth/ingestionHealth-redis';
import type { AuthContext } from '../types/user';
import { executionContext } from '../utils/access';
import { type ManagerDefinition, registerManager } from './managerModule';

const INGESTION_HEALTH_MANAGER_ID = 'INGESTION_HEALTH_MANAGER';
const INGESTION_HEALTH_MANAGER_CONTEXT = 'ingestion_health_manager';

const INGESTION_HEALTH_MANAGER_ENABLED = booleanConf('ingestion_health_manager:enabled', true);
const INGESTION_HEALTH_MANAGER_KEY = conf.get('ingestion_health_manager:lock_key') || 'ingestion_health_manager_lock';
const SCHEDULE_TIME = conf.get('ingestion_health_manager:interval') || 60000; // 1 minute
// Two pings seen by the manager count as close within 2 periods (never below 120 seconds):
// a longer period must not leave a connector pinging every 40 seconds unable to qualify
const CLOSE_PINGS_BOUND_SECONDS = closePingsBoundSeconds(SCHEDULE_TIME / 1000);

// Evaluate one source: remember its heartbeat, then, on a change only, refresh its cached health (RFC 0001 §4.4).
// This is the only place the health is evaluated: the UI reads this cache.
// The cache is written directly in the index on purpose: an entity update would move updated_at,
// which is the very heartbeat NO_HEARTBEAT measures, and would emit a stream event.
export const evaluateIngestionSource = async (context: AuthContext, source: IngestionSourceSnapshot, now: Date): Promise<boolean> => {
  const { connector, input, previous_heartbeat: previousHeartbeat, heartbeat } = source;
  if (JSON.stringify(previousHeartbeat) !== JSON.stringify(heartbeat)) {
    await redisSetIngestionHealthObservation(connector.internal_id, heartbeat);
  }
  const health = computeIngestionHealth(input, now);
  const checks = JSON.stringify(health.checks);
  const isStatusChanged = connector.ingestion_health_status !== health.status;
  if (!isStatusChanged && connector.ingestion_health_summary === health.summary && connector.ingestion_health_checks === checks) {
    return false;
  }
  const doc = {
    ingestion_health_status: health.status,
    // since tells when the status began, not when its explanation last changed
    ingestion_health_since: isStatusChanged ? now.toISOString() : (connector.ingestion_health_since ?? now.toISOString()),
    ingestion_health_summary: health.summary,
    ingestion_health_checks: checks,
  };
  await elReplace(context, connector._index, connector.internal_id, { doc });
  if (isStatusChanged) {
    logApp.info(`[OPENCTI-MODULE] Ingestion health of ${connector.name} is now ${health.status}`, {
      manager: INGESTION_HEALTH_MANAGER_ID,
      id: connector.internal_id,
      previous_status: connector.ingestion_health_status,
      summary: health.summary,
    });
  }
  return true;
};

export const ingestionHealthHandler = async () => {
  const context = executionContext(INGESTION_HEALTH_MANAGER_CONTEXT);
  const now = new Date();
  // Blind for a while (platform restart, lost lock...), or never run: a wide gap between two pings
  // is then the manager not looking, not the connector being irregular
  const lastRun = await redisGetIngestionHealthLastRun();
  const managerWasBlind = !lastRun || (now.getTime() - lastRun.getTime()) / 1000 > CLOSE_PINGS_BOUND_SECONDS;
  const sources = await collectIngestionSources(context, { boundSeconds: CLOSE_PINGS_BOUND_SECONDS, managerWasBlind });
  for (let i = 0; i < sources.length; i += 1) {
    try {
      await evaluateIngestionSource(context, sources[i], now);
    } catch (e) {
      logApp.warn('[OPENCTI-MODULE] Ingestion health evaluation error', { cause: e, manager: INGESTION_HEALTH_MANAGER_ID, id: sources[i].connector.internal_id });
    }
  }
  // Only a cycle that listed the connectors counts as a look. Its start time is recorded,
  // so the next cycle compares start with start
  await redisSetIngestionHealthLastRun(now);
};

const INGESTION_HEALTH_MANAGER_DEFINITION: ManagerDefinition = {
  id: INGESTION_HEALTH_MANAGER_ID,
  label: 'Ingestion health manager',
  executionContext: INGESTION_HEALTH_MANAGER_CONTEXT,
  cronSchedulerHandler: {
    handler: ingestionHealthHandler,
    interval: SCHEDULE_TIME,
    lockKey: INGESTION_HEALTH_MANAGER_KEY,
  },
  enabledByConfig: INGESTION_HEALTH_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

// Own lock and own manager on purpose: a watchdog must not share a lock with what it watches (RFC 0001 §11.1)
if (isFeatureEnabled(INGESTION_HEALTH_FEATURE_FLAG)) {
  registerManager(INGESTION_HEALTH_MANAGER_DEFINITION);
}
```

In `src/manager/index.ts`, alphabetically after `import './indicatorDecayManager';`:

```ts
import './ingestionHealthManager';
```

In `config/default.json`, after the `"data_sanity_manager": { ... },` block:

```json
  "ingestion_health_manager": {
    "enabled": true,
    "lock_key": "ingestion_health_manager_lock",
    "interval": 60000
  },
```

`interval` is the manager period in ms, 60 s by default. The close-pings bound and the blind threshold follow it (see `CLOSE_PINGS_BOUND_SECONDS`).

In `config/test.json`, right after the `"ingestion_manager": { "enabled": false },` block:

```json
  "ingestion_health_manager": {
    "enabled": false
  },
```

`test.json` turns every flag on (`"*"`). Without this block, the manager would run every 60 s during the integration suite, writing `ingestion_health_*` fields and Redis keys on the test connectors whenever its timing allows. That can make an existing test comparing connector documents fail at random. The manager is covered by its unit tests; the end-to-end check is the manual run of Task 7.

- [ ] **Step 5: Delete the observation with the connector**

In `src/domain/connector.ts`:
- extend the conf import: `import { BUS_TOPICS, INGESTION_HEALTH_FEATURE_FLAG, isFeatureEnabled, logApp, PLATFORM_VERSION } from '../config/conf';`
- add the import: `import { redisDeleteIngestionHealthObservation } from '../modules/ingestionHealth/ingestionHealth-redis';`
- in `connectorDelete`, right after `await unregisterConnector(connectorId);`:

```ts
  if (isFeatureEnabled(INGESTION_HEALTH_FEATURE_FLAG)) {
    // The ingestion health observation has no TTL, it lives as long as its connector
    await redisDeleteIngestionHealthObservation(connectorId);
  }
```

- [ ] **Step 6: Backend label translations**

Add these 5 keys to each `opencti-platform/opencti-front/lang/back/<lang>.json`:

| lang | `Ingestion health manager` | `Ingestion health status` | `Ingestion health since` | `Ingestion health summary` | `Ingestion health checks` |
|---|---|---|---|---|---|
| en | Ingestion health manager | Ingestion health status | Ingestion health since | Ingestion health summary | Ingestion health checks |
| fr | Gestionnaire de santé de l'ingestion | État de santé de l'ingestion | Santé de l'ingestion depuis | Résumé de la santé de l'ingestion | Contrôles de santé de l'ingestion |
| de | Ingestion-Health-Manager | Ingestion-Health-Status | Ingestion-Health seit | Ingestion-Health-Zusammenfassung | Ingestion-Health-Prüfungen |
| es | Gestor de salud de la ingesta | Estado de salud de la ingesta | Salud de la ingesta desde | Resumen de la salud de la ingesta | Comprobaciones de salud de la ingesta |
| it | Gestore dello stato di salute dell'ingestione | Stato di salute dell'ingestione | Stato di salute dell'ingestione dal | Riepilogo dello stato di salute dell'ingestione | Controlli dello stato di salute dell'ingestione |
| ja | 取り込みヘルスマネージャー | 取り込みヘルスステータス | 取り込みヘルスの開始日時 | 取り込みヘルスの概要 | 取り込みヘルスチェック |
| ko | 수집 상태 관리자 | 수집 상태 | 수집 상태 시작 시각 | 수집 상태 요약 | 수집 상태 점검 |
| ru | Менеджер состояния загрузки | Состояние загрузки | Состояние загрузки с | Сводка состояния загрузки | Проверки состояния загрузки |
| zh | 采集健康管理器 | 采集健康状态 | 采集健康状态起始时间 | 采集健康摘要 | 采集健康检查 |

Then: `cd opencti-platform/opencti-front && yarn sort-translation`

- [ ] **Step 7: Run the tests and check they pass**

Run: `cd opencti-platform/opencti-graphql && yarn test:ci-unit tests/01-unit/manager/ingestionHealthManager-test.ts tests/01-unit/modules/ingestionHealth`
Expected: PASS (9 + 26 + 13 tests)

Then, with the local stack: `yarn test:dev tests/03-integration/02-resolvers/connector-test.ts`
Expected: PASS, including the `afterAll` cleanup assertion.

- [ ] **Step 8: Type-check and lint**

Run: `cd opencti-platform/opencti-graphql && yarn check-ts && yarn lint`
Expected: no error

- [ ] **Step 9: Commit**

```bash
git add opencti-platform/opencti-graphql/src/modules/ingestionHealth/ingestionHealth-attributes.ts opencti-platform/opencti-graphql/src/manager/ingestionHealthManager.ts opencti-platform/opencti-graphql/src/modules/attributes/internalObject-registrationAttributes.ts opencti-platform/opencti-graphql/src/manager/index.ts opencti-platform/opencti-graphql/src/domain/connector.ts opencti-platform/opencti-graphql/config/default.json opencti-platform/opencti-graphql/config/test.json opencti-platform/opencti-front/lang/back opencti-platform/opencti-graphql/tests/01-unit/manager/ingestionHealthManager-test.ts opencti-platform/opencti-graphql/tests/03-integration/02-resolvers/connector-test.ts
git commit -S -m "feat(ingestion-health): observe connector heartbeats and cache their health with a dedicated manager (#18305)"
```

---

### Task 5: Front — health chip in Integrations › Deployed (lines and cards)

**Files:**
- Create: `opencti-platform/opencti-front/src/private/components/data/connectors/IngestionHealthChip.tsx`
- Test: `opencti-platform/opencti-front/src/private/components/data/connectors/IngestionHealthChip.test.tsx`
- Modify: `opencti-platform/opencti-front/src/private/components/data/connectors/ConnectorsState.tsx`
- Modify: `opencti-platform/opencti-front/src/private/components/integrations/deployed/useDeployedIntegrations.ts` (+ `useDeployedIntegrations.test.ts`)
- Modify: `opencti-platform/opencti-front/src/private/components/integrations/deployed/DeployedIntegrationLine.tsx` (+ `DeployedIntegrationLine.test.tsx`)
- Modify: `opencti-platform/opencti-front/src/private/components/integrations/deployed/DeployedIntegrationCard.tsx`

**Interfaces:**
- Consumes (Task 3): `Connector.ingestion_health { status summary }`.
- Produces:
  - `IngestionHealthChip`, default export, props `{ status: string; summary: string; since?: string | null; details?: ReadonlyArray<string> }`
  - `DeployedIntegrationItem.health?: { status: string; summary: string } | null`

- [ ] **Step 1: Write the failing chip tests**

`src/private/components/data/connectors/IngestionHealthChip.test.tsx`:

```tsx
import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import IngestionHealthChip from './IngestionHealthChip';

describe('IngestionHealthChip', () => {
  it('shows the translated status', () => {
    testRender(<IngestionHealthChip status="critical" summary="No ping received since 2026-10-07T10:00:00.000Z" />);
    expect(screen.getByText('Critical')).toBeInTheDocument();
  });

  it('falls back to Unknown on a status this front does not know yet', () => {
    testRender(<IngestionHealthChip status="%future added value" summary="Something" />);
    expect(screen.getByText('Unknown')).toBeInTheDocument();
  });

  it('shows the server summary and every detail line in its tooltip', async () => {
    const { user } = testRender(
      <IngestionHealthChip status="unknown" summary="Pinging every 40 seconds, data intake not evaluated yet" details={['⚠ User is not a service account']} />,
    );
    await user.hover(screen.getByText('Unknown'));
    expect((await screen.findAllByText('Pinging every 40 seconds, data intake not evaluated yet')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('⚠ User is not a service account')).length).toBeGreaterThan(0);
  });
});
```

`testRender` already mounts the FDS `TooltipProvider` (`src/utils/tests/test-render.tsx:94`). If `hover` does not open the Radix tooltip in jsdom, replace it with `await user.tab()`: the chip is focusable through `tabIndex={0}`, and Radix also opens on focus.

- [ ] **Step 2: Run and check it fails**

Run: `cd opencti-platform/opencti-front && yarn vitest run src/private/components/data/connectors/IngestionHealthChip.test.tsx`
Expected: FAIL (`Failed to resolve import "./IngestionHealthChip"`)

- [ ] **Step 3: Implement the chip**

`src/private/components/data/connectors/IngestionHealthChip.tsx`:

```tsx
import React from 'react';
import { Chip, type ChipSeverity, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';

export interface IngestionHealthChipProps {
  status: string;
  // Server English sentence, displayed as is
  summary: string;
  since?: string | null;
  // Extra server English lines: runtime checks, configuration warnings
  details?: ReadonlyArray<string>;
}

const severityOf = (status: string): ChipSeverity => {
  switch (status) {
    case 'critical':
      return 'critical';
    case 'degraded':
      return 'medium';
    case 'healthy':
      return 'low';
    default: // unknown, stopped, idle
      return 'neutral';
  }
};

// Runtime health of an ingestion source (RFC 0001), the summary and details in the tooltip
const IngestionHealthChip = ({ status, summary, since, details = [] }: IngestionHealthChipProps) => {
  const { t_i18n, nsdt } = useFormatter();
  const label = (() => {
    switch (status) {
      case 'healthy':
        return t_i18n('Healthy');
      case 'idle':
        return t_i18n('Idle');
      case 'degraded':
        return t_i18n('Degraded');
      case 'critical':
        return t_i18n('Critical');
      case 'stopped':
        return t_i18n('Stopped');
      default:
        return t_i18n('Unknown');
    }
  })();
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Chip label={label} severity={severityOf(status)} tabIndex={0} data-testid="ingestion-health-chip" />
      </TooltipTrigger>
      <TooltipContent>
        <div>{summary}</div>
        {since && <div>{`${t_i18n('Since')} ${nsdt(since)}`}</div>}
        {details.map((line) => <div key={line}>{line}</div>)}
      </TooltipContent>
    </Tooltip>
  );
};

export default IngestionHealthChip;
```

- [ ] **Step 4: Run and check it passes**

Run: `cd opencti-platform/opencti-front && yarn vitest run src/private/components/data/connectors/IngestionHealthChip.test.tsx`
Expected: PASS (3 tests)

- [ ] **Step 5: Add the field to the polled list query**

In `src/private/components/data/connectors/ConnectorsState.tsx`, in `query ConnectorsStateQuery { connectors { ... } }`, after `manager_requested_status`:

```graphql
      ingestion_health {
        status
        summary
      }
```

Then: `cd opencti-platform/opencti-front && yarn relay`

- [ ] **Step 6: Write the failing list tests**

In `src/private/components/integrations/deployed/useDeployedIntegrations.test.ts`, add inside the main `describe` (reusing `renderIntegrations`, `makeConnector` and `makeState`):

```ts
  it('carries the connector ingestion health from the polled state', () => {
    const health = { status: 'critical', summary: 'No ping received since 2026-10-07T10:00:00.000Z' };
    const { result } = renderIntegrations({ connectors: [makeConnector()], states: [makeState({ ingestion_health: health })] });
    expect(result.current[0].health).toEqual(health);
  });

  it('has no ingestion health when the flag is off or the connector is not evaluated', () => {
    const { result } = renderIntegrations({ connectors: [makeConnector()], states: [makeState({ ingestion_health: null })] });
    expect(result.current[0].health).toBeNull();
  });
```

In `src/private/components/integrations/deployed/DeployedIntegrationLine.test.tsx`, add:

```tsx
  it('shows no health chip when there is no ingestion health', () => {
    testRender(<DeployedIntegrationLine item={item} onChange={vi.fn()} />, { route: '/dashboard/integrations/deployed' });
    expect(screen.queryByTestId('ingestion-health-chip')).toBeNull();
  });

  it('shows the health chip next to the status', () => {
    const withHealth = { ...item, health: { status: 'critical', summary: 'No ping received since 2026-10-07T10:00:00.000Z' } };
    testRender(<DeployedIntegrationLine item={withHealth} onChange={vi.fn()} />, { route: '/dashboard/integrations/deployed' });
    expect(screen.getByTestId('ingestion-health-chip')).toHaveTextContent('Critical');
  });
```

- [ ] **Step 7: Run and check they fail**

Run: `cd opencti-platform/opencti-front && yarn vitest run src/private/components/integrations/deployed/useDeployedIntegrations.test.ts src/private/components/integrations/deployed/DeployedIntegrationLine.test.tsx`
Expected: FAIL. `health` is `undefined`, and no element has `data-testid="ingestion-health-chip"`.

- [ ] **Step 8: Carry the health on the item, render it in line and card**

In `useDeployedIntegrations.ts`:
- in `interface DeployedIntegrationItem`, after `statusLabel: string;`:

```ts
  // Runtime ingestion health (RFC 0001), connectors only, null when INGESTION_HEALTH is off
  health?: { status: string; summary: string } | null;
```

- in the connector loop, in `items.push({ ... })`, after `statusLabel: label,`:

```ts
        health: state?.ingestion_health ?? null,
```

In `DeployedIntegrationLine.tsx`:
- import: `import IngestionHealthChip from '@components/data/connectors/IngestionHealthChip';`
- in the status column `<Stack direction="column" alignItems="flex-start" gap={0.5}>`, after the `ItemBoolean` ternary:

```tsx
          {item.health && <IngestionHealthChip status={item.health.status} summary={item.health.summary} />}
```

In `DeployedIntegrationCard.tsx`:
- add the same import;
- in `<Stack direction="column" alignItems="flex-end" gap={0.75} ...>`, after `{statusChip}`:

```tsx
            {item.health && <IngestionHealthChip status={item.health.status} summary={item.health.summary} />}
```

- [ ] **Step 9: Run and check they pass**

Run: `cd opencti-platform/opencti-front && yarn vitest run src/private/components/data/connectors/IngestionHealthChip.test.tsx src/private/components/integrations/deployed`
Expected: PASS, both the new and the existing tests

- [ ] **Step 10: Lint, types, FDS gate**

Run:
```bash
cd opencti-platform/opencti-front && yarn lint && yarn check-ts
cd ../.. && node fds-migration/scripts/check-mui-regression.mjs && node fds-migration/scripts/check-fds-conformity.mjs
```
Expected: all green, with no new MUI `Chip`/`Tooltip` import.

- [ ] **Step 11: Commit**

```bash
git add opencti-platform/opencti-front/src/private/components/data/connectors/IngestionHealthChip.tsx opencti-platform/opencti-front/src/private/components/data/connectors/IngestionHealthChip.test.tsx opencti-platform/opencti-front/src/private/components/data/connectors/ConnectorsState.tsx opencti-platform/opencti-front/src/private/components/data/connectors/__generated__ opencti-platform/opencti-front/src/private/components/integrations/deployed
git commit -S -m "feat(ingestion-health): show the connector health in the deployed integrations (#18305)"
```

---

### Task 6: Front — connector detail page and managers settings

**Files:**
- Modify: `opencti-platform/opencti-front/src/private/components/data/connectors/Connector.tsx` (fragment `Connector_connector` ~line 1060; title area ~line 977)
- Modify: `opencti-platform/opencti-front/src/private/components/data/connectors/Connector.test.tsx`
- Modify: `opencti-platform/opencti-front/src/private/components/settings/settings_managers/settingsManagersUtils.ts` (`DOMAIN_BY_MANAGER`, ~line 69)
- Modify: `opencti-platform/opencti-front/src/private/components/settings/settings_managers/settingsManagersUtils.test.ts` (~line 153)
- Modify: `opencti-platform/opencti-front/lang/front/*.json` (9 files)

**Interfaces:**
- Consumes:
  - `IngestionHealthChip` (Task 5);
  - `Connector.ingestion_health { status summary since checks { message } }` and `Connector.ingestion_warnings { message }` (Task 3);
  - manager id `INGESTION_HEALTH_MANAGER` (Task 4).
- Produces: nothing for later tasks.

- [ ] **Step 1: Write the failing detail tests**

In `Connector.test.tsx`, inside `describe('Connector', ...)`, reusing `ConnectorTestWrapper`, `baseMockConnector` and the same `testRender` setup as the existing tests:

```tsx
  it('should display the ingestion health chip with its details in the tooltip', async () => {
    const { relayEnv, user } = testRender(<ConnectorTestWrapper connectorId="connector-id" />, {
      userContext: createMockUserContext({
        schema: { scos: [], sdos: [], smos: [], scrs: [], schemaRelationsTypesMapping: new Map(), schemaRelationsRefTypesMapping: new Map(), filterKeysSchema: new Map() },
      }),
    });
    await waitFor(() => {
      relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
        Connector: () => ({
          ...baseMockConnector,
          ingestion_health: { status: 'critical', summary: 'No ping received since 2026-10-07T10:00:00.000Z', since: null, checks: [{ message: 'No ping received since 2026-10-07T10:00:00.000Z' }] },
          ingestion_warnings: [{ message: 'User is not a service account' }],
        }),
      }));
    });
    const chip = await screen.findByTestId('ingestion-health-chip');
    expect(chip).toHaveTextContent('Critical');
    await user.hover(chip);
    expect((await screen.findAllByText('⚠ User is not a service account')).length).toBeGreaterThan(0);
  });

  it('should display no ingestion health chip when the flag is off', async () => {
    const { relayEnv } = testRender(<ConnectorTestWrapper connectorId="connector-id" />, {
      userContext: createMockUserContext({
        schema: { scos: [], sdos: [], smos: [], scrs: [], schemaRelationsTypesMapping: new Map(), schemaRelationsRefTypesMapping: new Map(), filterKeysSchema: new Map() },
      }),
    });
    await waitFor(() => {
      relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
        Connector: () => ({ ...baseMockConnector, ingestion_health: null, ingestion_warnings: null }),
      }));
    });
    await waitFor(() => expect(screen.getByText('State')).toBeTruthy());
    expect(screen.queryByTestId('ingestion-health-chip')).toBeNull();
  });
```

In `settingsManagersUtils.test.ts`, in the manager id list (~line 153), insert `'INGESTION_HEALTH_MANAGER',` between `'INDICATOR_DEPLOYMENT_MANAGER',` and `'INGESTION_MANAGER',`.

- [ ] **Step 2: Run and check they fail**

Run: `cd opencti-platform/opencti-front && yarn vitest run src/private/components/data/connectors/Connector.test.tsx src/private/components/settings/settings_managers/settingsManagersUtils.test.ts`
Expected: FAIL. There is no chip yet, and `INGESTION_HEALTH_MANAGER` lands in the `other` domain.

- [ ] **Step 3: Fragment and rendering**

In `Connector.tsx`, in `fragment Connector_connector on Connector { ... }`, after `built_in`:

```graphql
        ingestion_health {
          status
          summary
          since
          checks {
            message
          }
        }
        ingestion_warnings {
          message
        }
```

Import: `import IngestionHealthChip from '@components/data/connectors/IngestionHealthChip';`

In the title, right after the block `<div style={{ display: 'inline-block', flexShrink: 0 }}><ConnectorStatusChip connector={connector} /></div>`:

```tsx
              {connector.ingestion_health && (
                <div style={{ display: 'inline-block', flexShrink: 0 }}>
                  <IngestionHealthChip
                    status={connector.ingestion_health.status}
                    summary={connector.ingestion_health.summary}
                    since={connector.ingestion_health.since}
                    details={[
                      // The headline check is already the summary
                      ...connector.ingestion_health.checks.map((check) => check.message).filter((message) => message !== connector.ingestion_health?.summary),
                      ...(connector.ingestion_warnings ?? []).map((warning) => `⚠ ${warning.message}`),
                    ]}
                  />
                </div>
              )}
```

The page already refetches every 5 s (`Connector.tsx:257`), so the chip shows the manager's last verdict within 5 s.

In `settingsManagersUtils.ts`, in `DOMAIN_BY_MANAGER`, after `INGESTION_MANAGER: 'ingestion',`:

```ts
  INGESTION_HEALTH_MANAGER: 'ingestion',
```

- [ ] **Step 4: Front translations**

Add `"INGESTION_HEALTH_MANAGER"` to each `lang/front/<lang>.json`, using the « Ingestion health manager » value from the Task 4 table (en: `Ingestion health manager`, fr: `Gestionnaire de santé de l'ingestion`, …). The other keys already exist: `Critical`, `Unknown`, `Stopped`, `Healthy`, `Idle`, `Degraded`, `Since`. Then:

```bash
cd opencti-platform/opencti-front && yarn relay && yarn sort-translation && yarn verify-translation
```
Expected: no missing translation, front or back.

- [ ] **Step 5: Run and check they pass**

Run: `cd opencti-platform/opencti-front && yarn vitest run src/private/components/data/connectors src/private/components/settings/settings_managers`
Expected: PASS

- [ ] **Step 6: Lint, types, FDS gate**

Run:
```bash
cd opencti-platform/opencti-front && yarn lint && yarn check-ts
cd ../.. && node fds-migration/scripts/check-mui-regression.mjs && node fds-migration/scripts/check-fds-conformity.mjs
```
Expected: all green

- [ ] **Step 7: Commit**

```bash
git add opencti-platform/opencti-front/src/private/components/data/connectors opencti-platform/opencti-front/src/private/components/settings/settings_managers opencti-platform/opencti-front/lang/front
git commit -S -m "feat(ingestion-health): show the connector health and warnings on the connector page (#18305)"
```

---

### Task 7: End-to-end check, PR, RFC

**Files:** none in the repo. `config/development.json` is local and never committed.

- [ ] **Step 1: Full gates**

```bash
cd opencti-platform/opencti-graphql && yarn test:ci-unit && yarn check-ts && yarn lint
cd ../opencti-front && yarn test && yarn check-ts && yarn lint && yarn verify-translation
cd ../.. && node fds-migration/scripts/check-mui-regression.mjs && node fds-migration/scripts/check-fds-conformity.mjs
```
Expected: all green.

- [ ] **Step 2: Flag OFF, nothing changes**

Start the platform without the flag.
Expected:
- `{ connectors { id ingestion_health { status } ingestion_warnings { code } } }` returns `null` for both fields, with no error;
- no health chip, neither in the list nor on the connector page;
- no `INGESTION_HEALTH_MANAGER` in Settings › Parameters;
- no `ingestion_health_*` field in the mapping of `opencti_internal_objects*`;
- no `ingestion-health-observation:*` key and no `ingestion-health-manager-last-run` key in Redis.

- [ ] **Step 3: Flag ON, live connector**

Set `"app": { "enabled_dev_features": ["INGESTION_HEALTH"] }` in `config/development.json` (or `APP__ENABLED_DEV_FEATURES='["INGESTION_HEALTH"]'`). Restart, then run a self-hosted pycti connector with a personal user.
Expected:
- before the first manager cycle, the list and the page show a neutral « Unknown » chip with « Not evaluated yet » in the tooltip;
- after the first cycle, the tooltip says « No ping every 40 seconds observed, heartbeat not evaluated »;
- after about 4 cycles, the key `ingestion-health-observation:<id>` holds `close_pings: 3`, and the tooltip says « Pinging every 40 seconds, data intake not evaluated yet »;
- on the page only, the tooltip also shows « ⚠ User is not a service account », with no user name;
- the Deployed list makes no Redis call: run `redis-cli MONITOR` while the list is open, and no `ingestion-health-observation` read appears between two manager cycles;
- « Last seen » (`updated_at`) keeps following the pings only.

- [ ] **Step 4: Flag ON, dead connector**

Stop the connector process.
Expected:
- after 5 min, « Inactive » appears; the red « Critical » chip follows at the next manager cycle (at most one period later, 60 s by default, plus the 5 s poll), with « No ping received since … » in the tooltip;
- the log shows `Ingestion health of <name> is now critical`, and « Since … » appears on the page;
- after the connector restarts, the chip goes back to « Unknown » at the next manager cycle: its first ping comes long after the last one, so the count restarts from 0.

Manager outage: with a connector showing « Pinging every 40 seconds », stop the platform for 3 min while the connector keeps running, restart the platform, then stop the connector. Expected: the chip turns red 5 min after the last ping, as without the outage, and `ingestion-health-manager-last-run` holds the start time of the latest full cycle.

Longer period: set `ingestion_health_manager:interval` to `300000`, restart, and run a live pycti connector. Expected: it reaches `close_pings: 3` after about 3 cycles (15 min), then stopping it still turns the chip red, at most 5 min after « Inactive ».

A managed connector stopped from the UI shows « Stopped » at the next manager cycle. Switching its user to a service account makes the warning disappear without a restart (user cache).

- [ ] **Step 5: Flag ON, legacy run-and-terminate connector**

Run a connector that handles run-and-terminate the legacy way (e.g. `external-import/cape` with `CONNECTOR_RUN_AND_TERMINATE=true`). Let one run last 1 to 3 min, then restart it more than 5 min later.
Expected: it is always « Unknown », never « Critical », including between the two runs. Its observation never goes above `close_pings: 2`.

- [ ] **Step 6: Open the PR**

Title: `feat(ingestion-health): preparation of connector health monitoring (#18305)`, linked to #18305. Description:
- the flag name and how to enable it;
- the scope decisions table of this plan;
- « never healthy in chunk 1 »;
- the 5 min threshold aligned on Active/Inactive, and the « pings every 40 s » condition (3 pings within max(120 s, 2 periods)) with its legacy run-and-terminate motivation, and the configurable period (60 s by default);
- the UI reads the manager cache, with no Redis on the read path, and lags Active/Inactive by up to one manager cycle;
- the accepted risks section of this plan, the `updated_at` warning first;
- the authentication path is not modified;
- screenshots of the list and the page.

- [ ] **Step 7: RFC update and follow-ups**

- Open an RFC 0001 update (PR on `filigran-private`) stating the chunk 1 gaps:
  - every deployed connector whatever its type, but no feed and no sync yet;
  - `unknown` instead of `healthy` for a connector that pings;
  - a single configuration warning (service account) instead of three, with `TOKEN_EXPIRED` not shipped;
  - a heartbeat threshold of 5 min aligned on `isConnectorActive`. The RFC gives no number, and the POC used 10 min;
  - `NO_HEARTBEAT` limited to connectors seen pinging every 40 s (3 pings within max(120 s, 2 manager periods)), with the observation kept in Redis;
  - the manager is the only evaluator, and the UI reads its cache (status, since, summary, checks).
- Open four issues:
  1. `TOKEN_EXPIRED`: the token a connector actually uses cannot be identified without touching authentication. A read-only heuristic on `{token_usage}:<tokenId>` is possible.
  2. A probable bug, inferred from the code and still to be checked: two managed connectors from different catalogs sharing one user revoke each other's composer token (`src/database/repository.js:133-141`).
  3. A dedicated ping timestamp, so that an edit or a composer status report no longer counts as a ping (the accepted `updated_at` risk).
  4. Make sure the Redis observation of a deleted connector is gone for good: a manager cycle running while the connector is deleted can write it again right after `connectorDelete` removed it, leaving an orphan key with no TTL.
- Tick the Chunk 1 items on the Notion page.
