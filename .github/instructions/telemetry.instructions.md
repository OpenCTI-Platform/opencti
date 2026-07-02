# Adding a New Telemetry Metric

## Scope
This guide covers adding a new usage telemetry metric to the OpenCTI platform (anonymous product analytics sent to Filigran).

## Code Review — Documentation Completeness Check

When reviewing a PR that touches telemetry files, **always verify that every registered metric is documented** in `docs/docs/reference/usage-telemetry.md`.

### Detection Rule

If a PR adds or modifies any of the following, flag it for missing documentation:

1. **A new `this.registerGauge(...)` call** in `TelemetryMeterManager.ts` → the metric MUST have a corresponding entry in `docs/docs/reference/usage-telemetry.md`.
2. **A new `TELEMETRY_GAUGE_*` constant** in `telemetryManager.ts` → same requirement.
3. **A new property ending in `Count` or starting with `is`** in `TelemetryMeterManager.ts` → same requirement.

### How to Check

- Open `docs/docs/reference/usage-telemetry.md` and search for a description matching the new metric.
- The documentation entry should describe **what** is measured in plain language (not the technical gauge name).
- If the metric is not listed, request the author to add it in the appropriate section of the documentation page.

### Review Comment Template

If a metric is missing from the documentation, leave the following comment:

> ⚠️ **Missing telemetry documentation** — The new metric `<gauge_name>` registered in `TelemetryMeterManager.ts` is not documented in `docs/docs/reference/usage-telemetry.md`. Every telemetry metric must be listed there so users know what data is collected. Please add a description in the appropriate section.

**Key files:**
- `src/telemetry/TelemetryMeterManager.ts` — Gauge definitions and state
- `src/manager/telemetryManager.ts` — Redis event constants, helper functions, data fetching, and gauge registration
- `src/database/redis.ts` — Low-level Redis telemetry storage (`redisSetTelemetryAdd`, `redisGetTelemetry`)

## Two Types of Metrics

There are two distinct patterns depending on **how** the metric value is produced:

| Type | Description | Example |
|------|-------------|---------|
| **Event counter (Redis-based)** | Incremented in real-time from business logic; stored in Redis and read periodically by the telemetry manager. | `userLoginCount`, `draftCreationCount`, `nlqQueryCount` |
| **Computed gauge (query-based)** | Calculated at each telemetry manager run by querying the database or cache directly. | `usersCount`, `activeConnectorsCount`, `draftCount`, `pirCount` |

---

## Case A — Event Counter (Redis-based)

Use this pattern when the metric tracks **occurrences of an action** (e.g., user logs in, draft is created, email is sent).

### A.1. Add the counter property in `TelemetryMeterManager.ts`

Add a new numeric property (initialized to `0`) with a descriptive comment:

```typescript
// Number of <describe what is counted>
myNewFeatureCount = 0;
```

### A.2. Add the setter method in `TelemetryMeterManager.ts`

Add a setter following the existing naming convention (`set<PropertyName>`):

```typescript
setMyNewFeatureCount(n: number) {
  this.myNewFeatureCount = n;
}
```

### A.3. Register the gauge in `registerFiligranTelemetry()` (same file)

Call `this.registerGauge(...)` with:
- **name**: snake_case metric name (prefixed automatically with `opencti_`)
- **description**: human-readable description
- **observer**: the property name (string) that holds the value

```typescript
this.registerGauge('my_new_feature_count', 'Number of new feature usages', 'myNewFeatureCount');
```

### A.4. Declare the Redis telemetry key in `telemetryManager.ts`

Add an exported constant for the Redis key:

```typescript
export const TELEMETRY_GAUGE_MY_NEW_FEATURE = 'myNewFeatureCount';
```

### A.5. Create the increment helper function in `telemetryManager.ts`

Export an async function that increments the counter in Redis:

```typescript
export const addMyNewFeatureCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_GAUGE_MY_NEW_FEATURE, 1);
};
```

### A.6. Fetch the value from Redis in `fetchTelemetryData()`

In the `fetchTelemetryData` function (same file), read the Redis value and set it on the manager:

```typescript
const myNewFeatureCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_MY_NEW_FEATURE);
manager.setMyNewFeatureCount(myNewFeatureCountInRedis);
```

### A.7. Call the helper from business logic

Import and call the increment helper wherever the tracked event occurs:

```typescript
import { addMyNewFeatureCount } from '../../manager/telemetryManager';

// Inside the relevant function:
await addMyNewFeatureCount();
```

### Summary Checklist (Event Counter)

| # | File | Action |
|---|------|--------|
| 1 | `TelemetryMeterManager.ts` | Add counter property (initialized to `0`) |
| 2 | `TelemetryMeterManager.ts` | Add setter method |
| 3 | `TelemetryMeterManager.ts` | Register gauge in `registerFiligranTelemetry()` |
| 4 | `telemetryManager.ts` | Add `TELEMETRY_GAUGE_*` constant |
| 5 | `telemetryManager.ts` | Add exported increment helper (`add*Count`) |
| 6 | `telemetryManager.ts` | Read from Redis and set on manager in `fetchTelemetryData()` |
| 7 | Business logic file | Import and call the increment helper |

---

## Case B — Computed Gauge (Query-based)

Use this pattern when the metric reflects a **current state** that can be computed by querying the database or cache (e.g., number of users, active connectors, active drafts).

### B.1. Add the counter property in `TelemetryMeterManager.ts`

Add a new numeric property (initialized to `0`) with a descriptive comment:

```typescript
// Number of <describe what is counted>
myEntityCount = 0;
```

### B.2. Add the setter method in `TelemetryMeterManager.ts`

```typescript
setMyEntityCount(n: number) {
  this.myEntityCount = n;
}
```

### B.3. Register the gauge in `registerFiligranTelemetry()` (same file)

```typescript
this.registerGauge('my_entity_count', 'Number of my entities', 'myEntityCount');
```

For boolean-like gauges (0 or 1), use:
```typescript
this.registerGauge('is_my_feature_enabled', 'Whether my feature is enabled', 'isMyFeatureEnabled', { unit: 'boolean' });
```

### B.4. Compute and set the value in `fetchTelemetryData()` (`telemetryManager.ts`)

Directly query the database/cache and set the value on the manager.

```typescript
// Example using cache
const myEntities = await getEntitiesListFromCache(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_MY_ENTITY);
manager.setMyEntityCount(myEntities.length);

// Example using ElasticSearch count
const myEntityCount = await elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, {
  types: [ENTITY_TYPE_MY_ENTITY],
});
manager.setMyEntityCount(myEntityCount);
```

### Summary Checklist (Computed Gauge)

| # | File | Action |
|---|------|--------|
| 1 | `TelemetryMeterManager.ts` | Add counter property (initialized to `0`) |
| 2 | `TelemetryMeterManager.ts` | Add setter method |
| 3 | `TelemetryMeterManager.ts` | Register gauge in `registerFiligranTelemetry()` |
| 4 | `telemetryManager.ts` | Compute value in `fetchTelemetryData()` and call setter |

> **No Redis key, no increment helper, no business logic call** — the value is recomputed from scratch at each telemetry cycle.

## Conventions

- **Property names**: camelCase ending with `Count` (e.g., `myNewFeatureCount`).
- **Gauge names**: snake_case (e.g., `my_new_feature_count`). The `opencti_` prefix is added automatically.
- **Redis keys**: use the same string as the property name.
- **Unit**: defaults to `'count'`. Use `{ unit: 'boolean' }` for 0/1 flags.
- **Temporality**: metrics use `DELTA` aggregation — counters reset after each export cycle (Redis is cleared via `redisClearTelemetry`).

## Important Notes

- Keep metric descriptions concise and consistent with existing ones.
- **Documentation is mandatory**: every new metric MUST be added to `docs/docs/reference/usage-telemetry.md` (see the exhaustive list of telemetry metrics). A PR adding a metric without updating that file is incomplete and should not be merged.
