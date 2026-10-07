# Feature Flags

A feature behind a flag must be gated at **every layer** it touches. A missing layer
leaks the feature when the flag is disabled — and some leaks are silent and permanent.

Flags are enabled through `app:enabled_dev_features` (env `APP__ENABLED_DEV_FEATURES`),
`*` enables all of them. Check with `isFeatureEnabled(FLAG)` from `src/config/conf.js`.

## Checklist

### 1. Declare the constant
In `src/config/conf.js`, next to the existing flags:
```js
// My feature flag (use isFeatureEnabled(MY_FEATURE_FEATURE_FLAG) to check activation)
export const MY_FEATURE_FEATURE_FLAG = 'MY_FEATURE';
```

### 2. Attribute definitions — `featureFlag` (CRITICAL, most often forgotten)
Every **new attribute** registered for the feature, and every **new nested `mappings`
entry** added to an existing object attribute, MUST set `featureFlag`:

```ts
{
  name: 'my_new_field',
  label: 'My new field',
  type: 'string',
  format: 'short',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  isFilterable: true,
  featureFlag: MY_FEATURE_FEATURE_FLAG, // <-- REQUIRED for a flagged feature
}
```

This applies wherever attributes are registered: a module definition's `attributes`
(`registerDefinition`), `schemaAttributesDefinition.registerAttributes(...)` in
`src/modules/attributes/*-registrationAttributes.ts`, and `mappings` of object attributes.

**Why:** `schemaAttributesDefinition.registerAttributes` (`src/schema/schema-attributes.ts`)
skips attributes — and filters nested mappings — whose `featureFlag` is not enabled.
The ElasticSearch/OpenSearch index mapping is generated from the registered attributes
(`engineMappingGenerator` in `src/database/engine-mapping-generator.ts`). Without `featureFlag`, the field is:
- written into the index mapping at platform start, even with the flag off
  (a mapping field cannot be removed afterwards without a reindex),
- counted against the index total fields limit,
- exposed in the schema: filters, imports/exports, STIX conversion, attribute lists.

Nothing fails when `featureFlag` is missing, so tests will not catch it — check it explicitly.

Reference implementation: `custom_field_values` in
`src/modules/attributes/stixDomainObject-registrationAttributes.ts`.

### 3. GraphQL schema — `@ff` directive
Annotate new queries, mutations and fields:
```graphql
myFeature(id: String!): MyFeature @auth(for: [KNOWLEDGE]) @ff(flags: ["MY_FEATURE"])
```
Use `softFail: true` (optionally with `defaultValue`) on fields read early by the front
end, so a disabled flag returns a default instead of an error.

### 4. Domain logic
- Mutations / entry points: `enforceEnableFeatureFlag(MY_FEATURE_FEATURE_FLAG)` (`src/utils/access.ts`).
- Conditional behaviour: `if (isFeatureEnabled(MY_FEATURE_FEATURE_FLAG)) { ... }`.

### 5. Managers
**New manager for the feature:** write it as a `ManagerDefinition` (`src/manager/managerModule.ts`)
and gate the **registration**, not `enabled()`:

```ts
const MY_FEATURE_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'MY_FEATURE_MANAGER',
  label: 'My feature manager',
  executionContext: 'my_feature_manager',
  cronSchedulerHandler: { handler: myFeatureHandler, interval: SCHEDULE_TIME, lockKey: MY_FEATURE_MANAGER_KEY },
  enabledByConfig: MY_FEATURE_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

if (isFeatureEnabled(MY_FEATURE_FEATURE_FLAG)) {
  registerManager(MY_FEATURE_MANAGER_DEFINITION);
}
```

- Import the file in `src/manager/index.ts` (or the module's `*-manager.ts` there). The import
  is unconditional; only `registerManager` is behind the flag.
- Keep `enabledByConfig` (`booleanConf('my_feature_manager:enabled', true)`) separate from the
  flag: the config lets an admin turn the manager off once the feature is GA, the flag goes away.
- Do not start it from `src/managers.ts`: that file holds legacy managers being migrated
  to `registerManager`.

**Why registration and not `enabled()`:** an unregistered manager does not start, takes no
lock, and is absent from `getAllManagersStatuses` (cluster manager, platform module list).
A registered manager with a flag inside `enabled()`/`enabledToStart()` still appears as a
platform module, and logs "not started (disabled by configuration)" at startup — the flag
leaks into the UI and the logs.

**Existing manager gaining flagged behaviour:** do not touch its registration; branch inside
the handler with `isFeatureEnabled(MY_FEATURE_FEATURE_FLAG)`. For a stream manager, also skip
the feature's events early, so events of a disabled feature are not processed.

Reference implementation: `src/manager/workflowStatusCleanupManager.ts`.

### 6. Front end
Gate UI with `const { isFeatureEnable } = useHelper();` then `isFeatureEnable('MY_FEATURE')`.

### 7. Removing the flag later
When the feature goes GA: delete the constant, every `featureFlag:` property, every
`@ff(...)`, `enforceEnableFeatureFlag` / `isFeatureEnabled` / `isFeatureEnable` call, and
unwrap the `if (isFeatureEnabled(...))` around `registerManager`.
`grep -rn "MY_FEATURE"` across `opencti-graphql` and `opencti-front` must return nothing.
