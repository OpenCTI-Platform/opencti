---
name: add-feature-flag
description: "Use when: putting a new or existing feature behind a feature flag (dev feature) in OpenCTI, adding attributes, GraphQL endpoints, managers or UI that must be hidden until a flag is enabled, or removing a feature flag"
---

# Add a Feature Flag

Full rules and rationale: [Feature Flags](../../instructions/backend/patterns/feature-flags.md).

## Prerequisites
- **Flag name**: UPPER_SNAKE_CASE string (e.g. `MY_FEATURE`) and its constant (`MY_FEATURE_FEATURE_FLAG`).
- **Scope**: list of new attributes / mappings, GraphQL endpoints, domain entry points and UI screens of the feature.

## Procedure

### Step 1 — Declare the constant
Add `export const MY_FEATURE_FEATURE_FLAG = 'MY_FEATURE';` with a one-line comment in
`opencti-platform/opencti-graphql/src/config/conf.js`, next to the other flags.

### Step 2 — Flag every new attribute definition (DO NOT SKIP)
For **each** attribute added by the feature — in a module definition's `attributes`, in
`src/modules/attributes/*-registrationAttributes.ts`, or as a new entry in the `mappings`
of an object attribute — add:
```ts
featureFlag: MY_FEATURE_FEATURE_FLAG,
```
Without it the field is pushed into the ElasticSearch index mapping at startup even when
the flag is off, and nothing fails. Re-read every attribute you added before moving on.

### Step 3 — Gate GraphQL endpoints
Add `@ff(flags: ["MY_FEATURE"])` to every new query, mutation and field
(`softFail: true` for fields read early by the front end). Run `yarn build:schema`.

### Step 4 — Gate domain logic
`enforceEnableFeatureFlag(MY_FEATURE_FEATURE_FLAG)` at the start of mutations / entry
points; `isFeatureEnabled(MY_FEATURE_FEATURE_FLAG)` for conditional branches.

### Step 5 — Gate managers
- **New manager:** import `ManagerDefinition` and `registerManager` from `src/manager/managerModule.ts`.
  Import the new manager file for side effects in `src/manager/index.ts`, and register it with
  `if (isFeatureEnabled(MY_FEATURE_FEATURE_FLAG)) { registerManager(DEFINITION); }`.
  Gate the registration, never `enabled()` / `enabledToStart()`: a registered manager shows
  in the platform modules and startup logs even when the flag is off. Keep its own
  `enabledByConfig` config. Do not add it to `src/managers.ts`.
- **Existing manager:** leave its registration alone; branch inside the handler with
  `isFeatureEnabled(MY_FEATURE_FEATURE_FLAG)`.

Reference: `src/manager/workflowStatusCleanupManager.ts`. Details in the Managers section of
[Feature Flags](../../instructions/backend/patterns/feature-flags.md).

### Step 6 — Gate the UI
`const { isFeatureEnable } = useHelper();` then `isFeatureEnable('MY_FEATURE')` around
menus, routes, tabs and form fields. Run `yarn relay` if GraphQL changed.

### Step 7 — Verify
- `grep -rn "featureFlag: MY_FEATURE_FEATURE_FLAG"` lists **every** new attribute and mapping.
- With fresh test indices, start the platform with the flag disabled: new attributes are absent
  from the index mapping and attribute registry. GraphQL fields remain in the schema, but
  flagged resolvers reject access (or return the soft-fail default); the new manager is
  neither logged at startup nor listed in the platform modules.
- Start with `APP__ENABLED_DEV_FEATURES='["MY_FEATURE"]'`: the feature works end to end.

## Removing a flag
Delete the constant, every `featureFlag: MY_FEATURE_FEATURE_FLAG`, every `@ff(...)` and
every `enforceEnableFeatureFlag` / `isFeatureEnabled` / `isFeatureEnable` call for it;
unwrap the `if` around `registerManager`.
Search for `MY_FEATURE` in `opencti-graphql` and `opencti-front` and verify that no declarations or guards for this flag remain; retain legitimate feature and manager identifiers.
