# Add Workflow Graph Editor To All Entity Types — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the already-built generic workflow graph editor, migration path, and mass-op backend reachable and usable for every workflow-eligible entity type (not just `DraftWorkspace`), in both `GLOBAL` and `RequestAccess` scope, plus fix cycle-tolerant ordering and add bulk (mass) workflow operations.

**Architecture:** Generalize the existing Workflow settings tab routing/query variables from a hardcoded `DraftWorkspace` literal to any `entityType`, driven by `isWorkflowUiEnabledForType`. Extend the workflow-definition CRUD mutations/query to accept a `scope` parameter so `RequestAccess`-scoped definitions can actually be authored (today only read-time resolution is scope-aware). Add a confirm-gated migration mutation reusing the existing `workflowMigrationPreview` query. Rewrite `computeStateOrder` for per-state longest-simple-path cycle tolerance. Add a new mass-op task action type calling `triggerWorkflowEvent`, and a frontend-only bulk bypass UI reusing the existing `setWorkflowStatus` mass-op path.

**Tech Stack:** TypeScript/Node.js (Apollo GraphQL) backend in `opencti-platform/opencti-graphql`; React/TypeScript + Relay + MUI frontend in `opencti-platform/opencti-front`; Vitest for both frontend and backend unit tests.

**Spec:** [openspec/changes/add-workflow-graph-editor-all-entity-types/design.md](../design.md), [specs/workflow-editor-rollout/spec.md](../specs/workflow-editor-rollout/spec.md), [specs/workflow-state-ordering/spec.md](../specs/workflow-state-ordering/spec.md), [specs/workflow-mass-operations/spec.md](../specs/workflow-mass-operations/spec.md)

## Global Constraints

- `ENTITIES_WORKFLOW` (`ENTITIES_WORKFLOW_FEATURE_FLAG` in `workflowFeatureFlag.ts`) only gates **UI visibility** of the new editor — publishing a `WorkflowDefinition` for a type always activates backend enforcement for that type immediately, regardless of flag state.
- `isWorkflowUiEnabledForType(entityType, isFeatureEnable)` is the single source of truth for "does this type show the new editor" — always `true` for `DraftWorkspace`, otherwise gated by the flag.
- Workflow-definition CRUD mutations (`workflowDefinitionSet`, `workflowDefinitionPublish`, `workflowDefinitionRestorePublished`, `workflowDefinitionDelete`) and the `workflowDefinition`/`workflowMigrationPreview` queries are `@auth(for: [SETTINGS_SETCUSTOMIZATION])`.
- Single-entity transition mutations (`triggerWorkflowEvent`, `setWorkflowStatus`) are `@auth(for: [KNOWLEDGE_KNUPDATE])`.
- `COMMENT_MAX_LENGTH = 1000` and `CLOSING_REASON_MAX_LENGTH = 1000` are enforced in `workflow-resolvers.ts` and must stay in sync with the frontend constants documented in `WorkflowStatus.tsx`/`WorkflowStatus.graphql.ts`.
- EE-gated definition content (actions/conditions on transitions, onEnter/onExit actions) triggers `checkEnterpriseEdition` in `setWorkflowDefinition` — this must still apply per-scope.
- `RequestAccess` scope is only offered in the UI when `hasRequestAccessConfig` (EE + `request_access_workflow` present in the type's `availableSettings`) is true, matching the existing gate in `GlobalWorkflowSettingsCard.tsx`.

---

## Task 1: Generalize Workflow tab routing in `Root.tsx`

**Files:**
- Modify: `opencti-platform/opencti-front/src/private/components/settings/sub_types/Root.tsx`
- Test: `opencti-platform/opencti-front/src/private/components/settings/sub_types/__tests__/Root.test.tsx` (create if it doesn't exist)

**Interfaces:**
- Consumes: `isWorkflowUiEnabledForType(entityType: string, isFeatureEnable: (flag: string) => boolean): boolean` from `../../common/workflow/workflowFeatureFlag` (already exists, unchanged).
- Consumes: `useHelper()` returning `{ isFeatureEnable }` (already exists, unchanged).

- [ ] **Step 1: Write the failing test**

```tsx
// Root.test.tsx
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import RootSubType from '../Root';

vi.mock('../../../../../utils/hooks/useHelper', () => ({
  default: () => ({ isFeatureEnable: (flag: string) => flag === 'ENTITIES_WORKFLOW' }),
}));
vi.mock('../SubTypeWorkflow', () => ({ default: () => <div>graph-editor</div> }));
vi.mock('../global_workflow_request_access/GlobalWorkflowSettingsCard', () => ({ default: () => <div>legacy-card</div> }));

it('renders the graph editor for a non-DraftWorkspace type when ENTITIES_WORKFLOW is enabled', () => {
  render(
    <MemoryRouter initialEntries={['/dashboard/settings/customization/entity_types/Incident/workflow']}>
      <Routes>
        <Route path="/dashboard/settings/customization/entity_types/:subTypeId/*" element={<RootSubType />} />
      </Routes>
    </MemoryRouter>,
  );
  expect(screen.getByText('graph-editor')).toBeInTheDocument();
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `yarn workspace opencti-graphql-frontend vitest run src/private/components/settings/sub_types/__tests__/Root.test.tsx` (or the repo's equivalent frontend test command — check `package.json` `test` script under `opencti-platform/opencti-front`)
Expected: FAIL — `legacy-card` renders instead of `graph-editor`, because `Root.tsx` still checks `subTypeId === 'DraftWorkspace'`.

- [ ] **Step 3: Write minimal implementation**

In `Root.tsx`, replace:

```tsx
const isDraftWorkspaceType = subTypeId === 'DraftWorkspace';
```

with:

```tsx
const isWorkflowEditorEnabled = isWorkflowUiEnabledForType(subTypeId, isFeatureEnable);
```

and the route:

```tsx
<Route path={SUBTYPE_TAB_WORKFLOW} element={isWorkflowEditorEnabled ? <SubTypeWorkflow entityType={subTypeId} /> : <GlobalWorkflowSettingsCard />} />
```

Add the import: `import { isWorkflowUiEnabledForType } from '../common/workflow/workflowFeatureFlag';`

- [ ] **Step 4: Run test to verify it passes**

Run: same command as Step 2
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add opencti-platform/opencti-front/src/private/components/settings/sub_types/Root.tsx opencti-platform/opencti-front/src/private/components/settings/sub_types/__tests__/Root.test.tsx
git commit -m "feat(front): route workflow tab to graph editor for any eligible entity type"
```

---

## Task 2: Thread `entityType` through `SubTypeWorkflow.tsx`

> Confirmed via code reading: `Workflow.tsx` **already** accepts an optional `entityType` prop (defaulting to `'DraftWorkspace'`) and already threads it into all three of its mutations (`WorkflowDefinitionMutation`, `WorkflowPublishMutation`, `WorkflowRestorePublishedMutation`) and `WorkflowEditionDrawer.tsx` — `Workflow.test.tsx` already exercises `entityType="Report"`. No changes to `Workflow.tsx` itself are needed for this task; only `SubTypeWorkflow.tsx`'s hardcoded query variables need to change, since it is currently the only caller and never overrides the default.

**Files:**
- Modify: `opencti-platform/opencti-front/src/private/components/settings/sub_types/SubTypeWorkflow.tsx`
- Test: `opencti-platform/opencti-front/src/private/components/settings/sub_types/__tests__/SubTypeWorkflow.test.tsx` (create if it doesn't exist)

**Interfaces:**
- Produces: `SubTypeWorkflow` now requires a prop `entityType: string` (previously took none, hardcoded `'DraftWorkspace'`).
- Consumes: `workflowQuery`'s existing `$entityType: String!` variable (unchanged shape).

- [ ] **Step 1: Write the failing test**

```tsx
// SubTypeWorkflow.test.tsx
import { render } from '@testing-library/react';
import { RelayEnvironmentProvider } from 'react-relay';
import { createMockEnvironment, MockPayloadGenerator } from 'relay-test-utils';
import SubTypeWorkflow, { workflowQuery } from '../SubTypeWorkflow';

it('queries workflowDefinition with the provided entityType, not a hardcoded literal', () => {
  const environment = createMockEnvironment();
  render(
    <RelayEnvironmentProvider environment={environment}>
      <SubTypeWorkflow entityType="Incident" />
    </RelayEnvironmentProvider>,
  );
  const operation = environment.mock.getMostRecentOperation();
  expect(operation.request.node.params.name).toBe(workflowQuery.params.name);
  expect(operation.request.variables.entityType).toBe('Incident');
  environment.mock.resolveMostRecentOperation((op) => MockPayloadGenerator.generate(op));
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `yarn workspace opencti-graphql-frontend vitest run src/private/components/settings/sub_types/__tests__/SubTypeWorkflow.test.tsx`
Expected: FAIL — `TypeError`/prop-type mismatch, since `SubTypeWorkflow` currently takes no props and always queries `entityType: 'DraftWorkspace'`.

- [ ] **Step 3: Write minimal implementation**

In `SubTypeWorkflow.tsx`:

```tsx
interface SubTypeWorkflowProps {
  entityType: string;
}

const SubTypeWorkflow = ({ entityType }: SubTypeWorkflowProps) => {
  const [workflowQueryRef, loadWorkflowQuery] = useQueryLoadingWithLoadQuery<SubTypeWorkflowQuery>(
    workflowQuery,
    { entityType, allowDraft: entityType === 'DraftWorkspace' },
    { fetchPolicy: 'network-only' },
  );

  const handleRefetch = useCallback(() => {
    loadWorkflowQuery({ entityType, allowDraft: entityType === 'DraftWorkspace' }, { fetchPolicy: 'network-only' });
  }, [loadWorkflowQuery, entityType]);
  // ...rest unchanged, pass entityType to <Workflow entityType={entityType} .../> via WorkflowWithDependencies
```

Thread `entityType` down through `WorkflowWithDependencies` (`WorkflowWithDependenciesProps` gets `entityType: string`) into `<Workflow queryRef={queryRef} depsQueryRef={depsQueryRef} onRefetch={onRefetch} entityType={entityType} />`.

- [ ] **Step 4: Run test to verify it passes**

Run: same command as Step 2
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add opencti-platform/opencti-front/src/private/components/settings/sub_types/SubTypeWorkflow.tsx opencti-platform/opencti-front/src/private/components/settings/sub_types/__tests__/SubTypeWorkflow.test.tsx
git commit -m "feat(front): thread entityType prop through SubTypeWorkflow instead of hardcoding DraftWorkspace"
```

---

## Task 3: Extend workflow-definition CRUD mutations/query with a `scope` argument (backend)

> Discovered gap: `getWorkflowDefinition`/`setWorkflowDefinition`/`publishWorkflowDefinition`/`restorePublishedWorkflowDefinition`/`deleteWorkflowDefinition` and their GraphQL mutations currently only ever read/write `entitySetting.workflow_id` (the `GLOBAL` definition). Runtime resolution (`getDefinitionData`, used by `triggerWorkflowEvent`) already supports reading `entitySetting.request_access_workflow.workflow_definition_id` for `StatusScope.RequestAccess`, but there is no way to **author** (set/publish/restore/delete) that RequestAccess-scoped definition today. This task is a prerequisite for Task 4's scope switcher.

**Files:**
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-domain.ts`
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/api/workflow-resolvers.ts`
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/api/workflow.graphql`
- Test: `opencti-platform/opencti-graphql/tests/unit/modules/workflow/workflow-domain-scope.test.ts` (create)

**Interfaces:**
- Produces: `getWorkflowDefinition(context, user, entityType, allowDraft = false, scope: StatusScope = StatusScope.Global)`.
- Produces: `setWorkflowDefinition(context, user, entityType, definition, scope: StatusScope = StatusScope.Global)` — writes to `entitySetting.workflow_id` when `scope === Global`, else creates/updates a `WorkflowDefinition` and stores its id at `entitySetting.request_access_workflow.workflow_definition_id` (preserving any existing `approved_workflow_id`/`declined_workflow_id` on that sub-object).
- Produces: `publishWorkflowDefinition`, `restorePublishedWorkflowDefinition`, `deleteWorkflowDefinition` — same `scope` parameter, same id-field switch.
- GraphQL: `workflowDefinition(entityType: String!, allowDraft: Boolean, scope: StatusScope)`, `workflowDefinitionSet(entityType: String!, definition: String!, scope: StatusScope)`, `workflowDefinitionPublish(entityType: String!, scope: StatusScope)`, `workflowDefinitionRestorePublished(entityType: String!, scope: StatusScope)`, `workflowDefinitionDelete(entityType: String!, scope: StatusScope)` — all default to `StatusScope.Global` when omitted, so every existing caller (including `DraftWorkspace`'s `SubTypeWorkflow` query) is unaffected.
- **Confirmed additional gap inside `publishWorkflowDefinition` itself** (the code already flags this as a known TODO in its own comments): `ensureFullStatusMapping` and `reconcileOrphanedStatuses` — both called from `publishWorkflowDefinition` — hardcode `{ key: ['scope'], values: [StatusScope.Global] }` when reading/creating `Status` records, instead of using the definition's own scope. `isStatusOrphaned` (used by the separate cleanup manager) similarly calls `getWorkflowDefinition(context, user, status.type, false)` with no scope, even though the `status` object it receives already carries its own `.scope` field. All three must accept/use a `scope` parameter (or, for `isStatusOrphaned`, simply pass `status.scope`) so publishing a `RequestAccess`-scope definition reconciles `RequestAccess`-scope `Status` records, not `Global` ones. Without this fix, Task 3's `setWorkflowDefinition` would work but `publishWorkflowDefinition` would silently reconcile the wrong scope's statuses.

- [ ] **Step 1: Write the failing test**

```ts
// workflow-domain-scope.test.ts
import { describe, it, expect } from 'vitest';
import { StatusScope } from '../../../../src/generated/graphql';
import { setWorkflowDefinition, getWorkflowDefinition } from '../../../../src/modules/workflow/domain/workflow-domain';
import { testContext, ADMIN_USER } from '../../../utils/testQuery';

describe('setWorkflowDefinition with scope', () => {
  it('stores a RequestAccess-scope definition on request_access_workflow.workflow_definition_id, not workflow_id', async () => {
    const entityType = 'Incident';
    const definition = JSON.stringify({ name: 'RA workflow', initialState: 'new', states: [{ statusId: 'new' }], transitions: [] });
    await setWorkflowDefinition(testContext, ADMIN_USER, entityType, definition, StatusScope.RequestAccess);
    const globalDef = await getWorkflowDefinition(testContext, ADMIN_USER, entityType, true, StatusScope.Global);
    const raDef = await getWorkflowDefinition(testContext, ADMIN_USER, entityType, true, StatusScope.RequestAccess);
    expect(raDef?.name).toBe('RA workflow');
    expect(globalDef?.id).not.toBe(raDef?.id);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `yarn workspace opencti-graphql test:unit -- workflow-domain-scope.test.ts` (check the exact script name in `opencti-platform/opencti-graphql/package.json`, e.g. `test:unit` or `vitest`)
Expected: FAIL — `setWorkflowDefinition` does not accept a 5th `scope` argument yet (TypeScript compile error) or silently ignores it.

- [ ] **Step 3: Write minimal implementation**

In `workflow-domain.ts`, add a small helper and thread `scope` through each function:

```ts
const resolveDefinitionIdField = (scope: StatusScope): 'workflow_id' | 'request_access_workflow.workflow_definition_id' => (
  scope === StatusScope.RequestAccess ? 'request_access_workflow.workflow_definition_id' : 'workflow_id'
);

export const getWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  allowDraft: boolean = false,
  scope: StatusScope = StatusScope.Global,
): Promise<WorkflowDefinitionResponse | null> => {
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  return getDefinitionData(context, user, entitySetting, allowDraft, scope);
};

export const setWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  definition: string,
  scope: StatusScope = StatusScope.Global,
): Promise<EntitySettingWithWorkflowResponse> => {
  // ...existing validation unchanged...
  const existingDefinitionId = scope === StatusScope.RequestAccess
    ? entitySetting.request_access_workflow?.workflow_definition_id
    : entitySetting.workflow_id;
  const errors = await validateWorkflowDefinitionData(executionContext, executionUser, definition, entityType, existingDefinitionId ?? undefined);
  // ...create/update the WorkflowDefinition entity as today...
  if (scope === StatusScope.RequestAccess) {
    await patchAttribute(executionContext, executionUser, entitySetting.id, ENTITY_TYPE_ENTITY_SETTING, {
      request_access_workflow: { ...entitySetting.request_access_workflow, workflow_definition_id: workflowDefinitionEntity.id },
    });
  } else {
    await patchAttribute(executionContext, executionUser, entitySetting.id, ENTITY_TYPE_ENTITY_SETTING, { workflow_id: workflowDefinitionEntity.id });
  }
  // ...return response unchanged shape...
};
```

Apply the same `scope`-driven branch (read vs. write to `workflow_id` vs. `request_access_workflow.workflow_definition_id`) to `publishWorkflowDefinition`, `restorePublishedWorkflowDefinition`, and `deleteWorkflowDefinition`. Additionally, thread `scope` into `publishWorkflowDefinition`'s two internal helpers — `ensureFullStatusMapping(context, user, entityType, definitionData, scope)` and `reconcileOrphanedStatuses(context, user, entityType, oldDefinitionData, newDefinitionData, scope)` — replacing their hardcoded `StatusScope.Global` filter/write with the passed `scope`; and change `isStatusOrphaned` to call `getWorkflowDefinition(context, user, status.type, false, status.scope)` instead of omitting scope. In `workflow.graphql`, add `scope: StatusScope` as an optional argument (default handled in the resolver, not SDL) to `workflowDefinition`, `workflowDefinitionSet`, `workflowDefinitionPublish`, `workflowDefinitionRestorePublished`, `workflowDefinitionDelete`. In `workflow-resolvers.ts`, pass `scope ?? StatusScope.Global` through to each domain call.

- [ ] **Step 4: Run test to verify it passes**

Run: same command as Step 2
Expected: PASS

- [ ] **Step 5: Add a publish-path regression test for the orphan-reconciliation fix**

Add a test asserting that publishing a `RequestAccess`-scope definition creates/reconciles `Status` records with `scope: StatusScope.RequestAccess` (not `Global`), and that a pre-existing `Global`-scope `Status` for the same entity type is left untouched by a `RequestAccess`-scope publish.

Run: same command as Step 2
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-domain.ts opencti-platform/opencti-graphql/src/modules/workflow/api/workflow-resolvers.ts opencti-platform/opencti-graphql/src/modules/workflow/api/workflow.graphql opencti-platform/opencti-graphql/tests/unit/modules/workflow/workflow-domain-scope.test.ts
git commit -m "feat(backend): support scope-aware read/write of RequestAccess workflow definitions"
```

---

## Task 4: Add the Global/RequestAccess scope switcher to `Workflow.tsx`

**Files:**
- Modify: `opencti-platform/opencti-front/src/private/components/settings/sub_types/workflow/Workflow.tsx`
- Modify: `opencti-platform/opencti-front/src/private/components/settings/sub_types/SubTypeWorkflow.tsx`
- Test: `opencti-platform/opencti-front/src/private/components/settings/sub_types/workflow/__tests__/Workflow.test.tsx` (extend existing)

**Interfaces:**
- Consumes: `hasRequestAccessConfig` gating logic — extract the existing inline check from `GlobalWorkflowSettingsCard.tsx` into a shared helper `hasRequestAccessWorkflowConfig(subType, isEnterpriseEdition): boolean` (new export) so both components share one source of truth.
- Produces: `Workflow` component gains `scope: StatusScope` state, defaulting to `Global`, with a segmented control rendered above the canvas when `hasRequestAccessWorkflowConfig` is true for the current `entityType`.

- [ ] **Step 1: Write the failing test**

```tsx
it('shows a scope switcher only when RequestAccess config is available, and reloads on switch', () => {
  // render <SubTypeWorkflow entityType="Incident" /> with a mocked entitySetting that has
  // request_access_workflow available and EE enabled
  // assert two selectable options: "Global" and "Request access"
  // click "Request access", assert the workflowDefinition query re-fires with scope: 'RequestAccess'
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `yarn workspace opencti-graphql-frontend vitest run src/private/components/settings/sub_types/workflow/__tests__/Workflow.test.tsx`
Expected: FAIL — no scope switcher exists yet.

- [ ] **Step 3: Write minimal implementation**

Add a `scope` state to `SubTypeWorkflow` (lifted above `Workflow`, since it drives the query variables), pass `scope`/`setScope` and `canSwitchScope={hasRequestAccessWorkflowConfig(...)}` into `Workflow`. Render a MUI `ToggleButtonGroup` with `GLOBAL`/`REQUEST_ACCESS` options when `canSwitchScope` is true, calling `setScope` on change, which triggers `loadWorkflowQuery({ entityType, scope, allowDraft: ... })`.

- [ ] **Step 4: Run test to verify it passes**

Run: same command as Step 2
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add opencti-platform/opencti-front/src/private/components/settings/sub_types/workflow/Workflow.tsx opencti-platform/opencti-front/src/private/components/settings/sub_types/SubTypeWorkflow.tsx opencti-platform/opencti-front/src/private/components/settings/sub_types/workflow/__tests__/Workflow.test.tsx
git commit -m "feat(front): add Global/RequestAccess scope switcher to the workflow graph editor"
```

---

## Task 5: Backend mutation to trigger the legacy-status migration

**Files:**
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/api/workflow.graphql`
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/api/workflow-resolvers.ts`
- Test: `opencti-platform/opencti-graphql/tests/unit/modules/workflow/migrate-status-mutation.test.ts` (create)

**Interfaces:**
- GraphQL: `migrateEntityTypeStatusToWorkflowDefinition(entityType: String!, scope: StatusScope!): MigrateEntityTypeStatusResult! @auth(for: [SETTINGS_SETCUSTOMIZATION])` where `MigrateEntityTypeStatusResult { entityType: String!, status: String! }` mirrors `MigrateEntityTypeStatusStatus` (`'migrated' | 'skipped_no_data' | 'skipped_already_migrated'`).
- Consumes: `migrateEntityTypeStatusToWorkflowDefinition(context, user, entityType, scope)` from `migrate-status-to-workflow-definition.ts` (extended in Task 8 to accept `scope`; until Task 8 lands, only `Global` scope is valid — the resolver passes `scope` through and lets the domain function reject unsupported scopes as it does today).

- [ ] **Step 1: Write the failing test**

```ts
// migrate-status-mutation.test.ts
import { describe, it, expect } from 'vitest';
import { executeInternalQuery } from '../../../utils/testQuery';

describe('migrateEntityTypeStatusToWorkflowDefinition mutation', () => {
  it('migrates legacy Global-scope Status data via GraphQL', async () => {
    const MUTATION = `mutation { migrateEntityTypeStatusToWorkflowDefinition(entityType: "Incident", scope: GLOBAL) { entityType status } }`;
    const result = await executeInternalQuery(MUTATION);
    expect(result.data.migrateEntityTypeStatusToWorkflowDefinition.status).toBe('migrated');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `yarn workspace opencti-graphql test:unit -- migrate-status-mutation.test.ts`
Expected: FAIL — `Cannot query field "migrateEntityTypeStatusToWorkflowDefinition" on type "Mutation"`.

- [ ] **Step 3: Write minimal implementation**

In `workflow.graphql`, add:

```graphql
type MigrateEntityTypeStatusResult {
    entityType: String!
    status: String!
}
```

and in `extend type Mutation`:

```graphql
migrateEntityTypeStatusToWorkflowDefinition(entityType: String!, scope: StatusScope!): MigrateEntityTypeStatusResult! @auth(for: [SETTINGS_SETCUSTOMIZATION])
```

In `workflow-resolvers.ts`, import and wire:

```ts
import { migrateEntityTypeStatusToWorkflowDefinition } from '../migration/migrate-status-to-workflow-definition';
// ...inside Mutation:
migrateEntityTypeStatusToWorkflowDefinition: (_: any, { entityType, scope }: { entityType: string; scope: StatusScope }, context: AuthContext) => {
  return migrateEntityTypeStatusToWorkflowDefinition(context, context.user!, entityType, scope);
},
```

- [ ] **Step 4: Run test to verify it passes**

Run: same command as Step 2
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add opencti-platform/opencti-graphql/src/modules/workflow/api/workflow.graphql opencti-platform/opencti-graphql/src/modules/workflow/api/workflow-resolvers.ts opencti-platform/opencti-graphql/tests/unit/modules/workflow/migrate-status-mutation.test.ts
git commit -m "feat(backend): expose legacy status migration as a callable GraphQL mutation"
```

---

## Task 6: Frontend confirm-gated migration dialog

**Files:**
- Create: `opencti-platform/opencti-front/src/private/components/settings/sub_types/workflow/WorkflowMigrationConfirmDialog.tsx`
- Modify: `opencti-platform/opencti-front/src/private/components/settings/sub_types/SubTypeWorkflow.tsx`
- Test: `opencti-platform/opencti-front/src/private/components/settings/sub_types/workflow/__tests__/WorkflowMigrationConfirmDialog.test.tsx` (create)

**Interfaces:**
- Produces: `WorkflowMigrationConfirmDialog({ entityType, scope, onConfirm, onCancel }: { entityType: string; scope: StatusScope; onConfirm: () => void; onCancel: () => void })` — runs a new `workflowMigrationPreviewQuery` and renders its `diagnostics` per state.
- Consumes: the `workflowMigrationPreview(entityType: String!)` **GraphQL schema field** (already implemented backend-side, confirmed present in `relay.schema.graphql`) and the new `migrateEntityTypeStatusToWorkflowDefinition` mutation from Task 5. **Confirmed via search: no frontend Relay query/generated artifact for `workflowMigrationPreview` exists yet** — this task must author a new `.graphql`-tagged query (e.g. `WorkflowMigrationConfirmDialogQuery`) in this component and run `yarn relay` to generate its types/hook, it is not simply "reuse an existing query."

- [ ] **Step 1: Write the failing test**

```tsx
it('does not call the migration mutation until the user confirms', () => {
  // render WorkflowMigrationConfirmDialog with a mocked preview showing 1 diagnostic
  // assert diagnostic text is visible
  // assert the migrate mutation has NOT been sent
  // click "Confirm"
  // assert the migrate mutation IS sent with the right entityType/scope
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `yarn workspace opencti-graphql-frontend vitest run src/private/components/settings/sub_types/workflow/__tests__/WorkflowMigrationConfirmDialog.test.tsx`
Expected: FAIL — component does not exist.

- [ ] **Step 3: Write minimal implementation**

Author a new tagged GraphQL query in the component file, e.g.:

```ts
const workflowMigrationPreviewQuery = graphql`
  query WorkflowMigrationConfirmDialogQuery($entityType: String!) {
    workflowMigrationPreview(entityType: $entityType) {
      results { scope diagnostics }
    }
  }
`;
```

Run `yarn relay` (from `opencti-platform/opencti-front`) to generate its `__generated__` types/hook before using it. Create the dialog component using `Dialog` (per `WorkflowBypassStatus.tsx`'s pattern), a `useLazyLoadQuery`/`useQueryLoading` call to this new query, rendering each `results[].diagnostics[]` entry as a list item, with "Confirm" wired to a `useMutation` of the new `migrateEntityTypeStatusToWorkflowDefinitionMutation`. In `SubTypeWorkflow.tsx`, when `workflowDefinition` is `null` for the current `entityType`/`scope` and a preview shows data, render this dialog before the graph canvas; on confirm success, call `handleRefetch()`.

- [ ] **Step 4: Run test to verify it passes**

Run: same command as Step 2
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add opencti-platform/opencti-front/src/private/components/settings/sub_types/workflow/WorkflowMigrationConfirmDialog.tsx opencti-platform/opencti-front/src/private/components/settings/sub_types/SubTypeWorkflow.tsx opencti-platform/opencti-front/src/private/components/settings/sub_types/workflow/__tests__/WorkflowMigrationConfirmDialog.test.tsx
git commit -m "feat(front): confirm-gated legacy status migration dialog in the workflow editor"
```

---

## Task 7: Resolve per-entity workflow scope in runtime functions (prerequisite for RequestAccess)

> Discovered gap (confirmed by reading the code, not assumed): every
> entity-scoped runtime function in `workflow-domain.ts` resolves
> `getDefinitionData` with a hardcoded `StatusScope.Global` default. Only
> entity *creation* (`initializeEntityWorkflow` via `resolveEntityCreationScope`)
> actually derives scope from the entity's own assigned `Status.scope`. This
> means `requestAccess-domain.ts`'s `approveRequestAccess`/`declineRequestAccess`
> — which patch `x_opencti_workflow_id` via a plain `updateAttribute`, relying
> on the generic post-attribute-update hook (`syncWorkflowInstanceFromExternalWrite`)
> to keep the `WorkflowInstance` projection in sync — will silently fail to
> sync for `RequestAccess`-scoped statuses: the hook resolves the (absent)
> `Global`-scope definition and no-ops. This task is a hard prerequisite for
> Task 8 (extending the migration function): persisting a `RequestAccess`-scope
> `WorkflowDefinition` is pointless if nothing at runtime can ever resolve it.
> No changes to `requestAccess-domain.ts` itself are needed — it already goes
> through the generic hook mechanism by design.

**Files:**
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-domain.ts`
- Test: `opencti-platform/opencti-graphql/tests/01-unit/modules/workflow-domain-test.ts` (extend existing)

**Interfaces:**
- Produces: `resolveStatusScope(context: AuthContext, user: AuthUser, statusId?: string): Promise<StatusScope>` — generalizes today's `resolveEntityCreationScope` (which becomes a thin wrapper: `resolveEntityCreationScope = (context, user, entity) => resolveStatusScope(context, user, entity.x_opencti_workflow_id)`), looking up `statusId`'s own `scope` field, defaulting to `StatusScope.Global` when `statusId` is absent or unresolvable.
- Modifies (internal call sites only, no public signature changes): `syncWorkflowInstanceFromExternalWrite` resolves scope from the `newStatusId` parameter it already receives (reusing the single `storeLoadById` lookup it already performs on that id, rather than fetching it twice); `getWorkflowInstance`, `getAllowedTransitions`, `triggerWorkflowEvent`, `setWorkflowStatus` resolve scope from the already-loaded `entity.x_opencti_workflow_id`; `batchWorkflowInstances` keys its `configByType` cache by `` `${entityType}:${scope}` `` instead of `entityType` alone, resolving each entity's scope from its own `x_opencti_workflow_id` before grouping.

- [ ] **Step 1: Write the failing test**

```ts
// workflow-domain-test.ts — add inside the existing "Task 8: syncWorkflowInstanceFromExternalWrite" describe block
it('resolves a RequestAccess-scope WorkflowDefinition when the written status is RequestAccess-scoped', async () => {
  (findByType as any).mockResolvedValue({
    id: 'setting-id',
    request_access_workflow: { workflow_definition_id: 'ra-workflow-def-id' },
  });
  const raDefinitionContent = JSON.stringify({
    initialState: 'new', states: [{ statusId: 'new' }, { statusId: 'approved' }], transitions: [],
  });
  const existingInstance = {
    id: 'instance-1', internal_id: 'instance-1', currentState: 'new', history: '[]', scope: StatusScope.RequestAccess,
  };
  (loadEntity as any).mockResolvedValue(existingInstance);
  (storeLoadById as any).mockImplementation((_ctx: any, _user: any, id: string) => {
    if (id === 'ra-workflow-def-id') {
      return Promise.resolve({ id: 'ra-workflow-def-id', name: 'ra-wf', published_version: { id: 'v1', content: raDefinitionContent, validation_errors: [] } });
    }
    if (id === 'status-approved-id') {
      return Promise.resolve({ id: 'status-approved-id', template_id: 'approved', scope: StatusScope.RequestAccess });
    }
    return Promise.resolve(null);
  });
  (updateAttribute as any).mockResolvedValue({ element: { id: 'instance-1' } });

  await syncWorkflowInstanceFromExternalWrite(mockContext, { id: 'rfi-1', internal_id: 'rfi-1', entity_type: 'Case-Rfi' }, 'status-approved-id');

  expect(updateAttribute).toHaveBeenCalledWith(
    expect.objectContaining({ user: WORKFLOW_MANAGER_USER }),
    WORKFLOW_MANAGER_USER,
    'instance-1',
    ENTITY_TYPE_WORKFLOW_INSTANCE,
    expect.arrayContaining([{ key: 'currentState', value: ['approved'] }]),
  );
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `yarn workspace opencti-graphql test:unit -- workflow-domain-test.ts`
Expected: FAIL — `syncWorkflowInstanceFromExternalWrite` resolves `getDefinitionData` with the default `Global` scope, finds no `workflow_id` on the mocked `EntitySetting` (only `request_access_workflow.workflow_definition_id` is set), so `definitionData` is `null` and the function no-ops without calling `updateAttribute`.

- [ ] **Step 3: Write minimal implementation**

In `workflow-domain.ts`, generalize the scope-resolution helper:

```ts
const resolveStatusScope = async (
  context: AuthContext,
  user: AuthUser,
  statusId?: string,
): Promise<StatusScope> => {
  if (!statusId) return StatusScope.Global;
  const status = await storeLoadById<BasicWorkflowStatus>(context, user, statusId, ENTITY_TYPE_STATUS);
  return status?.scope ?? StatusScope.Global;
};

const resolveEntityCreationScope = async (
  context: AuthContext,
  user: AuthUser,
  entity: { x_opencti_workflow_id?: string },
): Promise<StatusScope> => resolveStatusScope(context, user, entity.x_opencti_workflow_id);
```

In `syncWorkflowInstanceFromExternalWrite`, move the existing `status` lookup earlier and derive scope from it before resolving `definitionData`:

```ts
export const syncWorkflowInstanceFromExternalWrite = async (
  context: AuthContext,
  entity: Record<string, any>,
  newStatusId: string,
): Promise<void> => {
  const executionContext = { ...bypassDraftContext(context), user: WORKFLOW_MANAGER_USER };

  const entitySetting = await getWorkflowConfig(executionContext, WORKFLOW_MANAGER_USER, entity.entity_type);
  const status = await storeLoadById<BasicWorkflowStatus>(executionContext, WORKFLOW_MANAGER_USER, newStatusId, ENTITY_TYPE_STATUS);
  const scope = status?.scope ?? StatusScope.Global;
  const definitionData = await getDefinitionData(executionContext, WORKFLOW_MANAGER_USER, entitySetting, false, scope);
  if (!definitionData) return;
  // ...rest unchanged, but reuse `status` below instead of re-fetching it...
```

Apply the same pattern (resolve `scope` from `entity.x_opencti_workflow_id` via `resolveStatusScope` before calling `getDefinitionData`) in `getWorkflowInstance`, `getAllowedTransitions`, `triggerWorkflowEvent`, and `setWorkflowStatus`. In `batchWorkflowInstances`, resolve each entity's scope first, group by `` `${type}:${scope}` `` instead of `type` alone when building `configByType`, and pass the per-entity scope through when calling `getDefinitionData` for each distinct group.

- [ ] **Step 4: Run test to verify it passes**

Run: same command as Step 2
Expected: PASS

- [ ] **Step 5: Add regression coverage for the other updated functions**

Add analogous `RequestAccess`-scope test cases to the existing `getWorkflowInstance`, `getAllowedTransitions`, `triggerWorkflowEvent`, `setWorkflowStatus`, and `batchWorkflowInstances` describe blocks in `workflow-domain-test.ts`, each asserting the `RequestAccess`-scope definition is resolved when the entity's current/target status carries that scope, and that existing `Global`-scope behavior (all pre-existing tests) is unchanged.

Run: `yarn workspace opencti-graphql test:unit -- workflow-domain-test.ts`
Expected: PASS (all existing + new cases)

- [ ] **Step 6: Add a real end-to-end integration test for RFI approve/decline sync**

Add a test to `opencti-platform/opencti-graphql/tests/03-integration/01-database/requestAccess-domain-test.ts` (real store, no mocks) that: configures a `RequestAccess`-scope `WorkflowDefinition` for `Case-Rfi` (via `setWorkflowDefinition`/`publishWorkflowDefinition`), creates a request access and calls the real `approveRequestAccess`, then asserts via `getWorkflowInstance` that the RFI's `WorkflowInstance.currentState`/history reflect the approval — proving the fix works through the actual `requestAccess-domain.ts` code path, not just mocked unit tests.

Run: `yarn workspace opencti-graphql test:integration -- requestAccess-domain-test.ts` (check exact script name in `opencti-platform/opencti-graphql/package.json`)
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-domain.ts opencti-platform/opencti-graphql/tests/01-unit/modules/workflow-domain-test.ts opencti-platform/opencti-graphql/tests/03-integration/01-database/requestAccess-domain-test.ts
git commit -m "fix(backend): resolve workflow scope per-entity instead of defaulting to Global"
```

---

## Task 8: Extend legacy migration to support `RequestAccess` scope

**Files:**
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/migration/migrate-status-to-workflow-definition.ts`
- Test: `opencti-platform/opencti-graphql/tests/unit/modules/workflow/migrate-status-to-workflow-definition.test.ts` (extend existing)

**Interfaces:**
- Produces: `migrateEntityTypeStatusToWorkflowDefinition(context, user, entityType, scope: StatusScope = StatusScope.Global): Promise<MigrateEntityTypeStatusResult>` — now accepts `scope` and, for `StatusScope.RequestAccess`, persists via `setWorkflowDefinition(..., StatusScope.RequestAccess)` + `publishWorkflowDefinition(..., StatusScope.RequestAccess)` from Task 3, instead of throwing.

- [ ] **Step 1: Write the failing test**

```ts
it('migrates RequestAccess-scoped legacy Status data instead of throwing', async () => {
  // seed Status entities with scope: StatusScope.RequestAccess for entityType 'Incident'
  const result = await migrateEntityTypeStatusToWorkflowDefinition(testContext, ADMIN_USER, 'Incident', StatusScope.RequestAccess);
  expect(result.status).toBe('migrated');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `yarn workspace opencti-graphql test:unit -- migrate-status-to-workflow-definition.test.ts`
Expected: FAIL — current code throws `FunctionalError('Cannot migrate: entity type has request_access-scoped Status data...')`.

- [ ] **Step 3: Write minimal implementation**

Replace the `RequestAccess` guard-throw block with scope-driven handling:

```ts
export const migrateEntityTypeStatusToWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  scope: StatusScope = StatusScope.Global,
): Promise<MigrateEntityTypeStatusResult> => {
  const entitySetting = await findEntitySettingByType(context, user, entityType);
  if (!entitySetting) {
    throw FunctionalError('Cannot migrate: no EntitySetting found for entity type', { entityType });
  }
  const existingId = scope === StatusScope.RequestAccess
    ? entitySetting.request_access_workflow?.workflow_definition_id
    : entitySetting.workflow_id;
  if (existingId) {
    return { entityType, status: 'skipped_already_migrated' };
  }

  const statuses = await fullEntitiesList<BasicWorkflowStatus>(context, user, [ENTITY_TYPE_STATUS], {
    filters: { mode: FilterMode.And, filters: [{ key: ['type'], values: [entityType] }], filterGroups: [] },
  });
  const templates = await fullEntitiesList<BasicWorkflowTemplateEntity>(context, user, [ENTITY_TYPE_STATUS_TEMPLATE]);
  const { byScope } = convertStatusToDefinition(statuses, templates);

  const scopeResult = byScope[scope];
  if (!scopeResult || scopeResult.definition.states.length === 0) {
    return { entityType, status: 'skipped_no_data' };
  }
  if (scopeResult.diagnostics.length > 0) {
    logApp.warn('[MIGRATION] workflow-definition-migration > conversion diagnostics', { entityType, scope, diagnostics: scopeResult.diagnostics });
  }
  await setWorkflowDefinition(context, user, entityType, JSON.stringify(scopeResult.definition), scope);
  return publishWorkflowDefinition(context, user, entityType, scope).then(() => ({ entityType, status: 'migrated' as const }));
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: same command as Step 2
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add opencti-platform/opencti-graphql/src/modules/workflow/migration/migrate-status-to-workflow-definition.ts opencti-platform/opencti-graphql/tests/unit/modules/workflow/migrate-status-to-workflow-definition.test.ts
git commit -m "feat(backend): support migrating RequestAccess-scoped legacy status data"
```

---

## Task 9: Cycle-scoped state ordering rewrite

**Files:**
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-ordering.ts`
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/workflow-validation.ts`
- Test: `opencti-platform/opencti-graphql/tests/unit/modules/workflow/workflow-ordering.test.ts` (extend existing)

**Interfaces:**
- Produces: `computeStateOrder(initialState: string, transitions: OrderingTransition[]): Map<string, number | null>` — **return type changes** from `Map<string, number> | null` to `Map<string, number | null>` (per-state result; `null` for a specific state means "needs manual order", not the whole map). Every caller must be updated.
- Consumes in `workflow-validation.ts`: replace `const computedOrder = computeStateOrder(...); if (computedOrder === null) { /* every state needs manual order */ }` with per-state lookup: `const order = computedOrder.get(stateId); if (order === null || order === undefined) { /* this state needs manual order */ }`.

- [ ] **Step 1: Write the failing test**

```ts
it('only requires manual order for states entangled in a cycle, not the whole graph', () => {
  // graph: initial -> a -> b -> a (cycle a<->b), initial -> c (unrelated)
  const transitions = [
    { from: 'initial', to: 'a' },
    { from: 'a', to: 'b' },
    { from: 'b', to: 'a' },
    { from: 'initial', to: 'c' },
  ];
  const order = computeStateOrder('initial', transitions);
  expect(order.get('c')).toBe(1); // unrelated state still auto-ordered
  expect(order.get('a')).toBeNull(); // entangled in a cycle
  expect(order.get('b')).toBeNull();
});

it('computes longest-simple-path length for acyclic graphs, matching prior BFS behavior on simple chains', () => {
  const transitions = [{ from: 'initial', to: 'a' }, { from: 'a', to: 'b' }];
  const order = computeStateOrder('initial', transitions);
  expect(order.get('initial')).toBe(0);
  expect(order.get('a')).toBe(1);
  expect(order.get('b')).toBe(2);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `yarn workspace opencti-graphql test:unit -- workflow-ordering.test.ts`
Expected: FAIL — current `computeStateOrder` returns `null` for the whole map when any cycle exists, so `order` itself is `null` and `.get(...)` throws/fails.

- [ ] **Step 3: Write minimal implementation**

```ts
const MAX_DFS_STEPS = 5000; // workflow graphs are small (tens of states); generous safety cap

export const computeStateOrder = (
  initialState: string,
  transitions: OrderingTransition[],
): Map<string, number | null> => {
  const adjacency = buildAdjacency(transitions);
  const reachable = new Set<string>();
  const bfsQueue = [initialState];
  reachable.add(initialState);
  while (bfsQueue.length > 0) {
    const current = bfsQueue.shift() as string;
    (adjacency.get(current) ?? new Set()).forEach((n) => {
      if (!reachable.has(n)) { reachable.add(n); bfsQueue.push(n); }
    });
  }

  const longestOrder = new Map<string, number>();
  let steps = 0;
  let capExceeded = false;

  const dfs = (state: string, depth: number, pathVisited: Set<string>) => {
    if (capExceeded) return;
    steps += 1;
    if (steps > MAX_DFS_STEPS) { capExceeded = true; return; }
    const current = longestOrder.get(state);
    if (current === undefined || depth > current) longestOrder.set(state, depth);
    const neighbors = adjacency.get(state) ?? new Set<string>();
    neighbors.forEach((neighbor) => {
      if (pathVisited.has(neighbor)) return; // cycle back-edge on this path — stop this branch
      const nextVisited = new Set(pathVisited);
      nextVisited.add(neighbor);
      dfs(neighbor, depth + 1, nextVisited);
    });
  };
  dfs(initialState, 0, new Set([initialState]));

  const cyclicStates = statesOnCycles(initialState, transitions);
  const result = new Map<string, number | null>();
  reachable.forEach((state) => {
    result.set(state, (capExceeded || cyclicStates.has(state)) ? null : (longestOrder.get(state) ?? null));
  });
  return result;
};
```

Note: a state only ends up with `null` in `longestOrder` if it is unreachable via any DFS branch that terminated cleanly (e.g., only reachable by looping forever through a cycle with no acyclic entry) — in practice, entanglement in a cycle still yields *a* longest-simple-path value in this implementation, so cycle-entangled states need a separate, concrete detection pass rather than relying on `longestOrder` alone:

```ts
// Collects every state that lies on at least one cycle reachable from initialState, using a
// white/gray/black DFS: a back-edge to a 'gray' (on-stack) ancestor means every state currently
// on the stack between that ancestor and the current node (inclusive) is part of a cycle.
const statesOnCycles = (initialState: string, transitions: OrderingTransition[]): Set<string> => {
  const adjacency = buildAdjacency(transitions);
  const color = new Map<string, 'gray' | 'black'>();
  const stack: string[] = [];
  const onCycle = new Set<string>();

  const dfs = (state: string) => {
    color.set(state, 'gray');
    stack.push(state);
    (adjacency.get(state) ?? new Set<string>()).forEach((neighbor) => {
      const neighborColor = color.get(neighbor);
      if (neighborColor === 'gray') {
        const ancestorIndex = stack.indexOf(neighbor);
        for (let i = ancestorIndex; i < stack.length; i += 1) onCycle.add(stack[i]);
      } else if (neighborColor === undefined) {
        dfs(neighbor);
      }
    });
    stack.pop();
    color.set(state, 'black');
  };
  dfs(initialState);
  return onCycle;
};
```

Union this with the DFS-computed `longestOrder`: a state's final value is `null` if it is in `statesOnCycles(...)`'s result OR if the bounded-cap fallback was hit, otherwise its `longestOrder` value.

- [ ] **Step 4: Run test to verify it passes**

Run: same command as Step 2
Expected: PASS

- [ ] **Step 5: Update the caller and its tests**

In `workflow-domain.ts` line ~690 and `workflow-validation.ts` lines ~336-356, change consumption from a whole-map-null check to a per-state check using `.get(stateId)`. Add/update `workflow-validation.test.ts` cases mirroring the new scenarios (unrelated state auto-ordered despite a cycle elsewhere; cycle-entangled state still flagged `MISSING_MANUAL_ORDER`).

Run: `yarn workspace opencti-graphql test:unit -- workflow-validation.test.ts`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-ordering.ts opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-domain.ts opencti-platform/opencti-graphql/src/modules/workflow/workflow-validation.ts opencti-platform/opencti-graphql/tests/unit/modules/workflow/workflow-ordering.test.ts opencti-platform/opencti-graphql/tests/unit/modules/workflow/workflow-validation.test.ts
git commit -m "fix(backend): scope manual-order requirement to only cycle-entangled states"
```

---

## Task 10: Mass real-transition apply — backend action type

**Files:**
- Modify: `opencti-platform/opencti-graphql/src/manager/taskManager.js`
- Test: `opencti-platform/opencti-graphql/tests/unit/manager/taskManager-workflow-mass-transition.test.ts` (create)

**Interfaces:**
- Produces: `ACTION_TYPE_WORKFLOW_MASS_TRANSITION = 'WORKFLOW_MASS_TRANSITION'` (new constant, exported).
- Produces: `isWorkflowMassTransitionAction(action)` — recognizes an action targeting `x_opencti_workflow_id` with `context.options.eventName` set (distinct from the existing `isWorkflowTransitionAction`'s `applyTransitionActions === true` bypass marker).
- Produces: `workflowMassTransitionOperationCallback(context, user, task, operations)` — calls `triggerWorkflowEvent(context, user, element.internal_id, eventName, ...)` per element, catching and logging per-element errors exactly like `workflowTransitionOperationCallback` does for `setWorkflowStatus`.

- [ ] **Step 1: Write the failing test**

```ts
it('applies a real workflow transition to eligible elements and tolerates ineligible ones', async () => {
  const operations = [{ context: { field: 'x_opencti_workflow_id', options: { eventName: 'approve' } } }];
  const task = { id: 'task-1', task_processed_number: 0 };
  const callback = workflowMassTransitionOperationCallback(testContext, ADMIN_USER, task, operations);
  await callback([{ internal_id: eligibleElementId }, { internal_id: ineligibleElementId }]);
  const eligibleInstance = await getWorkflowInstance(testContext, ADMIN_USER, eligibleElementId);
  expect(eligibleInstance.currentState).toBe('approved');
  // ineligible element's state is unchanged, no exception thrown out of the callback
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `yarn workspace opencti-graphql test:unit -- taskManager-workflow-mass-transition.test.ts`
Expected: FAIL — `workflowMassTransitionOperationCallback` is not exported/does not exist.

- [ ] **Step 3: Write minimal implementation**

```js
export const ACTION_TYPE_WORKFLOW_MASS_TRANSITION = 'WORKFLOW_MASS_TRANSITION';

export const isWorkflowMassTransitionAction = (action) => (
  action.context?.field === WORKFLOW_TRANSITION_FIELD
  && typeof action.context?.options?.eventName === 'string'
);

export const workflowMassTransitionOperationCallback = (context, user, task, operations) => {
  const eventName = operations[0]?.context?.options?.eventName;
  let totalProcessed = task.task_processed_number;
  return async (elements) => {
    for (let index = 0; index < elements.length; index += 1) {
      await doYield();
      const element = elements[index];
      try {
        await triggerWorkflowEvent(context, user, element.internal_id, eventName);
      } catch (error) {
        logApp.error('[OPENCTI-MODULE][TASK-MANAGER] Task manager error during mass workflow transition, skipping element', { cause: error, id: element.internal_id });
      }
    }
    totalProcessed += elements.length;
    await updateTask(context, task.id, { task_processed_number: totalProcessed });
  };
};
```

Wire it into `computeOperationCallback`:

```js
if (actionType === ACTION_TYPE_WORKFLOW_MASS_TRANSITION) {
  return workflowMassTransitionOperationCallback(context, user, task, operations);
}
```

and into the action-type detection function (near `isWorkflowTransitionAction` usage, ~line 735) so `isWorkflowMassTransitionAction(action)` is checked before the existing bypass check (mass-transition and bypass both target `x_opencti_workflow_id`, so order matters — check `eventName` first, `applyTransitionActions === true` second).

- [ ] **Step 4: Run test to verify it passes**

Run: same command as Step 2
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add opencti-platform/opencti-graphql/src/manager/taskManager.js opencti-platform/opencti-graphql/tests/unit/manager/taskManager-workflow-mass-transition.test.ts
git commit -m "feat(backend): add mass real-transition task action calling triggerWorkflowEvent"
```

---

## Task 11: Mass real-transition apply — frontend UI

**Files:**
- Modify: `opencti-platform/opencti-front/src/private/components/data/DataTableToolBar.jsx`
- Test: `opencti-platform/opencti-front/src/private/components/data/__tests__/DataTableToolBar.test.tsx` (extend existing, or create)

**Interfaces:**
- Produces: a new mass-edit case `'x_opencti_workflow_id_transition'` alongside the existing `'x_opencti_workflow_id'` (bypass/legacy Status) option — only shown when `isWorkflowUiEnabledForType(selectedTypes[0], isFeatureEnable)` is true, offering an `Autocomplete` of the selected type's `allowedTransitions`-style event names (queried via a new lightweight `workflowTransitionEvents(entityType: String!): [String!]!` field or reuse `workflowDefinition.transitions[].event`, deduplicated), submitting a task with `context: { field: 'x_opencti_workflow_id', options: { eventName } }`.

- [ ] **Step 1: Write the failing test**

```tsx
it('shows a "Apply transition" mass-edit option for workflow-enabled types and submits eventName', () => {
  // render DataTableToolBar with selectedTypes=['Incident'], mock isWorkflowUiEnabledForType -> true
  // open the mass-edit menu, select "Apply transition", pick an event, submit
  // assert the task mutation is called with context.options.eventName set
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `yarn workspace opencti-graphql-frontend vitest run src/private/components/data/__tests__/DataTableToolBar.test.tsx`
Expected: FAIL — option does not exist yet.

- [ ] **Step 3: Write minimal implementation**

Add the new dropdown entry near the existing `{ label: t('Status'), value: 'x_opencti_workflow_id' }` (line ~1061), gated the same way but additionally checking `isWorkflowUiEnabledForType`. Add a new `case 'x_opencti_workflow_id_transition':` render branch near line ~1717 rendering an `Autocomplete` of transition events for the single selected type, and build the mutation's `context.options` to include `{ eventName: selectedEvent }` instead of the bypass's `applyTransitionActions`.

- [ ] **Step 4: Run test to verify it passes**

Run: same command as Step 2
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add opencti-platform/opencti-front/src/private/components/data/DataTableToolBar.jsx opencti-platform/opencti-front/src/private/components/data/__tests__/DataTableToolBar.test.tsx
git commit -m "feat(front): mass-apply a real workflow transition from the bulk toolbar"
```

---

## Task 12: Mass bypass forced status update — frontend UI

**Files:**
- Create: `opencti-platform/opencti-front/src/private/components/common/workflow/WorkflowBypassMassStatus.tsx`
- Modify: `opencti-platform/opencti-front/src/private/components/data/DataTableToolBar.jsx`
- Test: `opencti-platform/opencti-front/src/private/components/common/workflow/__tests__/WorkflowBypassMassStatus.test.tsx` (create)

**Interfaces:**
- Produces: `WorkflowBypassMassStatus({ entityType, selectedIds, selectAll, filters }: { entityType: string; selectedIds: string[]; selectAll: boolean; filters?: FilterGroup })` — mirrors `WorkflowBypassStatus.tsx`'s target-status + apply-actions-toggle + comment UI, gated on `isBypassUser`, submitting the existing bulk task mutation with `context: { field: 'x_opencti_workflow_id', options: { applyTransitionActions } }` (the already-implemented bypass mass-op path from `workflowTransitionOperationCallback`).

- [ ] **Step 1: Write the failing test**

```tsx
it('is hidden for non-bypass users and submits the bypass mass task for bypass users', () => {
  // render WorkflowBypassMassStatus with a mocked isBypassUser -> false: expect null render
  // rerender with isBypassUser -> true: pick a status, toggle apply-actions, submit
  // assert task mutation called with context.field 'x_opencti_workflow_id' and options.applyTransitionActions
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `yarn workspace opencti-graphql-frontend vitest run src/private/components/common/workflow/__tests__/WorkflowBypassMassStatus.test.tsx`
Expected: FAIL — component does not exist.

- [ ] **Step 3: Write minimal implementation**

Copy `WorkflowBypassStatus.tsx`'s status-fetch + toggle + comment UI, replacing the single-entity `setWorkflowStatus` mutation call with the existing bulk task-creation mutation (the one `DataTableToolBar.jsx` already uses for its `'x_opencti_workflow_id'` case), passing `selectedIds`/`selectAll`/`filters` instead of a single `entityId`. **Preserve `WorkflowBypassStatus.tsx`'s `{ key: 'scope', values: [StatusScopeEnum.GLOBAL] }` filter on the status search** — do not copy `DataTableToolBar.jsx`'s own plain `'x_opencti_workflow_id'` case's status search (`searchStatuses`, confirmed to have no `scope` filter at all, an unrelated pre-existing gap outside this change's scope) as the template instead. Wire the new component into `DataTableToolBar.jsx` as the bypass-only variant of the existing `'x_opencti_workflow_id'` case (shown instead of the plain Status autocomplete when `isBypassUser(me)` is true).

- [ ] **Step 4: Run test to verify it passes**

Run: same command as Step 2
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add opencti-platform/opencti-front/src/private/components/common/workflow/WorkflowBypassMassStatus.tsx opencti-platform/opencti-front/src/private/components/data/DataTableToolBar.jsx opencti-platform/opencti-front/src/private/components/common/workflow/__tests__/WorkflowBypassMassStatus.test.tsx
git commit -m "feat(front): bypass-only forced mass status update for bulk selections"
```

---

## Task 13: Rollout verification

**Files:**
- No new production files — this is a manual/e2e verification pass plus a config check.
- Modify (if needed): `opencti-platform/opencti-graphql/config/development.json` (`app.enabled_dev_features`) — confirm `ENTITIES_WORKFLOW` is included or `"*"` is set for local verification.

- [ ] **Step 1:** Run the full unit suite for the touched backend modules:

Run: `yarn workspace opencti-graphql test:unit -- src/modules/workflow`
Expected: PASS

- [ ] **Step 2:** Run the full unit suite for the touched frontend components:

Run: `yarn workspace opencti-graphql-frontend vitest run src/private/components/settings/sub_types src/private/components/common/workflow src/private/components/data/DataTableToolBar.test.tsx`
Expected: PASS

- [ ] **Step 3:** Manually verify end-to-end in a local dev stack (per repo instructions: `cd opencti-platform/opencti-dev && docker compose up -d`, then `yarn dev:venv` from repo root) for one non-DraftWorkspace type (e.g. `Incident`) in `GLOBAL` scope: open Workflow tab → confirm migration dialog → confirm → verify graph editor loads and edits persist.

- [ ] **Step 4:** Repeat Step 3 for `RequestAccess` scope on an EE-licensed instance for a type with `request_access_workflow` configured, then submit and approve/decline a real Request-For-Information (RFI) and confirm the `WorkflowInstance`'s `currentState`/history for that RFI reflects the approve/decline outcome (the concrete scenario Task 7 fixed).

- [ ] **Step 5:** Manually verify both new mass-op UIs (real-transition mass-apply, bypass forced mass update) against a multi-row selection in a list view for the migrated type.

- [ ] **Step 6: Commit** (only if config changes were needed)

```bash
git add opencti-platform/opencti-graphql/config/development.json
git commit -m "chore: enable ENTITIES_WORKFLOW for local verification"
```
