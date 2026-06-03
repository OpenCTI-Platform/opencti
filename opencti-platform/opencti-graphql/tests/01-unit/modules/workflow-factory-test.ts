import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WorkflowFactory } from '../../../src/modules/workflow/engine/workflow-factory';
import type { WorkflowSchema } from '../../../src/modules/workflow/engine/workflow-schema';
import * as workflowActionsModule from '../../../src/modules/workflow/registry/workflow-actions';
import { FilterMode, FilterOperator } from '../../../src/generated/graphql';

// ---------------------------------------------------------------------------
// Mock heavy dependencies
// ---------------------------------------------------------------------------
vi.mock('../../../src/modules/workflow/registry/workflow-actions', () => ({
  ActionRegistry: {},
  ActionDefinitions: {},
}));

vi.mock('../../../src/config/conf', () => ({
  logApp: { info: vi.fn(), error: vi.fn(), warn: vi.fn() },
}));

// ---------------------------------------------------------------------------
// Minimal schema builder helpers
// ---------------------------------------------------------------------------
const makeSchema = (transitionOverrides: Partial<WorkflowSchema['transitions'][0]> = {}): WorkflowSchema => ({
  id: 'wf-1',
  name: 'Test workflow',
  initialState: 'draft',
  states: [
    { statusId: 'draft' },
    { statusId: 'review' },
  ],
  transitions: [
    {
      from: 'draft',
      to: 'review',
      event: 'submit',
      ...transitionOverrides,
    },
  ],
});

// ---------------------------------------------------------------------------
// WorkflowFactory.createDefinition – comment propagation
// ---------------------------------------------------------------------------

describe('WorkflowFactory.createDefinition – comment field', () => {
  it('propagates the comment from the schema to the transition definition', () => {
    const schema = makeSchema({ comment: 'Needs manager approval' });
    const definition = WorkflowFactory.createDefinition(schema);

    const transition = definition.getTransition('draft', 'submit');
    expect(transition).toBeDefined();
    expect(transition!.comment).toBe('Needs manager approval');
  });

  it('leaves comment undefined when the schema transition has no comment', () => {
    const schema = makeSchema(); // no comment field
    const definition = WorkflowFactory.createDefinition(schema);

    const transition = definition.getTransition('draft', 'submit');
    expect(transition).toBeDefined();
    expect(transition!.comment).toBeUndefined();
  });

  it('propagates distinct comments across multiple transitions', () => {
    const schema: WorkflowSchema = {
      id: 'wf-multi',
      name: 'Multi-transition',
      initialState: 'draft',
      states: [
        { statusId: 'draft' },
        { statusId: 'review' },
        { statusId: 'approved' },
      ],
      transitions: [
        { from: 'draft', to: 'review', event: 'submit', comment: 'Submit for review' },
        { from: 'review', to: 'approved', event: 'approve', comment: 'Approved by manager' },
      ],
    };

    const definition = WorkflowFactory.createDefinition(schema);

    expect(definition.getTransition('draft', 'submit')!.comment).toBe('Submit for review');
    expect(definition.getTransition('review', 'approve')!.comment).toBe('Approved by manager');
  });

  it('handles a mix of transitions with and without comments', () => {
    const schema: WorkflowSchema = {
      id: 'wf-mixed',
      name: 'Mixed comments',
      initialState: 'draft',
      states: [
        { statusId: 'draft' },
        { statusId: 'review' },
        { statusId: 'rejected' },
      ],
      transitions: [
        { from: 'draft', to: 'review', event: 'submit', comment: 'Needs review' },
        { from: 'draft', to: 'rejected', event: 'reject' }, // no comment
      ],
    };

    const definition = WorkflowFactory.createDefinition(schema);

    expect(definition.getTransition('draft', 'submit')!.comment).toBe('Needs review');
    expect(definition.getTransition('draft', 'reject')!.comment).toBeUndefined();
  });

  it('exposes comment via getTransitions for all outgoing transitions from a state', () => {
    const schema: WorkflowSchema = {
      id: 'wf-out',
      name: 'Outgoing',
      initialState: 'draft',
      states: [
        { statusId: 'draft' },
        { statusId: 'review' },
        { statusId: 'archived' },
      ],
      transitions: [
        { from: 'draft', to: 'review', event: 'submit', comment: 'For review' },
        { from: 'draft', to: 'archived', event: 'archive' },
      ],
    };

    const definition = WorkflowFactory.createDefinition(schema);
    const transitions = definition.getTransitions('draft');

    expect(transitions).toHaveLength(2);
    const submitTransition = transitions.find((t) => t.event === 'submit');
    const archiveTransition = transitions.find((t) => t.event === 'archive');

    expect(submitTransition!.comment).toBe('For review');
    expect(archiveTransition!.comment).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// WorkflowFactory.getInstance – comment accessible on the produced instance
// ---------------------------------------------------------------------------

describe('WorkflowFactory.getInstance – comment accessible via definition', () => {
  it('the instance definition retains the transition comment', () => {
    const schema = makeSchema({ comment: 'Instance comment check' });
    const definition = WorkflowFactory.createDefinition(schema);
    WorkflowFactory.getInstance(schema, definition, 'draft', { user: {}, entity: {}, context: {} } as any);

    // Verify via the definition directly – the instance is built from this definition
    const transitions = definition.getTransitions('draft');
    expect(transitions).toHaveLength(1);
    expect(transitions[0].comment).toBe('Instance comment check');
  });

  it('the instance definition exposes undefined comment when not set', () => {
    const schema = makeSchema(); // no comment
    const definition = WorkflowFactory.createDefinition(schema);
    WorkflowFactory.getInstance(schema, definition, 'draft', { user: {}, entity: {}, context: {} } as any);

    const transitions = definition.getTransitions('draft');
    expect(transitions).toHaveLength(1);
    expect(transitions[0].comment).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// WorkflowFactory – evaluateFilter operators (tested via createConditions)
// ---------------------------------------------------------------------------

describe('WorkflowFactory – evaluateFilter operators', () => {
  const evalFilter = async (
    key: string,
    operator: string,
    values: string[],
    ctx: any,
    filterMode: string = FilterMode.Or,
  ): Promise<boolean> => {
    const conditions = WorkflowFactory.createConditions({
      filters: {
        mode: FilterMode.And,
        filters: [{ key, operator, values, mode: filterMode }],
        filterGroups: [],
      } as any,
    });
    return conditions[0](ctx as any);
  };

  const nameCtx = (name: string) => ({ entity: { name }, user: {}, context: {} });

  it('eq – matches scalar value', async () => {
    expect(await evalFilter('name', FilterOperator.Eq, ['Alice'], nameCtx('Alice'))).toBe(true);
  });

  it('eq – does not match different scalar', async () => {
    expect(await evalFilter('name', FilterOperator.Eq, ['Alice'], nameCtx('Bob'))).toBe(false);
  });

  it('eq – matches when actual is an array containing the value', async () => {
    const ctx = { entity: {}, user: { groups: [{ id: 'g1' }, { id: 'g2' }] }, context: {} };
    expect(await evalFilter('workflow_group', FilterOperator.Eq, ['g1'], ctx)).toBe(true);
  });

  it('eq – does not match when array does not contain value', async () => {
    const ctx = { entity: {}, user: { groups: [{ id: 'g2' }] }, context: {} };
    expect(await evalFilter('workflow_group', FilterOperator.Eq, ['g1'], ctx)).toBe(false);
  });

  it('notEq – true when scalar does not match', async () => {
    expect(await evalFilter('name', FilterOperator.NotEq, ['Alice'], nameCtx('Bob'))).toBe(true);
  });

  it('notEq – false when scalar matches', async () => {
    expect(await evalFilter('name', FilterOperator.NotEq, ['Alice'], nameCtx('Alice'))).toBe(false);
  });

  it('notEq – false when array contains the value', async () => {
    const ctx = { entity: {}, user: { groups: [{ id: 'g1' }] }, context: {} };
    expect(await evalFilter('workflow_group', FilterOperator.NotEq, ['g1'], ctx)).toBe(false);
  });

  it('gt – true when actual > expected', async () => {
    const ctx = { entity: { level: '9' }, user: {}, context: {} };
    expect(await evalFilter('entity.level', FilterOperator.Gt, ['5'], ctx)).toBe(true);
  });

  it('gt – false when actual <= expected', async () => {
    const ctx = { entity: { level: '3' }, user: {}, context: {} };
    expect(await evalFilter('entity.level', FilterOperator.Gt, ['5'], ctx)).toBe(false);
  });

  it('gte – true when actual equals expected', async () => {
    const ctx = { entity: { level: '5' }, user: {}, context: {} };
    expect(await evalFilter('entity.level', FilterOperator.Gte, ['5'], ctx)).toBe(true);
  });

  it('lt – true when actual < expected', async () => {
    const ctx = { entity: { level: '3' }, user: {}, context: {} };
    expect(await evalFilter('entity.level', FilterOperator.Lt, ['5'], ctx)).toBe(true);
  });

  it('lt – false when actual >= expected', async () => {
    const ctx = { entity: { level: '9' }, user: {}, context: {} };
    expect(await evalFilter('entity.level', FilterOperator.Lt, ['5'], ctx)).toBe(false);
  });

  it('lte – true when actual equals expected', async () => {
    const ctx = { entity: { level: '5' }, user: {}, context: {} };
    expect(await evalFilter('entity.level', FilterOperator.Lte, ['5'], ctx)).toBe(true);
  });

  it('nil – true when value is empty string', async () => {
    expect(await evalFilter('name', FilterOperator.Nil, [''], nameCtx(''))).toBe(true);
  });

  it('nil – true when property is missing (undefined)', async () => {
    expect(await evalFilter('name', FilterOperator.Nil, [''], { entity: {}, user: {}, context: {} })).toBe(true);
  });

  it('nil – false when value is present', async () => {
    expect(await evalFilter('name', FilterOperator.Nil, [''], nameCtx('present'))).toBe(false);
  });

  it('notNil – true when value is present', async () => {
    expect(await evalFilter('name', FilterOperator.NotNil, [''], nameCtx('Alice'))).toBe(true);
  });

  it('notNil – false when value is empty string', async () => {
    expect(await evalFilter('name', FilterOperator.NotNil, [''], nameCtx(''))).toBe(false);
  });

  it('contains – true when string contains value (case-insensitive)', async () => {
    expect(await evalFilter('name', FilterOperator.Contains, ['alice'], nameCtx('Alice Smith'))).toBe(true);
  });

  it('contains – false when string does not contain value', async () => {
    expect(await evalFilter('name', FilterOperator.Contains, ['bob'], nameCtx('Alice Smith'))).toBe(false);
  });

  it('contains – true when array includes value', async () => {
    const ctx = { entity: {}, user: { groups: [{ id: 'g1' }] }, context: {} };
    expect(await evalFilter('workflow_group', FilterOperator.Contains, ['g1'], ctx)).toBe(true);
  });

  it('startsWith – true when string starts with value (case-insensitive)', async () => {
    expect(await evalFilter('name', FilterOperator.StartsWith, ['ali'], nameCtx('Alice'))).toBe(true);
  });

  it('startsWith – false when string does not start with value', async () => {
    expect(await evalFilter('name', FilterOperator.StartsWith, ['bob'], nameCtx('Alice'))).toBe(false);
  });

  it('unknown operator – returns false', async () => {
    expect(await evalFilter('name', 'unknown_op' as any, ['x'], nameCtx('x'))).toBe(false);
  });

  it('filter OR mode – returns true when any value matches', async () => {
    expect(await evalFilter('name', FilterOperator.Eq, ['Alice', 'Bob'], nameCtx('Alice'), FilterMode.Or)).toBe(true);
  });

  it('filter AND mode – requires all values to produce true results', async () => {
    // 'Alice' == 'Alice' → true, 'Alice' == 'Bob' → false → AND = false
    expect(await evalFilter('name', FilterOperator.Eq, ['Alice', 'Bob'], nameCtx('Alice'), FilterMode.And)).toBe(false);
  });

  it('returns true when key is missing (null/falsy)', async () => {
    const conditions = WorkflowFactory.createConditions({
      filters: {
        mode: FilterMode.And,
        filters: [{ key: null as any, operator: FilterOperator.Eq, values: ['x'], mode: FilterMode.Or }],
        filterGroups: [],
      } as any,
    });
    expect(await conditions[0](nameCtx('x') as any)).toBe(true);
  });

  it('returns true when operator is missing (null/falsy)', async () => {
    const conditions = WorkflowFactory.createConditions({
      filters: {
        mode: FilterMode.And,
        filters: [{ key: 'name', operator: null as any, values: ['x'], mode: FilterMode.Or }],
        filterGroups: [],
      } as any,
    });
    expect(await conditions[0](nameCtx('x') as any)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// WorkflowFactory – evaluateFilterGroup modes and nesting
// ---------------------------------------------------------------------------

describe('WorkflowFactory – evaluateFilterGroup modes', () => {
  const nameCtx = (name: string) => ({ entity: { name }, user: {}, context: {} });

  it('AND group: returns false when any filter fails', async () => {
    const conditions = WorkflowFactory.createConditions({
      filters: {
        mode: FilterMode.And,
        filters: [
          { key: 'name', operator: FilterOperator.Eq, values: ['Alice'], mode: FilterMode.Or },
          { key: 'name', operator: FilterOperator.Eq, values: ['Bob'], mode: FilterMode.Or },
        ],
        filterGroups: [],
      } as any,
    });
    expect(await conditions[0](nameCtx('Alice') as any)).toBe(false);
  });

  it('AND group: returns true when all filters pass', async () => {
    const conditions = WorkflowFactory.createConditions({
      filters: {
        mode: FilterMode.And,
        filters: [
          { key: 'name', operator: FilterOperator.Eq, values: ['Alice'], mode: FilterMode.Or },
          { key: 'name', operator: FilterOperator.NotEq, values: ['Bob'], mode: FilterMode.Or },
        ],
        filterGroups: [],
      } as any,
    });
    expect(await conditions[0](nameCtx('Alice') as any)).toBe(true);
  });

  it('OR group: returns true when any filter passes', async () => {
    const conditions = WorkflowFactory.createConditions({
      filters: {
        mode: FilterMode.Or,
        filters: [
          { key: 'name', operator: FilterOperator.Eq, values: ['Alice'], mode: FilterMode.Or },
          { key: 'name', operator: FilterOperator.Eq, values: ['Bob'], mode: FilterMode.Or },
        ],
        filterGroups: [],
      } as any,
    });
    expect(await conditions[0](nameCtx('Bob') as any)).toBe(true);
  });

  it('OR group: returns false when no filter passes', async () => {
    const conditions = WorkflowFactory.createConditions({
      filters: {
        mode: FilterMode.Or,
        filters: [
          { key: 'name', operator: FilterOperator.Eq, values: ['Alice'], mode: FilterMode.Or },
          { key: 'name', operator: FilterOperator.Eq, values: ['Bob'], mode: FilterMode.Or },
        ],
        filterGroups: [],
      } as any,
    });
    expect(await conditions[0](nameCtx('Charlie') as any)).toBe(false);
  });

  it('empty group (no filters, no filterGroups) returns true', async () => {
    const conditions = WorkflowFactory.createConditions({
      filters: {
        mode: FilterMode.And,
        filters: [],
        filterGroups: [],
      } as any,
    });
    expect(await conditions[0](nameCtx('anything') as any)).toBe(true);
  });

  it('nested filterGroups are evaluated recursively', async () => {
    const conditions = WorkflowFactory.createConditions({
      filters: {
        mode: FilterMode.And,
        filters: [],
        filterGroups: [
          {
            mode: FilterMode.Or,
            filters: [
              { key: 'name', operator: FilterOperator.Eq, values: ['Alice'], mode: FilterMode.Or },
              { key: 'name', operator: FilterOperator.Eq, values: ['Bob'], mode: FilterMode.Or },
            ],
            filterGroups: [],
          },
        ],
      } as any,
    });
    expect(await conditions[0](nameCtx('Alice') as any)).toBe(true);
    expect(await conditions[0](nameCtx('Charlie') as any)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// WorkflowFactory.createConditions – edge cases
// ---------------------------------------------------------------------------

describe('WorkflowFactory.createConditions – edge cases', () => {
  it('returns an empty array when called with no argument', () => {
    expect(WorkflowFactory.createConditions()).toEqual([]);
  });

  it('returns an empty array when filters is undefined', () => {
    expect(WorkflowFactory.createConditions({ filters: undefined as any })).toEqual([]);
  });

  it('returns a single validator when filters are provided', () => {
    const validators = WorkflowFactory.createConditions({
      filters: { mode: FilterMode.And, filters: [], filterGroups: [] } as any,
    });
    expect(validators).toHaveLength(1);
    expect(typeof validators[0]).toBe('function');
  });
});

// ---------------------------------------------------------------------------
// WorkflowFactory – getNestedValue special keys
// ---------------------------------------------------------------------------

describe('WorkflowFactory – getNestedValue special keys', () => {
  const evalWithKey = async (key: string, values: string[], ctx: any): Promise<boolean> => {
    const conditions = WorkflowFactory.createConditions({
      filters: {
        mode: FilterMode.And,
        filters: [{ key, operator: FilterOperator.Eq, values, mode: FilterMode.Or }],
        filterGroups: [],
      } as any,
    });
    return conditions[0](ctx as any);
  };

  it('workflow_group resolves to user.groups[].id', async () => {
    const ctx = { entity: {}, user: { groups: [{ id: 'g1' }] }, context: {} };
    expect(await evalWithKey('workflow_group', ['g1'], ctx)).toBe(true);
  });

  it('workflow_organization resolves to user.organizations[].id', async () => {
    const ctx = { entity: {}, user: { organizations: [{ id: 'org-1' }] }, context: {} };
    expect(await evalWithKey('workflow_organization', ['org-1'], ctx)).toBe(true);
  });

  it('workflow_role resolves to user.roles[].name', async () => {
    const ctx = { entity: {}, user: { roles: [{ name: 'Admin' }] }, context: {} };
    expect(await evalWithKey('workflow_role', ['Admin'], ctx)).toBe(true);
  });

  it('workflow_user resolves to user.id', async () => {
    const ctx = { entity: {}, user: { id: 'user-42' }, context: {} };
    expect(await evalWithKey('workflow_user', ['user-42'], ctx)).toBe(true);
  });

  it('workflow_user falls back to user.internal_id when id is absent', async () => {
    const ctx = { entity: {}, user: { internal_id: 'uid-99' }, context: {} };
    expect(await evalWithKey('workflow_user', ['uid-99'], ctx)).toBe(true);
  });

  it('dotted path resolves a nested property', async () => {
    const ctx = { entity: { meta: { priority: 'high' } }, user: {}, context: {} };
    expect(await evalWithKey('entity.meta.priority', ['high'], ctx)).toBe(true);
  });

  it('array key flatMaps values from multiple fields', async () => {
    const ctx = { entity: { name: 'Alice' }, user: {}, context: {} };
    const conditions = WorkflowFactory.createConditions({
      filters: {
        mode: FilterMode.And,
        filters: [{ key: ['name', 'name'] as any, operator: FilterOperator.Eq, values: ['Alice'], mode: FilterMode.Or }],
        filterGroups: [],
      } as any,
    });
    expect(await conditions[0](ctx as any)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// WorkflowFactory.createSideEffects
// ---------------------------------------------------------------------------

describe('WorkflowFactory.createSideEffects', () => {
  beforeEach(() => {
    delete (workflowActionsModule.ActionRegistry as any)['testSync'];
    delete (workflowActionsModule.ActionRegistry as any)['testAsync'];
  });

  it('returns an empty array when called with no argument', () => {
    expect(WorkflowFactory.createSideEffects()).toEqual([]);
  });

  it('returns an empty array when given an empty array', () => {
    expect(WorkflowFactory.createSideEffects([])).toEqual([]);
  });

  it('returns a no-op function for an unknown action type', async () => {
    const sideEffects = WorkflowFactory.createSideEffects([{ type: 'unknownAction', mode: 'sync' as any }]);
    expect(sideEffects).toHaveLength(1);
    await expect(sideEffects[0]({} as any)).resolves.toBeUndefined();
  });

  it('executes a sync action and awaits its completion', async () => {
    const mockFn = vi.fn().mockResolvedValue(undefined);
    (workflowActionsModule.ActionRegistry as any)['testSync'] = mockFn;

    const sideEffects = WorkflowFactory.createSideEffects([{ type: 'testSync', mode: 'sync' as any }]);
    const ctx = { user: {}, entity: {}, context: {} };
    await sideEffects[0](ctx as any);

    expect(mockFn).toHaveBeenCalledWith(ctx, undefined);
  });

  it('passes params to the sync action', async () => {
    const mockFn = vi.fn().mockResolvedValue(undefined);
    (workflowActionsModule.ActionRegistry as any)['testSync'] = mockFn;

    const params = { message: 'hello' };
    const sideEffects = WorkflowFactory.createSideEffects([{ type: 'testSync', mode: 'sync' as any, params }]);
    const ctx = { user: {}, entity: {}, context: {} };
    await sideEffects[0](ctx as any);

    expect(mockFn).toHaveBeenCalledWith(ctx, params);
  });

  it('executes an async action (fire-and-forget) without throwing', async () => {
    const mockFn = vi.fn().mockResolvedValue(undefined);
    (workflowActionsModule.ActionRegistry as any)['testAsync'] = mockFn;

    const sideEffects = WorkflowFactory.createSideEffects([{ type: 'testAsync', mode: 'async' as any }]);
    const ctx = { user: {}, entity: {}, context: {} };
    await sideEffects[0](ctx as any);

    expect(mockFn).toHaveBeenCalledWith(ctx, undefined);
  });

  it('async action errors are caught silently (fire-and-forget)', async () => {
    const mockFn = vi.fn().mockRejectedValue(new Error('boom'));
    (workflowActionsModule.ActionRegistry as any)['testAsync'] = mockFn;

    const sideEffects = WorkflowFactory.createSideEffects([{ type: 'testAsync', mode: 'async' as any }]);
    await expect(sideEffects[0]({} as any)).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// WorkflowFactory.getInstance – error and branch paths
// ---------------------------------------------------------------------------

describe('WorkflowFactory.getInstance – error and branch paths', () => {
  it('throws when neither schema nor defaultDefinition is provided', () => {
    expect(() =>
      WorkflowFactory.getInstance(undefined, undefined, 'draft', {} as any),
    ).toThrow('No workflow definition provided');
  });

  it('uses defaultDefinition when no schema is provided', () => {
    const schema = makeSchema();
    const defaultDef = WorkflowFactory.createDefinition(schema);
    const instance = WorkflowFactory.getInstance(undefined, defaultDef, 'draft', {} as any);
    expect(instance.getCurrentState()).toBe('draft');
  });

  it('schema takes precedence over defaultDefinition', () => {
    const schema = makeSchema();
    const defaultDef = WorkflowFactory.createDefinition(schema);
    const instance = WorkflowFactory.getInstance(schema, defaultDef, 'review', {} as any);
    expect(instance.getCurrentState()).toBe('review');
  });
});
