import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WorkflowFactory } from '../../../src/modules/workflow/engine/workflow-factory';
import type { WorkflowSchema } from '../../../src/modules/workflow/engine/workflow-schema';
import { FilterMode, FilterOperator, type Filter, type FilterGroup } from '../../../src/generated/graphql';
import { SYSTEM_USER } from '../../../src/utils/access';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';

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

const { stixLoadByIdMock, stixLoadByIdsMock, isStixMatchFilterGroupMock, buildResolutionMapMock } = vi.hoisted(() => ({
  stixLoadByIdMock: vi.fn(),
  stixLoadByIdsMock: vi.fn(),
  isStixMatchFilterGroupMock: vi.fn(),
  buildResolutionMapMock: vi.fn(),
}));

vi.mock('../../../src/utils/access', () => ({
  SYSTEM_USER: { id: 'system-user' },
}));

vi.mock('../../../src/database/middleware', () => ({
  stixLoadById: stixLoadByIdMock,
  stixLoadByIds: stixLoadByIdsMock,
}));

vi.mock('../../../src/utils/filtering/filtering-stix/stix-filtering', () => ({
  isStixMatchFilterGroup_MockableForUnitTests: isStixMatchFilterGroupMock,
}));

vi.mock('../../../src/utils/filtering/filtering-constants', () => ({
  FILTER_KEYS_WITH_ME_VALUE: ['objectAssignee', 'objectParticipant'],
  ME_FILTER_VALUE: '@me',
}));

vi.mock('../../../src/utils/filtering/filtering-resolution', () => ({
  extractFilterGroupValuesToResolveForCache: (fg: FilterGroup) => {
    const extract = (g: FilterGroup): string[] => [
      ...g.filters.filter((f) => f.key[0] === 'objectLabel').flatMap((f) => f.values),
      ...g.filterGroups.flatMap(extract),
    ];
    return extract(fg);
  },
  buildResolutionMapForFilterGroup: buildResolutionMapMock,
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
// WorkflowFactory.createConditions – entity attribute filters
// ---------------------------------------------------------------------------

describe('WorkflowFactory.createConditions – entity attribute filters', () => {
  const stixEntity = { id: 'report--1', type: 'report' };
  const authContext = { source: 'test' };
  const conditionContext = () => ({
    entity: { internal_id: 'entity-1', entity_type: 'Report', name: 'My report' },
    user: { id: 'manager' },
    triggeringUser: { id: 'user-1', groups: [{ id: 'group-1' }], organizations: [] },
    context: authContext,
  });
  const filter = (key: string, values: string[], operator = FilterOperator.Eq): Filter => ({ key: [key], values, operator, mode: FilterMode.Or });
  const group = (mode: FilterMode, filters: Filter[], filterGroups: FilterGroup[] = []): FilterGroup => ({ mode, filters, filterGroups });
  const evaluate = (filters: FilterGroup) => WorkflowFactory.createConditions({ filters })[0](conditionContext() as any);

  const resolutionMap = new Map([['label-1', 'malware']]);
  const labelStix = { id: 'label--1', value: 'malware', extensions: { [STIX_EXT_OCTI]: { id: 'label-1' } } };

  beforeEach(() => {
    stixLoadByIdMock.mockReset().mockResolvedValue(stixEntity);
    stixLoadByIdsMock.mockReset().mockResolvedValue([labelStix]);
    buildResolutionMapMock.mockReset().mockResolvedValue(resolutionMap);
    isStixMatchFilterGroupMock.mockReset();
  });

  it('evaluates workflow user keys without loading the entity', async () => {
    const result = await evaluate(group(FilterMode.And, [filter('workflow_group', ['group-1'])]));
    expect(result).toBe(true);
    expect(stixLoadByIdMock).not.toHaveBeenCalled();
    expect(isStixMatchFilterGroupMock).not.toHaveBeenCalled();
  });

  it('delegates an entity attribute filter to the stix matcher on the loaded entity', async () => {
    isStixMatchFilterGroupMock.mockResolvedValue(true);
    const labelFilter = filter('objectLabel', ['label-1']);
    const result = await evaluate(group(FilterMode.And, [labelFilter]));
    expect(result).toBe(true);
    expect(stixLoadByIdMock).toHaveBeenCalledWith(authContext, SYSTEM_USER, 'entity-1');
    expect(isStixMatchFilterGroupMock).toHaveBeenCalledWith(authContext, SYSTEM_USER, stixEntity, group(FilterMode.And, [labelFilter]), resolutionMap);
  });

  it('resolves filter values from the database, not from the stream filters cache', async () => {
    isStixMatchFilterGroupMock.mockResolvedValue(true);
    const labelGroup = group(FilterMode.And, [filter('objectLabel', ['label-1'])]);
    await evaluate(labelGroup);
    expect(stixLoadByIdsMock).toHaveBeenCalledWith(authContext, SYSTEM_USER, ['label-1']);
    expect(buildResolutionMapMock).toHaveBeenCalledWith(authContext, SYSTEM_USER, labelGroup, new Map([['label-1', labelStix]]));
  });

  it('skips the resolution load when no filter value needs resolving', async () => {
    isStixMatchFilterGroupMock.mockResolvedValue(true);
    await evaluate(group(FilterMode.And, [filter('workflow_id', ['status-1'])]));
    expect(stixLoadByIdsMock).not.toHaveBeenCalled();
  });

  it('accepts entity filter keys stored as a plain string', async () => {
    isStixMatchFilterGroupMock.mockResolvedValue(true);
    const stringKeyFilter = { ...filter('workflow_id', ['status-1']), key: 'workflow_id' } as unknown as Filter;
    await evaluate(group(FilterMode.And, [stringKeyFilter]));
    expect(isStixMatchFilterGroupMock.mock.calls[0][3].filters[0].key).toEqual(['workflow_id']);
  });

  it('fails the filter instead of throwing when the stix matcher rejects it', async () => {
    isStixMatchFilterGroupMock.mockRejectedValue(new Error('Stix filtering is not compatible with the provided filter key'));
    expect(await evaluate(group(FilterMode.And, [filter('created_at', ['2026-01-01'])]))).toBe(false);
  });

  it('fails the condition when the stix matcher does not match', async () => {
    isStixMatchFilterGroupMock.mockResolvedValue(false);
    expect(await evaluate(group(FilterMode.And, [filter('workflow_id', ['status-1'])]))).toBe(false);
  });

  it('combines user keys and entity keys in an AND group', async () => {
    isStixMatchFilterGroupMock.mockResolvedValue(false);
    const result = await evaluate(group(FilterMode.And, [filter('workflow_group', ['group-1']), filter('objectLabel', ['label-1'])]));
    expect(result).toBe(false);
  });

  it('combines user keys and entity keys in an OR group', async () => {
    isStixMatchFilterGroupMock.mockResolvedValue(true);
    const result = await evaluate(group(FilterMode.Or, [filter('workflow_group', ['other-group']), filter('objectLabel', ['label-1'])]));
    expect(result).toBe(true);
  });

  it('evaluates entity keys inside nested filter groups', async () => {
    isStixMatchFilterGroupMock.mockResolvedValue(true);
    const nested = group(FilterMode.And, [filter('objectMarking', ['marking-1'])]);
    const result = await evaluate(group(FilterMode.And, [filter('workflow_group', ['group-1'])], [nested]));
    expect(result).toBe(true);
    expect(isStixMatchFilterGroupMock).toHaveBeenCalledTimes(1);
  });

  it('loads the stix entity only once per evaluation', async () => {
    isStixMatchFilterGroupMock.mockResolvedValue(true);
    await evaluate(group(FilterMode.And, [filter('objectLabel', ['label-1']), filter('workflow_id', ['status-1'])]));
    expect(isStixMatchFilterGroupMock).toHaveBeenCalledTimes(2);
    expect(stixLoadByIdMock).toHaveBeenCalledTimes(1);
  });

  it('shares the loaded entity and resolved values across the transitions of a same context', async () => {
    isStixMatchFilterGroupMock.mockResolvedValue(true);
    const ctx = conditionContext();
    const [first] = WorkflowFactory.createConditions({ filters: group(FilterMode.And, [filter('objectLabel', ['label-1'])]) });
    const [second] = WorkflowFactory.createConditions({ filters: group(FilterMode.And, [filter('objectLabel', ['label-1'])]) });
    await Promise.all([first(ctx as any), second(ctx as any)]);
    expect(stixLoadByIdMock).toHaveBeenCalledTimes(1);
    expect(stixLoadByIdsMock).toHaveBeenCalledTimes(1);
  });

  it('resolves the values of a whole condition in a single load', async () => {
    isStixMatchFilterGroupMock.mockResolvedValue(true);
    const nested = group(FilterMode.Or, [filter('objectLabel', ['label-2'])]);
    await evaluate(group(FilterMode.And, [filter('objectLabel', ['label-1'])], [nested]));
    expect(stixLoadByIdsMock).toHaveBeenCalledTimes(1);
    expect(stixLoadByIdsMock).toHaveBeenCalledWith(authContext, SYSTEM_USER, ['label-1', 'label-2']);
  });

  it('replaces @me with the user triggering the transition', async () => {
    isStixMatchFilterGroupMock.mockResolvedValue(true);
    await evaluate(group(FilterMode.And, [filter('objectAssignee', ['@me', 'other-user'])]));
    expect(isStixMatchFilterGroupMock.mock.calls[0][3].filters[0].values).toEqual(['user-1', 'other-user']);
  });

  it('fails an entity attribute filter when the entity cannot be loaded', async () => {
    stixLoadByIdMock.mockResolvedValue(null);
    expect(await evaluate(group(FilterMode.And, [filter('objectLabel', ['label-1'])]))).toBe(false);
    expect(isStixMatchFilterGroupMock).not.toHaveBeenCalled();
  });

  it('keeps evaluating the name key against the entity name', async () => {
    // the frontend stores the filter key as a plain string
    const nameFilter = { ...filter('name', ['report'], FilterOperator.Contains), key: 'name' } as unknown as Filter;
    expect(await evaluate(group(FilterMode.And, [nameFilter]))).toBe(true);
    expect(stixLoadByIdMock).not.toHaveBeenCalled();
  });
});
