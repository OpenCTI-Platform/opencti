import { describe, expect, it, vi, beforeEach } from 'vitest';

const fullRelationsList = vi.fn();
const fullEntitiesList = vi.fn();
const stixObjectOrRelationshipAddRefRelation = vi.fn();
const stixObjectOrRelationshipDeleteRefRelation = vi.fn();
const mergeEntities = vi.fn();
const patchAttribute = vi.fn();
const createRelation = vi.fn();
const deleteElementById = vi.fn();

vi.mock('../../../../src/database/middleware-loader', () => ({
  fullRelationsList: (...args: unknown[]) => fullRelationsList(...args),
  fullEntitiesList: (...args: unknown[]) => fullEntitiesList(...args),
}));
vi.mock('../../../../src/domain/stixObjectOrStixRelationship', () => ({
  stixObjectOrRelationshipAddRefRelation: (...args: unknown[]) => stixObjectOrRelationshipAddRefRelation(...args),
  stixObjectOrRelationshipDeleteRefRelation: (...args: unknown[]) => stixObjectOrRelationshipDeleteRefRelation(...args),
}));
vi.mock('../../../../src/database/middleware', () => ({
  mergeEntities: (...args: unknown[]) => mergeEntities(...args),
  patchAttribute: (...args: unknown[]) => patchAttribute(...args),
  createRelation: (...args: unknown[]) => createRelation(...args),
  deleteElementById: (...args: unknown[]) => deleteElementById(...args),
}));
vi.mock('../../../../src/database/redis', () => ({ notify: vi.fn() }));

const { userMergeOperationalRelationsHandler } = await import('../../../../src/modules/userMerge/userMerge-operationalRelationsHandler');
const { userMergeIndividualHandler } = await import('../../../../src/modules/userMerge/userMerge-individualHandler');
const { userMergeRightsHandler } = await import('../../../../src/modules/userMerge/userMerge-rightsHandler');
const { UserMergeRightsStrategy } = await import('../../../../src/modules/userMerge/userMerge-types');

const SOURCE_ID = 'source-uuid';
const TARGET_ID = 'target-uuid';

const contextOf = (extra: Record<string, unknown> = {}) => ({
  context: {} as never,
  sourceId: SOURCE_ID,
  targetId: TARGET_ID,
  sourceUser: { internal_id: SOURCE_ID, user_email: 'source@filigran.test' },
  targetUser: { internal_id: TARGET_ID, user_email: 'target@filigran.test' },
  options: { rightsStrategy: UserMergeRightsStrategy.Strict },
  ...extra,
}) as never;

/** The last argument of a call, where every one of these functions takes its options. */
const optionsOf = (call: unknown[]) => call[call.length - 1] as Record<string, unknown>;

describe('user merge writes nothing to the live stream', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('suppresses the events of the re-pointed operational relations', async () => {
    fullRelationsList.mockImplementation((_context, _user, _type, filters) => {
      const held = (filters as { toId?: string }).toId === SOURCE_ID;
      return Promise.resolve(held ? [{ internal_id: 'rel-1', fromId: 'case-1', fromType: 'Case-Rfi', toId: SOURCE_ID }] : []);
    });
    await userMergeOperationalRelationsHandler.apply(contextOf(), { handler: 'operational-relations', changes: [], alerts: [] });
    expect(stixObjectOrRelationshipAddRefRelation).toHaveBeenCalled();
    expect(stixObjectOrRelationshipDeleteRefRelation).toHaveBeenCalled();
    stixObjectOrRelationshipAddRefRelation.mock.calls.forEach((call) => {
      expect(optionsOf(call)).toEqual({ publishStreamEvent: false });
    });
    stixObjectOrRelationshipDeleteRefRelation.mock.calls.forEach((call) => {
      expect(optionsOf(call)).toEqual({ publishStreamEvent: false });
    });
  });

  it('suppresses the events of the individual merge and re-point', async () => {
    fullEntitiesList.mockResolvedValue([
      { internal_id: 'individual-target', contact_information: 'target@filigran.test' },
      { internal_id: 'individual-source', contact_information: 'source@filigran.test' },
    ]);
    await userMergeIndividualHandler.apply(contextOf(), { handler: 'user-individual', changes: [], alerts: [] });
    expect(mergeEntities).toHaveBeenCalled();
    expect(optionsOf(mergeEntities.mock.calls[0])).toEqual({ publishStreamEvent: false });
  });

  it('suppresses the events of the individual re-point when a single individual carries the source email', async () => {
    fullEntitiesList.mockResolvedValue([
      { internal_id: 'individual-source', contact_information: 'source@filigran.test' },
    ]);
    await userMergeIndividualHandler.apply(contextOf(), { handler: 'user-individual', changes: [], alerts: [] });
    expect(patchAttribute).toHaveBeenCalled();
    expect(optionsOf(patchAttribute.mock.calls[0])).toEqual({ bypassIndividualUpdate: true, publishStreamEvent: false });
  });

  it('suppresses the events of the rights transfer', async () => {
    fullRelationsList.mockImplementation((_context, _user, _type, filters) => {
      const fromSource = (filters as { fromId?: string }).fromId === SOURCE_ID;
      return Promise.resolve(fromSource ? [{ internal_id: 'rel-1', toId: 'group-1' }] : []);
    });
    await userMergeRightsHandler.apply(
      contextOf({ options: { rightsStrategy: UserMergeRightsStrategy.Union } }),
      { handler: 'user-rights', changes: [], alerts: [] },
    );
    expect(createRelation).toHaveBeenCalled();
    expect(deleteElementById).toHaveBeenCalled();
    createRelation.mock.calls.forEach((call) => {
      expect(optionsOf(call)).toEqual({ publishStreamEvent: false });
    });
    deleteElementById.mock.calls.forEach((call) => {
      expect(optionsOf(call)).toEqual({ publishStreamEvent: false });
    });
  });
});
