import { beforeEach, describe, expect, it, vi } from 'vitest';
import { stixObjectOrRelationshipAddRefRelations } from '../../../src/domain/stixObjectOrStixRelationship';

const mocks = vi.hoisted(() => ({
  convertDatabaseNameToInputName: vi.fn(),
  storeLoadByIdWithRefs: vi.fn(),
  transformPatchToInput: vi.fn(),
  updateAttributeFromLoadedWithRefs: vi.fn(),
  validateCreatedBy: vi.fn(),
  validateMarking: vi.fn(),
  validateMarkings: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  pageEntitiesOrRelationsConnection: vi.fn(),
  storeLoadById: vi.fn(),
}));

vi.mock('../../../src/database/middleware', () => ({
  storeLoadByIdWithRefs: mocks.storeLoadByIdWithRefs,
  transformPatchToInput: mocks.transformPatchToInput,
  updateAttributeFromLoadedWithRefs: mocks.updateAttributeFromLoadedWithRefs,
  validateCreatedBy: mocks.validateCreatedBy,
}));

vi.mock('../../../src/schema/schema-relationsRef', () => ({
  schemaRelationsRefDefinition: {
    convertDatabaseNameToInputName: mocks.convertDatabaseNameToInputName,
  },
}));

vi.mock('../../../src/utils/access', () => ({
  validateMarking: mocks.validateMarking,
  validateMarkings: mocks.validateMarkings,
}));

describe('stixObjectOrRelationshipAddRefRelations validation', () => {
  const context = {} as any;
  const user = {} as any;

  beforeEach(() => {
    vi.clearAllMocks();
    mocks.convertDatabaseNameToInputName.mockReturnValue('objectMarking');
    mocks.storeLoadByIdWithRefs.mockResolvedValue({ entity_type: 'Report' });
    mocks.transformPatchToInput.mockReturnValue([]);
    mocks.updateAttributeFromLoadedWithRefs.mockResolvedValue({
      element: { id: 'report--1' },
    });
  });

  it('validates all object markings before applying one bulk relation patch', async () => {
    await stixObjectOrRelationshipAddRefRelations(
      context,
      user,
      'report--1',
      {
        relationship_type: 'object-marking',
        toIds: ['marking-definition--1', 'marking-definition--2'],
      },
      'Stix-Core-Object',
    );

    expect(mocks.validateMarkings).toHaveBeenCalledWith(
      context,
      user,
      ['marking-definition--1', 'marking-definition--2'],
    );
    expect(mocks.updateAttributeFromLoadedWithRefs).toHaveBeenCalledOnce();
  });

  it('validates every created-by target before applying one bulk relation patch', async () => {
    await stixObjectOrRelationshipAddRefRelations(
      context,
      user,
      'report--1',
      {
        relationship_type: 'created-by',
        toIds: ['identity--1', 'identity--2'],
      },
      'Stix-Core-Object',
    );

    expect(mocks.validateCreatedBy).toHaveBeenNthCalledWith(
      1,
      context,
      user,
      'identity--1',
    );
    expect(mocks.validateCreatedBy).toHaveBeenNthCalledWith(
      2,
      context,
      user,
      'identity--2',
    );
    expect(mocks.updateAttributeFromLoadedWithRefs).toHaveBeenCalledOnce();
  });
});
