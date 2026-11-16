import { beforeEach, describe, expect, it, vi } from 'vitest';
import stixDomainObjectResolvers from '../../../src/resolvers/stixDomainObject';
import { loadAssignees } from '../../../src/database/members';
import { schemaRelationsRefDefinition } from '../../../src/schema/schema-relationsRef';

vi.mock('../../../src/database/members', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  loadAssignees: vi.fn(),
}));

describe('StixDomainObject.objectAssignee resolver', () => {
  const context = { user: { id: 'user-id' } };
  const resolveAssignees = (entityType: string) => stixDomainObjectResolvers.StixDomainObject.objectAssignee({ entity_type: entityType }, {}, context);

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns an empty list, without loading, when the entity type has no assignee ref', async () => {
    vi.spyOn(schemaRelationsRefDefinition, 'getRelationRef').mockReturnValue(undefined);

    expect(await resolveAssignees('Note')).toEqual([]);
    expect(loadAssignees).not.toHaveBeenCalled();
  });

  it('loads the assignees when the entity type has the ref', async () => {
    vi.spyOn(schemaRelationsRefDefinition, 'getRelationRef').mockReturnValue({ inputName: 'objectAssignee' } as never);
    vi.mocked(loadAssignees).mockResolvedValue([{ id: 'assignee-id' }] as never);

    expect(await resolveAssignees('Report')).toEqual([{ id: 'assignee-id' }]);
    expect(loadAssignees).toHaveBeenCalledOnce();
  });
});
