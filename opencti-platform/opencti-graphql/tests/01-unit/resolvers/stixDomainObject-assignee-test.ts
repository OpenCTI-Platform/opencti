import { beforeEach, describe, expect, it, vi } from 'vitest';
import stixDomainObjectResolvers from '../../../src/resolvers/stixDomainObject';
import { loadAssignees, loadParticipants } from '../../../src/database/members';
import { schemaRelationsRefDefinition } from '../../../src/schema/schema-relationsRef';

vi.mock('../../../src/database/members', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  loadAssignees: vi.fn(),
  loadParticipants: vi.fn(),
}));

describe('StixDomainObject.objectAssignee resolver', () => {
  const context = { user: { id: 'user-id' } };
  const resolveAssignees = (entityType: string) => stixDomainObjectResolvers.StixDomainObject.objectAssignee({ entity_type: entityType }, {}, context);

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns an empty list, without loading, when the entity type has no assignee ref', async () => {
    vi.spyOn(schemaRelationsRefDefinition, 'getRelationRef').mockReturnValue(null);

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

describe('StixDomainObject.objectParticipant resolver', () => {
  const context = { user: { id: 'user-id' } };
  const resolveParticipants = (entityType: string) => stixDomainObjectResolvers.StixDomainObject.objectParticipant({ entity_type: entityType }, {}, context);

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns an empty list, without loading, when the entity type has no participant ref', async () => {
    vi.spyOn(schemaRelationsRefDefinition, 'getRelationRef').mockReturnValue(null);

    expect(await resolveParticipants('Feedback')).toEqual([]);
    expect(loadParticipants).not.toHaveBeenCalled();
  });

  it('loads the participants when the entity type has the ref', async () => {
    vi.spyOn(schemaRelationsRefDefinition, 'getRelationRef').mockReturnValue({ inputName: 'objectParticipant' } as never);
    vi.mocked(loadParticipants).mockResolvedValue([{ id: 'participant-id' }] as never);

    expect(await resolveParticipants('Report')).toEqual([{ id: 'participant-id' }]);
    expect(loadParticipants).toHaveBeenCalledOnce();
  });
});
