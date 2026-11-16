import { beforeEach, describe, expect, it, vi } from 'vitest';
import caseResolvers from '../../../src/modules/case/case-resolvers';
import { loadParticipants } from '../../../src/database/members';
import { schemaRelationsRefDefinition } from '../../../src/schema/schema-relationsRef';

vi.mock('../../../src/database/members', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  loadParticipants: vi.fn(),
}));

describe('Case.objectParticipant resolver', () => {
  const context = { user: { id: 'user-id' } };
  const resolveParticipants = (entityType: string) => (caseResolvers as any).Case.objectParticipant({ entity_type: entityType }, {}, context);

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns an empty list, without loading, when the case type has no participant ref', async () => {
    vi.spyOn(schemaRelationsRefDefinition, 'getRelationRef').mockReturnValue(null);

    expect(await resolveParticipants('Feedback')).toEqual([]);
    expect(loadParticipants).not.toHaveBeenCalled();
  });

  it('loads the participants when the case type has the ref', async () => {
    vi.spyOn(schemaRelationsRefDefinition, 'getRelationRef').mockReturnValue({ inputName: 'objectParticipant' } as never);
    vi.mocked(loadParticipants).mockResolvedValue([{ id: 'participant-id' }] as never);

    expect(await resolveParticipants('Case-Rfi')).toEqual([{ id: 'participant-id' }]);
    expect(loadParticipants).toHaveBeenCalledOnce();
  });
});
