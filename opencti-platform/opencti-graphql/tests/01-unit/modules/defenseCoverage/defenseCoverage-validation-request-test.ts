import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList, internalFindByIds, storeLoadById } from '../../../../src/database/middleware-loader';
import { validateDefenseGaps } from '../../../../src/modules/defenseCoverage/defenseCoverage-domain';
import type { DefenseValidationInput } from '../../../../src/generated/graphql';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(async () => undefined),
  internalFindByIds: vi.fn(async () => []),
  fullEntitiesList: vi.fn(async () => []),
  fullRelationsList: vi.fn(async () => []),
}));

const context = {} as AuthContext;
const user = {} as AuthUser;
const technique = { internal_id: 'attack-pattern-1', standard_id: 'attack-pattern--1' };

describe('Defense validation request', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const ids = (count: number) => Array.from({ length: count }, (_, index) => `attack-pattern-${index}`);
  it.each<[string, DefenseValidationInput]>([
    ['attackPatternIds', { attackPatternIds: ids(2001) }],
    ['gaps', { attackPatternIds: [], gaps: ids(2001).map((attackPatternId) => ({ attackPatternId, platformId: 'platform-1' })) }],
    ['platformIds', { attackPatternIds: ['attack-pattern-1'], platformIds: Array.from({ length: 2001 }, (_, index) => `platform-${index}`) }],
  ])('should refuse more than 2000 entries in %s before loading anything', async (field, input) => {
    await expect(validateDefenseGaps(context, user, input)).rejects.toThrow(`A validation request cannot hold more than 2000 entries in ${field}`);
    expect(vi.mocked(internalFindByIds)).not.toHaveBeenCalled();
  });

  it('should refuse more techniques on more platforms than the gaps limit before loading the platforms', async () => {
    const techniques = ids(11).map((id) => ({ internal_id: id, standard_id: `${id}-standard`, revoked: false }));
    vi.mocked(internalFindByIds).mockResolvedValueOnce(techniques as never);
    const platformIds = Array.from({ length: 199 }, (_, index) => `platform-${index}`);
    await expect(validateDefenseGaps(context, user, { attackPatternIds: ids(11), platformIds }))
      .rejects.toThrow('A validation request cannot be tracked on more than 2000 gaps');
    expect(vi.mocked(fullEntitiesList)).not.toHaveBeenCalled();
  });

  it('should refuse a revoked technique', async () => {
    vi.mocked(internalFindByIds).mockResolvedValueOnce([{ ...technique, revoked: true }] as never);
    await expect(validateDefenseGaps(context, user, { attackPatternIds: ['attack-pattern-1'] }))
      .rejects.toThrow('Some techniques of the validation request are revoked');
    expect(vi.mocked(storeLoadById)).not.toHaveBeenCalled();
  });

  it('should refuse a revoked threat', async () => {
    vi.mocked(internalFindByIds).mockResolvedValueOnce([{ ...technique, revoked: false }] as never);
    vi.mocked(storeLoadById).mockResolvedValueOnce({ internal_id: 'intrusion-set-1', revoked: true } as never);
    await expect(validateDefenseGaps(context, user, { attackPatternIds: ['attack-pattern-1'], threatId: 'intrusion-set-1' }))
      .rejects.toThrow('The threat of the validation request is revoked');
  });
});
