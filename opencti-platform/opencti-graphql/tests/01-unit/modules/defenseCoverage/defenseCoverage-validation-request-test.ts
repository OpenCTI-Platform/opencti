import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList, internalFindByIds, storeLoadById } from '../../../../src/database/middleware-loader';
import { connectorsForEnrichment } from '../../../../src/database/repository';
import { deleteElementById } from '../../../../src/database/middleware';
import { addGrouping } from '../../../../src/modules/grouping/grouping-domain';
import { addSecurityCoverage } from '../../../../src/modules/securityCoverage/securityCoverage-domain';
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
vi.mock('../../../../src/database/repository', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/repository')>()),
  connectorsForEnrichment: vi.fn(async () => []),
}));
vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  deleteElementById: vi.fn(async () => undefined),
}));
vi.mock('../../../../src/modules/grouping/grouping-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/grouping/grouping-domain')>()),
  addGrouping: vi.fn(async () => ({ id: 'grouping-1' })),
}));
vi.mock('../../../../src/modules/securityCoverage/securityCoverage-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/securityCoverage/securityCoverage-domain')>()),
  addSecurityCoverage: vi.fn(async () => {
    throw new Error('Security coverage not created');
  }),
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

  it('should mark the grouping and the security coverage with the markings of the threat and the techniques, and name them without the threat', async () => {
    vi.mocked(internalFindByIds).mockResolvedValueOnce([
      { ...technique, revoked: false, 'object-marking': ['marking-amber'] },
      { internal_id: 'attack-pattern-2', standard_id: 'attack-pattern--2', revoked: false, 'object-marking': ['marking-amber', 'marking-red'] },
    ] as never);
    vi.mocked(storeLoadById).mockResolvedValueOnce({ internal_id: 'intrusion-set-1', name: 'Restricted threat', revoked: false, 'object-marking': ['marking-clear'] } as never);
    vi.mocked(connectorsForEnrichment).mockResolvedValueOnce([{ id: 'connector-1' }] as never);
    await expect(validateDefenseGaps(context, user, { attackPatternIds: ['attack-pattern-1', 'attack-pattern-2'], threatId: 'intrusion-set-1' }))
      .rejects.toThrow('Security coverage not created');
    const objectMarking = ['marking-amber', 'marking-red', 'marking-clear'];
    // The default name never holds the threat name: its organizations cannot be carried to the generated entities
    const name = expect.stringMatching(/^Defense validation - 2 techniques - \d{4}-\d{2}-\d{2}$/);
    expect(vi.mocked(addGrouping)).toHaveBeenCalledWith(context, user, expect.objectContaining({ name, objectMarking }));
    expect(vi.mocked(addSecurityCoverage)).toHaveBeenCalledWith(context, user, expect.objectContaining({ name, objectCovered: 'grouping-1', objectMarking }));
    expect(vi.mocked(deleteElementById)).toHaveBeenCalledWith(context, user, 'grouping-1', expect.any(String));
  });
});
