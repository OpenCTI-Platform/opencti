import { beforeEach, describe, expect, it, vi } from 'vitest';
import { internalFindByIds, storeLoadById } from '../../../../src/database/middleware-loader';
import { validateDefenseGaps } from '../../../../src/modules/defenseCoverage/defenseCoverage-domain';
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
