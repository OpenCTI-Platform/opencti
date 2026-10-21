import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList, internalFindByIds, storeLoadById } from '../../../../src/database/middleware-loader';
import { defenseGapValidationStatus, findDefenseTechnique } from '../../../../src/modules/defenseCoverage/defenseCoverage-domain';
import { DefenseValidationRequestStatus } from '../../../../src/generated/graphql';
import type { DefenseGapValidationRequest } from '../../../../src/modules/defenseCoverage/defenseGap/defenseGap-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(async () => undefined),
  internalFindByIds: vi.fn(async () => []),
  fullEntitiesList: vi.fn(async () => []),
}));

const user = { id: 'reader' } as AuthUser;
const request = (securityCoverageId: string) => ({
  security_coverage_id: securityCoverageId,
  grouping_id: 'grouping-1',
  requested_at: '2026-10-07T10:00:00.000Z',
  requested_by: 'requester',
}) as DefenseGapValidationRequest;

describe('Defense validation requests and techniques per reader', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should answer a revoked technique as a missing one', async () => {
    vi.mocked(storeLoadById).mockResolvedValueOnce({ internal_id: 'attack-pattern-1', name: 'Phishing', revoked: true } as never);
    await expect(findDefenseTechnique({} as AuthContext, user, 'attack-pattern-1', {})).resolves.toBeNull();
    expect(vi.mocked(fullEntitiesList)).not.toHaveBeenCalled();
  });

  it('should read the progress of a request only on a security coverage the reader can access', async () => {
    vi.mocked(internalFindByIds).mockResolvedValueOnce([{ internal_id: 'coverage-accessible' }] as never);
    vi.mocked(fullEntitiesList).mockResolvedValueOnce([{ event_source_id: 'coverage-accessible' }, { event_source_id: 'coverage-restricted' }] as never);
    const context = {} as AuthContext;
    const statuses = await Promise.all([
      defenseGapValidationStatus(context, user, request('coverage-accessible')),
      defenseGapValidationStatus(context, user, request('coverage-restricted')),
    ]);
    expect(statuses).toEqual([DefenseValidationRequestStatus.Running, DefenseValidationRequestStatus.Waiting]);
    const filters = (vi.mocked(fullEntitiesList).mock.calls[0][3] as { filters: { filters: Array<{ key: string[]; values: string[] }> } }).filters;
    expect(filters.filters.find((filter) => filter.key[0] === 'event_source_id')?.values).toEqual(['coverage-accessible']);
  });
});
