import { beforeEach, describe, expect, it, vi } from 'vitest';
import { internalFindByIdsMapped } from '../../../../src/database/middleware-loader';
import { coveragePlatformsInformationForReader } from '../../../../src/modules/defenseCoverage/defenseCoverage-domain';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIdsMapped: vi.fn(async () => ({})),
}));

const context = {} as AuthContext;
const user = {} as AuthUser;
const entry = (platformRef: unknown) => ({ platform_ref: platformRef, coverage_name: 'Detection', coverage_score: 100 });

describe('Defense coverage per platform of a relationship', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should return only the entries of the platforms the reader can access', async () => {
    vi.mocked(internalFindByIdsMapped).mockResolvedValueOnce({ 'security-platform--accessible': { internal_id: 'platform-1' } } as never);
    const information = [entry('security-platform--accessible'), entry('security-platform--restricted'), entry('security-platform--accessible')];
    await expect(coveragePlatformsInformationForReader(context, user, information))
      .resolves.toEqual([entry('security-platform--accessible'), entry('security-platform--accessible')]);
    expect(vi.mocked(internalFindByIdsMapped)).toHaveBeenCalledWith(
      context,
      user,
      ['security-platform--accessible', 'security-platform--restricted'],
      expect.objectContaining({ mapWithAllIds: true }),
    );
  });

  it('should drop the malformed entries without reading anything when none is left', async () => {
    await expect(coveragePlatformsInformationForReader(context, user, [null, entry(42)] as never)).resolves.toEqual([]);
    expect(vi.mocked(internalFindByIdsMapped)).not.toHaveBeenCalled();
  });

  it('should keep an absent value as it is', async () => {
    await expect(coveragePlatformsInformationForReader(context, user, null)).resolves.toBeNull();
    await expect(coveragePlatformsInformationForReader(context, user, undefined)).resolves.toBeUndefined();
    expect(vi.mocked(internalFindByIdsMapped)).not.toHaveBeenCalled();
  });
});
