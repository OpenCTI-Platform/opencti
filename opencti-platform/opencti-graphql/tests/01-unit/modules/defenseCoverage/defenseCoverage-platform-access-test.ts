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

  it.each([
    ['without a name', { platform_ref: 'security-platform--accessible', coverage_score: 100 }],
    ['with a name that is not a text', { platform_ref: 'security-platform--accessible', coverage_name: 12, coverage_score: 100 }],
    ['without a score', { platform_ref: 'security-platform--accessible', coverage_name: 'Detection' }],
    ['with a score that is not a number', { platform_ref: 'security-platform--accessible', coverage_name: 'Detection', coverage_score: '100' }],
    ['with a score that is not finite', { platform_ref: 'security-platform--accessible', coverage_name: 'Detection', coverage_score: Number.NaN }],
  ])('should skip an entry %s, which the GraphQL type cannot carry', async (_, malformed) => {
    vi.mocked(internalFindByIdsMapped).mockResolvedValueOnce({ 'security-platform--accessible': { internal_id: 'platform-1' } } as never);
    await expect(coveragePlatformsInformationForReader(context, user, [malformed, entry('security-platform--accessible')] as never))
      .resolves.toEqual([entry('security-platform--accessible')]);
  });

  it('should round a decimal score to the integer of the GraphQL type', async () => {
    vi.mocked(internalFindByIdsMapped).mockResolvedValueOnce({ 'security-platform--accessible': { internal_id: 'platform-1' } } as never);
    await expect(coveragePlatformsInformationForReader(context, user, [{ ...entry('security-platform--accessible'), coverage_score: 66.6 }]))
      .resolves.toEqual([{ ...entry('security-platform--accessible'), coverage_score: 67 }]);
  });

  it('should keep an absent value as it is', async () => {
    await expect(coveragePlatformsInformationForReader(context, user, null)).resolves.toBeNull();
    await expect(coveragePlatformsInformationForReader(context, user, undefined)).resolves.toBeUndefined();
    expect(vi.mocked(internalFindByIdsMapped)).not.toHaveBeenCalled();
  });
});
