import { beforeEach, describe, expect, it, vi } from 'vitest';
import { internalFindByIdsMapped } from '../../../../src/database/middleware-loader';
import { coveragePlatformsInformationForReader } from '../../../../src/modules/defenseCoverage/defenseCoverage-domain';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../../../src/modules/securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_IDENTITY_SYSTEM } from '../../../../src/schema/stixDomainObject';
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

  it('should return only the entries of the security platforms and systems the reader can access', async () => {
    vi.mocked(internalFindByIdsMapped).mockResolvedValueOnce({ 'security-platform--accessible': { internal_id: 'platform-1' } } as never);
    const information = [entry('security-platform--accessible'), entry('security-platform--restricted'), entry('security-platform--accessible')];
    await expect(coveragePlatformsInformationForReader(context, user, information))
      .resolves.toEqual([entry('security-platform--accessible'), entry('security-platform--accessible')]);
    expect(vi.mocked(internalFindByIdsMapped)).toHaveBeenCalledWith(
      context,
      user,
      ['security-platform--accessible', 'security-platform--restricted'],
      expect.objectContaining({ mapWithAllIds: true, type: [ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, ENTITY_TYPE_IDENTITY_SYSTEM] }),
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
    ['with a score above the GraphQL integer range', { platform_ref: 'security-platform--accessible', coverage_name: 'Detection', coverage_score: 1e20 }],
    ['with a score rounded below the GraphQL integer range', { platform_ref: 'security-platform--accessible', coverage_name: 'Detection', coverage_score: -(2 ** 31) - 0.6 }],
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

  it('should keep a score at the bounds of the GraphQL integer range', async () => {
    vi.mocked(internalFindByIdsMapped).mockResolvedValueOnce({ 'security-platform--accessible': { internal_id: 'platform-1' } } as never);
    const bounds = [{ ...entry('security-platform--accessible'), coverage_score: 2 ** 31 - 1 }, { ...entry('security-platform--accessible'), coverage_score: -(2 ** 31) }];
    await expect(coveragePlatformsInformationForReader(context, user, bounds)).resolves.toEqual(bounds);
  });

  it('should keep an absent value as it is', async () => {
    await expect(coveragePlatformsInformationForReader(context, user, null)).resolves.toBeNull();
    await expect(coveragePlatformsInformationForReader(context, user, undefined)).resolves.toBeUndefined();
    expect(vi.mocked(internalFindByIdsMapped)).not.toHaveBeenCalled();
  });
});
