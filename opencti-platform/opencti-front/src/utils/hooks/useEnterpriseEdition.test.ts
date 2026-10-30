import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import useAuth from './useAuth';
import useEnterpriseEdition, { isEnterpriseEditionFromXtmOne } from './useEnterpriseEdition';

vi.mock('./useAuth', () => ({ default: vi.fn() }));

// The backend resolves one Enterprise Edition (own OpenCTI license, or a verified XTM license): the UI reads it as is.
const mockEnterpriseEdition = (platformEnterpriseEdition: Record<string, unknown> | null) => {
  (useAuth as Mock).mockReturnValue({ settings: { platform_enterprise_edition: platformEnterpriseEdition } });
};

describe('useEnterpriseEdition', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('is enabled by an OpenCTI license', () => {
    mockEnterpriseEdition({ license_validated: true, license_source: 'OPENCTI_LICENSE' });
    expect(useEnterpriseEdition()).toBe(true);
  });

  it('is enabled by a verified XTM One license, grace period included', () => {
    mockEnterpriseEdition({ license_validated: true, license_source: 'XTM_ONE_LICENSE' });
    expect(useEnterpriseEdition()).toBe(true);
    mockEnterpriseEdition({ license_validated: true, license_expired: true, license_extra_expiration: true, license_source: 'XTM_ONE_LICENSE' });
    expect(useEnterpriseEdition()).toBe(true);
  });

  it('is disabled once no license grants it any more', () => {
    mockEnterpriseEdition({ license_validated: false, license_source: 'OPENCTI_LICENSE' });
    expect(useEnterpriseEdition()).toBe(false);
  });
});

describe('isEnterpriseEditionFromXtmOne', () => {
  it('tells an Enterprise Edition granted by the XTM One license from an OpenCTI license', () => {
    expect(isEnterpriseEditionFromXtmOne({ license_source: 'XTM_ONE_LICENSE' })).toBe(true);
    expect(isEnterpriseEditionFromXtmOne({ license_source: 'OPENCTI_LICENSE' })).toBe(false);
    expect(isEnterpriseEditionFromXtmOne({ license_source: null })).toBe(false);
    expect(isEnterpriseEditionFromXtmOne(undefined)).toBe(false);
  });
});
