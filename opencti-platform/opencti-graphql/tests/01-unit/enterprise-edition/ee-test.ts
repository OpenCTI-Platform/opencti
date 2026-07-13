import { afterEach, describe, expect, it, vi } from 'vitest';
import * as cache from '../../../src/database/cache';
import { isEnterpriseEditionAuthorized } from '../../../src/enterprise-edition/ee';

describe('ee: isEnterpriseEditionAuthorized()', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return true without checking enterprise edition when the module is not enterpriseEditionOnly', async () => {
    const getEntityFromCacheSpy = vi.spyOn(cache, 'getEntityFromCache');

    const isAuthorized = await isEnterpriseEditionAuthorized({ executionContext: 'test_module' });

    expect(isAuthorized).toBe(true);
    expect(getEntityFromCacheSpy).not.toHaveBeenCalled();
  });

  it('should return true when the module is enterpriseEditionOnly and enterprise edition is enabled', async () => {
    vi.spyOn(cache, 'getEntityFromCache').mockResolvedValue({ valid_enterprise_edition: true } as any);

    const isAuthorized = await isEnterpriseEditionAuthorized({ executionContext: 'test_module', enterpriseEditionOnly: true });

    expect(isAuthorized).toBe(true);
  });

  it('should return false when the module is enterpriseEditionOnly and enterprise edition is disabled', async () => {
    vi.spyOn(cache, 'getEntityFromCache').mockResolvedValue({ valid_enterprise_edition: false } as any);

    const isAuthorized = await isEnterpriseEditionAuthorized({ executionContext: 'test_module', enterpriseEditionOnly: true });

    expect(isAuthorized).toBe(false);
  });
});
