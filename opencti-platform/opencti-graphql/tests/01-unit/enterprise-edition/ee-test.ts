import { afterEach, describe, expect, it, vi } from 'vitest';
import * as cache from '../../../src/database/cache';
import * as middlewareLoader from '../../../src/database/middleware-loader';
import * as licensing from '../../../src/modules/settings/licensing';
import { checkEnterpriseEdition, isEnterpriseEdition, isEnterpriseEditionFromSettings, isEnterpriseEditionUpToDate } from '../../../src/enterprise-edition/ee';

describe('ee: isEnterpriseEditionFromSettings()', () => {
  it('should return true when valid_enterprise_edition is true', () => {
    expect(isEnterpriseEditionFromSettings({ valid_enterprise_edition: true })).toBe(true);
  });

  it('should return false when valid_enterprise_edition is false', () => {
    expect(isEnterpriseEditionFromSettings({ valid_enterprise_edition: false })).toBe(false);
  });

  it('should return false when settings is undefined', () => {
    expect(isEnterpriseEditionFromSettings(undefined)).toBe(false);
  });
});

describe('ee: isEnterpriseEdition()', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return true when the cached settings have enterprise edition enabled', async () => {
    vi.spyOn(cache, 'getEntityFromCache').mockResolvedValue({ valid_enterprise_edition: true } as any);

    const result = await isEnterpriseEdition({} as any);

    expect(result).toBe(true);
  });

  it('should return false when the cached settings have enterprise edition disabled', async () => {
    vi.spyOn(cache, 'getEntityFromCache').mockResolvedValue({ valid_enterprise_edition: false } as any);

    const result = await isEnterpriseEdition({} as any);

    expect(result).toBe(false);
  });
});

describe('ee: isEnterpriseEditionUpToDate()', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should take a license the settings cache does not know yet into account', async () => {
    // The cache of this node still says there is no license, the database has it
    vi.spyOn(cache, 'getEntityFromCache').mockResolvedValue({ valid_enterprise_edition: false } as any);
    vi.spyOn(middlewareLoader, 'topEntitiesList').mockResolvedValue([{ enterprise_license: 'pem' }] as any);
    vi.spyOn(licensing, 'getEnterpriseEditionInfo').mockReturnValue({ license_validated: true } as any);

    expect(await isEnterpriseEdition({} as any)).toBe(false);
    expect(await isEnterpriseEditionUpToDate({} as any)).toBe(true);
  });

  it('should be false when the license of the database is not valid', async () => {
    vi.spyOn(middlewareLoader, 'topEntitiesList').mockResolvedValue([{ enterprise_license: 'pem' }] as any);
    vi.spyOn(licensing, 'getEnterpriseEditionInfo').mockReturnValue({ license_validated: false } as any);

    expect(await isEnterpriseEditionUpToDate({} as any)).toBe(false);
  });

  it('should be false when there are no settings', async () => {
    vi.spyOn(middlewareLoader, 'topEntitiesList').mockResolvedValue([] as any);

    expect(await isEnterpriseEditionUpToDate({} as any)).toBe(false);
  });
});

describe('ee: checkEnterpriseEdition()', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should not throw when enterprise edition is enabled', async () => {
    vi.spyOn(cache, 'getEntityFromCache').mockResolvedValue({ valid_enterprise_edition: true } as any);

    await expect(checkEnterpriseEdition({} as any)).resolves.toBeUndefined();
  });

  it('should throw when enterprise edition is disabled', async () => {
    vi.spyOn(cache, 'getEntityFromCache').mockResolvedValue({ valid_enterprise_edition: false } as any);

    await expect(checkEnterpriseEdition({} as any)).rejects.toThrow('Enterprise edition is not enabled');
  });
});
