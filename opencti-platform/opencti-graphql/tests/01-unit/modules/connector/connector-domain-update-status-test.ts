import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/modules/catalog/catalog-repository', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/catalog/catalog-repository')>()),
  findCatalogContractsBySlugs: vi.fn(),
}));

import { findCatalogContractsBySlugs } from '../../../../src/modules/catalog/catalog-repository';
import { computeConnectorsUpdateStatus } from '../../../../src/modules/connector/connector-domain';
import { DECOUPLING_VERSIONS_FEATURE_FLAG, ENABLED_FEATURE_FLAGS } from '../../../../src/config/conf';

const NO_UPDATE_STATUS = { update_available: false, latest_compatible_version: null, has_newer_incompatible_version: false };

const contract = (slug: string, contract_version: string, min_version: string) => ({
  slug,
  contract_version,
  min_version,
  max_version: null,
  support_version: null,
});

describe('computeConnectorsUpdateStatus', () => {
  const previousEnabledFeatureFlags = [...ENABLED_FEATURE_FLAGS];

  beforeEach(() => {
    vi.clearAllMocks();
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length, DECOUPLING_VERSIONS_FEATURE_FLAG);
  });

  afterEach(() => {
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length, ...previousEnabledFeatureFlags);
  });

  it('should not query the catalog when connector versions are not decoupled', async () => {
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length);
    const alpha = { id: 'alpha', manager_contract: { slug: 'alpha', contract_version: '1.0.0' } };

    const statuses = await computeConnectorsUpdateStatus({} as never, {} as never, [alpha]);

    expect(findCatalogContractsBySlugs).not.toHaveBeenCalled();
    expect(statuses).toEqual([NO_UPDATE_STATUS]);
  });

  it('should load the catalog contracts of the whole list in one query', async () => {
    vi.mocked(findCatalogContractsBySlugs).mockResolvedValue([
      contract('alpha', '1.0.0', '1.0.0'),
      contract('alpha', '2.0.0', '1.0.0'),
      contract('alpha', '3.0.0', '99999.0.0'),
      contract('beta', '1.0.0', '1.0.0'),
    ] as never);
    const alpha = { id: 'alpha', manager_contract: { slug: 'alpha', contract_version: '1.0.0' } };
    const beta = { id: 'beta', manager_contract: { slug: 'Beta', contract_version: '1.0.0' } };
    const manual = { id: 'manual' };

    // alpha is requested three times, as the three update fields of a connector are
    const statuses = await computeConnectorsUpdateStatus({} as never, {} as never, [alpha, beta, alpha, manual, alpha]);

    expect(findCatalogContractsBySlugs).toHaveBeenCalledTimes(1);
    expect(findCatalogContractsBySlugs).toHaveBeenCalledWith({}, {}, ['alpha', 'beta']);
    const alphaStatus = { update_available: true, latest_compatible_version: '2.0.0', has_newer_incompatible_version: true };
    expect(statuses).toEqual([
      alphaStatus,
      { update_available: false, latest_compatible_version: '1.0.0', has_newer_incompatible_version: false },
      alphaStatus,
      NO_UPDATE_STATUS,
      alphaStatus,
    ]);
  });

  it('should not query the catalog when no connector comes from it', async () => {
    // A connector without a catalog contract has no deployed version to compare with, even with an image
    const statuses = await computeConnectorsUpdateStatus({} as never, {} as never, [{ id: 'manual' }, { id: 'image-only', manager_contract_image: 'docker.io/opencti/connector-gamma:1.0.0' }]);

    expect(findCatalogContractsBySlugs).not.toHaveBeenCalled();
    expect(statuses).toEqual([NO_UPDATE_STATUS, NO_UPDATE_STATUS]);
  });

  it('should report no update for every connector when the catalog cannot be read', async () => {
    vi.mocked(findCatalogContractsBySlugs).mockRejectedValue(new Error('catalog unavailable'));
    const alpha = { id: 'alpha', manager_contract: { slug: 'alpha', contract_version: '1.0.0' } };

    const statuses = await computeConnectorsUpdateStatus({} as never, {} as never, [alpha, { id: 'manual' }]);

    expect(statuses).toEqual([NO_UPDATE_STATUS, NO_UPDATE_STATUS]);
  });
});
