import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/modules/catalog/catalog-repository', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/catalog/catalog-repository')>()),
  findCatalogContractsBySlugs: vi.fn(),
  findCatalogContractsByImageNames: vi.fn(),
}));

import { findCatalogContractsByImageNames, findCatalogContractsBySlugs } from '../../../src/modules/catalog/catalog-repository';
import { computeConnectorsUpdateStatus } from '../../../src/database/repository';

const NO_UPDATE_STATUS = { update_available: false, latest_compatible_version: null, incompatibility: false };

const contract = (slug: string, image: string, contract_version: string, min_version: string) => ({
  slug,
  image,
  contract_version,
  min_version,
  max_version: null,
  support_version: null,
});

describe('computeConnectorsUpdateStatus', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should load the catalog contracts of the whole list in one query per lookup kind', async () => {
    vi.mocked(findCatalogContractsBySlugs).mockResolvedValue([
      contract('alpha', 'opencti/connector-alpha', '1.0.0', '1.0.0'),
      contract('alpha', 'opencti/connector-alpha', '2.0.0', '1.0.0'),
      contract('alpha', 'opencti/connector-alpha', '3.0.0', '99999.0.0'),
      contract('beta', 'opencti/connector-beta', '1.0.0', '1.0.0'),
    ] as never);
    vi.mocked(findCatalogContractsByImageNames).mockResolvedValue([
      contract('gamma', 'opencti/connector-gamma', '2.0.0', '1.0.0'),
    ] as never);
    const alpha = { id: 'alpha', manager_contract: { slug: 'alpha', contract_version: '1.0.0' } };
    const beta = { id: 'beta', manager_contract: { slug: 'Beta', contract_version: '1.0.0' } };
    const imageOnly = { id: 'image-only', manager_contract_image: 'docker.io/opencti/connector-gamma:1.0.0' };
    const manual = { id: 'manual' };

    // alpha is requested three times, as the three update fields of a connector are
    const statuses = await computeConnectorsUpdateStatus({} as never, {} as never, [alpha, beta, alpha, imageOnly, manual, alpha]);

    expect(findCatalogContractsBySlugs).toHaveBeenCalledTimes(1);
    expect(findCatalogContractsBySlugs).toHaveBeenCalledWith({}, {}, ['alpha', 'beta']);
    expect(findCatalogContractsByImageNames).toHaveBeenCalledTimes(1);
    expect(findCatalogContractsByImageNames).toHaveBeenCalledWith({}, {}, ['opencti/connector-gamma']);
    const alphaStatus = { update_available: true, latest_compatible_version: '2.0.0', incompatibility: true };
    expect(statuses).toEqual([
      alphaStatus,
      { update_available: false, latest_compatible_version: '1.0.0', incompatibility: false },
      alphaStatus,
      // No deployed version to compare with: no update, only the catalog information
      { update_available: false, latest_compatible_version: '2.0.0', incompatibility: false },
      NO_UPDATE_STATUS,
      alphaStatus,
    ]);
  });

  it('should not query the catalog when no connector comes from it', async () => {
    const statuses = await computeConnectorsUpdateStatus({} as never, {} as never, [{ id: 'manual' }, { id: 'no-image', manager_contract_image: '' }]);

    expect(findCatalogContractsBySlugs).not.toHaveBeenCalled();
    expect(findCatalogContractsByImageNames).not.toHaveBeenCalled();
    expect(statuses).toEqual([NO_UPDATE_STATUS, NO_UPDATE_STATUS]);
  });
});
