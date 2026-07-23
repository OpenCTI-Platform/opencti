import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/modules/catalog/catalog-domain', () => ({
  encryptValue: vi.fn(),
  getSupportedContractsByImage: vi.fn(),
  mapCatalogContractToConnectorManagerContract: vi.fn(),
}));

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return {
    ...actual,
    isFeatureEnabled: vi.fn((feature: string) => feature !== 'DECOUPLING_CONNECTOR_VERSIONS'),
    logApp: {
      warn: vi.fn(),
      error: vi.fn(),
      info: vi.fn(),
      debug: vi.fn(),
    },
  };
});

import {
  computeManagerConnectorContract,
  computeManagerConnectorExcerpt,
  computeManagerConnectorImage,
} from '../../../src/database/repository';
import { getSupportedContractsByImage, mapCatalogContractToConnectorManagerContract } from '../../../src/modules/catalog/catalog-domain';
import { logApp } from '../../../src/config/conf';

describe('repository.ts managed connector resolution with decoupling flag disabled', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should ignore snapshot and resolve runtime contract from catalog', async () => {
    const catalogContract = {
      title: 'Catalog Contract',
      slug: 'ipinfo',
      logo: 'data:image/png;base64,def',
      container_image: 'opencti/connector-ipinfo',
      container_version: '1.2.3',
    };
    vi.mocked(getSupportedContractsByImage).mockResolvedValue(new Map([['opencti/connector-ipinfo', catalogContract]]) as never);

    const connector = {
      internal_id: 'connector--2',
      name: 'connector-2',
      manager_contract_image: 'opencti/connector-ipinfo',
      manager_contract: {
        title: 'Snapshot Contract',
        slug: 'snapshot',
        logo: 'data:image/png;base64,abc',
        container_image: 'opencti/connector-ipinfo',
        container_version: '9.9.9',
      },
    } as any;

    const contractDefinition = await computeManagerConnectorContract(undefined, undefined, connector);
    const excerpt = await computeManagerConnectorExcerpt(undefined, undefined, connector);
    const image = await computeManagerConnectorImage(connector);

    expect(getSupportedContractsByImage).toHaveBeenCalled();
    expect(mapCatalogContractToConnectorManagerContract).not.toHaveBeenCalled();
    expect(logApp.warn).not.toHaveBeenCalled();
    expect(contractDefinition).toContain('"Catalog Contract"');
    expect(excerpt).toEqual({ title: 'Catalog Contract', slug: 'ipinfo', logo: 'data:image/png;base64,def' });
    expect(image).toEqual('opencti/connector-ipinfo:1.2.3');
  });
});
