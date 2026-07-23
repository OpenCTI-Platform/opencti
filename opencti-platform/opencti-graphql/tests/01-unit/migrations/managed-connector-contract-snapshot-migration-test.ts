import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/config/conf', () => ({
  logMigration: {
    info: vi.fn(),
    warn: vi.fn(),
  },
}));

vi.mock('../../../src/database/utils', () => ({
  READ_INDEX_INTERNAL_OBJECTS: 'internal_objects',
}));

vi.mock('../../../src/generated/graphql', () => ({
  FilterMode: { And: 'and' },
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
}));

vi.mock('../../../src/utils/access', () => ({
  executionContext: vi.fn(() => ({ source: 'migration-test' })),
  SYSTEM_USER: { id: 'system-user' },
}));

vi.mock('../../../src/schema/internalObject', () => ({
  ENTITY_TYPE_CONNECTOR: 'Connector',
}));

vi.mock('../../../src/database/middleware', () => ({
  patchAttribute: vi.fn(),
}));

vi.mock('../../../src/modules/catalog/catalog-domain', () => ({
  getSupportedContractByImage: vi.fn(),
  mapCatalogContractToConnectorManagerContract: vi.fn(),
}));

import { fullEntitiesList } from '../../../src/database/middleware-loader';
import { patchAttribute } from '../../../src/database/middleware';
import { getSupportedContractByImage, mapCatalogContractToConnectorManagerContract } from '../../../src/modules/catalog/catalog-domain';
import { up } from '../../../src/migrations/1780100000000-backfill-managed-connector-contract-snapshot';

describe('managed connectors snapshot migration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should patch missing manager_contract and manager_upgrade_strategy', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([
      {
        id: 'connector-1',
        manager_contract_image: 'opencti/connector-ipinfo',
      },
    ] as never);
    vi.mocked(getSupportedContractByImage).mockResolvedValue({ container_image: 'opencti/connector-ipinfo' } as never);
    vi.mocked(mapCatalogContractToConnectorManagerContract).mockReturnValue({ slug: 'ipinfo' } as never);

    const next = vi.fn();
    await up(next);

    expect(getSupportedContractByImage).toHaveBeenCalledWith('opencti/connector-ipinfo');
    expect(patchAttribute).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      'connector-1',
      'Connector',
      { manager_contract: { slug: 'ipinfo' }, manager_upgrade_strategy: 'latest' },
    );
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('should warn and only patch strategy when catalog contract is missing', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([
      {
        id: 'connector-2',
        manager_contract_image: 'opencti/connector-missing',
      },
    ] as never);
    vi.mocked(getSupportedContractByImage).mockResolvedValue(undefined as never);

    const next = vi.fn();
    await up(next);

    expect(mapCatalogContractToConnectorManagerContract).not.toHaveBeenCalled();
    expect(patchAttribute).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      'connector-2',
      'Connector',
      { manager_upgrade_strategy: 'latest' },
    );
    expect(next).toHaveBeenCalledTimes(1);
  });
});
