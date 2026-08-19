import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { BasicStoreEntityConnector } from '../../../../src/types/connector';

const {
  mockFindManagedConnectorsByCatalogId,
  mockFindLatestCompatibleCatalogContractBySlug,
  mockMapContractEntityFieldsToEmbeddedConnectorManagerContract,
  mockPatchAttribute,
  mockPublishUserAction,
} = vi.hoisted(() => ({
  mockFindManagedConnectorsByCatalogId: vi.fn(),
  mockFindLatestCompatibleCatalogContractBySlug: vi.fn(),
  mockMapContractEntityFieldsToEmbeddedConnectorManagerContract: vi.fn((c) => ({ ...c })),
  mockPatchAttribute: vi.fn(),
  mockPublishUserAction: vi.fn(),
}));

vi.mock('../../../../src/modules/connector/connector-repository', () => ({
  findManagedConnectorsByCatalogId: mockFindManagedConnectorsByCatalogId,
}));

vi.mock('../../../../src/modules/catalog/catalog-repository', () => ({
  findLatestCompatibleCatalogContractBySlug: mockFindLatestCompatibleCatalogContractBySlug,
}));

vi.mock('../../../../src/modules/catalog/catalog-domain', () => ({
  mapContractEntityFieldsToEmbeddedConnectorManagerContract: mockMapContractEntityFieldsToEmbeddedConnectorManagerContract,
}));

vi.mock('../../../../src/database/middleware', () => ({
  patchAttribute: mockPatchAttribute,
}));

vi.mock('../../../../src/listener/UserActionListener', () => ({
  publishUserAction: mockPublishUserAction,
}));

vi.mock('../../../../src/config/conf', () => ({
  logApp: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

import { autoUpgradeManagedConnectors } from '../../../../src/modules/connector/connector-domain';

const buildManagedConnector = (overrides: Partial<BasicStoreEntityConnector> = {}): BasicStoreEntityConnector => {
  const connector = {
    id: 'connector-1',
    internal_id: 'connector-1',
    name: 'Managed connector',
    connector_type: 'EXTERNAL_IMPORT',
    active: true,
    auto: true,
    built_in: false,
    only_contextual: false,
    connector_scope: '*',
    updated_at: new Date(),
    connector_user_id: 'user-1',
    connector_info: {} as any,
    playbook_compatible: false,
    xtm_one_intent: null,
    connector_state: '',
    connector_state_reset: false,
    connector_trigger_filters: '',
    catalog_id: 'catalog-1',
    manager_upgrade_strategy: 'latest',
    manager_contract_image: 'opencti/connector-test:1.0.0',
    manager_contract: {
      slug: 'ipinfo',
      contract_version: '1.0.0',
      content_hash: 'hash-1',
    } as any,
    ...overrides,
  };
  return connector as BasicStoreEntityConnector;
};

const latestCompatibleContract = {
  slug: 'ipinfo',
  contract_version: '1.1.0',
  content_hash: 'hash-2',
  image: 'opencti/connector-test',
};

describe('connector-domain auto-upgrade', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFindManagedConnectorsByCatalogId.mockResolvedValue([]);
    mockFindLatestCompatibleCatalogContractBySlug.mockResolvedValue(undefined);
  });

  it('should skip connectors when strategy is not latest', async () => {
    mockFindManagedConnectorsByCatalogId.mockResolvedValue([
      buildManagedConnector({ manager_upgrade_strategy: 'manual' as any }),
    ]);
    await autoUpgradeManagedConnectors({ source: 'test' } as any, { id: 'user-1' } as any, ['catalog-1']);
    expect(mockPatchAttribute).not.toHaveBeenCalled();
  });

  it('should skip connectors without manager_contract snapshot', async () => {
    mockFindManagedConnectorsByCatalogId.mockResolvedValue([
      buildManagedConnector({ manager_contract: undefined }),
    ]);
    await autoUpgradeManagedConnectors({ source: 'test' } as any, { id: 'user-1' } as any, ['catalog-1']);
    expect(mockFindLatestCompatibleCatalogContractBySlug).not.toHaveBeenCalled();
    expect(mockPatchAttribute).not.toHaveBeenCalled();
  });

  it('should skip patch when connector already has latest compatible contract', async () => {
    mockFindManagedConnectorsByCatalogId.mockResolvedValue([
      buildManagedConnector({
        manager_contract: {
          slug: 'ipinfo',
          contract_version: '1.1.0',
          content_hash: 'hash-2',
        } as any,
      }),
    ]);
    mockFindLatestCompatibleCatalogContractBySlug.mockResolvedValue(latestCompatibleContract);
    await autoUpgradeManagedConnectors({ source: 'test' } as any, { id: 'user-1' } as any, ['catalog-1']);
    expect(mockPatchAttribute).not.toHaveBeenCalled();
  });

  it('should patch managed connector when a newer compatible contract exists', async () => {
    mockFindManagedConnectorsByCatalogId.mockResolvedValue([buildManagedConnector()]);
    mockFindLatestCompatibleCatalogContractBySlug.mockResolvedValue(latestCompatibleContract);
    await autoUpgradeManagedConnectors({ source: 'test' } as any, { id: 'user-1' } as any, ['catalog-1']);
    expect(mockMapContractEntityFieldsToEmbeddedConnectorManagerContract).toHaveBeenCalledWith(latestCompatibleContract);
    expect(mockPatchAttribute).toHaveBeenCalledWith(
      { source: 'test' },
      { id: 'user-1' },
      'connector-1',
      'Connector',
      expect.objectContaining({
        manager_contract_image: 'opencti/connector-test',
      }),
    );
    expect(mockPublishUserAction).toHaveBeenCalled();
  });

  it('should patch managed connector when latest compatible contract is an older version (downgrade)', async () => {
    mockFindManagedConnectorsByCatalogId.mockResolvedValue([
      buildManagedConnector({
        manager_contract: {
          slug: 'ipinfo',
          contract_version: '2.0.0',
          content_hash: 'hash-newer',
        } as any,
      }),
    ]);
    mockFindLatestCompatibleCatalogContractBySlug.mockResolvedValue({
      ...latestCompatibleContract,
      contract_version: '1.9.0',
      content_hash: 'hash-older',
    });
    await autoUpgradeManagedConnectors({ source: 'test' } as any, { id: 'user-1' } as any, ['catalog-1']);
    expect(mockPatchAttribute).toHaveBeenCalled();
    expect(mockPublishUserAction).toHaveBeenCalled();
  });

  it('should patch managed connector when version is equal but content hash differs', async () => {
    mockFindManagedConnectorsByCatalogId.mockResolvedValue([
      buildManagedConnector({
        manager_contract: {
          slug: 'ipinfo',
          contract_version: '1.1.0',
          content_hash: 'old-hash',
        } as any,
      }),
    ]);
    mockFindLatestCompatibleCatalogContractBySlug.mockResolvedValue({
      ...latestCompatibleContract,
      contract_version: '1.1.0',
      content_hash: 'new-hash',
    });
    await autoUpgradeManagedConnectors({ source: 'test' } as any, { id: 'user-1' } as any, ['catalog-1']);
    expect(mockPatchAttribute).toHaveBeenCalled();
    expect(mockPublishUserAction).toHaveBeenCalled();
  });

  it('should skip patch when no compatible contract can be found', async () => {
    mockFindManagedConnectorsByCatalogId.mockResolvedValue([buildManagedConnector()]);
    mockFindLatestCompatibleCatalogContractBySlug.mockResolvedValue(undefined);
    await autoUpgradeManagedConnectors({ source: 'test' } as any, { id: 'user-1' } as any, ['catalog-1']);
    expect(mockPatchAttribute).not.toHaveBeenCalled();
    expect(mockPublishUserAction).not.toHaveBeenCalled();
  });
});
