import { beforeEach, describe, expect, it, vi } from 'vitest';

const {
  mockSynchronizeCatalogs,
  mockAutoUpgradeManagedConnectors,
} = vi.hoisted(() => ({
  mockSynchronizeCatalogs: vi.fn(),
  mockAutoUpgradeManagedConnectors: vi.fn(),
}));

vi.mock('../../../../src/modules/catalog/sync/catalog-sync-domain', () => ({
  synchronizeCatalogs: mockSynchronizeCatalogs,
}));

vi.mock('../../../../src/modules/connector/connector-domain', () => ({
  autoUpgradeManagedConnectors: mockAutoUpgradeManagedConnectors,
}));

vi.mock('../../../../src/manager/managerModule', () => ({
  registerManager: vi.fn(),
}));

// The handler remembers a complete synchronization: each test needs a fresh module
const loadCatalogManagerHandler = async () => {
  vi.resetModules();
  const { catalogManagerHandler } = await import('../../../../src/modules/catalog/catalog-manager');
  return catalogManagerHandler;
};

describe('catalog-manager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSynchronizeCatalogs.mockResolvedValue({ synchronizedCatalogIds: ['embedded-catalog'], isEmbeddedOnlySyncComplete: true });
    mockAutoUpgradeManagedConnectors.mockResolvedValue({ hasErrors: false });
  });

  it('should skip the next runs once the embedded catalogs are synchronized and the connectors upgraded', async () => {
    const catalogManagerHandler = await loadCatalogManagerHandler();
    await catalogManagerHandler();
    await catalogManagerHandler();
    expect(mockSynchronizeCatalogs).toHaveBeenCalledTimes(1);
    expect(mockAutoUpgradeManagedConnectors).toHaveBeenCalledTimes(1);
    expect(mockAutoUpgradeManagedConnectors).toHaveBeenCalledWith(expect.anything(), expect.anything(), ['embedded-catalog']);
  });

  it('should keep running while a non embedded catalog source is configured', async () => {
    mockSynchronizeCatalogs.mockResolvedValue({ synchronizedCatalogIds: ['embedded-catalog', 'custom-catalog'], isEmbeddedOnlySyncComplete: false });
    const catalogManagerHandler = await loadCatalogManagerHandler();
    await catalogManagerHandler();
    await catalogManagerHandler();
    expect(mockSynchronizeCatalogs).toHaveBeenCalledTimes(2);
  });

  it('should keep running until the connectors auto-upgrade succeeds', async () => {
    mockAutoUpgradeManagedConnectors.mockResolvedValueOnce({ hasErrors: true });
    const catalogManagerHandler = await loadCatalogManagerHandler();
    await catalogManagerHandler();
    await catalogManagerHandler();
    await catalogManagerHandler();
    expect(mockSynchronizeCatalogs).toHaveBeenCalledTimes(2);
    expect(mockAutoUpgradeManagedConnectors).toHaveBeenCalledTimes(2);
  });
});
