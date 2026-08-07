import { afterEach, describe, expect, it, vi } from 'vitest';

const DECOUPLING_CONNECTOR_VERSIONS = 'DECOUPLING_CONNECTOR_VERSIONS';

const importCatalogEntityWithFeatureFlag = async (enabled: boolean) => {
  vi.resetModules();
  const registerDefinitionMock = vi.fn();

  vi.doMock('../../../../src/schema/module', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../../../src/schema/module')>();
    return {
      ...actual,
      registerDefinition: (...args: unknown[]) => registerDefinitionMock(...args),
    };
  });

  vi.doMock('../../../../src/config/conf', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../../../src/config/conf')>();
    return {
      ...actual,
      isFeatureEnabled: (feature: string) => feature === DECOUPLING_CONNECTOR_VERSIONS && enabled,
    };
  });

  await import('../../../../src/modules/catalog/catalog-entity');

  return registerDefinitionMock;
};

describe('catalog-entity registration', () => {
  afterEach(() => {
    vi.doUnmock('../../../../src/schema/module');
    vi.doUnmock('../../../../src/config/conf');
    vi.resetModules();
    vi.clearAllMocks();
  });

  it('registers catalog entities when decoupling FF is enabled', async () => {
    const registerDefinitionMock = await importCatalogEntityWithFeatureFlag(true);

    expect(registerDefinitionMock).toHaveBeenCalledTimes(3);
    expect(registerDefinitionMock.mock.calls[0]?.[0]?.type?.name).toBe('CatalogContract');
    expect(registerDefinitionMock.mock.calls[1]?.[0]?.type?.name).toBe('CatalogLogo');
    expect(registerDefinitionMock.mock.calls[2]?.[0]?.type?.name).toBe('CatalogManifest');
  });

  it('does not register catalog entities when decoupling FF is disabled', async () => {
    const registerDefinitionMock = await importCatalogEntityWithFeatureFlag(false);

    expect(registerDefinitionMock).not.toHaveBeenCalled();
  });
});
