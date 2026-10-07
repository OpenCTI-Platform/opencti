import { beforeEach, describe, expect, it, vi } from 'vitest';
import { registerConnector } from '../../../src/domain/connector';
import { patchAttribute } from '../../../src/database/middleware';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { ConnectorType } from '../../../src/generated/graphql';
import type { AuthContext, AuthUser } from '../../../src/types/user';

vi.mock('../../../src/database/middleware', () => ({
  patchAttribute: vi.fn(),
  createEntity: vi.fn(),
  deleteElementById: vi.fn(),
  internalDeleteElementById: vi.fn(),
  updateAttribute: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  storeLoadById: vi.fn(),
  fullEntitiesList: vi.fn(),
  internalLoadById: vi.fn(),
  pageEntitiesConnection: vi.fn(),
}));

vi.mock('../../../src/database/rabbitmq', () => ({
  registerConnectorQueues: vi.fn(),
  purgeConnectorQueues: vi.fn(),
  getConnectorQueueDetails: vi.fn(),
  unregisterConnector: vi.fn(),
  unregisterExchanges: vi.fn(),
  connectorConfig: vi.fn().mockReturnValue({}),
}));

vi.mock('../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/redis')>()),
  notify: vi.fn(),
}));

const testContext = { source: 'test' } as unknown as AuthContext;
const testUser = { id: 'test-user-id' } as unknown as AuthUser;

const storedConnector = {
  id: 'connector-1',
  internal_id: 'connector-1',
  name: 'MITRE ATT&CK',
  connector_type: 'EXTERNAL_IMPORT',
  slug: 'mitre',
  catalog_slug_manual: 'mitre-atlas',
  updated_at: '2026-01-01T00:00:00.000Z',
};

const registration = {
  id: 'connector-1',
  name: 'MITRE ATT&CK',
  type: ConnectorType.ExternalImport,
  scope: ['application/stix+json;version=2.1'],
};

describe('registerConnector slug', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(storeLoadById).mockResolvedValue(storedConnector as never);
    vi.mocked(patchAttribute).mockResolvedValue({ element: storedConnector } as never);
  });

  it('should keep the known slug when the registration reports none', async () => {
    await registerConnector(testContext, testUser, { ...registration, slug: null, version: null });
    const patch = vi.mocked(patchAttribute).mock.calls[0][4];
    expect(patch).not.toHaveProperty('slug');
    expect(patch).toHaveProperty('version', null);
  });

  it('should keep the known slug when the registration reports an empty one', async () => {
    await registerConnector(testContext, testUser, { ...registration, slug: '' });
    expect(vi.mocked(patchAttribute).mock.calls[0][4]).not.toHaveProperty('slug');
  });

  it('should store the slug reported by the registration', async () => {
    await registerConnector(testContext, testUser, { ...registration, slug: 'mitre-atlas', version: '6.9.0' });
    expect(vi.mocked(patchAttribute).mock.calls[0][4]).toMatchObject({ slug: 'mitre-atlas', version: '6.9.0' });
  });

  it('should never touch the catalog entry chosen by hand', async () => {
    await registerConnector(testContext, testUser, { ...registration, slug: 'mitre' });
    expect(vi.mocked(patchAttribute).mock.calls[0][4]).not.toHaveProperty('catalog_slug_manual');
  });
});
