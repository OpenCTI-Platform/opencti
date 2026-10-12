import { describe, expect, it, vi, beforeEach } from 'vitest';

vi.mock('../../../src/database/middleware', () => ({
  updateAttribute: vi.fn(),
  createEntity: vi.fn(),
  patchAttribute: vi.fn(),
  deleteElementById: vi.fn(),
  internalDeleteElementById: vi.fn(),
}));
vi.mock('../../../src/database/engine', () => ({
  elLoadById: vi.fn(), elUpdate: vi.fn(), elList: vi.fn(), elCount: vi.fn(), elFindByIds: vi.fn(),
}));
vi.mock('../../../src/database/redis', () => ({
  notify: vi.fn(),
  setEditContext: vi.fn(),
  delEditContext: vi.fn(),
  redisGetWork: vi.fn(),
  redisSetConnectorHealthMetrics: vi.fn(),
  redisGetConnectorHealthMetrics: vi.fn(),
  redisSetConnectorLogs: vi.fn(),
}));
vi.mock('../../../src/database/rabbitmq', () => ({
  unregisterConnector: vi.fn(), registerConnectorQueues: vi.fn(),
  purgeConnectorQueues: vi.fn(), getConnectorQueueDetails: vi.fn(), unregisterExchanges: vi.fn(),
}));
vi.mock('../../../src/database/repository', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/database/repository')>();
  return {
    ...actual,
    connector: vi.fn(),
    connectors: vi.fn(),
    connectorsFor: vi.fn(),
    completeConnector: vi.fn(),
  };
});
vi.mock('../../../src/database/middleware-loader', () => ({
  storeLoadById: vi.fn(), fullEntitiesList: vi.fn(), internalLoadById: vi.fn(), pageEntitiesConnection: vi.fn(),
}));
vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(), completeContextDataForEntity: vi.fn(),
}));
vi.mock('../../../src/modules/catalog/catalog-domain', () => ({
  computeConnectorTargetContract: vi.fn(), getSupportedContractsByImage: vi.fn(),
}));
vi.mock('../../../src/database/cache', () => ({ getEntitiesMapFromCache: vi.fn() }));
vi.mock('../../../src/manager/telemetryManager', () => ({
  addConnectorDeployedCount: vi.fn(), addWorkbenchDraftConvertionCount: vi.fn(), addWorkbenchValidationCount: vi.fn(),
}));
vi.mock('../../../src/modules/user/user-domain', () => ({ createOnTheFlyUser: vi.fn() }));
vi.mock('../../../src/modules/draftWorkspace/draftWorkspace-domain', () => ({ addDraftWorkspace: vi.fn() }));
vi.mock('../../../src/utils/platformCrypto', () => ({
  getPlatformCrypto: vi.fn(),
}));
vi.mock('../../../src/domain/connector-sync-crypto', () => ({
  encryptSynchronizerCredential: vi.fn(), decryptSynchronizerCredential: vi.fn(),
}));
vi.mock('../../../src/modules/ingestion/ingestion-common', () => ({
  verifyIngestionUri: vi.fn(),
}));
vi.mock('../../../src/domain/connector-utils', () => ({
  testSync: vi.fn(), createSyncHttpUri: vi.fn(),
}));
vi.mock('../../../src/database/file-storage', () => ({
  loadFile: vi.fn(), uploadJobImport: vi.fn(), defaultValidationMode: vi.fn(),
}));
vi.mock('../../../src/database/entity-representative', () => ({ extractEntityRepresentativeName: vi.fn() }));
vi.mock('../../../src/utils/http-client', () => ({ getHttpClient: vi.fn() }));
vi.mock('../../../src/utils/confidence-level', () => ({ controlUserConfidenceAgainstElement: vi.fn() }));
vi.mock('../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../src/config/conf');
  return { ...actual, logApp: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() } };
});
vi.mock('../../../src/enterprise-edition/ee', () => ({ checkEnterpriseEdition: vi.fn() }));
vi.mock('../../../src/modules/catalog/catalog-repository', () => ({
  findLatestCompatibleCatalogContractByImageName: vi.fn(),
  findCatalogContractsByImageName: vi.fn(),
}));

import { findCatalogContractsByImageName, findLatestCompatibleCatalogContractByImageName } from '../../../src/modules/catalog/catalog-repository';
import { managedConnectorAdd } from '../../../src/domain/connector';

const fakeContext = {} as any;
const fakeUser = { id: 'user-1', name: 'Test User', capabilities: [] } as any;
const input = {
  name: 'my-connector',
  user_id: 'user-connector',
  catalog_id: 'catalog-id',
  manager_contract_image: 'opencti/connector-test',
  manager_contract_configuration: [],
} as any;

describe('connector.ts — managedConnectorAdd contract compatibility', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should reject a connector whose contracts are all incompatible with the platform version', async () => {
    vi.mocked(findLatestCompatibleCatalogContractByImageName).mockResolvedValue(undefined as never);
    vi.mocked(findCatalogContractsByImageName).mockResolvedValue([{ contract_id: 'test-2.0.0', min_version: '9999.0.0' }] as never);

    await expect(managedConnectorAdd(fakeContext, fakeUser, input)).rejects.toThrow('This connector is not compatible with the platform version');
  });

  it('should reject an unknown connector image', async () => {
    vi.mocked(findLatestCompatibleCatalogContractByImageName).mockResolvedValue(undefined as never);
    vi.mocked(findCatalogContractsByImageName).mockResolvedValue([] as never);

    await expect(managedConnectorAdd(fakeContext, fakeUser, input)).rejects.toThrow('Target contract not found');
  });

  it('should go on with the latest compatible contract', async () => {
    vi.mocked(findLatestCompatibleCatalogContractByImageName).mockResolvedValue({ contract_id: 'test-1.0.0', manager_supported: false } as never);

    await expect(managedConnectorAdd(fakeContext, fakeUser, input)).rejects.toThrow('You have not chosen a connector supported by the manager');
    expect(findCatalogContractsByImageName).not.toHaveBeenCalled();
  });
});
