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
}));
vi.mock('../../../src/modules/connector/connector-redis', () => ({
  redisSetConnectorHealthMetrics: vi.fn(),
  redisGetConnectorHealthMetrics: vi.fn(),
  redisSetConnectorLogs: vi.fn(),
}));
vi.mock('../../../src/modules/connector/connector-rabbitmq', () => ({
  unregisterConnector: vi.fn(), registerConnectorQueues: vi.fn(),
  purgeConnectorQueues: vi.fn(), getConnectorQueueDetails: vi.fn(), unregisterExchanges: vi.fn(),
}));
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
import { managedConnectorAdd, managedConnectorEdit } from '../../../src/modules/connector/connector-domain';
import { fullEntitiesList, storeLoadById } from '../../../src/database/middleware-loader';
import { createOnTheFlyUser } from '../../../src/modules/user/user-domain';

const fakeContext = {} as any;
const fakeUser = { id: 'user-1', name: 'Test User', capabilities: [] } as any;
const input = {
  name: 'my-connector',
  user_id: 'user-connector',
  catalog_id: 'catalog-id',
  manager_contract_image: 'opencti/connector-test',
  manager_contract_configuration: [],
} as any;

describe('connector-domain.ts — managedConnectorAdd contract compatibility', () => {
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

describe('connector-domain.ts — managedConnectorAdd input validation', () => {
  const manager = { id: 'manager-1', public_key: 'manager-public-key' };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(storeLoadById).mockReset();
    vi.mocked(findLatestCompatibleCatalogContractByImageName).mockResolvedValue({ contract_id: 'test-1.0.0', manager_supported: true } as never);
    vi.mocked(fullEntitiesList).mockResolvedValue([manager] as never);
  });

  it('should reject a connector when no connector manager is registered', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([] as never);

    await expect(managedConnectorAdd(fakeContext, fakeUser, input)).rejects.toThrow('There is no connector manager configured');
  });

  it('should reject a connector without a user responsible for data creation', async () => {
    await expect(managedConnectorAdd(fakeContext, fakeUser, { ...input, user_id: 'u' })).rejects.toThrow('You have not chosen a user responsible for data creation');
  });

  it('should create the connector user on the fly when asked to', async () => {
    vi.mocked(createOnTheFlyUser).mockResolvedValue({ id: 'created-user-id' } as never);
    vi.mocked(storeLoadById).mockResolvedValue(undefined as never);

    await expect(managedConnectorAdd(fakeContext, fakeUser, { ...input, automatic_user: true, confidence_level: '80' }))
      .rejects.toThrow('Connector user not found');
    expect(createOnTheFlyUser).toHaveBeenCalledWith(fakeContext, fakeUser, { userName: 'user-connector', serviceAccount: true, confidenceLevel: 80 });
    expect(storeLoadById).toHaveBeenCalledWith(fakeContext, fakeUser, 'created-user-id', 'User');
  });

  it('should reject a connector whose user does not exist', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(undefined as never);

    await expect(managedConnectorAdd(fakeContext, fakeUser, input)).rejects.toThrow('Connector user not found');
    expect(createOnTheFlyUser).not.toHaveBeenCalled();
  });

  it('should reject a name too short to be a container name', async () => {
    vi.mocked(storeLoadById).mockResolvedValue({ id: 'user-connector' } as never);

    await expect(managedConnectorAdd(fakeContext, fakeUser, { ...input, name: 'a' })).rejects.toThrow('Invalid connector name');
  });
});

describe('connector-domain.ts — managedConnectorEdit input validation', () => {
  const editInput = {
    id: 'connector-1',
    name: 'my-connector',
    title: 'My connector',
    connector_user_id: 'user-connector',
    manager_contract_configuration: [],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(storeLoadById).mockReset();
    vi.mocked(fullEntitiesList).mockResolvedValue([{ id: 'manager-1', public_key: 'manager-public-key' }] as never);
  });

  it('should reject an unknown connector', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(undefined as never);

    await expect(managedConnectorEdit(fakeContext, fakeUser, editInput)).rejects.toThrow('Connector not found');
  });

  it('should reject a connector that is not managed', async () => {
    vi.mocked(storeLoadById).mockResolvedValue({ id: 'connector-1', name: 'my-connector' } as never);

    await expect(managedConnectorEdit(fakeContext, fakeUser, editInput)).rejects.toThrow('Target contract not found');
  });

  it('should reject the edition when no connector manager is registered', async () => {
    vi.mocked(storeLoadById).mockResolvedValue({ id: 'connector-1', name: 'my-connector', manager_contract: { connector_type: 'EXTERNAL_IMPORT' } } as never);
    vi.mocked(fullEntitiesList).mockResolvedValue([] as never);

    await expect(managedConnectorEdit(fakeContext, fakeUser, editInput)).rejects.toThrow('There is no connector manager configured');
  });
});
