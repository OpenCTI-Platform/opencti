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
  redisGetConnectorsHeartbeats: vi.fn(async () => new Map()),
  redisSetConnectorHealthMetrics: vi.fn(),
  redisGetConnectorHealthMetrics: vi.fn(),
  redisSetConnectorLogs: vi.fn(),
}));
vi.mock('../../../src/modules/connector/connector-rabbitmq', () => ({
  connectorConfig: vi.fn(), unregisterConnector: vi.fn(), registerConnectorQueues: vi.fn(),
  purgeConnectorQueues: vi.fn(), getConnectorQueueDetails: vi.fn(), unregisterExchanges: vi.fn(),
}));
vi.mock('../../../src/modules/connector/connector-repository', () => ({
  findConnectors: vi.fn(async () => []),
}));
vi.mock('../../../src/modules/connector/connector-built-in-domain', () => ({
  builtInConnector: vi.fn(), builtInConnectorsRuntime: vi.fn(async () => []),
}));
vi.mock('../../../src/database/middleware-loader', () => ({
  storeLoadById: vi.fn(), fullEntitiesList: vi.fn(), internalLoadById: vi.fn(), pageEntitiesConnection: vi.fn(),
}));
vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(), completeContextDataForEntity: vi.fn(),
}));
vi.mock('../../../src/modules/catalog/catalog-domain', async (importOriginal) => ({
  computeConnectorTargetContract: vi.fn(),
  getSupportedContractsByImage: vi.fn(),
  mapContractEntityFieldsToEmbeddedConnectorManagerContract: vi.fn(),
  redactContractConfigurationSecrets: (await importOriginal<typeof import('../../../src/modules/catalog/catalog-domain')>()).redactContractConfigurationSecrets,
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
import { createEntity } from '../../../src/database/middleware';
import { fullEntitiesList, storeLoadById } from '../../../src/database/middleware-loader';
import { findConnectors } from '../../../src/modules/connector/connector-repository';
import { createOnTheFlyUser } from '../../../src/modules/user/user-domain';
import { computeConnectorTargetContract } from '../../../src/modules/catalog/catalog-domain';
import { publishUserAction } from '../../../src/listener/UserActionListener';
import { REDACTED_INFORMATION } from '../../../src/database/utils';

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
    expect(createOnTheFlyUser).toHaveBeenCalledWith(fakeContext, fakeUser, { userName: 'user-connector', serviceAccount: true, confidenceLevel: 80 }, { beforeWrite: undefined });
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

describe('connector-domain.ts — managedConnectorAdd write boundary', () => {
  const automaticInput = { ...input, user_id: '[C] My connector', automatic_user: true, confidence_level: '50' };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(findLatestCompatibleCatalogContractByImageName).mockResolvedValue({ contract_id: 'test-1.0.0', manager_supported: true } as never);
    vi.mocked(fullEntitiesList).mockResolvedValue([{ id: 'manager-1', public_key: 'key' }] as never);
    vi.mocked(findConnectors).mockResolvedValue([] as never);
    vi.mocked(createOnTheFlyUser).mockResolvedValue({ id: 'service-account-1' } as never);
    vi.mocked(storeLoadById).mockResolvedValue({ id: 'service-account-1' } as never);
    vi.mocked(createEntity).mockResolvedValue({ id: 'connector-1', internal_id: 'connector-1', name: 'my-connector' } as never);
    vi.mocked(computeConnectorTargetContract).mockReturnValue([]);
  });

  it('should refuse a missing connector manager before writing anything', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([] as never);
    const beforeWrite = vi.fn();

    await expect(managedConnectorAdd(fakeContext, fakeUser, automaticInput, { beforeWrite })).rejects.toThrow('There is no connector manager configured');
    expect(beforeWrite).not.toHaveBeenCalled();
    expect(createOnTheFlyUser).not.toHaveBeenCalled();
  });

  it('should refuse a name collision before creating the service account', async () => {
    vi.mocked(findConnectors).mockResolvedValue([{ id: 'connector-0', name: 'my-connector' }] as never);
    const beforeWrite = vi.fn();

    await expect(managedConnectorAdd(fakeContext, fakeUser, automaticInput, { beforeWrite })).rejects.toThrow('CONNECTOR_NAME_ALREADY_EXISTS');
    expect(beforeWrite).not.toHaveBeenCalled();
    expect(createOnTheFlyUser).not.toHaveBeenCalled();
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('should announce the write right before creating the service account and the connector', async () => {
    const order: string[] = [];
    const beforeWrite = vi.fn(() => order.push('beforeWrite'));
    vi.mocked(createOnTheFlyUser).mockImplementation(async (_context, _user, _input, options) => {
      order.push('createOnTheFlyUser checks');
      options?.beforeWrite?.();
      order.push('createOnTheFlyUser write');
      return { id: 'service-account-1' } as never;
    });
    vi.mocked(createEntity).mockImplementation(async () => {
      order.push('createEntity');
      return { id: 'connector-1', internal_id: 'connector-1', name: 'my-connector' } as never;
    });

    const created = await managedConnectorAdd(fakeContext, fakeUser, automaticInput, { beforeWrite });
    expect(created.id).toEqual('connector-1');
    expect(order).toEqual(['createOnTheFlyUser checks', 'beforeWrite', 'createOnTheFlyUser write', 'beforeWrite', 'createEntity']);
  });

  it('should announce nothing when the service account checks refuse before writing', async () => {
    vi.mocked(createOnTheFlyUser).mockRejectedValue(new Error('You have not defined a default group for ingestion users'));
    const beforeWrite = vi.fn();

    await expect(managedConnectorAdd(fakeContext, fakeUser, automaticInput, { beforeWrite })).rejects.toThrow('You have not defined a default group for ingestion users');
    expect(beforeWrite).not.toHaveBeenCalled();
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('should never record the secret settings of the deployment in the activity log', async () => {
    vi.mocked(computeConnectorTargetContract).mockReturnValue([
      { key: 'API_KEY', value: 'encrypted-value', encrypted: true },
      { key: 'API_URL', value: 'https://api.example.com' },
    ]);
    const configuration = [{ key: 'API_KEY', value: 'clear-secret' }, { key: 'API_URL', value: 'https://api.example.com' }];

    await managedConnectorAdd(fakeContext, fakeUser, { ...automaticInput, manager_contract_configuration: configuration });
    const activity = vi.mocked(publishUserAction).mock.calls[0][0] as any;
    expect(activity.context_data.input.manager_contract_configuration).toEqual([
      { key: 'API_KEY', value: REDACTED_INFORMATION },
      { key: 'API_URL', value: 'https://api.example.com' },
    ]);
    expect(JSON.stringify(activity)).not.toContain('clear-secret');
  });

  it('should leave the settings the deployment does not store out of the activity log', async () => {
    vi.mocked(computeConnectorTargetContract).mockReturnValue([
      { key: 'API_KEY', value: 'encrypted-value', encrypted: true },
      { key: 'API_URL', value: 'https://api.example.com' },
    ]);
    const configuration = [
      { key: 'OPENCTI_TOKEN', value: 'clear-platform-token' },
      { key: 'API_KEY', value: 'clear-secret' },
      { key: 'UNKNOWN_SETTING', value: 'clear-unknown' },
      { key: 'API_URL', value: 'https://api.example.com' },
    ];

    await managedConnectorAdd(fakeContext, fakeUser, { ...automaticInput, manager_contract_configuration: configuration });
    const activity = vi.mocked(publishUserAction).mock.calls[0][0] as any;
    expect(activity.context_data.input.manager_contract_configuration).toEqual([
      { key: 'API_KEY', value: REDACTED_INFORMATION },
      { key: 'API_URL', value: 'https://api.example.com' },
    ]);
    const recorded = JSON.stringify(activity);
    expect(recorded).not.toContain('clear-platform-token');
    expect(recorded).not.toContain('clear-secret');
    expect(recorded).not.toContain('clear-unknown');
  });

  it('should record a setting entered twice with the entry the deployment keeps, never an earlier password', async () => {
    const catalogDomain = await vi.importActual<typeof import('../../../src/modules/catalog/catalog-domain')>('../../../src/modules/catalog/catalog-domain');
    vi.mocked(computeConnectorTargetContract).mockImplementation(catalogDomain.computeConnectorTargetContract);
    vi.mocked(findLatestCompatibleCatalogContractByImageName).mockResolvedValue({
      contract_id: 'test-1.0.0',
      manager_supported: true,
      slug: 'test',
      title: 'Test',
      config_schema: {
        type: 'object',
        properties: { API_KEY: { type: 'string', format: 'password', default: 'default-key' }, API_URL: { type: 'string' } },
        required: ['API_KEY', 'API_URL'],
      },
    } as never);
    const configuration = [
      { key: 'API_KEY', value: 'clear-secret' },
      { key: 'API_URL', value: 'https://api.example.com' },
      { key: 'API_KEY', value: '' },
    ];

    await managedConnectorAdd(fakeContext, fakeUser, { ...automaticInput, manager_contract_configuration: configuration });
    const stored = vi.mocked(createEntity).mock.calls[0][2] as any;
    expect(stored.manager_contract_configuration).toEqual([
      { key: 'API_KEY', value: 'default-key' },
      { key: 'API_URL', value: 'https://api.example.com' },
    ]);
    const activity = vi.mocked(publishUserAction).mock.calls[0][0] as any;
    expect(activity.context_data.input.manager_contract_configuration).toEqual([
      { key: 'API_KEY', value: '' },
      { key: 'API_URL', value: 'https://api.example.com' },
    ]);
    expect(JSON.stringify(activity)).not.toContain('clear-secret');
  });
});
