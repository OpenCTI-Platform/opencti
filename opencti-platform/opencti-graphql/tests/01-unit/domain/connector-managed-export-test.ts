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
vi.mock('../../../src/modules/catalog/catalog-domain', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/modules/catalog/catalog-domain')>();
  return {
    computeConnectorTargetContract: vi.fn(),
    mapContractEntityFieldsToEmbeddedConnectorManagerContract: vi.fn(),
    getContractConfigSchemaWithoutExcludedRuntimeVars: actual.getContractConfigSchemaWithoutExcludedRuntimeVars,
    queryContractBySlug: vi.fn(),
  };
});
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

import { Readable } from 'node:stream';
import type { FileHandle } from 'fs/promises';
import { findCatalogContractsByImageName, findLatestCompatibleCatalogContractByImageName } from '../../../src/modules/catalog/catalog-repository';
import { queryContractBySlug } from '../../../src/modules/catalog/catalog-domain';
import { getEntitiesMapFromCache } from '../../../src/database/cache';
import { managedConnectorAddInputFromImport, managedConnectorExport } from '../../../src/domain/connector';

const fakeContext = {} as any;
const fakeUser = { id: 'user-1', name: 'Test User', capabilities: [] } as any;

const configSchema = {
  properties: {
    CONNECTOR_LOG_LEVEL: { type: 'string' },
    CONNECTOR_DURATION_PERIOD: { type: 'string', format: 'duration' },
    OPENCTI_URL: { type: 'string' },
    API_KEY: { type: 'string', format: 'password' },
    OPTIONAL_SECRET: { type: 'string', format: 'password' },
    UNUSED_SECRET: { type: 'string', format: 'password' },
  },
  required: ['API_KEY', 'OPENCTI_URL'],
};

const managedConnector = {
  id: 'connector-internal-id',
  name: 'my-connector',
  title: 'My connector',
  catalog_id: 'catalog-id',
  connector_user_id: 'connector-user-id',
  manager_contract_image: 'opencti/connector-test',
  manager_upgrade_strategy: 'latest',
  manager_current_status: 'started',
  manager_requested_status: 'started',
  connector_state: '{"last_run": 1}',
  manager_contract: { slug: 'test', contract_version: '1.0.0', config_schema: configSchema },
  manager_contract_configuration: [
    { key: 'CONNECTOR_LOG_LEVEL', value: 'info' },
    { key: 'CONNECTOR_DURATION_PERIOD', value: 'PT1H' },
    { key: 'OPENCTI_URL', value: 'http://localhost:4000' },
    { key: 'API_KEY', value: 'encrypted-api-key', encrypted: true },
    { key: 'OPTIONAL_SECRET', value: 'encrypted-secret', encrypted: true },
  ],
} as any;

const toFile = (content: string) => Promise.resolve({ createReadStream: () => Readable.from([Buffer.from(content)]) } as unknown as FileHandle);

describe('connector.ts — managed connector configuration export', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map([['connector-user-id', { user_confidence_level: { max_confidence: 60 } }]]) as never);
  });

  it('should export the configuration without the credentials nor the runtime information', async () => {
    const exported = await managedConnectorExport(fakeContext, managedConnector);
    const parsed = JSON.parse(exported);

    expect(parsed.type).toBe('connector');
    expect(parsed.configuration).toEqual({
      name: 'My connector',
      catalog_id: 'catalog-id',
      contract_slug: 'test',
      contract_version: '1.0.0',
      manager_contract_image: 'opencti/connector-test',
      manager_upgrade_strategy: 'latest',
      confidence_level: 60,
      manager_contract_configuration: [
        { key: 'CONNECTOR_LOG_LEVEL', value: 'info' },
        { key: 'CONNECTOR_DURATION_PERIOD', value: 'PT1H' },
      ],
      required_at_import: ['API_KEY', 'OPTIONAL_SECRET'],
    });
    expect(exported).not.toContain('encrypted-');
    expect(exported).not.toContain('connector-internal-id');
    expect(exported).not.toContain('connector-user-id');
  });

  it('should export a null confidence level when the connector user is unknown', async () => {
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map() as never);
    const parsed = JSON.parse(await managedConnectorExport(fakeContext, managedConnector));

    expect(parsed.configuration.confidence_level).toBeNull();
  });

  it('should not export a credential declared as a plain string in the catalog', async () => {
    const connectorWithPlainApiKey = {
      ...managedConnector,
      manager_contract: {
        ...managedConnector.manager_contract,
        config_schema: {
          properties: { ...configSchema.properties, INTEGRATION_API_KEY: { type: 'string' } },
          required: [...configSchema.required, 'INTEGRATION_API_KEY'],
        },
      },
      manager_contract_configuration: [
        ...managedConnector.manager_contract_configuration,
        { key: 'INTEGRATION_API_KEY', value: 'plain-api-key' },
      ],
    };
    const exported = await managedConnectorExport(fakeContext, connectorWithPlainApiKey);
    const parsed = JSON.parse(exported);

    expect(exported).not.toContain('plain-api-key');
    expect(parsed.configuration.required_at_import).toEqual(['API_KEY', 'OPTIONAL_SECRET', 'INTEGRATION_API_KEY']);
  });

  it('should refuse to export a connector registered from outside the platform', async () => {
    await expect(managedConnectorExport(fakeContext, { ...managedConnector, catalog_id: undefined }))
      .rejects.toThrow('Only a managed connector configuration can be exported');
  });
});

describe('connector.ts — managed connector configuration import', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map() as never);
  });

  it('should rebuild a creation input from an exported configuration', async () => {
    const exported = await managedConnectorExport(fakeContext, managedConnector);
    // The latest compatible contract no longer defines CONNECTOR_DURATION_PERIOD
    const { CONNECTOR_DURATION_PERIOD: _, ...newProperties } = configSchema.properties;
    vi.mocked(findLatestCompatibleCatalogContractByImageName)
      .mockResolvedValue({ slug: 'test', manager_supported: true, config_schema: { ...configSchema, properties: newProperties } } as never);
    vi.mocked(queryContractBySlug).mockResolvedValue({ catalog_id: 'new-catalog-id', contract: '{"slug":"test"}' });

    const imported = await managedConnectorAddInputFromImport(fakeContext, fakeUser, toFile(exported));

    expect(queryContractBySlug).toHaveBeenCalledWith(fakeContext, fakeUser, 'test');
    expect(imported).toEqual({
      name: 'My connector',
      catalog_id: 'new-catalog-id',
      contract: '{"slug":"test"}',
      confidence_level: null,
      manager_contract_configuration: [{ key: 'CONNECTOR_LOG_LEVEL', value: 'info' }],
      required_at_import: ['API_KEY', 'OPTIONAL_SECRET'],
    });
  });

  it('should reject a file that is not a managed connector configuration export', async () => {
    const playbook = JSON.stringify({ openCTI_version: '7.0.0', type: 'playbook', configuration: { name: 'playbook' } });

    await expect(managedConnectorAddInputFromImport(fakeContext, fakeUser, toFile(playbook)))
      .rejects.toThrow('Invalid file: this is not a managed connector configuration export');
    await expect(managedConnectorAddInputFromImport(fakeContext, fakeUser, toFile('not a json')))
      .rejects.toThrow('Invalid file: this is not a managed connector configuration export');
  });

  it('should reject a connector that the platform version cannot run', async () => {
    const exported = await managedConnectorExport(fakeContext, managedConnector);
    vi.mocked(findLatestCompatibleCatalogContractByImageName).mockResolvedValue(undefined as never);
    vi.mocked(findCatalogContractsByImageName).mockResolvedValue([{ contract_id: 'test-2.0.0', min_version: '9999.0.0' }] as never);

    await expect(managedConnectorAddInputFromImport(fakeContext, fakeUser, toFile(exported)))
      .rejects.toThrow('This connector is not compatible with the platform version');
    expect(queryContractBySlug).not.toHaveBeenCalled();
  });
});
