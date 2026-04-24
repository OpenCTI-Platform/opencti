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
vi.mock('../../../src/database/repository', () => ({
  connector: vi.fn(), connectors: vi.fn(), connectorsFor: vi.fn(), completeConnector: vi.fn(),
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
  encryptDatabaseValue: vi.fn(), decryptDatabaseValue: vi.fn(), getPlatformCrypto: vi.fn(),
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

import { encryptDatabaseValue } from '../../../src/utils/platformCrypto';
import { testSync } from '../../../src/domain/connector-utils';
import { updateAttribute, createEntity } from '../../../src/database/middleware';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { notify } from '../../../src/database/redis';
import { syncEditField, registerSync, findSyncById } from '../../../src/domain/connector';
import { publishUserAction } from '../../../src/listener/UserActionListener';

const fakeContext = {} as any;
const fakeUser = { id: 'user-1', name: 'Test User', capabilities: [] } as any;

describe('connector.ts — syncEditField token encryption', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(encryptDatabaseValue).mockImplementation(async (v) => v ? `encrypted:${v}` : v);
    vi.mocked(updateAttribute).mockResolvedValue({ element: { id: 'x', name: 'y' } } as never);
    vi.mocked(publishUserAction).mockResolvedValue([] as void[]);
    vi.mocked(notify).mockResolvedValue(undefined as never);
  });

  it('should encrypt token value before calling updateAttribute', async () => {
    const input = [
      { key: 'token', value: ['my-plain-token'] },
      { key: 'name', value: ['updated name'] },
    ];

    await syncEditField(fakeContext, fakeUser, 'test-sync-id', input);

    expect(encryptDatabaseValue).toHaveBeenCalledWith('my-plain-token');
    expect(input[0].value[0]).toBe('encrypted:my-plain-token');
    expect(input[1].value[0]).toBe('updated name');
  });

  it('should not encrypt when input has no token key', async () => {
    const input = [{ key: 'name', value: ['updated name'] }];

    await syncEditField(fakeContext, fakeUser, 'test-sync-id', input);

    expect(encryptDatabaseValue).not.toHaveBeenCalled();
    expect(input[0].value[0]).toBe('updated name');
  });

  it('should not encrypt when token value is empty string', async () => {
    const input = [{ key: 'token', value: [''] }];

    await syncEditField(fakeContext, fakeUser, 'test-sync-id', input);

    expect(encryptDatabaseValue).not.toHaveBeenCalled();
  });
});

describe('connector.ts — registerSync token encryption', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(encryptDatabaseValue).mockImplementation(async (v) => v ? `encrypted:${v}` : v);
    vi.mocked(testSync).mockResolvedValue('Connection success' as never);
    vi.mocked(createEntity).mockResolvedValue({
      element: { id: 'test-sync-id', internal_id: 'test-sync-id' },
      isCreation: true,
    } as never);
    vi.mocked(publishUserAction).mockResolvedValue([] as void[]);
  });

  it('should encrypt token before createEntity', async () => {
    const input = {
      name: 'Test synchronizer',
      uri: 'http://remote-opencti.invalid',
      token: 'secret-stream-token',
      stream_id: 'live',
      user_id: fakeUser.id,
      listen_deletion: false,
      no_dependencies: false,
    } as never;

    await registerSync(fakeContext, fakeUser, input);

    expect(encryptDatabaseValue).toHaveBeenCalledWith('secret-stream-token');
    expect(testSync).toHaveBeenCalled();
    expect(createEntity).toHaveBeenCalled();
  });

  it('should not encrypt when token is absent', async () => {
    const input = {
      name: 'Test synchronizer no token',
      uri: 'http://remote-opencti.invalid',
      stream_id: 'live',
      user_id: fakeUser.id,
      listen_deletion: false,
      no_dependencies: false,
    } as never;

    await registerSync(fakeContext, fakeUser, input);

    expect(encryptDatabaseValue).not.toHaveBeenCalled();
    expect(createEntity).toHaveBeenCalled();
  });
});

describe('connector.ts — findSyncById', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(storeLoadById).mockResolvedValue({ id: 'test-sync-id', name: 'My Sync' } as never);
  });

  it('should delegate to storeLoadById', async () => {
    const result = await findSyncById(fakeContext, fakeUser, 'test-sync-id');

    expect(storeLoadById).toHaveBeenCalledWith(fakeContext, fakeUser, 'test-sync-id', 'Sync');
    expect(result).toEqual({ id: 'test-sync-id', name: 'My Sync' });
  });
});
