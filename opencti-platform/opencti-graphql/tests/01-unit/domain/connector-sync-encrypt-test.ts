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

import { encryptSynchronizerCredential } from '../../../src/domain/connector-sync-crypto';
import { testSync } from '../../../src/domain/connector-utils';
import { updateAttribute, createEntity } from '../../../src/database/middleware';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { notify } from '../../../src/database/redis';
import { createOnTheFlyUser } from '../../../src/modules/user/user-domain';
import { verifyIngestionUri } from '../../../src/modules/ingestion/ingestion-common';
import { syncEditField, registerSync, findSyncById } from '../../../src/domain/connector';
import { publishUserAction } from '../../../src/listener/UserActionListener';

const fakeContext = {} as any;
const fakeUser = { id: 'user-1', name: 'Test User', capabilities: [] } as any;

describe('connector.ts — syncEditField token encryption', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(encryptSynchronizerCredential).mockImplementation(async (v: string | null | undefined) => v ? `encrypted:${v}` : v);
    vi.mocked(verifyIngestionUri).mockImplementation(() => undefined);
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

    expect(encryptSynchronizerCredential).toHaveBeenCalledWith('my-plain-token');
    expect(input[0].value[0]).toBe('encrypted:my-plain-token');
    expect(input[1].value[0]).toBe('updated name');
  });

  it('should not encrypt when input has no token key', async () => {
    const input = [{ key: 'name', value: ['updated name'] }];

    await syncEditField(fakeContext, fakeUser, 'test-sync-id', input);

    expect(encryptSynchronizerCredential).not.toHaveBeenCalled();
  });

  it('should not encrypt when token value is empty string', async () => {
    const input = [{ key: 'token', value: [''] }];

    await syncEditField(fakeContext, fakeUser, 'test-sync-id', input);

    expect(encryptSynchronizerCredential).not.toHaveBeenCalled();
  });

  it('should validate uri against deny list when uri is edited', async () => {
    const input = [{ key: 'uri', value: ['https://example.allowed.com'] }];

    await syncEditField(fakeContext, fakeUser, 'test-sync-id', input);

    expect(verifyIngestionUri).toHaveBeenCalledWith('https://example.allowed.com');
    expect(updateAttribute).toHaveBeenCalled();
  });

  it('should reject uri edition when uri is denied', async () => {
    vi.mocked(verifyIngestionUri).mockImplementation(() => {
      throw new Error('This URI is not allowed for ingestion.');
    });
    const input = [{ key: 'uri', value: ['https://example.denied.com'] }];

    await expect(syncEditField(fakeContext, fakeUser, 'test-sync-id', input))
      .rejects.toThrow('This URI is not allowed for ingestion.');

    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('should fail fast on denied uri before token encryption', async () => {
    vi.mocked(verifyIngestionUri).mockImplementation(() => {
      throw new Error('This URI is not allowed for ingestion.');
    });
    const input = [
      { key: 'uri', value: ['https://example.denied.com'] },
      { key: 'token', value: ['my-plain-token'] },
    ];

    await expect(syncEditField(fakeContext, fakeUser, 'test-sync-id', input))
      .rejects.toThrow('This URI is not allowed for ingestion.');

    expect(encryptSynchronizerCredential).not.toHaveBeenCalled();
    expect(updateAttribute).not.toHaveBeenCalled();
  });
});

describe('connector.ts — registerSync token encryption', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(encryptSynchronizerCredential).mockImplementation(async (v: string | null | undefined) => v ? `encrypted:${v}` : v);
    vi.mocked(verifyIngestionUri).mockImplementation(() => undefined);
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

    expect(verifyIngestionUri).toHaveBeenCalledWith('http://remote-opencti.invalid');
    expect(encryptSynchronizerCredential).toHaveBeenCalledWith('secret-stream-token');
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

    expect(verifyIngestionUri).toHaveBeenCalledWith('http://remote-opencti.invalid');
    expect(encryptSynchronizerCredential).not.toHaveBeenCalled();
    expect(createEntity).toHaveBeenCalled();
  });

  it('should reject creation when uri is denied', async () => {
    vi.mocked(verifyIngestionUri).mockImplementation(() => {
      throw new Error('This URI is not allowed for ingestion.');
    });
    const input = {
      name: 'Test synchronizer denied uri',
      uri: 'http://example.denied.com',
      token: 'secret-stream-token',
      stream_id: 'live',
      user_id: fakeUser.id,
      listen_deletion: false,
      no_dependencies: false,
    } as never;

    await expect(registerSync(fakeContext, fakeUser, input))
      .rejects.toThrow('This URI is not allowed for ingestion.');

    expect(testSync).not.toHaveBeenCalled();
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('should fail fast on denied uri before auto user creation', async () => {
    vi.mocked(verifyIngestionUri).mockImplementation(() => {
      throw new Error('This URI is not allowed for ingestion.');
    });
    vi.mocked(createOnTheFlyUser).mockResolvedValue({ id: 'auto-user-id' } as never);

    const input = {
      name: 'Test synchronizer denied uri with automatic user',
      uri: 'http://example.denied.com',
      stream_id: 'live',
      user_id: 'auto-user-name',
      automatic_user: true,
      confidence_level: 50,
      listen_deletion: false,
      no_dependencies: false,
    } as never;

    await expect(registerSync(fakeContext, fakeUser, input))
      .rejects.toThrow('This URI is not allowed for ingestion.');

    expect(createOnTheFlyUser).not.toHaveBeenCalled();
    expect(testSync).not.toHaveBeenCalled();
    expect(createEntity).not.toHaveBeenCalled();
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
