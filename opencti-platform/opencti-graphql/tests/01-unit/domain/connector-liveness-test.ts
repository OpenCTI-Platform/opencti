import { beforeEach, describe, expect, it, vi } from 'vitest';
import { connectorDelete, pingConnector, registerConnector } from '../../../src/domain/connector';
import { connector, connectors, isConnectorActive } from '../../../src/database/repository';
import { internalDeleteElementById, patchAttribute } from '../../../src/database/middleware';
import { storeLoadById, topEntitiesList } from '../../../src/database/middleware-loader';
import { redisDeleteConnectorHeartbeat, redisGetConnectorHeartbeat, redisGetConnectorsHeartbeats, redisSetConnectorHeartbeat } from '../../../src/database/redis';
import { ConnectorType } from '../../../src/generated/graphql';
import type { AuthContext, AuthUser } from '../../../src/types/user';

// ---------------------------------------------------------------------------
// Regression tests for OpenCTI-Platform/opencti#18851: the connector `active`
// flag used to be derived from updated_at, which any write on the connector
// entity bumps (migration, catalog auto-upgrade, edition...), making dead
// connectors look alive. Liveness now only comes from the heartbeats recorded
// in redis by connector pings and registrations.
// ---------------------------------------------------------------------------

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
  topEntitiesList: vi.fn(),
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
  redisSetConnectorHeartbeat: vi.fn(),
  redisGetConnectorHeartbeat: vi.fn(),
  redisGetConnectorsHeartbeats: vi.fn(),
  redisDeleteConnectorHeartbeat: vi.fn(),
}));

vi.mock('../../../src/connector/connector-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/connector/connector-domain')>()),
  builtInConnectorsRuntime: vi.fn().mockResolvedValue([]),
}));

vi.mock('../../../src/domain/work', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/domain/work')>()),
  deleteWorkForConnector: vi.fn(),
}));

vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
  completeContextDataForEntity: vi.fn(),
}));

const testContext = { source: 'test' } as unknown as AuthContext;
const testUser = { id: 'test-user-id' } as unknown as AuthUser;

const minutesAgo = (minutes: number) => new Date(Date.now() - minutes * 60 * 1000).toISOString();

const baseConnector = {
  id: 'connector-1',
  internal_id: 'connector-1',
  name: 'Test Connector',
  connector_type: 'EXTERNAL_IMPORT',
  connector_scope: 'Report',
  built_in: false,
};

describe('isConnectorActive', () => {
  it('should not be active without heartbeat, even if the connector entity was just updated', () => {
    expect(isConnectorActive({ ...baseConnector, updated_at: minutesAgo(0) }, null)).toBe(false);
  });

  it('should be active with a recent heartbeat', () => {
    expect(isConnectorActive(baseConnector, minutesAgo(1))).toBe(true);
  });

  it('should not be active with a heartbeat older than 5 minutes', () => {
    expect(isConnectorActive(baseConnector, minutesAgo(6))).toBe(false);
  });

  it('should not be active when a managed connector is stopped, whatever its heartbeat', () => {
    const managedConnector = { ...baseConnector, catalog_id: 'catalog-1', manager_current_status: 'stopped' };
    expect(isConnectorActive(managedConnector, minutesAgo(0))).toBe(false);
  });

  it('should rely on the active flag for built-in connectors', () => {
    expect(isConnectorActive({ ...baseConnector, built_in: true }, null)).toBe(true);
    expect(isConnectorActive({ ...baseConnector, built_in: true, active: false }, minutesAgo(0))).toBe(false);
  });
});

describe('pingConnector liveness', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should record a heartbeat and no longer force updated_at on the connector entity', async () => {
    vi.mocked(storeLoadById).mockResolvedValueOnce({ ...baseConnector, connector_state: 'state' } as never);
    vi.mocked(patchAttribute).mockResolvedValueOnce({ element: { ...baseConnector, connector_state: 'state' } } as never);

    const result = await pingConnector(testContext, testUser, 'connector-1', 'state', undefined as never);

    expect(vi.mocked(patchAttribute).mock.calls[0][4]).not.toHaveProperty('updated_at');
    expect(redisSetConnectorHeartbeat).toHaveBeenCalledWith('connector-1', expect.any(String));
    const [, recordedLastSeenAt] = vi.mocked(redisSetConnectorHeartbeat).mock.calls[0];
    expect(result.last_seen_at).toBe(recordedLastSeenAt);
    expect(result.active).toBe(true);
  });
});

describe('heartbeat storage failures', () => {
  const redisError = new Error('OOM command not allowed when used memory > maxmemory');

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should fail the ping, as recording the heartbeat is its purpose', async () => {
    vi.mocked(storeLoadById).mockResolvedValueOnce({ ...baseConnector, connector_state: 'state' } as never);
    vi.mocked(patchAttribute).mockResolvedValueOnce({ element: { ...baseConnector, connector_state: 'state' } } as never);
    vi.mocked(redisSetConnectorHeartbeat).mockRejectedValueOnce(redisError);

    await expect(pingConnector(testContext, testUser, 'connector-1', 'state', undefined as never)).rejects.toThrow(redisError);
  });

  it('should still register the connector', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(baseConnector as never);
    vi.mocked(patchAttribute).mockResolvedValueOnce({ element: baseConnector } as never);
    vi.mocked(redisSetConnectorHeartbeat).mockRejectedValueOnce(redisError);

    const input = { id: 'connector-1', name: 'Test Connector', type: ConnectorType.ExternalImport, scope: ['Report'] };
    const result = await registerConnector(testContext, testUser, input);

    expect(result?.id).toBe('connector-1');
  });

  it('should still delete the connector', async () => {
    vi.mocked(internalDeleteElementById).mockResolvedValueOnce({ element: baseConnector } as never);
    vi.mocked(redisDeleteConnectorHeartbeat).mockRejectedValueOnce(redisError);

    expect(await connectorDelete(testContext, testUser, 'connector-1')).toBe('connector-1');
  });

  it('should still load a connector, considered inactive', async () => {
    vi.mocked(storeLoadById).mockResolvedValueOnce({ ...baseConnector, updated_at: minutesAgo(0) } as never);
    vi.mocked(redisGetConnectorHeartbeat).mockRejectedValueOnce(redisError);

    const result = await connector(testContext, testUser, 'connector-1');

    expect(result.active).toBe(false);
    expect(result.last_seen_at).toBeNull();
  });

  it('should still list connectors, considered inactive', async () => {
    vi.mocked(topEntitiesList).mockResolvedValueOnce([{ ...baseConnector, updated_at: minutesAgo(0) }] as never);
    vi.mocked(redisGetConnectorsHeartbeats).mockRejectedValueOnce(redisError);

    const result = await connectors(testContext, testUser);

    expect(result).toHaveLength(1);
    expect(result[0].active).toBe(false);
    expect(result[0].last_seen_at).toBeNull();
  });
});
