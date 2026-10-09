import { beforeEach, describe, expect, it, vi } from 'vitest';
import { connectorDelete, pingConnector, registerConnector, updateConnectorRequestedStatus } from '../../../src/domain/connector';
import { connector, connectors, isConnectorActive } from '../../../src/database/repository';
import { createEntity, internalDeleteElementById, patchAttribute, updateAttribute } from '../../../src/database/middleware';
import { storeLoadById, topEntitiesList } from '../../../src/database/middleware-loader';
import { notify, redisDeleteConnectorHeartbeat, redisGetConnectorHeartbeat, redisGetConnectorsHeartbeats, redisSetConnectorHeartbeat } from '../../../src/database/redis';
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

describe('connector writes and the connectors cache', () => {
  const input = { id: 'connector-1', name: 'Test Connector', type: ConnectorType.ExternalImport, scope: ['Report'] };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  // The notification resets the connectors cache: a reload in between would cache the connector without its heartbeat
  it('should record the heartbeat before notifying the registration of an existing connector', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(baseConnector as never);
    vi.mocked(patchAttribute).mockResolvedValueOnce({ element: baseConnector } as never);

    await registerConnector(testContext, testUser, input);

    expect(vi.mocked(redisSetConnectorHeartbeat).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(notify).mock.invocationCallOrder[0]);
  });

  it('should record the heartbeat before notifying the registration of a new connector', async () => {
    vi.mocked(storeLoadById).mockResolvedValueOnce(undefined as never);
    vi.mocked(createEntity).mockResolvedValueOnce(baseConnector as never);

    await registerConnector(testContext, testUser, input);

    expect(vi.mocked(redisSetConnectorHeartbeat).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(notify).mock.invocationCallOrder[0]);
  });

  it('should return the completed connector, with its liveness, from connector updates', async () => {
    const lastSeenAt = minutesAgo(0);
    vi.mocked(updateAttribute).mockResolvedValueOnce({ element: baseConnector } as never);
    vi.mocked(redisGetConnectorHeartbeat).mockResolvedValueOnce(lastSeenAt);

    const result = await updateConnectorRequestedStatus(testContext, testUser, { id: 'connector-1', status: 'starting' } as never);

    expect(result.active).toBe(true);
    expect(result.last_seen_at).toBe(lastSeenAt);
    expect(result.connector_scope).toEqual(['Report']);
  });
});

// Built-in connectors (e.g. the connectors representing built-in feeds) are registered by the platform
// and never ping: their liveness is their configured `active`.
describe('built-in connectors liveness', () => {
  const input = { id: 'connector-1', name: '[FEED - CSV] Feed', type: ConnectorType.ExternalImport, scope: ['Report'] };
  const builtInConnector = { ...baseConnector, built_in: true, active: false };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should not record a heartbeat when registering an existing built-in connector', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(builtInConnector as never);
    vi.mocked(patchAttribute).mockResolvedValueOnce({ element: builtInConnector } as never);

    const result = await registerConnector(testContext, testUser, input, { built_in: true, active: false });

    expect(redisSetConnectorHeartbeat).not.toHaveBeenCalled();
    expect(result?.last_seen_at).toBeNull();
    expect(result?.active).toBe(false);
  });

  it('should not record a heartbeat when registering a new built-in connector', async () => {
    vi.mocked(storeLoadById).mockResolvedValueOnce(undefined as never);
    vi.mocked(createEntity).mockResolvedValueOnce(builtInConnector as never);

    const result = await registerConnector(testContext, testUser, input, { built_in: true, active: false });

    expect(redisSetConnectorHeartbeat).not.toHaveBeenCalled();
    expect(result?.last_seen_at).toBeNull();
  });

  it('should ignore any heartbeat of a built-in connector', async () => {
    vi.mocked(topEntitiesList).mockResolvedValueOnce([builtInConnector] as never);
    vi.mocked(redisGetConnectorsHeartbeats).mockResolvedValueOnce(new Map([['connector-1', minutesAgo(0)]]));

    const [result] = await connectors(testContext, testUser);

    expect(result.last_seen_at).toBeNull();
    expect(result.active).toBe(false);
  });
});

describe('heartbeat storage failures', () => {
  const redisError = new Error('OOM command not allowed when used memory > maxmemory');

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should fail the ping, as recording the heartbeat is its purpose', async () => {
    vi.mocked(storeLoadById).mockResolvedValueOnce({ ...baseConnector, connector_state: 'state' } as never);
    vi.mocked(redisSetConnectorHeartbeat).mockRejectedValueOnce(redisError);

    await expect(pingConnector(testContext, testUser, 'connector-1', 'state', undefined as never)).rejects.toThrow(redisError);
  });

  it('should keep a pending state reset when the heartbeat fails, so that the retry delivers it', async () => {
    const resetConnector = { ...baseConnector, connector_state: '', connector_state_reset: true };
    // The connector pings with its stale local state while a reset is pending
    vi.mocked(storeLoadById).mockResolvedValueOnce(resetConnector as never);
    vi.mocked(redisSetConnectorHeartbeat).mockRejectedValueOnce(redisError);

    await expect(pingConnector(testContext, testUser, 'connector-1', 'stale-state', undefined as never)).rejects.toThrow(redisError);
    expect(patchAttribute).not.toHaveBeenCalled();

    // The retry still finds the reset pending: it consumes it and returns the reset state, without writing the stale one
    vi.mocked(storeLoadById).mockResolvedValueOnce(resetConnector as never);
    vi.mocked(patchAttribute).mockResolvedValueOnce({ element: { ...resetConnector, connector_state_reset: false } } as never);

    const result = await pingConnector(testContext, testUser, 'connector-1', 'stale-state', undefined as never);

    expect(vi.mocked(patchAttribute).mock.calls[0][4]).toEqual({ connector_state_reset: false });
    expect(result.connector_state).toBe('');
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
