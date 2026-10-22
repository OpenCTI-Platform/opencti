import { describe, expect, it, vi, beforeEach } from 'vitest';
import { pingConnector, resetStateConnector } from '../../../src/modules/connector/connector-domain';
import { patchAttribute } from '../../../src/database/middleware';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { registerConnectorQueues, purgeConnectorQueues } from '../../../src/modules/connector/connector-rabbitmq';
import { redisGetConnectorErrors, redisSaveConnectorErrors } from '../../../src/modules/connector/connector-redis';
import { logApp } from '../../../src/config/conf';
import { publishUserAction } from '../../../src/listener/UserActionListener';
import type { AuthContext, AuthUser } from '../../../src/types/user';

// ---------------------------------------------------------------------------
// Regression tests for OpenCTI-Platform/opencti#17472 (server-side part):
// pingConnector/resetStateConnector used to write the new connector_state via
// patchAttribute(...) then discard the already-consistent `element` it
// returns, performing a second, independent storeLoadById read to build the
// response. Under Elasticsearch read-after-write latency, that second read
// can return a stale copy of the document, so the response echoes back an
// out-of-date connector_state even though the write just succeeded.
//
// These tests simulate that latency by making the mocked storeLoadById
// return a document older than the one patchAttribute just persisted, and
// assert the returned connector reflects the freshly written state instead.
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
}));

vi.mock('../../../src/modules/connector/connector-rabbitmq', () => ({
  registerConnectorQueues: vi.fn(),
  purgeConnectorQueues: vi.fn(),
  getConnectorQueueDetails: vi.fn(),
  unregisterConnector: vi.fn(),
  unregisterExchanges: vi.fn(),
  connectorConfig: vi.fn().mockReturnValue({}),
}));

vi.mock('../../../src/modules/connector/connector-redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/connector/connector-redis')>()),
  redisSetConnectorHeartbeat: vi.fn(),
  redisGetConnectorHeartbeat: vi.fn().mockResolvedValue(null),
  redisGetConnectorErrors: vi.fn(),
  redisSaveConnectorErrors: vi.fn(),
}));

vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
  completeContextDataForEntity: vi.fn(),
}));

const testContext = { source: 'test' } as unknown as AuthContext;
const testUser = { id: 'test-user-id' } as unknown as AuthUser;

const baseConnector = {
  id: 'connector-1',
  internal_id: 'connector-1',
  name: 'Test Connector',
  connector_type: 'EXTERNAL_IMPORT',
  connector_scope: 'Report',
  built_in: false,
  updated_at: '2026-01-01T00:00:00.000Z',
};

describe('pingConnector / resetStateConnector state consistency', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(registerConnectorQueues).mockResolvedValue(undefined as never);
    vi.mocked(purgeConnectorQueues).mockResolvedValue(undefined as never);
    vi.mocked(publishUserAction).mockResolvedValue(undefined as never);
  });

  it('pingConnector should return the freshly written connector_state, not a stale re-read under ES latency', async () => {
    // First storeLoadById call: initial load of the connector before the write.
    vi.mocked(storeLoadById).mockResolvedValueOnce({ ...baseConnector, connector_state: 'old-state' } as never);
    // patchAttribute performs the write and returns the already up-to-date element.
    vi.mocked(patchAttribute).mockResolvedValueOnce({
      element: { ...baseConnector, connector_state: 'new-state' },
    } as never);
    // Simulate ES read-after-write latency: a subsequent read still returns the old document.
    vi.mocked(storeLoadById).mockResolvedValueOnce({ ...baseConnector, connector_state: 'old-state' } as never);

    const result = await pingConnector(testContext, testUser, 'connector-1', 'new-state', undefined as never);

    expect(result.connector_state).toBe('new-state');
  });

  it('resetStateConnector should return the freshly reset connector_state, not a stale re-read under ES latency', async () => {
    vi.mocked(patchAttribute).mockResolvedValueOnce({
      element: { ...baseConnector, connector_state: '', connector_state_reset: true },
    } as never);
    // Simulate ES read-after-write latency: a subsequent read still returns the pre-reset document.
    vi.mocked(storeLoadById).mockResolvedValueOnce({ ...baseConnector, connector_state: 'old-state', connector_state_reset: false } as never);

    const result = await resetStateConnector(testContext, testUser, 'connector-1');

    expect(result.connector_state).toBe('');
    expect(result.connector_state_reset).toBe(true);
  });
});

describe('pingConnector', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // clearAllMocks keeps the queued once values, which the tests above can leave unconsumed
    vi.mocked(storeLoadById).mockReset();
    vi.mocked(patchAttribute).mockReset();
    vi.mocked(registerConnectorQueues).mockResolvedValue(undefined as never);
  });

  it('should reject a ping from an unknown connector', async () => {
    vi.mocked(storeLoadById).mockResolvedValueOnce(undefined as never);

    await expect(pingConnector(testContext, testUser, 'unknown-connector', 'state', undefined as never))
      .rejects.toThrow('No connector found with the specified ID');
    expect(registerConnectorQueues).not.toHaveBeenCalled();
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('should only acknowledge a pending state reset instead of writing the pinged state', async () => {
    vi.mocked(storeLoadById).mockResolvedValueOnce({ ...baseConnector, connector_state: '', connector_state_reset: true } as never);
    vi.mocked(patchAttribute).mockResolvedValueOnce({
      element: { ...baseConnector, connector_state: '', connector_state_reset: false },
    } as never);

    const result = await pingConnector(testContext, testUser, 'connector-1', 'state-before-reset', undefined as never);

    expect(patchAttribute).toHaveBeenCalledWith(testContext, testUser, 'connector-1', 'Connector', { connector_state_reset: false });
    expect(result.connector_state).toBe('');
  });
});

describe('pingConnector errors', () => {
  const baseConnectorInfo = { run_and_terminate: false, buffering: false, queue_threshold: 500, queue_messages_size: 0 };
  const connectorInfo = {
    ...baseConnectorInfo,
    errors: [
      { code: 'RATE_LIMITED', message: 'Too many requests', criticity: 1 },
      { code: '   ', message: 'blank code', criticity: 3 },
      { code: 'API_UNREACHABLE', message: 'Source API returned 503', criticity: 2 },
    ],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(storeLoadById).mockReset();
    vi.mocked(patchAttribute).mockReset();
    vi.mocked(redisGetConnectorErrors).mockReset();
    vi.mocked(redisSaveConnectorErrors).mockReset();
    vi.mocked(registerConnectorQueues).mockResolvedValue(undefined as never);
    vi.mocked(redisGetConnectorErrors).mockResolvedValue([]);
    vi.mocked(storeLoadById).mockResolvedValueOnce({ ...baseConnector } as never);
    vi.mocked(patchAttribute).mockResolvedValueOnce({ element: { ...baseConnector } } as never);
  });

  it('should record sanitized errors in redis and not in elasticsearch', async () => {
    await pingConnector(testContext, testUser, 'connector-1', 'state', connectorInfo);

    expect(redisSaveConnectorErrors).toHaveBeenCalledWith('connector-1', [
      { code: 'API_UNREACHABLE', message: 'Source API returned 503', criticity: 2, last_seen_at: expect.any(Number) },
      { code: 'RATE_LIMITED', message: 'Too many requests', criticity: 1, last_seen_at: expect.any(Number) },
    ], []);
    const patch = vi.mocked(patchAttribute).mock.calls[0][4] as { connector_info: Record<string, unknown> };
    expect(patch.connector_info).not.toHaveProperty('errors');
  });

  it('should merge reported errors with the stored ones', async () => {
    const stored = { code: 'PREVIOUS', message: 'From a previous ping', criticity: 3, last_seen_at: Date.now() - 1000 };
    vi.mocked(redisGetConnectorErrors).mockResolvedValue([stored]);

    await pingConnector(testContext, testUser, 'connector-1', 'state', connectorInfo);

    const [, kept, removedCodes] = vi.mocked(redisSaveConnectorErrors).mock.calls[0];
    expect(kept.map(({ code }) => code)).toEqual(['PREVIOUS', 'API_UNREACHABLE', 'RATE_LIMITED']);
    expect(removedCodes).toEqual([]);
  });

  it.each([
    ['without errors', baseConnectorInfo],
    ['with only invalid errors', { ...baseConnectorInfo, errors: [{ code: '   ', message: 'blank code', criticity: 1 }] }],
  ])('should not touch the recorded errors on a ping %s', async (_, info) => {
    await pingConnector(testContext, testUser, 'connector-1', 'state', info);

    expect(redisGetConnectorErrors).not.toHaveBeenCalled();
    expect(redisSaveConnectorErrors).not.toHaveBeenCalled();
  });

  it('should leave the recorded errors untouched on a legacy ping without connector info', async () => {
    await pingConnector(testContext, testUser, 'connector-1', 'state', undefined as never);

    expect(redisSaveConnectorErrors).not.toHaveBeenCalled();
  });

  it('should not fail the ping when errors cannot be recorded', async () => {
    const warnSpy = vi.spyOn(logApp, 'warn').mockImplementation(() => {});
    vi.mocked(redisGetConnectorErrors).mockRejectedValueOnce(new Error('redis down'));

    const result = await pingConnector(testContext, testUser, 'connector-1', 'state', connectorInfo);

    expect(result.id).toBe('connector-1');
    expect(warnSpy).toHaveBeenCalledWith('[OPENCTI-MODULE] Unable to record connector errors', expect.objectContaining({ connectorId: 'connector-1' }));
    warnSpy.mockRestore();
  });
});
