import { describe, expect, it, vi, beforeEach } from 'vitest';
import { pingConnector, resetStateConnector } from '../../../src/domain/connector';
import { patchAttribute } from '../../../src/database/middleware';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { registerConnectorQueues, purgeConnectorQueues } from '../../../src/database/rabbitmq';
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

vi.mock('../../../src/database/rabbitmq', () => ({
  registerConnectorQueues: vi.fn(),
  purgeConnectorQueues: vi.fn(),
  getConnectorQueueDetails: vi.fn(),
  unregisterConnector: vi.fn(),
  unregisterExchanges: vi.fn(),
  connectorConfig: vi.fn().mockReturnValue({}),
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
