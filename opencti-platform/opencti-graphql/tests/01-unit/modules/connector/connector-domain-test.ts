import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createLocalJWKSet, jwtVerify } from 'jose';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const {
  mockStoreLoadById,
  mockUpdateAttribute,
  mockRedisGetConnectorHealthMetrics,
  mockRedisGetConnectorHeartbeat,
} = vi.hoisted(() => ({
  mockStoreLoadById: vi.fn(),
  mockUpdateAttribute: vi.fn(),
  mockRedisGetConnectorHealthMetrics: vi.fn(),
  mockRedisGetConnectorHeartbeat: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: mockStoreLoadById,
}));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  updateAttribute: mockUpdateAttribute,
}));

vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  notify: vi.fn(),
}));

vi.mock('../../../../src/listener/UserActionListener', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/listener/UserActionListener')>()),
  publishUserAction: vi.fn(),
}));

vi.mock('../../../../src/modules/connector/connector-redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/connector/connector-redis')>()),
  redisGetConnectorHealthMetrics: mockRedisGetConnectorHealthMetrics,
  redisGetConnectorHeartbeat: mockRedisGetConnectorHeartbeat,
}));

import { connectorGetUptime, connectorTriggerUpdate, getConnectorJwks, issueConnectorJWT } from '../../../../src/modules/connector/connector-domain';

const context = {} as AuthContext;
const user = { id: 'user-1' } as AuthUser;

describe('connectorTriggerUpdate', () => {
  const importConnector = { id: 'connector-1', internal_id: 'connector-1', name: 'Import connector', connector_type: 'INTERNAL_IMPORT_FILE' };
  const triggerFilters = (filters: unknown) => [{ key: 'connector_trigger_filters', value: [JSON.stringify(filters)] }];

  beforeEach(() => {
    vi.clearAllMocks();
    mockStoreLoadById.mockResolvedValue(importConnector);
    mockUpdateAttribute.mockImplementation(async () => ({ element: importConnector }));
    mockRedisGetConnectorHeartbeat.mockResolvedValue(null);
  });

  it('should reject an unknown connector', async () => {
    mockStoreLoadById.mockResolvedValue(undefined);

    await expect(connectorTriggerUpdate(context, user, 'unknown-connector', triggerFilters({})))
      .rejects.toThrow('Cant find element to update');
    expect(mockUpdateAttribute).not.toHaveBeenCalled();
  });

  it('should reject a connector that is neither an internal enrichment nor an import file connector', async () => {
    mockStoreLoadById.mockResolvedValue({ ...importConnector, connector_type: 'EXTERNAL_IMPORT' });

    await expect(connectorTriggerUpdate(context, user, 'connector-1', triggerFilters({})))
      .rejects.toThrow('Update is only possible on internal enrichment or import file connectors types');
  });

  it('should reject any other key than the trigger filters', async () => {
    await expect(connectorTriggerUpdate(context, user, 'connector-1', [{ key: 'name', value: ['renamed'] }]))
      .rejects.toThrow('Update is only possible on these input keys: connector_trigger_filters');
    expect(mockUpdateAttribute).not.toHaveBeenCalled();
  });

  it('should store an empty filter group as no filter', async () => {
    await connectorTriggerUpdate(context, user, 'connector-1', triggerFilters({ mode: 'and', filters: [], filterGroups: [] }));

    expect(mockUpdateAttribute).toHaveBeenCalledWith(context, user, 'connector-1', 'Connector', [
      { key: 'connector_trigger_filters', value: [''] },
    ]);
  });

  it('should store the trigger filters of an internal enrichment connector', async () => {
    mockStoreLoadById.mockResolvedValue({ ...importConnector, connector_type: 'INTERNAL_ENRICHMENT' });
    const filters = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Indicator'] }], filterGroups: [] };

    const lastSeenAt = new Date().toISOString();
    mockRedisGetConnectorHeartbeat.mockResolvedValue(lastSeenAt);

    const updatedConnector = await connectorTriggerUpdate(context, user, 'connector-1', triggerFilters(filters));

    expect(mockUpdateAttribute).toHaveBeenCalledWith(context, user, 'connector-1', 'Connector', triggerFilters(filters));
    expect(mockRedisGetConnectorHeartbeat).toHaveBeenCalledWith('connector-1');
    expect(updatedConnector).toMatchObject({ id: 'connector-1', last_seen_at: lastSeenAt, active: true });
  });
});

describe('connectorGetUptime', () => {
  const NOW = new Date('2026-10-08T12:00:00.000Z');

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ now: NOW });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should compute the uptime in seconds from the start date reported by the manager', async () => {
    mockRedisGetConnectorHealthMetrics.mockResolvedValue({ started_at: '2026-10-08T11:00:00.000Z' });

    await expect(connectorGetUptime(context, user, 'connector-1')).resolves.toBe(3600);
    expect(mockRedisGetConnectorHealthMetrics).toHaveBeenCalledWith('connector-1');
  });

  it('should return no uptime without health metrics', async () => {
    mockRedisGetConnectorHealthMetrics.mockResolvedValue(null);

    await expect(connectorGetUptime(context, user, 'connector-1')).resolves.toBeNull();
  });

  it('should return no uptime for an invalid start date', async () => {
    mockRedisGetConnectorHealthMetrics.mockResolvedValue({ started_at: 'not-a-date' });

    await expect(connectorGetUptime(context, user, 'connector-1')).resolves.toBeNull();
  });

  it('should return no uptime for a start date in the future', async () => {
    mockRedisGetConnectorHealthMetrics.mockResolvedValue({ started_at: '2026-10-08T13:00:00.000Z' });

    await expect(connectorGetUptime(context, user, 'connector-1')).resolves.toBeNull();
  });
});

describe('connector JWT', () => {
  it('should issue a one hour connector JWT that verifies against the published JWKS', async () => {
    const token = await issueConnectorJWT();
    const jwks = JSON.parse(await getConnectorJwks());

    const { payload } = await jwtVerify(token, createLocalJWKSet(jwks));

    expect(payload).toMatchObject({ iss: 'opencti', sub: 'connector' });
    expect(payload.exp! - payload.iat!).toBe(3600);
  });

  it('should only publish public key material', async () => {
    const jwks = JSON.parse(await getConnectorJwks());

    expect(jwks.keys.length).toBeGreaterThan(0);
    jwks.keys.forEach((key: Record<string, unknown>) => {
      expect(key).not.toHaveProperty('d');
    });
  });
});
