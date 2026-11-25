import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// ── Mocks (must be declared before imports) ─────────────────────────────

vi.mock('../../../../src/config/conf', () => ({
  default: { get: vi.fn() },
  logApp: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

vi.mock('../../../../src/database/utils', () => ({
  RABBIT_QUEUE_PREFIX: '',
}));

vi.mock('../../../../src/database/rabbitmq', () => ({
  getCachedRabbitmqMetrics: vi.fn(),
  rabbitMQIsAlive: vi.fn(),
}));

vi.mock('../../../../src/database/engine', () => ({
  isEngineAlive: vi.fn(),
}));

vi.mock('../../../../src/database/redis', () => ({ redisGetPlatformUsageMetrics: vi.fn(), redisIsAlive: vi.fn() }));
vi.mock('../../../../src/database/raw-file-storage', () => ({ isStorageAlive: vi.fn() }));
vi.mock('../../../../src/config/tracing', () => ({ meterManager: {} }));
vi.mock('../../../../src/database/cache', () => ({ getEntitiesListFromCache: vi.fn() }));

vi.mock('../../../../src/telemetry/platformHealthMetrics', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/telemetry/platformHealthMetrics')>()),
  getPlatformUsageMetrics: vi.fn(),
}));

vi.mock('../../../../src/modules/connector/connector-domain', () => ({
  isConnectorStopped: (connector: any) => connector.manager_requested_status === 'stopped',
  refreshConnectorsLiveness: vi.fn(async (cachedConnectors: any[]) => cachedConnectors),
}));

// ── Imports (after mocks) ───────────────────────────────────────────────

import { getCachedRabbitmqMetrics } from '../../../../src/database/rabbitmq';
import { getEntitiesListFromCache } from '../../../../src/database/cache';
import { getPlatformUsageMetrics, type PlatformUsageMetrics } from '../../../../src/telemetry/platformHealthMetrics';
import { buildConnectorsHealth, buildRabbitmqHealth, buildXtmOneHealthSnapshot } from '../../../../src/modules/xtm/one/xtm-one-health';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = {} as AuthContext;
const user = { id: 'user-1' } as AuthUser;
const noUsageMetrics: PlatformUsageMetrics = { es_used_size: null, es_status: null, es_disk_used_percent: null, s3_used_size: null, queue_consumers: null };

const queues = [
  { name: 'push_c1', messages: 40, consumers: 3 },
  { name: 'listen_c1', messages: 2, consumers: 1 },
  { name: 'push_c2', messages: 0, consumers: 3 },
  { name: 'listen_c2', messages: 5, consumers: 1 },
];

describe('XTM One health snapshot', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should sum the messages waiting in the push queues and keep their consumers', () => {
    expect(buildRabbitmqHealth({ consumers: 3, queues })).toEqual({ queue_messages: 40, consumers: 3 });
  });

  it('should report no consumer when no push queue is read', () => {
    expect(buildRabbitmqHealth({ consumers: 0, queues: [{ name: 'push_c1', messages: 12, consumers: 0 }] }))
      .toEqual({ queue_messages: 12, consumers: 0 });
  });

  it('should describe each connector with its activity, last heartbeat and queued messages', () => {
    const health = { status: 'healthy', status_since: '2026-11-20T00:00:00.000Z' };
    const registered = [
      { id: 'c1', internal_id: 'c1', name: 'MITRE', title: 'MITRE ATT&CK', last_seen_at: '2026-11-20T00:00:00.000Z', ingestion_health: health },
      { id: 'c2', internal_id: 'c2', name: 'Stopped', manager_requested_status: 'stopped', catalog_id: 'x', last_seen_at: null, ingestion_health: health },
      { id: 'c3', internal_id: 'c3', name: 'Not evaluated yet' },
      { id: 'built', internal_id: 'built', name: 'Built-in', built_in: true },
    ];
    expect(buildConnectorsHealth(registered as any, queues)).toEqual([
      { id: 'c1', name: 'MITRE ATT&CK', active: true, updated_at: '2026-11-20T00:00:00.000Z', queue_messages: 42 },
      { id: 'c2', name: 'Stopped', active: false, queue_messages: 5 },
      { id: 'c3', name: 'Not evaluated yet', active: false, queue_messages: 0 },
    ]);
  });

  it('should read the search engine health collected by the platform usage metrics manager', async () => {
    vi.mocked(getCachedRabbitmqMetrics).mockRejectedValue(new Error('broker unreachable'));
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([{ id: 'c1', internal_id: 'c1', name: 'MITRE', ingestion_health: { status: 'critical' } }]);
    vi.mocked(getPlatformUsageMetrics).mockReturnValue({ ...noUsageMetrics, es_status: 'yellow', es_disk_used_percent: 87 });

    expect(await buildXtmOneHealthSnapshot(context, user)).toEqual({
      schema_version: 1,
      connectors: [{ id: 'c1', name: 'MITRE', active: true, queue_messages: 0 }],
      search_engine: { status: 'yellow', disk_used_percent: 87 },
    });
  });

  it('should leave out a part that does not answer in time and still return the others', async () => {
    vi.useFakeTimers();
    vi.mocked(getCachedRabbitmqMetrics).mockResolvedValue({ consumers: 3, queues } as any);
    vi.mocked(getEntitiesListFromCache).mockReturnValue(new Promise(() => {}));
    vi.mocked(getPlatformUsageMetrics).mockReturnValue({ ...noUsageMetrics, es_status: 'green' });

    const pending = buildXtmOneHealthSnapshot(context, user);
    await vi.advanceTimersByTimeAsync(15_000);

    expect(await pending).toEqual({ schema_version: 1, rabbitmq: { queue_messages: 40, consumers: 3 }, search_engine: { status: 'green' } });
  });

  it('should return the bare format when nothing can be read', async () => {
    vi.mocked(getCachedRabbitmqMetrics).mockRejectedValue(new Error('down'));
    vi.mocked(getEntitiesListFromCache).mockRejectedValue(new Error('down'));
    vi.mocked(getPlatformUsageMetrics).mockReturnValue(noUsageMetrics);

    expect(await buildXtmOneHealthSnapshot(context, user)).toEqual({ schema_version: 1 });
  });
});
