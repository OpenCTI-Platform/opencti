import { beforeEach, describe, expect, it, vi } from 'vitest';

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
}));

vi.mock('../../../../src/database/engine', () => ({
  getEngineHealth: vi.fn(),
}));

vi.mock('../../../../src/modules/connector/connector-domain', () => ({
  connectors: vi.fn(),
  findRegularlyPingingConnectors: vi.fn(),
  isConnectorStopped: (connector: any) => connector.manager_requested_status === 'stopped',
}));

// ── Imports (after mocks) ───────────────────────────────────────────────

import { getCachedRabbitmqMetrics } from '../../../../src/database/rabbitmq';
import { getEngineHealth } from '../../../../src/database/engine';
import { connectors, findRegularlyPingingConnectors } from '../../../../src/modules/connector/connector-domain';
import {
  buildConnectorsHealth,
  buildRabbitmqHealth,
  buildSearchEngineHealth,
  buildXtmOneHealthSnapshot,
} from '../../../../src/modules/xtm/one/xtm-one-health';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = {} as AuthContext;
const user = { id: 'user-1' } as AuthUser;

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

  it('should sum the messages waiting in the push queues and keep their consumers', () => {
    expect(buildRabbitmqHealth({ consumers: 3, queues })).toEqual({ queue_messages: 40, consumers: 3 });
  });

  it('should report no consumer when no push queue is read', () => {
    expect(buildRabbitmqHealth({ consumers: 0, queues: [{ name: 'push_c1', messages: 12, consumers: 0 }] }))
      .toEqual({ queue_messages: 12, consumers: 0 });
  });

  it('should describe each connector with its liveness, last heartbeat and queued messages', () => {
    const registered = [
      { id: 'c1', internal_id: 'c1', name: 'MITRE', title: 'MITRE ATT&CK', last_seen_at: '2026-11-20T00:00:00.000Z' },
      { id: 'c2', internal_id: 'c2', name: 'Stopped', manager_requested_status: 'stopped', catalog_id: 'x', last_seen_at: null },
      { id: 'c3', internal_id: 'c3', name: 'Run and terminate' },
      { id: 'built', internal_id: 'built', name: 'Built-in', built_in: true },
    ];
    const health = buildConnectorsHealth(registered, new Set(['c1', 'c2']), queues);
    expect(health).toEqual([
      { id: 'c1', name: 'MITRE ATT&CK', active: true, updated_at: '2026-11-20T00:00:00.000Z', queue_messages: 42 },
      { id: 'c2', name: 'Stopped', active: false, queue_messages: 5 },
      { id: 'c3', name: 'Run and terminate', active: false, queue_messages: 0 },
    ]);
  });

  it('should keep a known search engine status and the fullest data node disk', () => {
    expect(buildSearchEngineHealth({ status: 'yellow', allocation: [{ 'disk.percent': '40' }, { 'disk.percent': '87' }, { node: 'UNASSIGNED' }] }))
      .toEqual({ status: 'yellow', disk_used_percent: 87 });
    expect(buildSearchEngineHealth({ status: 'unknown', allocation: [] })).toEqual({});
  });

  it('should leave out a part that cannot be read and still return the others', async () => {
    vi.mocked(getCachedRabbitmqMetrics).mockRejectedValue(new Error('broker unreachable'));
    vi.mocked(connectors).mockResolvedValue([{ id: 'c1', internal_id: 'c1', name: 'MITRE' }] as any);
    vi.mocked(findRegularlyPingingConnectors).mockResolvedValue([{ internal_id: 'c1' }] as any);
    vi.mocked(getEngineHealth).mockResolvedValue({ status: 'green', allocation: [{ 'disk.percent': '12' }] });

    const snapshot = await buildXtmOneHealthSnapshot(context, user);

    expect(snapshot).toEqual({
      schema_version: 1,
      connectors: [{ id: 'c1', name: 'MITRE', active: true, queue_messages: 0 }],
      search_engine: { status: 'green', disk_used_percent: 12 },
    });
  });

  it('should return the bare format when nothing can be read', async () => {
    vi.mocked(getCachedRabbitmqMetrics).mockRejectedValue(new Error('down'));
    vi.mocked(connectors).mockRejectedValue(new Error('down'));
    vi.mocked(findRegularlyPingingConnectors).mockResolvedValue([]);
    vi.mocked(getEngineHealth).mockRejectedValue(new Error('down'));

    expect(await buildXtmOneHealthSnapshot(context, user)).toEqual({ schema_version: 1 });
  });
});
