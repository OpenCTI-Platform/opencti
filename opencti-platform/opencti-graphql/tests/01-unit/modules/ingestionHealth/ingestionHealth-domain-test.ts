import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getEntitiesMapFromCache } from '../../../../src/database/cache';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { redisGetConnectorsHeartbeats } from '../../../../src/database/redis';
import {
  buildActingUser,
  buildIngestionHealthInput,
  collectIngestionSources,
  isIngestionConnector,
  resolveIngestionHealth,
  resolveIngestionWarnings,
} from '../../../../src/modules/ingestionHealth/ingestionHealth-domain';
import { redisGetIngestionHealthObservation } from '../../../../src/modules/ingestionHealth/ingestionHealth-redis';

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  getEntitiesMapFromCache: vi.fn(),
}));
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  fullEntitiesList: vi.fn(),
}));
vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<any>()),
  redisGetConnectorsHeartbeats: vi.fn(),
}));
vi.mock('../../../../src/modules/ingestionHealth/ingestionHealth-redis', () => ({
  redisGetIngestionHealthObservation: vi.fn(),
}));

const RECENT = '2026-10-07T11:59:30.000Z';
const OLD = '2026-10-07T10:00:00.000Z';
const users = new Map<string, any>([
  ['service-user', { id: 'service-user', name: 'Service', user_service_account: true }],
  ['personal-user', { id: 'personal-user', name: 'John' }],
]);
const connector = (overrides: Record<string, unknown> = {}): any => ({
  internal_id: 'connector-id',
  name: 'My connector',
  _index: 'opencti_internal_objects-000001',
  connector_type: 'EXTERNAL_IMPORT',
  connector_user_id: 'service-user',
  ...overrides,
});
const regular = (lastSeen: string) => ({ last_seen_at: lastSeen, close_pings: 3 });

describe('Ingestion health domain', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (getEntitiesMapFromCache as any).mockResolvedValue(users);
    (redisGetIngestionHealthObservation as any).mockResolvedValue(null);
    (redisGetConnectorsHeartbeats as any).mockResolvedValue(new Map([['connector-id', RECENT], ['a', RECENT]]));
  });

  it('should evaluate every deployed connector whatever its type, managed or self-hosted', () => {
    expect(isIngestionConnector({ connector_type: 'EXTERNAL_IMPORT' })).toBe(true);
    expect(isIngestionConnector({ connector_type: 'INTERNAL_ENRICHMENT', built_in: false })).toBe(true);
    expect(isIngestionConnector({ connector_type: 'INTERNAL_EXPORT_FILE' })).toBe(true);
    expect(isIngestionConnector({ connector_type: 'STREAM' })).toBe(true);
    expect(isIngestionConnector({ connector_type: 'EXTERNAL_IMPORT', built_in: true })).toBe(false); // platform plumbing or feed twin
    expect(isIngestionConnector({ connector_type: 'internal' })).toBe(false); // queue-backed internal connector
  });

  it('should build the input from the connector, its last ping and its heartbeat observation', () => {
    expect(buildIngestionHealthInput(connector({ connector_info: { run_and_terminate: true } }), new Date(RECENT), regular(RECENT))).toEqual({
      running: true,
      run_and_terminate: true,
      last_seen_at: new Date(RECENT),
      pings_regularly: true,
    });
  });

  it('should take the last ping as an argument, never from the connector', () => {
    expect(buildIngestionHealthInput(connector({ updated_at: RECENT }), null, regular(RECENT)).last_seen_at).toBeNull();
    expect(buildIngestionHealthInput(connector(), new Date(OLD), regular(RECENT)).last_seen_at).toEqual(new Date(OLD));
  });

  it('should consider a managed connector stopped by a person only when it was requested to stop', () => {
    const managed = { catalog_id: 'catalog-id' };
    const runningOf = (overrides: Record<string, unknown>) => buildIngestionHealthInput(connector({ ...managed, ...overrides }), new Date(RECENT), regular(RECENT)).running;
    expect(runningOf({ manager_requested_status: 'stopping' })).toBe(false);
    expect(runningOf({ manager_requested_status: 'stopped' })).toBe(false);
    expect(runningOf({ manager_requested_status: 'starting' })).toBe(true);
    // A crashed container: the composer reports current stopped while the requested status stays starting.
    // Only the requested status is a person's decision, the crash goes through the heartbeat check
    expect(runningOf({ manager_requested_status: 'starting', manager_current_status: 'stopped' })).toBe(true);
    expect(runningOf({ manager_current_status: 'stopped' })).toBe(true);
    // A self-hosted connector cannot be switched off from the platform
    expect(buildIngestionHealthInput(connector({ manager_requested_status: 'stopped' }), new Date(RECENT), regular(RECENT)).running).toBe(true);
  });

  it('should build the acting user without its name, a user without the service account flag being a personal account', () => {
    expect(buildActingUser(connector(), users)).toEqual({ service_account: true });
    expect(buildActingUser(connector({ connector_user_id: 'personal-user' }), users)).toEqual({ service_account: false });
    expect(buildActingUser(connector({ connector_user_id: 'deleted-user' }), users)).toBeUndefined();
    expect(buildActingUser(connector({ connector_user_id: null }), users)).toBeUndefined();
  });

  describe('resolution at read time, from the manager cache only', () => {
    const noHeartbeat = [{ kind: 'runtime', code: 'NO_HEARTBEAT', severity: 'blocking', params: { last_seen: OLD }, message: `No ping received since ${OLD}` }];

    it('should return the cached status, summary, checks and since', () => {
      const cachedCritical = connector({
        ingestion_health_status: 'critical',
        ingestion_health_since: RECENT,
        ingestion_health_summary: `No ping received since ${OLD}`,
        ingestion_health_checks: JSON.stringify(noHeartbeat),
      });
      expect(resolveIngestionHealth(cachedCritical)).toEqual({
        status: 'critical',
        summary: `No ping received since ${OLD}`,
        checks: noHeartbeat,
        since: new Date(RECENT),
      });
    });

    it('should be unknown, never critical, before the manager evaluated the connector, at activation for instance', () => {
      expect(resolveIngestionHealth(connector())).toEqual({ status: 'unknown', summary: 'Not evaluated yet', checks: [], since: null });
    });

    it('should read unreadable cached checks as no check', () => {
      expect(resolveIngestionHealth(connector({ ingestion_health_status: 'unknown', ingestion_health_checks: 'not json' }))?.checks).toEqual([]);
    });

    it('should never call Redis: the deployed list polls this field every 5 seconds', async () => {
      resolveIngestionHealth(connector({ ingestion_health_status: 'critical' }));
      await resolveIngestionWarnings({} as any, connector());
      expect(redisGetIngestionHealthObservation).not.toHaveBeenCalled();
      expect(redisGetConnectorsHeartbeats).not.toHaveBeenCalled();
    });

    it('should resolve the configuration warnings separately from the status', async () => {
      const personal = connector({ connector_user_id: 'personal-user', ingestion_health_status: 'unknown' });
      expect(resolveIngestionHealth(personal)?.status).toBe('unknown');
      expect((await resolveIngestionWarnings({} as any, personal))?.map((warning) => warning.code)).toEqual(['USER_NOT_SERVICE_ACCOUNT']);
    });

    it('should resolve nothing for a connector that is not an ingestion source', async () => {
      const builtIn = connector({ connector_type: 'internal' });
      expect(resolveIngestionHealth(builtIn)).toBeNull();
      expect(await resolveIngestionWarnings({} as any, builtIn)).toBeNull();
    });
  });

  it('should collect every ingestion connector with its previous and next heartbeat observation', async () => {
    (fullEntitiesList as any).mockResolvedValue([
      connector({ internal_id: 'a' }),
      connector({ internal_id: 'b', built_in: true }),
    ]);
    const previous = { last_seen_at: '2026-10-07T11:58:40.000Z', close_pings: 2 };
    (redisGetIngestionHealthObservation as any).mockResolvedValue(previous);
    const sources = await collectIngestionSources({} as any, { boundSeconds: 120, managerWasBlind: false });
    expect(sources.map((source) => source.connector.internal_id)).toEqual(['a']);
    expect(sources[0].previous_heartbeat).toEqual(previous);
    expect(sources[0].heartbeat).toEqual(regular(RECENT)); // a third close ping, 50 seconds after the previous one
    expect(sources[0].input.pings_regularly).toBe(true);
    expect(sources[0].input.last_seen_at).toEqual(new Date(RECENT));
  });

  it('should read the heartbeats from Redis once per cycle, not once per connector', async () => {
    (fullEntitiesList as any).mockResolvedValue([connector({ internal_id: 'a' }), connector({ internal_id: 'b' }), connector({ internal_id: 'c' })]);
    await collectIngestionSources({} as any, { boundSeconds: 120, managerWasBlind: false });
    expect(redisGetConnectorsHeartbeats).toHaveBeenCalledTimes(1);
  });

  it('should measure the last ping on the Redis heartbeat and ignore updated_at', async () => {
    // updated_at is recent (any entity update moves it) but the connector stopped pinging long ago
    (fullEntitiesList as any).mockResolvedValue([connector({ internal_id: 'a', updated_at: RECENT })]);
    (redisGetConnectorsHeartbeats as any).mockResolvedValue(new Map([['a', OLD]]));
    const [source] = await collectIngestionSources({} as any, { boundSeconds: 120, managerWasBlind: false });
    expect(source.input.last_seen_at).toEqual(new Date(OLD));
    expect(source.heartbeat.last_seen_at).toBe(OLD);
  });

  it('should read a connector with no heartbeat, or an unparseable one, as never seen', async () => {
    (fullEntitiesList as any).mockResolvedValue([connector({ internal_id: 'a' }), connector({ internal_id: 'b' })]);
    (redisGetConnectorsHeartbeats as any).mockResolvedValue(new Map([['b', 'not a date']]));
    const sources = await collectIngestionSources({} as any, { boundSeconds: 120, managerWasBlind: false });
    expect(sources.map((source) => source.input.last_seen_at)).toEqual([null, null]);
  });

  it('should fail the collection when the heartbeats cannot be read, with no fallback to an empty map', async () => {
    (fullEntitiesList as any).mockResolvedValue([connector({ internal_id: 'a' })]);
    (redisGetConnectorsHeartbeats as any).mockRejectedValue(new Error('redis unavailable'));
    await expect(collectIngestionSources({} as any, { boundSeconds: 120, managerWasBlind: false })).rejects.toThrow('redis unavailable');
  });

  it('should keep the count of a regular connector after a manager outage, so its death is still caught', async () => {
    (fullEntitiesList as any).mockResolvedValue([connector({ internal_id: 'a' })]);
    // Last seen by the manager long before its outage, pinging during it
    (redisGetIngestionHealthObservation as any).mockResolvedValue(regular(OLD));
    const [afterOutage] = await collectIngestionSources({} as any, { boundSeconds: 120, managerWasBlind: true });
    expect(afterOutage.heartbeat).toEqual(regular(RECENT));
    const [withoutOutage] = await collectIngestionSources({} as any, { boundSeconds: 120, managerWasBlind: false });
    expect(withoutOutage.heartbeat.close_pings).toBe(0);
  });
});
