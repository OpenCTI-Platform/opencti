import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createRelation, patchAttribute } from '../../../../src/database/middleware';
import { internalLoadById } from '../../../../src/database/middleware-loader';
import { addObservedData } from '../../../../src/domain/observedData';
import { addStixCyberObservable } from '../../../../src/domain/stixCyberObservable';
import { addSystem } from '../../../../src/domain/system';
import { createHuntHitObservations, huntRunObservedGroups, iocValueObservable, nextHuntObservedCount } from '../../../../src/modules/hunt/hunt-hit-observations';
import type { BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import { RELATION_RELATED_TO } from '../../../../src/schema/stixCoreRelationship';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/domain/stixCyberObservable', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/domain/stixCyberObservable')>(),
  addStixCyberObservable: vi.fn(async (_context: unknown, _user: unknown, input: { type: string }) => ({
    internal_id: `${input.type}-1`,
    standard_id: `${input.type.toLowerCase()}--00000000-0000-4000-8000-000000000001`,
  })),
}));

vi.mock('../../../../src/domain/observedData', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/domain/observedData')>(),
  addObservedData: vi.fn(async () => ({ internal_id: 'observed-data-1' })),
}));

vi.mock('../../../../src/domain/system', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/domain/system')>(),
  addSystem: vi.fn(async () => ({ internal_id: 'system-1', standard_id: 'system--00000000-0000-4000-8000-000000000002' })),
}));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  createRelation: vi.fn(async () => ({ internal_id: 'relation-1' })),
  patchAttribute: vi.fn(async () => ({ element: {} })),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  internalLoadById: vi.fn(async () => null),
}));

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/cache')>(),
  getEntitiesMapFromCache: vi.fn(async () => new Map()),
}));

vi.mock('../../../../src/modules/hunt/hunt-lock', () => ({
  withHuntLock: async <T>(_key: string, action: () => Promise<T>) => action(),
}));

const indicatorHunt = { internal_id: 'hunt-1', hunt_type: 'indicators' } as unknown as BasicStoreEntityHunt;

const domainResult = {
  key: 'ioc-domain',
  value: 'evil.example',
  observable_type: 'Domain-Name',
  source_ids: ['indicator-1'],
  verdict: 'seen',
  hits_count: 3,
  hosts: ['ws-042'],
};

// A run of an indicator hunt whose connector reported its hits on one victim, over every hit
const indicatorRun = (overrides: Record<string, unknown> = {}) => ({
  internal_id: 'run-2',
  security_platform_id: null,
  hits_count: 3,
  first_hit_at: '2026-10-05T08:00:00.000Z',
  last_hit_at: '2026-10-05T09:00:00.000Z',
  ioc_results: [domainResult],
  observations: [{ key: 'ioc-domain', host: 'ws-042', hits_count: 3, new_hits_count: 3, first_seen: '2026-10-05T08:00:00.000Z', last_seen: '2026-10-05T09:00:00.000Z' }],
  hits_sample: [{
    event_id: 'event-1',
    timestamp: '2026-10-05T08:00:00.000Z',
    detection: null,
    matched: [{ field: 'principal.hostname', value_preview: 'evil.example', value_complete: true }],
    host: 'ws-042',
    user: null,
    process: null,
  }],
  ...overrides,
} as unknown as BasicStoreEntityHuntRun);

const storedObservedData = (overrides: Record<string, unknown>) => {
  vi.mocked(internalLoadById).mockResolvedValue({
    internal_id: 'observed-data-1',
    number_observed: 3,
    first_observed: '2026-10-05T08:00:00.000Z',
    last_observed: '2026-10-05T09:00:00.000Z',
    x_opencti_hunt_run_id: 'run-1',
    ...overrides,
  } as never);
};

describe('Observed data of the hits of a run', () => {
  beforeEach(() => {
    vi.mocked(addStixCyberObservable).mockClear();
    vi.mocked(addObservedData).mockClear();
    vi.mocked(addSystem).mockClear();
    vi.mocked(createRelation).mockClear();
    vi.mocked(patchAttribute).mockClear();
    vi.mocked(internalLoadById).mockResolvedValue(null as never);
  });

  it('should observe a value of an indicator hunt typed by its indicator, on its victim as a system related to its hostname', async () => {
    const result = await createHuntHitObservations({} as AuthContext, indicatorHunt, indicatorRun());
    // The domain is a Domain-Name, as its indicator says, never a Hostname read from the field that held it
    const observableTypes = vi.mocked(addStixCyberObservable).mock.calls.map(([, , input]) => (input as { type: string }).type);
    expect(observableTypes).toContain('Domain-Name');
    expect(vi.mocked(addStixCyberObservable).mock.calls.some(([, , input]) => JSON.stringify(input).includes('"Hostname":{"value":"evil.example"}'))).toBe(false);
    expect(addSystem).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.objectContaining({ name: 'ws-042' }));
    expect(createRelation).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.objectContaining({
      fromId: 'system-1',
      toId: 'Hostname-1',
      relationship_type: RELATION_RELATED_TO,
    }));
    expect(addObservedData).toHaveBeenCalledTimes(1);
    expect(addObservedData).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.objectContaining({
      objects: ['Domain-Name-1', 'system-1'],
      number_observed: 3,
      first_observed: '2026-10-05T08:00:00.000Z',
      last_observed: '2026-10-05T09:00:00.000Z',
      x_opencti_hunt_run_id: 'run-2',
    }));
    expect(result.observedDataIds).toEqual(['observed-data-1']);
  });

  it('should add nothing when a second run reports the same identified hits, and keep the dates', async () => {
    storedObservedData({});
    const second = indicatorRun({
      internal_id: 'run-3',
      observations: [{ key: 'ioc-domain', host: 'ws-042', hits_count: 3, new_hits_count: 0, first_seen: '2026-10-05T08:00:00.000Z', last_seen: '2026-10-05T09:00:00.000Z' }],
    });
    await createHuntHitObservations({} as AuthContext, indicatorHunt, second);
    expect(addObservedData).not.toHaveBeenCalled();
    expect(patchAttribute).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'observed-data-1', expect.anything(), expect.objectContaining({
      number_observed: 3,
      first_observed: '2026-10-05T08:00:00.000Z',
      last_observed: '2026-10-05T09:00:00.000Z',
      x_opencti_hunt_run_id: 'run-3',
    }));
  });

  it('should add the new hits of a later run and move the last observation to them', async () => {
    storedObservedData({});
    const later = indicatorRun({
      internal_id: 'run-3',
      observations: [{ key: 'ioc-domain', host: 'ws-042', hits_count: 4, new_hits_count: 2, first_seen: '2026-10-05T08:00:00.000Z', last_seen: '2026-10-06T10:00:00.000Z' }],
    });
    await createHuntHitObservations({} as AuthContext, indicatorHunt, later);
    expect(patchAttribute).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'observed-data-1', expect.anything(), expect.objectContaining({
      number_observed: 5,
      first_observed: '2026-10-05T08:00:00.000Z',
      last_observed: '2026-10-06T10:00:00.000Z',
    }));
  });

  it('should leave the observed data a replayed finalization of the run already updated as it is', async () => {
    storedObservedData({ x_opencti_hunt_run_id: 'run-2' });
    const result = await createHuntHitObservations({} as AuthContext, indicatorHunt, indicatorRun());
    expect(patchAttribute).not.toHaveBeenCalled();
    expect(addObservedData).not.toHaveBeenCalled();
    expect(result.observedDataIds).toEqual(['observed-data-1']);
  });
});

describe('Observation groups and counts of a run', () => {
  it('should count identified hits once, and keep the larger count for hits that are not', () => {
    expect(nextHuntObservedCount(null, { hitsCount: 3, newHitsCount: 3 })).toEqual(3);
    expect(nextHuntObservedCount(3, { hitsCount: 3, newHitsCount: 0 })).toEqual(3);
    expect(nextHuntObservedCount(3, { hitsCount: 4, newHitsCount: 2 })).toEqual(5);
    expect(nextHuntObservedCount(5, { hitsCount: 3, newHitsCount: null })).toEqual(5);
    expect(nextHuntObservedCount(2, { hitsCount: 3, newHitsCount: null })).toEqual(3);
  });

  it('should take the values seen with their hosts when the connector reports no observation', () => {
    const groups = huntRunObservedGroups(indicatorHunt, indicatorRun({ observations: null }));
    expect(groups).toEqual([{
      key: 'ioc-domain',
      hosts: ['ws-042'],
      hitsCount: 3,
      newHitsCount: null,
      firstSeen: '2026-10-05T08:00:00.000Z',
      lastSeen: '2026-10-05T09:00:00.000Z',
    }]);
  });

  it('should type the observable of a value by its indicator', () => {
    expect(iocValueObservable({ observable_type: 'Domain-Name', value: 'evil.example', hash_algorithm: null })).toMatchObject({ type: 'Domain-Name', input: { DomainName: { value: 'evil.example' } } });
    expect(iocValueObservable({ observable_type: 'StixFile', value: 'A'.repeat(64), hash_algorithm: null })).toMatchObject({ type: 'StixFile', input: { StixFile: { hashes: [{ algorithm: 'SHA-256', hash: 'a'.repeat(64) }] } } });
    expect(iocValueObservable({ observable_type: 'Unknown', value: 'x', hash_algorithm: null })).toBeNull();
  });
});
