import { describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import {
  type BackfillSourceResolver,
  computeBackfillAssertions,
  createRunningWorkIndex,
  findRunningWorkConnector,
  groupSharedUserWrites,
  readBackfillState,
  runProvenanceBackfillBatch,
} from '../../../../src/modules/provenance/provenance-backfill';
import type { AssertionSource, ProvenanceBackfillState } from '../../../../src/modules/provenance/provenance-types';
import { RULE_MANAGER_USER } from '../../../../src/utils/access';
import { elCount, elPaginate, elRawSearch } from '../../../../src/database/engine';
import { getEntitiesListFromCache } from '../../../../src/database/cache';
import { patchAttribute } from '../../../../src/database/middleware';
import { findByManagerId } from '../../../../src/modules/managerConfiguration/managerConfiguration-domain';
import { listProvenanceTrackedTypes } from '../../../../src/modules/provenance/provenance-tracking';
import { resolveSourceOfUser } from '../../../../src/modules/provenance/provenance-source';
import { applyProvenanceUpdate } from '../../../../src/modules/provenance/provenance-write';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/engine')>(),
  elCount: vi.fn(),
  elPaginate: vi.fn(),
  elRawSearch: vi.fn(),
}));

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/cache')>(),
  getEntitiesListFromCache: vi.fn(),
}));

vi.mock('../../../../src/modules/provenance/provenance-source', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/provenance/provenance-source')>(),
  resolveSourceOfUser: vi.fn(),
}));

vi.mock('../../../../src/modules/provenance/provenance-write', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/provenance/provenance-write')>(),
  applyProvenanceUpdate: vi.fn(),
}));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  patchAttribute: vi.fn(),
}));

vi.mock('../../../../src/modules/managerConfiguration/managerConfiguration-domain', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/managerConfiguration/managerConfiguration-domain')>(),
  findByManagerId: vi.fn(),
}));

vi.mock('../../../../src/modules/provenance/provenance-tracking', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/provenance/provenance-tracking')>(),
  listProvenanceTrackedTypes: vi.fn(),
}));

const connectorSource = (id: string): AssertionSource => ({ source_id: id, source_kind: 'connector', source_name: `Connector ${id}`, work_id: null });
const userSource = (id: string): AssertionSource => ({ source_id: id, source_kind: 'user', source_name: `User ${id}`, work_id: null });

// connector-user writes through connector A before March, connector B afterwards; analyst is a human user
const resolver: BackfillSourceResolver = async (userId, at) => {
  if (userId === 'connector-user') {
    return connectorSource(at < '2026-03-01T00:00:00.000Z' ? 'A' : 'B');
  }
  return userSource(userId);
};

describe('Provenance backfill', () => {
  it('should rebuild one assertion per source from the history of the element', async () => {
    const assertions = await computeBackfillAssertions({
      internal_id: 'malware-1',
      entity_type: 'Malware',
      _index: 'opencti_stix_domain_objects',
      creator_id: ['analyst'],
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-02-01T00:00:00.000Z',
      confidence: 75,
    } as any, [
      { user_id: 'analyst', first: '2026-01-01T00:00:00.000Z', last: '2026-01-15T00:00:00.000Z', count: 3 },
      { user_id: 'connector-user', first: '2026-01-10T00:00:00.000Z', last: '2026-01-20T00:00:00.000Z', count: 4 },
    ], resolver);
    expect(assertions).toHaveLength(2);
    expect(assertions.find((a) => a.source_id === 'analyst')).toMatchObject({
      source_kind: 'user',
      first_asserted_at: '2026-01-01T00:00:00.000Z',
      last_asserted_at: '2026-01-15T00:00:00.000Z',
      assert_count: 3,
      confidence: 75,
    });
    expect(assertions.find((a) => a.source_id === 'A')).toMatchObject({ source_kind: 'connector', assert_count: 4 });
  });

  it('should assert each group of writes of a shared user by the connector running at their dates', async () => {
    const assertions = await computeBackfillAssertions({
      internal_id: 'rel-1',
      entity_type: 'uses',
      _index: 'opencti_stix_core_relationships',
      creator_id: ['connector-user'],
      created_at: '2026-01-10T00:00:00.000Z',
      updated_at: '2026-04-01T00:00:00.000Z',
    } as any, [{
      user_id: 'connector-user',
      first: '2026-01-10T00:00:00.000Z',
      last: '2026-04-01T00:00:00.000Z',
      count: 5,
      segments: [
        { first: '2026-01-10T00:00:00.000Z', last: '2026-02-20T00:00:00.000Z', count: 3 },
        { first: '2026-03-05T00:00:00.000Z', last: '2026-04-01T00:00:00.000Z', count: 2 },
      ],
    }], resolver);
    expect(assertions.map((a) => [a.source_id, a.assert_count, a.first_asserted_at, a.last_asserted_at])).toEqual([
      ['A', 3, '2026-01-10T00:00:00.000Z', '2026-02-20T00:00:00.000Z'],
      ['B', 2, '2026-03-05T00:00:00.000Z', '2026-04-01T00:00:00.000Z'],
    ]);
  });

  it('should keep every writer of an element, whatever their number', async () => {
    const history = Array.from({ length: 120 }, (_, index) => ({
      user_id: `analyst-${index}`,
      first: '2026-01-01T00:00:00.000Z',
      last: '2026-01-02T00:00:00.000Z',
      count: 1,
    }));
    const assertions = await computeBackfillAssertions({
      internal_id: 'indicator-1',
      entity_type: 'Indicator',
      _index: 'opencti_stix_domain_objects',
      creator_id: ['analyst-0'],
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-01-02T00:00:00.000Z',
    } as any, history, resolver);
    expect(assertions).toHaveLength(120);
  });

  it('should group the writes of a shared user by running connector, even when connectors alternate', () => {
    const works = [
      { id: 'work-a1', connector_id: 'A', start: '2026-01-01T00:00:00.000Z', end: '2026-01-01T01:00:00.000Z' },
      { id: 'work-b1', connector_id: 'B', start: '2026-01-01T02:00:00.000Z', end: '2026-01-01T03:00:00.000Z' },
      { id: 'work-a2', connector_id: 'A', start: '2026-01-01T04:00:00.000Z', end: '2026-01-01T05:00:00.000Z' },
      { id: 'work-c1', connector_id: 'C', start: '2026-01-01T04:00:00.000Z', end: '2026-01-01T08:00:00.000Z' },
    ];
    const writes = [
      { element_id: 'e1', user_id: 'shared', at: '2026-01-01T04:30:00.000Z' }, // A (C is not a connector of this user)
      { element_id: 'e1', user_id: 'shared', at: '2026-01-01T00:30:00.000Z' }, // A
      { element_id: 'e1', user_id: 'shared', at: '2026-01-01T02:30:00.000Z' }, // B
      { element_id: 'e1', user_id: 'shared', at: '2026-01-01T06:00:00.000Z' }, // no running work: stays the user's
      { element_id: 'e2', user_id: 'shared', at: '2026-01-01T02:15:00.000Z' }, // B
    ];
    const segments = groupSharedUserWrites(writes, works, new Map([['shared', ['A', 'B']]]));
    expect(segments.get('e1')?.get('shared')).toEqual([
      { first: '2026-01-01T00:30:00.000Z', last: '2026-01-01T04:30:00.000Z', count: 2 },
      { first: '2026-01-01T02:30:00.000Z', last: '2026-01-01T02:30:00.000Z', count: 1 },
      { first: '2026-01-01T06:00:00.000Z', last: '2026-01-01T06:00:00.000Z', count: 1 },
    ]);
    expect(segments.get('e2')?.get('shared')).toEqual([{ first: '2026-01-01T02:15:00.000Z', last: '2026-01-01T02:15:00.000Z', count: 1 }]);
  });

  it('should answer like a full scan when dates are read in order, and after a date earlier than the previous one', () => {
    const works = [
      { id: 'work-a', connector_id: 'A', start: '2026-01-01T00:00:00.000Z', end: '2026-01-01T02:00:00.000Z' },
      { id: 'work-b', connector_id: 'B', start: '2026-01-01T01:00:00.000Z', end: '2026-01-01T03:00:00.000Z' },
      { id: 'work-a2', connector_id: 'A', start: '2026-01-01T05:00:00.000Z', end: '2026-01-01T06:00:00.000Z' },
    ];
    const runningAt = createRunningWorkIndex(works);
    const dates = ['2026-01-01T00:30:00.000Z', '2026-01-01T01:30:00.000Z', '2026-01-01T02:30:00.000Z', '2026-01-01T05:30:00.000Z', '2026-01-01T00:15:00.000Z'];
    dates.forEach((at) => {
      expect(runningAt(['A', 'B'], at)).toEqual(findRunningWorkConnector(works, ['A', 'B'], at));
    });
  });

  it('should keep creators whose history was purged and attribute human creations to the author', async () => {
    const assertions = await computeBackfillAssertions({
      internal_id: 'report-1',
      entity_type: 'Report',
      _index: 'opencti_stix_domain_objects',
      creator_id: ['analyst', 'connector-user'],
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-05-01T00:00:00.000Z',
      'rel_created-by.internal_id': ['organization-1'],
    } as any, [], resolver, new Map([['organization-1', 'ACME CERT']]));
    expect(assertions).toEqual(expect.arrayContaining([
      expect.objectContaining({ source_id: 'organization-1', source_kind: 'author', source_name: 'ACME CERT', first_asserted_at: '2026-01-01T00:00:00.000Z' }),
      expect.objectContaining({ source_id: 'B', source_kind: 'connector', last_asserted_at: '2026-05-01T00:00:00.000Z' }),
    ]));
    expect(assertions).toHaveLength(2);
  });

  it('should assert inferred knowledge by the rules that inferred it', async () => {
    const assertions = await computeBackfillAssertions({
      internal_id: 'inferred-1',
      entity_type: 'targets',
      _index: 'opencti_inferred_relationships',
      creator_id: [RULE_MANAGER_USER.id],
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-01-02T00:00:00.000Z',
      i_rule_attribution_targets: [{ explanation: [], dependencies: [], hash: 'h' }],
      i_rule_empty: [],
    } as any, [{ user_id: RULE_MANAGER_USER.id, first: '2026-01-01T00:00:00.000Z', last: '2026-01-02T00:00:00.000Z', count: 2 }], resolver);
    expect(assertions).toEqual([expect.objectContaining({ source_id: 'attribution_targets', source_kind: 'inference', assert_count: 1 })]);
  });

  it('should only rebuild what happened before the watermark, the live tracking having recorded the rest', async () => {
    const watermark = '2026-03-01T00:00:00.000Z';
    // The connector user only wrote after the watermark: no assertion, and no creator fallback for it either
    const assertions = await computeBackfillAssertions({
      internal_id: 'malware-2',
      entity_type: 'Malware',
      _index: 'opencti_stix_domain_objects',
      creator_id: ['analyst', 'connector-user'],
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-04-01T00:00:00.000Z',
    } as any, [
      { user_id: 'analyst', first: '2026-01-01T00:00:00.000Z', last: '2026-02-01T00:00:00.000Z', count: 2 },
      { user_id: 'connector-user', first: watermark, last: watermark, count: 0 },
    ], resolver, new Map(), watermark);
    expect(assertions).toEqual([expect.objectContaining({ source_id: 'analyst', assert_count: 2, last_asserted_at: '2026-02-01T00:00:00.000Z' })]);
    // The first creator created the element before the watermark: its purged creation is rebuilt even though it wrote after it
    const recreated = await computeBackfillAssertions({
      internal_id: 'malware-3',
      entity_type: 'Malware',
      _index: 'opencti_stix_domain_objects',
      creator_id: ['connector-user'],
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-04-01T00:00:00.000Z',
    } as any, [{ user_id: 'connector-user', first: watermark, last: watermark, count: 0 }], resolver, new Map(), watermark);
    expect(recreated).toEqual([expect.objectContaining({
      source_id: 'A',
      assert_count: 1,
      first_asserted_at: '2026-01-01T00:00:00.000Z',
      last_asserted_at: '2026-01-01T00:00:00.000Z',
    })]);
    // A creator whose history was purged is dated before the watermark, never after
    const purged = await computeBackfillAssertions({
      internal_id: 'report-2',
      entity_type: 'Report',
      _index: 'opencti_stix_domain_objects',
      creator_id: ['analyst', 'second-analyst'],
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-04-01T00:00:00.000Z',
    } as any, [], resolver, new Map(), watermark);
    expect(purged.find((a) => a.source_id === 'second-analyst')).toMatchObject({ first_asserted_at: '2026-01-01T00:00:00.000Z', last_asserted_at: '2026-01-01T00:00:00.000Z' });
    // Created or inferred after the watermark: nothing to rebuild
    const recent = await computeBackfillAssertions({
      internal_id: 'inferred-2',
      entity_type: 'targets',
      _index: 'opencti_inferred_relationships',
      creator_id: [RULE_MANAGER_USER.id, 'analyst'],
      created_at: '2026-03-02T00:00:00.000Z',
      updated_at: '2026-03-03T00:00:00.000Z',
      i_rule_attribution_targets: [{ explanation: [], dependencies: [], hash: 'h' }],
    } as any, [], resolver, new Map(), watermark);
    expect(recent).toEqual([]);
    // Inferred before the watermark and updated after: the rule asserted it until the watermark at most
    const inferred = await computeBackfillAssertions({
      internal_id: 'inferred-3',
      entity_type: 'targets',
      _index: 'opencti_inferred_relationships',
      creator_id: [RULE_MANAGER_USER.id],
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-03-03T00:00:00.000Z',
      i_rule_attribution_targets: [{ explanation: [], dependencies: [], hash: 'h' }],
    } as any, [], resolver, new Map(), watermark);
    expect(inferred).toEqual([expect.objectContaining({ source_id: 'attribution_targets', last_asserted_at: '2026-01-01T00:00:00.000Z' })]);
  });

  it('should resolve the connector of a shared user only when exactly one work was running', () => {
    const works = [
      { id: 'work-a', connector_id: 'A', start: '2026-01-01T00:00:00.000Z', end: '2026-01-01T02:00:00.000Z' },
      { id: 'work-b', connector_id: 'B', start: '2026-01-01T01:00:00.000Z', end: '2026-01-01T03:00:00.000Z' },
      { id: 'work-c', connector_id: 'C', start: '2026-01-01T00:00:00.000Z', end: '2026-01-02T00:00:00.000Z' },
    ];
    expect(findRunningWorkConnector(works, ['A', 'B'], '2026-01-01T00:30:00.000Z')).toEqual({ connector_id: 'A', work_id: 'work-a' });
    expect(findRunningWorkConnector(works, ['A', 'B'], '2026-01-01T01:30:00.000Z')).toBeNull();
    expect(findRunningWorkConnector(works, ['A', 'B'], '2026-01-01T05:00:00.000Z')).toBeNull();
  });

  it('should read a partial backfill state with defaults', () => {
    expect(readBackfillState(undefined)).toMatchObject({ status: 'pending', processed: 0, cursor: null });
    expect(readBackfillState({ status: 'running', processed: 10 })).toMatchObject({ status: 'running', processed: 10, expected: 0 });
  });

  it('should save a new watermark before the first page, so that a run stopped in its first batch restarts with it', async () => {
    const context = { source: 'provenance-backfill-test' } as AuthContext;
    const saved: ProvenanceBackfillState[] = [];
    vi.mocked(findByManagerId).mockImplementation(async () => ({ id: 'backfill-configuration', manager_setting: saved.at(-1) }) as any);
    vi.mocked(patchAttribute).mockImplementation(async (...args: any[]) => {
      saved.push(structuredClone(args[4].manager_setting));
      return {} as any;
    });
    vi.mocked(listProvenanceTrackedTypes).mockResolvedValue(['Malware']);
    vi.mocked(elCount).mockResolvedValue(3);
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      vi.setSystemTime(new Date('2026-03-01T00:00:00.000Z'));
      vi.mocked(elPaginate).mockRejectedValueOnce(new Error('stopped during the first batch'));
      await expect(runProvenanceBackfillBatch(context, { batchSize: 500 })).rejects.toThrow('stopped during the first batch');
      expect(saved).toEqual([expect.objectContaining({ status: 'running', started_at: '2026-03-01T00:00:00.000Z', cursor: null, processed: 0, expected: 3 })]);
      // The next run reads the history before the saved watermark, not before its own start
      vi.setSystemTime(new Date('2026-03-01T00:05:00.000Z'));
      vi.mocked(elPaginate).mockResolvedValueOnce({ elements: { edges: [], pageInfo: { hasNextPage: false } }, endCursor: null } as any);
      expect(await runProvenanceBackfillBatch(context, { batchSize: 500 })).toMatchObject({ status: 'completed', started_at: '2026-03-01T00:00:00.000Z' });
      expect(saved).toHaveLength(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('should try a failed element again at the end of the batch and only count a second failure as an error', async () => {
    const context = { source: 'provenance-backfill-test' } as AuthContext;
    const state = { status: 'running', started_at: '2026-03-01T00:00:00.000Z', expected: 3 };
    vi.mocked(findByManagerId).mockResolvedValue({ id: 'backfill-configuration', manager_setting: state } as any);
    vi.mocked(patchAttribute).mockResolvedValue({} as any);
    vi.mocked(listProvenanceTrackedTypes).mockResolvedValue(['Malware']);
    const element = (id: string) => ({ _index: 'stix_domain_objects', internal_id: id, creator_id: ['analyst'], created_at: '2026-01-01T00:00:00.000Z' });
    vi.mocked(elPaginate).mockResolvedValueOnce({
      elements: { edges: ['fails-once', 'succeeds', 'always-fails'].map((id) => ({ node: element(id) })), pageInfo: { hasNextPage: false } },
      endCursor: null,
    } as any);
    vi.mocked(elRawSearch).mockResolvedValue({ aggregations: { writers: { buckets: [] } } });
    vi.mocked(getEntitiesListFromCache).mockResolvedValue([]);
    vi.mocked(resolveSourceOfUser).mockImplementation(async (_context, userId) => userSource(userId));
    const attempts: string[] = [];
    vi.mocked(applyProvenanceUpdate).mockImplementation(async (_context, target) => {
      attempts.push(target.internal_id);
      if (target.internal_id === 'always-fails' || (target.internal_id === 'fails-once' && attempts.length === 1)) {
        throw new Error('transient write failure');
      }
      return {};
    });
    expect(await runProvenanceBackfillBatch(context, { batchSize: 500 })).toMatchObject({ status: 'completed', processed: 3, updated: 2, errors: 1 });
    expect(attempts).toEqual(['fails-once', 'succeeds', 'always-fails', 'fails-once', 'always-fails']);
  });
});
