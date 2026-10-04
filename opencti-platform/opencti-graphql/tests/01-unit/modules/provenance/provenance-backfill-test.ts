import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import {
  type BackfillSourceResolver,
  computeBackfillAssertions,
  createRunningWorkIndex,
  findRunningWorkConnector,
  groupSharedUserWrites,
  readBackfillState,
} from '../../../../src/modules/provenance/provenance-backfill';
import type { AssertionSource } from '../../../../src/modules/provenance/provenance-types';
import { RULE_MANAGER_USER } from '../../../../src/utils/access';

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
});
