import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { type BackfillSourceResolver, computeBackfillAssertions, findRunningWorkConnector, readBackfillState } from '../../../../src/modules/provenance/provenance-backfill';
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

  it('should split the writes of a shared user between the connectors running at their dates', async () => {
    const assertions = await computeBackfillAssertions({
      internal_id: 'rel-1',
      entity_type: 'uses',
      _index: 'opencti_stix_core_relationships',
      creator_id: ['connector-user'],
      created_at: '2026-01-10T00:00:00.000Z',
      updated_at: '2026-04-01T00:00:00.000Z',
    } as any, [
      { user_id: 'connector-user', first: '2026-01-10T00:00:00.000Z', last: '2026-04-01T00:00:00.000Z', count: 5 },
    ], resolver);
    expect(assertions.map((a) => [a.source_id, a.assert_count, a.first_asserted_at, a.last_asserted_at])).toEqual([
      ['A', 1, '2026-01-10T00:00:00.000Z', '2026-01-10T00:00:00.000Z'],
      ['B', 4, '2026-04-01T00:00:00.000Z', '2026-04-01T00:00:00.000Z'],
    ]);
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
