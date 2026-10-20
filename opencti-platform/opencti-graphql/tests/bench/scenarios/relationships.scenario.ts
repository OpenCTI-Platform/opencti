// Relationship write path: today's per-relationship path against the batch prototype,
// with every relationship on its own endpoints (spread) or all on one shared entity (hub).
import { describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { createRelation } from '../../../src/database/middleware';
import { ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { RELATION_USES } from '../../../src/schema/stixCoreRelationship';
import { benchParam, createEntities, createOne, denormalizedCount, measure, writeResults } from '../bench-utils';
import { batchWriteRelations, checkBulkResolution } from '../batch-writer';

const N = benchParam('N', 2000);
const CONCURRENCY = benchParam('CONCURRENCY', 8);
const CHUNK = benchParam('CHUNK', 500);

const uses = (fromIds: string[], toIds: string[] | string) => fromIds.map((fromId, i) => ({
  fromId,
  toId: Array.isArray(toIds) ? toIds[i] : toIds,
  relationship_type: RELATION_USES,
}));
const create = (input: Record<string, any>) => createRelation(testContext, ADMIN_USER, input).then(() => undefined);

describe('Relationships scenario', () => {
  it('measures the relationship write path', async () => {
    const results: Record<string, any> = { params: { n: N, concurrency: CONCURRENCY, chunk: CHUNK } };
    const sources = await createEntities(ENTITY_TYPE_INTRUSION_SET, 'rel-src', N * 6);
    const targets = await createEntities(ENTITY_TYPE_MALWARE, 'rel-dst', N * 3);
    const hubs = [await createOne(ENTITY_TYPE_MALWARE, 'rel-hub-0'), await createOne(ENTITY_TYPE_MALWARE, 'rel-hub-1'), await createOne(ENTITY_TYPE_MALWARE, 'rel-hub-2')];
    const share = (k: number, ids: string[]) => ids.slice(k * N, (k + 1) * N);

    // Today's path: one createRelation per relationship, as the worker triggers it
    results.spread_sequential = await measure(uses(share(0, sources), share(0, targets)), 1, create);
    results.hub_sequential = await measure(uses(share(1, sources), hubs[0].internal_id), 1, create);
    results.spread_concurrent = await measure(uses(share(2, sources), share(1, targets)), CONCURRENCY, create);
    results.hub_concurrent = await measure(uses(share(3, sources), hubs[1].internal_id), CONCURRENCY, create);

    // Batch prototype, one writer
    results.bulk_resolution_check = await checkBulkResolution(uses(share(4, sources), hubs[2].internal_id)[0], RELATION_USES);
    results.spread_batch = await batchWriteRelations(uses(share(5, sources), share(2, targets)), RELATION_USES, CHUNK);
    results.hub_batch = await batchWriteRelations(uses(share(4, sources), hubs[2].internal_id), RELATION_USES, CHUNK);

    // Every shared entity must list all its relationships
    results.checks = {
      hub_sequential_denormalized: await denormalizedCount(hubs[0].internal_id, hubs[0]._index, RELATION_USES),
      hub_concurrent_denormalized: await denormalizedCount(hubs[1].internal_id, hubs[1]._index, RELATION_USES),
      hub_batch_denormalized: await denormalizedCount(hubs[2].internal_id, hubs[2]._index, RELATION_USES),
      expected: N,
    };
    writeResults('relationships', results);
    expect(results.bulk_resolution_check.identical).toBe(true);
    expect([results.checks.hub_sequential_denormalized, results.checks.hub_concurrent_denormalized, results.checks.hub_batch_denormalized]).toEqual([N, N, N]);
  });
});
