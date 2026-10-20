// Batch prototype variants: chunk size, and several writers contending for the same shared entity.
import { describe, expect, it } from 'vitest';
import { ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { RELATION_USES } from '../../../src/schema/stixCoreRelationship';
import { benchParam, createEntities, createOne, denormalizedCount, writeResults } from '../bench-utils';
import { batchWriteRelations } from '../batch-writer';

const N = benchParam('N', 2000);

// [label, chunk size, writers]
const HUB_VARIANTS: [string, number, number][] = [
  ['hub_chunk100_1writer', 100, 1],
  ['hub_chunk500_1writer', 500, 1],
  ['hub_chunk1000_1writer', 1000, 1],
  ['hub_chunk250_4writers', 250, 4],
  ['hub_chunk100_8writers', 100, 8],
];

describe('Batch variants scenario', () => {
  it('measures chunk sizes and concurrent writers', async () => {
    const results: Record<string, any> = { params: { n: N } };
    const sources = await createEntities(ENTITY_TYPE_INTRUSION_SET, 'bv-src', N * (HUB_VARIANTS.length + 1));
    const targets = await createEntities(ENTITY_TYPE_MALWARE, 'bv-dst', N);
    const hubs: any[] = [];
    for (let v = 0; v < HUB_VARIANTS.length; v += 1) {
      hubs.push(await createOne(ENTITY_TYPE_MALWARE, `bv-hub-${v}`));
    }
    for (let v = 0; v < HUB_VARIANTS.length; v += 1) {
      const [label, chunk, writers] = HUB_VARIANTS[v];
      const inputs = sources.slice(v * N, (v + 1) * N).map((fromId) => ({ fromId, toId: hubs[v].internal_id, relationship_type: RELATION_USES }));
      results[label] = await batchWriteRelations(inputs, RELATION_USES, chunk, writers);
    }
    const spreadSources = sources.slice(HUB_VARIANTS.length * N);
    results.spread_chunk500_1writer = await batchWriteRelations(
      spreadSources.map((fromId, i) => ({ fromId, toId: targets[i], relationship_type: RELATION_USES })),
      RELATION_USES,
      500,
    );
    results.checks = {
      hubs_denormalized: await Promise.all(hubs.map((hub) => denormalizedCount(hub.internal_id, hub._index, RELATION_USES))),
      expected: N,
    };
    writeResults('batch-variants', results);
    expect(results.checks.hubs_denormalized).toEqual(HUB_VARIANTS.map(() => N));
  });
});
