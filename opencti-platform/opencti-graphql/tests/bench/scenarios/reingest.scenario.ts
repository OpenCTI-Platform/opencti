// Re-ingestion: the same relationships sent again, unchanged or with a new description (upsert path).
import { describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { createRelation } from '../../../src/database/middleware';
import { ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { RELATION_USES } from '../../../src/schema/stixCoreRelationship';
import { benchParam, createEntities, createOne, measure, writeResults } from '../bench-utils';

const N = benchParam('N', 500);
const CONCURRENCY = benchParam('CONCURRENCY', 8);

const create = (input: Record<string, any>) => createRelation(testContext, ADMIN_USER, input).then(() => undefined);

describe('Re-ingestion scenario', () => {
  it('measures first ingestion against re-ingestion', async () => {
    const results: Record<string, any> = { params: { n: N, concurrency: CONCURRENCY } };
    const spreadFrom = await createEntities(ENTITY_TYPE_INTRUSION_SET, 'ri-sf', N);
    const spreadTo = await createEntities(ENTITY_TYPE_MALWARE, 'ri-st', N);
    const hubFrom = await createEntities(ENTITY_TYPE_INTRUSION_SET, 'ri-hf', N);
    const hub = await createOne(ENTITY_TYPE_MALWARE, 'ri-hub');
    const spread = spreadFrom.map((fromId, i) => ({ fromId, toId: spreadTo[i], relationship_type: RELATION_USES, description: 'v1' }));
    const onHub = hubFrom.map((fromId) => ({ fromId, toId: hub.internal_id, relationship_type: RELATION_USES, description: 'v1' }));
    const changed = (inputs: Record<string, any>[]) => inputs.map((input) => ({ ...input, description: 'v2' }));

    results.spread_first_sequential = await measure(spread, 1, create);
    results.spread_unchanged_sequential = await measure(spread, 1, create);
    results.spread_changed_sequential = await measure(changed(spread), 1, create);
    results.hub_first_sequential = await measure(onHub, 1, create);
    results.hub_unchanged_sequential = await measure(onHub, 1, create);
    results.hub_unchanged_concurrent = await measure(onHub, CONCURRENCY, create);
    results.hub_changed_concurrent = await measure(changed(onHub), CONCURRENCY, create);
    writeResults('reingest', results);
    expect(results.spread_unchanged_sequential.errors).toEqual({});
  });
});
