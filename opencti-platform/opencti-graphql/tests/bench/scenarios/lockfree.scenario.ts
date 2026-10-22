// Lock-free write path, throughput: entities and relationships carrying refs (author, marking, three labels),
// one per call as the worker sends them, concurrent, and in chunks, against today's path and the batch prototype
// on the same platform and data. Also a hub that already lists 20,000 relationships, and re-ingestion.
import { describe, expect, it } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { createEntity, createRelation } from '../../../src/database/middleware';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { elRawBulk } from '../../../src/database/engine';
import { inferIndexFromConceptType } from '../../../src/database/utils';
import { generateStandardId, MARKING_TLP_GREEN } from '../../../src/schema/identifier';
import { ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../src/schema/stixMetaObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { RELATION_USES } from '../../../src/schema/stixCoreRelationship';
import { addLabel } from '../../../src/domain/label';
import { benchParam, createOne, denormalizedCount, measure, RUN_ID, writeResults } from '../bench-utils';
import { batchWriteRelations } from '../batch-writer';
import { deterministicId, registerExisting } from '../../../src/database/lockfree/identity';
import { writeEntities, writeRelations } from '../lockfree/run';

// Inputs as these scenarios build them, turned into the write path's createEntity / createRelation inputs
type EntityInput = { type: string; name: string; [key: string]: any };
type RelationInput = Record<string, any>;
const toItems = (list: EntityInput[]) => list.map(({ type, ...input }) => ({ type, input }));
const toRelations = (list: RelationInput[]) => list.map(({ source_ref, target_ref, source_type: _sourceType, target_type: _targetType, ...rest }) => ({
  ...rest, fromId: source_ref, toId: target_ref,
}));

const N = benchParam('N', 2000);
const CONCURRENCY = benchParam('CONCURRENCY', 8);
const CHUNK = benchParam('CHUNK', 500);
const SETTLE_MS = benchParam('SETTLE_MS', 250);
const BIG_HUB = 20000;

const name = (label: string, i?: number) => `bench-${RUN_ID}-lft-${label}${i === undefined ? '' : `-${i}`}`;
const sid = (type: string, entityName: string) => generateStandardId(type, { name: entityName });
const idOf = (type: string, entityName: string) => deterministicId(sid(type, entityName));
const range = (n: number) => [...Array(n).keys()];

describe('Lock-free throughput scenario', () => {
  it('measures the lock-free write path against today and the batch prototype', async () => {
    const results: Record<string, any> = { params: { n: N, concurrency: CONCURRENCY, chunk: CHUNK, settle_every_ms: SETTLE_MS, big_hub: BIG_HUB } };
    const single = (concurrency: number) => ({ chunkSize: 1, concurrency, settleEveryMs: SETTLE_MS });
    const chunked = { chunkSize: CHUNK, concurrency: 1, settleEveryMs: SETTLE_MS };

    // Refs on every object, as most feeds send them
    const author: any = await createOne(ENTITY_TYPE_IDENTITY_ORGANIZATION, 'lft-author');
    const labels: any[] = [];
    for (let l = 0; l < 3; l += 1) labels.push(await addLabel(testContext, ADMIN_USER, { value: `bench-${RUN_ID}-lft-label-${l}` }));
    const green: any = await storeLoadById(testContext, ADMIN_USER, MARKING_TLP_GREEN, ENTITY_TYPE_MARKING_DEFINITION);
    await registerExisting([author, ...labels, green]);
    const lfRefs = { createdBy: author.standard_id, objectMarking: [MARKING_TLP_GREEN], objectLabel: labels.map((l) => l.standard_id) };
    const todayRefs = { createdBy: author.internal_id, objectMarking: [green.internal_id], objectLabel: labels.map((l) => l.internal_id) };

    // Entities with refs
    const entities = (label: string, type = ENTITY_TYPE_INTRUSION_SET): EntityInput[] => range(N).map((i) => ({ type, name: name(label, i), description: 'benchmark', ...lfRefs }));
    results.today_entities_sequential = await measure(range(N), 1, async (i) => {
      await createEntity(testContext, ADMIN_USER, { name: name('today-entity', i), description: 'benchmark', ...todayRefs }, ENTITY_TYPE_INTRUSION_SET);
    });
    results.lf_entities_single_sequential = await writeEntities(toItems(entities('lf-e1')), single(1));
    results.lf_entities_single_concurrent = await writeEntities(toItems(entities('lf-e2')), single(CONCURRENCY));
    results.lf_entities_batch = await writeEntities(toItems(entities('lf-e3')), chunked);

    // Ends of the relationships, written lock-free (setup): sources, four target sets, hubs
    const sources = entities('src');
    const targetSets = [0, 1, 2, 3].map((k) => entities(`dst${k}`, ENTITY_TYPE_MALWARE));
    const hubs = range(8).map((h) => ({ type: ENTITY_TYPE_MALWARE, name: name('hub', h), description: 'benchmark', ...lfRefs }));
    await writeEntities(toItems([...sources, ...targetSets.flat(), ...hubs]), chunked);
    const sourceIds = sources.map((s) => idOf(s.type, s.name));
    const hubId = (h: number) => idOf(ENTITY_TYPE_MALWARE, hubs[h].name);
    const hubIndex = inferIndexFromConceptType(ENTITY_TYPE_MALWARE);
    const today = (toIds: string[] | string, extra: Record<string, any> = {}) => sourceIds.map((fromId, i) => ({
      fromId, toId: Array.isArray(toIds) ? toIds[i] : toIds, relationship_type: RELATION_USES, description: 'benchmark', ...todayRefs, ...extra,
    }));
    const lf = (to: EntityInput[] | EntityInput, extra: Partial<RelationInput> = {}): RelationInput[] => sources.map((s, i) => {
      const target = Array.isArray(to) ? to[i] : to;
      return {
        relationship_type: RELATION_USES,
        source_ref: sid(s.type, s.name),
        target_ref: sid(target.type, target.name),
        source_type: s.type,
        target_type: target.type,
        description: 'benchmark',
        ...lfRefs,
        ...extra,
      };
    });
    const create = (input: Record<string, any>) => createRelation(testContext, ADMIN_USER, input).then(() => undefined);

    // Today's path and the batch prototype
    results.today_spread_sequential = await measure(today(targetSets[0].map((t) => idOf(t.type, t.name))), 1, create);
    results.today_hub_concurrent = await measure(today(hubId(0)), CONCURRENCY, create);
    results.batch_hub = await batchWriteRelations(today(hubId(1)), RELATION_USES, CHUNK);

    // Lock-free
    results.lf_spread_single_sequential = await writeRelations(toRelations(lf(targetSets[1])), single(1));
    results.lf_spread_single_concurrent = await writeRelations(toRelations(lf(targetSets[2])), single(CONCURRENCY));
    results.lf_hub_single_concurrent = await writeRelations(toRelations(lf(hubs[2])), single(CONCURRENCY));
    results.lf_hub_batch = await writeRelations(toRelations(lf(hubs[3])), chunked);
    results.lf_spread_batch = await writeRelations(toRelations(lf(targetSets[3])), chunked);

    // Re-ingestion of the hub: unchanged, then changed (every write a merge, with an update event)
    results.today_hub_reingest_changed_concurrent = await measure(today(hubId(0), { description: 'changed' }), CONCURRENCY, create);
    results.lf_hub_reingest_unchanged_concurrent = await writeRelations(toRelations(lf(hubs[2])), single(CONCURRENCY));
    results.lf_hub_reingest_changed_concurrent = await writeRelations(toRelations(lf(hubs[2], { description: 'changed' })), single(CONCURRENCY));

    // A hub that already lists 20,000 relationships: each list update rewrites the whole document
    const seed = async (h: number) => {
      const ids = range(BIG_HUB).map(() => uuidv4());
      await elRawBulk(testContext, {
        refresh: true,
        body: [{ update: { _index: hubIndex, _id: hubId(h) } }, { script: { source: "ctx._source['rel_uses.internal_id'] = params.ids", params: { ids } } }],
      });
    };
    await seed(4);
    await seed(5);
    const bigN = Math.min(N, 500);
    results.today_big_hub_concurrent = await measure(today(hubId(4)).slice(0, bigN), CONCURRENCY, create);
    results.lf_big_hub_single_concurrent = await writeRelations(toRelations(lf(hubs[5]).slice(0, bigN)), single(CONCURRENCY));

    results.checks = {
      expected: N,
      today_hub: await denormalizedCount(hubId(0), hubIndex, RELATION_USES),
      batch_hub: await denormalizedCount(hubId(1), hubIndex, RELATION_USES),
      lf_hub_single: await denormalizedCount(hubId(2), hubIndex, RELATION_USES),
      lf_hub_batch: await denormalizedCount(hubId(3), hubIndex, RELATION_USES),
      today_big_hub: await denormalizedCount(hubId(4), hubIndex, RELATION_USES),
      lf_big_hub: await denormalizedCount(hubId(5), hubIndex, RELATION_USES),
      big_hub_expected: BIG_HUB + bigN,
    };
    writeResults('lockfree', results);
    const c = results.checks;
    expect([c.today_hub, c.batch_hub, c.lf_hub_single, c.lf_hub_batch]).toEqual([N, N, N, N]);
    expect([c.today_big_hub, c.lf_big_hub]).toEqual([BIG_HUB + bigN, BIG_HUB + bigN]);
  });
});
