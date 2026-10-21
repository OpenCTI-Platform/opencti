// Lock-free prototype in chunks: where its batch ceiling is, against the batch prototype.
// Same hub and spread shapes as the relationships and batch-variants scenarios, without refs (comparable with
// them) and with refs (author, marking, 3 labels), with 1, 4 and 8 chunk writers in parallel, other chunk sizes,
// and bundles that carry their entities and relationships together. Every lock-free case records the time of
// each step of a chunk (phases_ms, lf_relation.* / lf_entity.* / lf_settle.*).
import { describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { inferIndexFromConceptType } from '../../../src/database/utils';
import { generateStandardId, MARKING_TLP_GREEN } from '../../../src/schema/identifier';
import { ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../src/schema/stixMetaObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { RELATION_USES } from '../../../src/schema/stixCoreRelationship';
import { addLabel } from '../../../src/domain/label';
import { benchParam, createOne, denormalizedCount, RUN_ID, writeResults } from '../bench-utils';
import { batchWriteRelations } from '../batch-writer';
import { deterministicId, registerExisting } from '../lockfree/identity';
import { writeBundles, writeEntities, writeRelations } from '../lockfree/run';

// Inputs as these scenarios build them, turned into the write path's createEntity / createRelation inputs
type EntityInput = { type: string; name: string; [key: string]: any };
type RelationInput = Record<string, any>;
const toItems = (list: EntityInput[]) => list.map(({ type, ...input }) => ({ type, input }));
const toRelations = (list: RelationInput[]) => list.map(({ source_ref, target_ref, source_type: _sourceType, target_type: _targetType, ...rest }) => ({
  ...rest, fromId: source_ref, toId: target_ref,
}));

const N = benchParam('N', 8000);
const CHUNK = benchParam('CHUNK', 500);
const SETTLE_MS = benchParam('SETTLE_MS', 250);
const BUNDLE = 250; // entities per bundle, each with one relationship to the hub

const name = (label: string, i?: number) => `bench-${RUN_ID}-lfb-${label}${i === undefined ? '' : `-${i}`}`;
const sid = (type: string, entityName: string) => generateStandardId(type, { name: entityName });
const idOf = (type: string, entityName: string) => deterministicId(sid(type, entityName));
const range = (n: number) => [...Array(n).keys()];

describe('Lock-free batch scenario', () => {
  it('measures the lock-free write path in chunks, with parallel writers', async () => {
    const results: Record<string, any> = { params: { n: N, chunk: CHUNK, settle_every_ms: SETTLE_MS, bundle: BUNDLE } };
    const chunks = (chunkSize: number, writers: number) => ({ chunkSize, concurrency: writers, settleEveryMs: SETTLE_MS });

    const author: any = await createOne(ENTITY_TYPE_IDENTITY_ORGANIZATION, 'lfb-author');
    const labels: any[] = [];
    for (let l = 0; l < 3; l += 1) labels.push(await addLabel(testContext, ADMIN_USER, { value: `bench-${RUN_ID}-lfb-label-${l}` }));
    const green: any = await storeLoadById(testContext, ADMIN_USER, MARKING_TLP_GREEN, ENTITY_TYPE_MARKING_DEFINITION);
    await registerExisting([author, ...labels, green]);
    const lfRefs = { createdBy: author.standard_id, objectMarking: [MARKING_TLP_GREEN], objectLabel: labels.map((l) => l.standard_id) };
    const todayRefs = { createdBy: author.internal_id, objectMarking: [green.internal_id], objectLabel: labels.map((l) => l.internal_id) };

    // Ends (setup, lock-free, without refs): N sources, two target sets, one hub per case
    const entities = (label: string, type: string): EntityInput[] => range(N).map((i) => ({ type, name: name(label, i), description: 'benchmark' }));
    const sources = entities('src', ENTITY_TYPE_INTRUSION_SET);
    const targetSets = [0, 1].map((k) => entities(`dst${k}`, ENTITY_TYPE_MALWARE));
    const hubs = range(16).map((h) => ({ type: ENTITY_TYPE_MALWARE, name: name('hub', h), description: 'benchmark' }));
    results.setup_entities = await writeEntities(toItems([...sources, ...targetSets.flat(), ...hubs]), chunks(CHUNK, 4));
    const sourceIds = sources.map((s) => idOf(s.type, s.name));
    const hubIndex = inferIndexFromConceptType(ENTITY_TYPE_MALWARE);
    let nextHub = 0;
    const hubCase = () => {
      const hub = hubs[nextHub];
      nextHub += 1;
      return { hub, id: idOf(hub.type, hub.name) };
    };
    const lf = (to: EntityInput[] | EntityInput, refs: boolean): RelationInput[] => sources.map((s, i) => {
      const target = Array.isArray(to) ? to[i] : to;
      return {
        relationship_type: RELATION_USES,
        source_ref: sid(s.type, s.name),
        target_ref: sid(target.type, target.name),
        source_type: s.type,
        target_type: target.type,
        description: 'benchmark',
        ...(refs ? lfRefs : {}),
      };
    });
    const today = (toId: string, refs: boolean) => sourceIds.map((fromId) => ({
      fromId, toId, relationship_type: RELATION_USES, description: 'benchmark', ...(refs ? todayRefs : {}),
    }));
    const hubChecks: Record<string, number> = {};

    // Without refs: comparable with relationships / batch-variants
    let h = hubCase();
    results.batch_hub_norefs = await batchWriteRelations(today(h.id, false), RELATION_USES, CHUNK);
    hubChecks.batch_hub_norefs = await denormalizedCount(h.id, hubIndex, RELATION_USES);
    for (const writers of [1, 4, 8]) {
      h = hubCase();
      results[`lf_hub_norefs_x${writers}`] = await writeRelations(toRelations(lf(h.hub, false)), chunks(CHUNK, writers));
      hubChecks[`lf_hub_norefs_x${writers}`] = await denormalizedCount(h.id, hubIndex, RELATION_USES);
    }
    h = hubCase();
    results.lf_hub_norefs_chunk100_x8 = await writeRelations(toRelations(lf(h.hub, false)), chunks(100, 8));
    hubChecks.lf_hub_norefs_chunk100_x8 = await denormalizedCount(h.id, hubIndex, RELATION_USES);
    h = hubCase();
    results.lf_hub_norefs_chunk2000_x1 = await writeRelations(toRelations(lf(h.hub, false)), chunks(2000, 1));
    hubChecks.lf_hub_norefs_chunk2000_x1 = await denormalizedCount(h.id, hubIndex, RELATION_USES);
    results.lf_spread_norefs_x1 = await writeRelations(toRelations(lf(targetSets[0], false)), chunks(CHUNK, 1));
    results.lf_spread_norefs_x4 = await writeRelations(toRelations(lf(targetSets[1], false)), chunks(CHUNK, 4));
    // The same spread shape with other pairs (source i to target i + 1), settled with 1 and 8 parallel bulks
    const shifted = (targets: EntityInput[]) => targets.map((_, i) => targets[(i + 1) % targets.length]);
    results.lf_spread_norefs_x4_settle1 = await writeRelations(toRelations(lf(shifted(targetSets[0]), false)), { ...chunks(CHUNK, 4), settleParallel: 1 });
    results.lf_spread_norefs_x4_settle8 = await writeRelations(toRelations(lf(shifted(targetSets[1]), false)), { ...chunks(CHUNK, 4), settleParallel: 8 });

    // With refs: each relationship is 6 documents
    h = hubCase();
    results.batch_hub_refs = await batchWriteRelations(today(h.id, true), RELATION_USES, CHUNK);
    hubChecks.batch_hub_refs = await denormalizedCount(h.id, hubIndex, RELATION_USES);
    h = hubCase();
    results.batch_hub_refs_4writers = await batchWriteRelations(today(h.id, true), RELATION_USES, CHUNK, 4);
    hubChecks.batch_hub_refs_4writers = await denormalizedCount(h.id, hubIndex, RELATION_USES);
    for (const writers of [1, 4, 8]) {
      h = hubCase();
      results[`lf_hub_refs_x${writers}`] = await writeRelations(toRelations(lf(h.hub, true)), chunks(CHUNK, writers));
      hubChecks[`lf_hub_refs_x${writers}`] = await denormalizedCount(h.id, hubIndex, RELATION_USES);
    }

    // Bundles: new entities with refs and their relationship to a hub, written together
    for (const writers of [1, 4]) {
      h = hubCase();
      const hubTarget = h.hub;
      const bundles: { entities: EntityInput[]; relations: RelationInput[] }[] = range(N / (2 * BUNDLE)).map((b) => {
        const fresh = range(BUNDLE).map((i) => ({ type: ENTITY_TYPE_INTRUSION_SET, name: name(`bundle${writers}-${b}`, i), description: 'benchmark', ...lfRefs }));
        return {
          entities: fresh,
          relations: fresh.map((e) => ({
            relationship_type: RELATION_USES,
            source_ref: sid(e.type, e.name),
            target_ref: sid(hubTarget.type, hubTarget.name),
            source_type: e.type,
            target_type: hubTarget.type,
            description: 'benchmark',
            ...lfRefs,
          })),
        };
      });
      results[`lf_bundles_refs_x${writers}`] = await writeBundles(bundles.map((b) => ({ entities: toItems(b.entities), relations: toRelations(b.relations) })), { chunkSize: 1, concurrency: writers, settleEveryMs: SETTLE_MS });
      hubChecks[`lf_bundles_refs_x${writers}`] = await denormalizedCount(h.id, hubIndex, RELATION_USES);
    }

    const expected = Object.fromEntries(Object.keys(hubChecks).map((k) => [k, k.startsWith('lf_bundles') ? N / 2 : N]));
    results.checks = { hubs: hubChecks, expected };
    writeResults('lockfree-batch', results);
    expect(hubChecks).toEqual(expected);
  });
});
