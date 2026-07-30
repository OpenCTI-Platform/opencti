import { describe, it, expect } from 'vitest';
import { addAttackPattern } from '../../../src/domain/attackPattern';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { createRelation, mergeEntities } from '../../../src/database/middleware';
import { RELATION_RELATED_TO } from '../../../src/schema/stixCoreRelationship';
import { fullRelationsList } from '../../../src/database/middleware-loader';
import { ABSTRACT_STIX_RELATIONSHIP } from '../../../src/schema/general';

// Real-infra (local Elasticsearch/Redis) benchmark for the merge fix (filterTargetByExisting O(n x m) -> O(n+m)).
// This complements the pure-algorithm micro-benchmark by measuring the *full* mergeEntities() pipeline,
// including relation loading from ES and bulk relation/entity updates, to check whether the algorithmic
// fix actually removes the end-to-end bottleneck or whether ES I/O becomes the new dominant cost.
//
// Scaled down from the production report (T1027, ~78k relations) to keep local seeding time reasonable:
// relation creation goes through the same lockResources() path as production (locks the shared "from"
// attack pattern), so it is serialized, not parallel.
const TARGET_RELATION_COUNT = 2500;
const SOURCE_RELATION_COUNT = 2500;
const CONCURRENT_BATCH_SIZE = 25;

const runInBatches = async <T>(items: T[], batchSize: number, worker: (item: T, index: number) => Promise<void>) => {
  for (let i = 0; i < items.length; i += batchSize) {
    const batch = items.slice(i, i + batchSize);
    // eslint-disable-next-line no-await-in-loop
    await Promise.all(batch.map((item, idx) => worker(item, i + idx)));
  }
};

describe('Real ES/Redis benchmark: merge of an entity with a large number of relationships', () => {
  it('should seed a target attack pattern with many relations and a duplicate source, then merge, timing the full pipeline', async () => {
    // GIVEN a target attack pattern that already has TARGET_RELATION_COUNT relationships (simulating T1027 after months of ingestion)
    const target = await addAttackPattern(testContext, ADMIN_USER, { name: `Benchmark-Target-${Date.now()}` });
    // AND a duplicate source attack pattern (the one that gets merged away) with SOURCE_RELATION_COUNT relationships, mostly non-overlapping
    const source = await addAttackPattern(testContext, ADMIN_USER, { name: `Benchmark-Source-${Date.now()}` });

    const seedStart = performance.now();

    // Seed "other side" entities cheaply (dummy attack patterns), then relate them to target / source.
    // Entity creation is parallelizable (distinct entities = distinct lock keys).
    const targetPeers = Array.from({ length: TARGET_RELATION_COUNT }).map((_, i) => i);
    const sourcePeers = Array.from({ length: SOURCE_RELATION_COUNT }).map((_, i) => i);

    const targetPeerIds: string[] = new Array(TARGET_RELATION_COUNT);
    const sourcePeerIds: string[] = new Array(SOURCE_RELATION_COUNT);

    await runInBatches(targetPeers, CONCURRENT_BATCH_SIZE, async (_, idx) => {
      const peer = await addAttackPattern(testContext, ADMIN_USER, { name: `Benchmark-TargetPeer-${Date.now()}-${idx}` });
      targetPeerIds[idx] = peer.id;
    });
    await runInBatches(sourcePeers, CONCURRENT_BATCH_SIZE, async (_, idx) => {
      const peer = await addAttackPattern(testContext, ADMIN_USER, { name: `Benchmark-SourcePeer-${Date.now()}-${idx}` });
      sourcePeerIds[idx] = peer.id;
    });

    // Relation creation to the SAME target/source locks that shared entity per call (matches production behavior) -> serialized.
    // eslint-disable-next-line no-restricted-syntax
    for (const peerId of targetPeerIds) {
      // eslint-disable-next-line no-await-in-loop
      await createRelation(testContext, ADMIN_USER, { fromId: target.id, toId: peerId, relationship_type: RELATION_RELATED_TO });
    }
    // eslint-disable-next-line no-restricted-syntax
    for (const peerId of sourcePeerIds) {
      // eslint-disable-next-line no-await-in-loop
      await createRelation(testContext, ADMIN_USER, { fromId: source.id, toId: peerId, relationship_type: RELATION_RELATED_TO });
    }

    const seedElapsed = performance.now() - seedStart;
    // eslint-disable-next-line no-console
    console.log(`[BENCHMARK][real-es] Seeding ${TARGET_RELATION_COUNT + SOURCE_RELATION_COUNT} relations took ${seedElapsed.toFixed(0)}ms`);

    // Sanity check relation counts were actually seeded before merge.
    const targetRelsBefore = await fullRelationsList(testContext, ADMIN_USER, ABSTRACT_STIX_RELATIONSHIP, { fromId: target.internal_id });
    const sourceRelsBefore = await fullRelationsList(testContext, ADMIN_USER, ABSTRACT_STIX_RELATIONSHIP, { fromId: source.internal_id });
    expect(targetRelsBefore.length).toEqual(TARGET_RELATION_COUNT);
    expect(sourceRelsBefore.length).toEqual(SOURCE_RELATION_COUNT);

    // WHEN merging source into target (real ES/Redis, current fixed filterTargetByExisting)
    const mergeStart = performance.now();
    await mergeEntities(testContext, ADMIN_USER, target.internal_id, [source.internal_id]);
    const mergeElapsed = performance.now() - mergeStart;

    // eslint-disable-next-line no-console
    console.log(`[BENCHMARK][real-es] Full mergeEntities() for ${TARGET_RELATION_COUNT}+${SOURCE_RELATION_COUNT} relations took ${mergeElapsed.toFixed(0)}ms`);

    // THEN all relations should now point to target, and none should remain duplicated.
    const targetRelsAfter = await fullRelationsList(testContext, ADMIN_USER, ABSTRACT_STIX_RELATIONSHIP, { fromId: target.internal_id });
    expect(targetRelsAfter.length).toEqual(TARGET_RELATION_COUNT + SOURCE_RELATION_COUNT);
  }, 20 * 60 * 1000); // generous timeout for local seeding + merge
});
