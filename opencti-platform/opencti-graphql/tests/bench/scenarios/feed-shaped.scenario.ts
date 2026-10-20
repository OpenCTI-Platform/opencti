// Data shaped like a connector feed: indicators carrying created-by, a marking and labels,
// about a dozen indicates relationships per indicator to a shared set of attack patterns, and reports.
import { describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { createRelation, storeLoadByIdWithRefs } from '../../../src/database/middleware';
import { MARKING_TLP_GREEN } from '../../../src/schema/identifier';
import { addIndicator } from '../../../src/modules/indicator/indicator-domain';
import { addReport } from '../../../src/domain/report';
import { addLabel } from '../../../src/domain/label';
import { checkIndicatorSyntax } from '../../../src/python/pythonBridge';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { RELATION_INDICATES } from '../../../src/schema/stixCoreRelationship';
import { benchParam, createOne, denormalizedCount, measure, now, phaseSummary, resetPhases, round, RUN_ID, writeResults } from '../bench-utils';
import { batchWriteRelations, checkBulkResolution } from '../batch-writer';

const N = benchParam('N', 300); // indicators per set
const CONCURRENCY = benchParam('CONCURRENCY', 8);
const CHUNK = benchParam('CHUNK', 500);
const RELATIONS_PER_INDICATOR = 12;
const ATTACK_PATTERNS = 40;
const REPORT_SIZES = [100, 500, 1000];

describe('Feed-shaped scenario', () => {
  it('measures indicators, indicates relationships with refs, and reports', async () => {
    const results: Record<string, any> = {
      params: { n: N, concurrency: CONCURRENCY, chunk: CHUNK, relations_per_indicator: RELATIONS_PER_INDICATOR, attack_patterns: ATTACK_PATTERNS },
    };
    // Shared refs, as most feeds attach them to every object
    const author = await createOne(ENTITY_TYPE_IDENTITY_ORGANIZATION, 'feed-author');
    const labels: any[] = [];
    for (let l = 0; l < 3; l += 1) {
      labels.push(await addLabel(testContext, ADMIN_USER, { value: `bench-${RUN_ID}-label-${l}` }));
    }
    const refs = { createdBy: author.internal_id, objectMarking: [MARKING_TLP_GREEN], objectLabel: labels.map((l) => l.internal_id) };
    const patternsA: string[] = [];
    const patternsB: string[] = [];
    for (let a = 0; a < ATTACK_PATTERNS; a += 1) {
      patternsA.push((await createOne(ENTITY_TYPE_ATTACK_PATTERN, `feed-apA-${a}`)).internal_id);
      patternsB.push((await createOne(ENTITY_TYPE_ATTACK_PATTERN, `feed-apB-${a}`)).internal_id);
    }

    // Indicators through addIndicator, as the worker's indicatorAdd does. Patterns are unique per run.
    const firstOctet = 11 + (Number(RUN_ID) % 200);
    const indicatorInput = (set: number, i: number) => ({
      name: `bench-${RUN_ID}-indicator-${set}-${i}`,
      pattern: `[ipv4-addr:value = '${firstOctet}.${(i >> 8) & 255}.${i & 255}.${set}']`,
      pattern_type: 'stix',
      x_opencti_main_observable_type: 'IPv4-Addr',
    });
    const plainIds: string[] = new Array(N);
    const withRefsIds: string[] = new Array(N);
    const indices = [...Array(N).keys()];
    results.indicator_no_refs_sequential = await measure(indices, 1, async (i) => {
      plainIds[i] = (await addIndicator(testContext, ADMIN_USER, indicatorInput(1, i) as any) as any).internal_id;
    });
    results.indicator_with_refs_sequential = await measure(indices, 1, async (i) => {
      withRefsIds[i] = (await addIndicator(testContext, ADMIN_USER, { ...indicatorInput(2, i), ...refs } as any) as any).internal_id;
    });
    results.pattern_check_only_sequential = await measure(indices, 1, async (i) => {
      await checkIndicatorSyntax(testContext, ADMIN_USER, 'stix', indicatorInput(3, i).pattern);
    });

    // indicates relationships, an indicator's relationships one after another as in a split bundle
    const indicates = (fromIds: string[], patterns: string[], withRefs: boolean) => fromIds.flatMap((fromId, i) => [...Array(RELATIONS_PER_INDICATOR).keys()].map((k) => ({
      fromId,
      toId: patterns[(i * 7 + k) % patterns.length],
      relationship_type: RELATION_INDICATES,
      ...(withRefs ? refs : {}),
    })));
    const relationIds: string[] = [];
    results.indicates_no_refs_sequential = await measure(indicates(plainIds, patternsA, false), 1, async (input) => {
      await createRelation(testContext, ADMIN_USER, input);
    });
    results.indicates_with_refs_sequential = await measure(indicates(withRefsIds, patternsA, true), 1, async (input) => {
      relationIds.push((await createRelation(testContext, ADMIN_USER, input) as any).internal_id);
    });
    results.indicates_with_refs_concurrent = await measure(indicates(withRefsIds, patternsB, true), CONCURRENCY, async (input) => {
      await createRelation(testContext, ADMIN_USER, input);
    });
    const batchInputs = indicates(plainIds, patternsB, true);
    results.bulk_resolution_check = await checkBulkResolution(batchInputs[0], RELATION_INDICATES);
    results.indicates_with_refs_batch = await batchWriteRelations(batchInputs, RELATION_INDICATES, CHUNK);

    // Reports: a container's object refs are written in one grouped bulk request
    const objects = [...withRefsIds, ...plainIds, ...patternsA, ...patternsB, ...relationIds];
    for (let r = 0; r < REPORT_SIZES.length; r += 1) {
      const size = REPORT_SIZES[r];
      resetPhases();
      const start = now();
      await addReport(testContext, ADMIN_USER, {
        name: `bench-${RUN_ID}-report-${size}`,
        published: '2026-10-01T00:00:00.000Z',
        objects: objects.slice(0, size),
        ...refs,
      });
      results[`report_${size}_objects`] = { objects: Math.min(size, objects.length), wall_ms: round(now() - start), phases_ms: phaseSummary() };
    }

    const relation: any = await storeLoadByIdWithRefs(testContext, ADMIN_USER, relationIds[0]);
    results.checks = {
      relation_refs: { createdBy: Boolean(relation?.createdBy), objectMarking: relation?.objectMarking?.length ?? 0, objectLabel: relation?.objectLabel?.length ?? 0 },
      indicator_denormalized_indicates: await denormalizedCount(plainIds[0], author._index, RELATION_INDICATES),
      attack_pattern_denormalized_indicates: await denormalizedCount(patternsB[0], author._index, RELATION_INDICATES),
      expected_indicator_denormalized: 2 * RELATIONS_PER_INDICATOR,
    };
    writeResults('feed-shaped', results);
    expect(results.bulk_resolution_check.identical).toBe(true);
    expect(results.checks.indicator_denormalized_indicates).toBe(2 * RELATIONS_PER_INDICATOR);
  });
});
