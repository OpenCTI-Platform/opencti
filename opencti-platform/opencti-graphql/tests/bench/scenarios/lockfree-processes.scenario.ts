// Several platform processes writing at once, as the nodes of a cluster do. run.py starts BENCH_PROCESSES copies of
// this scenario side by side (each a whole platform process, with its own port), each writing its share of the
// objects. They meet at barriers in Redis so that every case starts together; run.py adds up the shares: items over
// the time from the first start to the last write returned (written) or to the shared settler queue being empty
// (settled). Cases: entities with refs, then relationships with refs from every process's entities to one hub.
import { describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { inferIndexFromConceptType } from '../../../src/database/utils';
import { getClientBase } from '../../../src/database/redis';
import { REDIS_PREFIX } from '../../../src/config/conf';
import { generateStandardId, MARKING_TLP_GREEN } from '../../../src/schema/identifier';
import { ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../src/schema/stixMetaObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { RELATION_USES } from '../../../src/schema/stixCoreRelationship';
import { addLabel } from '../../../src/domain/label';
import { benchParam, createOne, denormalizedCount, writeResults } from '../bench-utils';
import { deterministicId, registerExisting } from '../lockfree/identity';
import { writeEntities, writeRelations } from '../lockfree/run';

const PROCESSES = benchParam('PROCESSES', 1);
const INDEX = benchParam('PROCESS_INDEX', 0);
const N = benchParam('N', 16000); // per case, all processes together
const CHUNK = benchParam('CHUNK', 500);
const WRITERS = benchParam('WRITERS', 2); // chunk writers in each process
const SETTLE_MS = benchParam('SETTLE_MS', 250);
const TAG = process.env.BENCH_RUN_TAG ?? `${Date.now()}`;

const share = Math.floor(N / PROCESSES);
const range = (n: number) => [...Array(n).keys()];
const name = (label: string, i?: number) => `bench-${TAG}-mp-${label}${i === undefined ? '' : `-${i}`}`;
const sid = (type: string, entityName: string) => generateStandardId(type, { name: entityName });

// Every process waits here until all of them arrived
const barrier = async (step: string) => {
  const key = `${REDIS_PREFIX}bench:barrier:${TAG}:${step}`;
  const client = getClientBase();
  await client.incr(key);
  await client.expire(key, 3600);
  const deadline = Date.now() + 15 * 60 * 1000;
  while (Number(await client.get(key)) < PROCESSES) {
    if (Date.now() > deadline) throw new Error(`Barrier ${step}: processes missing`);
    await new Promise((resolve) => {
      setTimeout(resolve, 20);
    });
  }
};

// The times run.py adds up, without the per-item results
const timesOf = (run: any) => {
  const { results: _results, ...rest } = run;
  return { ...rest, written_at: run.started_at + run.write_ms, settled_at: run.started_at + run.settled_ms };
};

describe('Lock-free processes scenario', () => {
  it('writes from several platform processes at once', async () => {
    const options = { chunkSize: CHUNK, concurrency: WRITERS, settleEveryMs: SETTLE_MS };
    const results: Record<string, any> = { params: { processes: PROCESSES, index: INDEX, n: N, share, chunk: CHUNK, writers: WRITERS } };
    // Refs shared by every object, created once by the first process
    const refsKey = `${REDIS_PREFIX}bench:refs:${TAG}`;
    if (INDEX === 0) {
      const author: any = await createOne(ENTITY_TYPE_IDENTITY_ORGANIZATION, `mp-${TAG}-author`);
      const labels: any[] = [];
      for (let l = 0; l < 3; l += 1) labels.push(await addLabel(testContext, ADMIN_USER, { value: `bench-${TAG}-mp-label-${l}` }));
      const green: any = await storeLoadById(testContext, ADMIN_USER, MARKING_TLP_GREEN, ENTITY_TYPE_MARKING_DEFINITION);
      await registerExisting([author, ...labels, green]);
      const refs = { createdBy: author.standard_id, objectMarking: [MARKING_TLP_GREEN], objectLabel: labels.map((l) => l.standard_id) };
      await getClientBase().set(refsKey, JSON.stringify(refs), 'EX', 3600);
      await writeEntities([{ type: ENTITY_TYPE_MALWARE, input: { name: name('hub'), is_family: true, description: 'benchmark', ...refs } }], options);
    }
    await barrier('refs');
    const refs = JSON.parse(await getClientBase().get(refsKey) as string);

    // Entities with refs, each process its own
    const sources = range(share).map((i) => ({
      type: ENTITY_TYPE_INTRUSION_SET,
      input: { name: name(`p${INDEX}-src`, i), description: 'benchmark', ...refs },
    }));
    await barrier('entities');
    results.entities = timesOf(await writeEntities(sources, options));
    await barrier('entities-done');

    // Relationships with refs from each process's entities to one shared hub
    const relations = sources.map((s) => ({
      relationship_type: RELATION_USES,
      fromId: sid(s.type, s.input.name),
      toId: sid(ENTITY_TYPE_MALWARE, name('hub')),
      description: 'benchmark',
      ...refs,
    }));
    await barrier('relations');
    results.relations_hub = timesOf(await writeRelations(relations, options));
    await barrier('relations-done');

    const hubId = deterministicId(sid(ENTITY_TYPE_MALWARE, name('hub')));
    results.checks = { hub_listed: await denormalizedCount(hubId, inferIndexFromConceptType(ENTITY_TYPE_MALWARE), RELATION_USES), expected: share * PROCESSES };
    writeResults('lockfree-processes', results);
    expect(results.entities.statuses.error ?? 0).toBe(0);
    expect(results.relations_hub.statuses.error ?? 0).toBe(0);
    expect(results.checks.hub_listed).toBe(results.checks.expected);
  });
});
