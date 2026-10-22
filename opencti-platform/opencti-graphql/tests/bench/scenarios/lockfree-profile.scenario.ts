// CPU profile of the lock-free write path in chunks: the profiler runs only around the measured writes (not the
// setup), in the process that does them, and saves one .cpuprofile per case in BENCH_PROFILE_DIR.
// Open the files in Chrome DevTools (Performance tab) or summarize them with tools/cpu_profile.py.
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Session } from 'node:inspector/promises';
import { describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { generateStandardId, MARKING_TLP_GREEN } from '../../../src/schema/identifier';
import { ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../src/schema/stixMetaObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { RELATION_USES } from '../../../src/schema/stixCoreRelationship';
import { addLabel } from '../../../src/domain/label';
import { benchParam, createOne, RUN_ID, writeResults } from '../bench-utils';
import { registerExisting } from '../../../src/database/lockfree/identity';
import { writeEntities, writeRelations } from '../lockfree/run';

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
const PROFILE_DIR = process.env.BENCH_PROFILE_DIR ?? '.';

const name = (label: string, i?: number) => `bench-${RUN_ID}-lfp-${label}${i === undefined ? '' : `-${i}`}`;
const sid = (type: string, entityName: string) => generateStandardId(type, { name: entityName });
const range = (n: number) => [...Array(n).keys()];

const profiled = async <T>(session: Session, label: string, fn: () => Promise<T>) => {
  await session.post('Profiler.setSamplingInterval', { interval: 200 });
  await session.post('Profiler.start');
  const result = await fn();
  const { profile } = await session.post('Profiler.stop');
  const file = join(PROFILE_DIR, `${label}.cpuprofile`);
  writeFileSync(file, JSON.stringify(profile));
  return { ...result as any, profile_file: file };
};

describe('Lock-free profile scenario', () => {
  it('profiles the lock-free write path in chunks', async () => {
    const results: Record<string, any> = { params: { n: N, chunk: CHUNK, settle_every_ms: SETTLE_MS } };
    const author: any = await createOne(ENTITY_TYPE_IDENTITY_ORGANIZATION, 'lfp-author');
    const labels: any[] = [];
    for (let l = 0; l < 3; l += 1) labels.push(await addLabel(testContext, ADMIN_USER, { value: `bench-${RUN_ID}-lfp-label-${l}` }));
    const green: any = await storeLoadById(testContext, ADMIN_USER, MARKING_TLP_GREEN, ENTITY_TYPE_MARKING_DEFINITION);
    await registerExisting([author, ...labels, green]);
    const refs = { createdBy: author.standard_id, objectMarking: [MARKING_TLP_GREEN], objectLabel: labels.map((l) => l.standard_id) };
    const sources: EntityInput[] = range(N).map((i) => ({ type: ENTITY_TYPE_INTRUSION_SET, name: name('src', i), description: 'benchmark' }));
    const hubs: EntityInput[] = range(3).map((h) => ({ type: ENTITY_TYPE_MALWARE, name: name('hub', h), description: 'benchmark' }));
    await writeEntities(toItems([...sources, ...hubs]), { chunkSize: CHUNK, concurrency: 4, settleEveryMs: SETTLE_MS });
    const toHub = (hub: EntityInput, withRefs: boolean): RelationInput[] => sources.map((s) => ({
      relationship_type: RELATION_USES,
      source_ref: sid(s.type, s.name),
      target_ref: sid(hub.type, hub.name),
      source_type: s.type,
      target_type: hub.type,
      description: 'benchmark',
      ...(withRefs ? refs : {}),
    }));
    const opts = { chunkSize: CHUNK, concurrency: 1, settleEveryMs: SETTLE_MS };
    const session = new Session();
    session.connect();
    await session.post('Profiler.enable');
    results.relations_norefs = await profiled(session, 'relations_norefs', () => writeRelations(toRelations(toHub(hubs[0], false)), opts));
    results.relations_refs = await profiled(session, 'relations_refs', () => writeRelations(toRelations(toHub(hubs[1], true)), opts));
    const fresh: EntityInput[] = range(N).map((i) => ({ type: ENTITY_TYPE_INTRUSION_SET, name: name('fresh', i), description: 'benchmark', ...refs }));
    results.entities_refs = await profiled(session, 'entities_refs', () => writeEntities(toItems(fresh), opts));
    session.disconnect();
    writeResults('lockfree-profile', results);
    expect(results.relations_norefs.created).toBe(N);
  });
});
