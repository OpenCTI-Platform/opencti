// Prototype of a batch write path for relationships, used by the benchmark scenarios only.
// It writes new relationships one chunk at a time instead of one relationship at a time:
// one search for every ref of the chunk, one lock for the chunk, one duplicate search, one elIndexElements call,
// then one stream event per relationship, as today.
// Not handled: updates of existing relationships, the time-window duplicate check, per-item access,
// confidence and consistency checks, container sharing tasks and the security coverage hook.
import * as R from 'ramda';
import { ADMIN_USER, testContext } from '../utils/testQuery';
import { inputResolveRefs } from '../../src/database/middleware';
import { elFindByIds, elIndexElements, isImpactedTypeAndSide, ROLE_FROM, ROLE_TO } from '../../src/database/engine';
import { internalFindByIds } from '../../src/database/middleware-loader';
import { buildRelationData } from '../../src/database/data-builder';
import { lockResources } from '../../src/lock/master-lock';
import { storeCreateRelationEvent } from '../../src/database/stream/stream-handler';
import { getEntitySettingFromCache } from '../../src/modules/entitySetting/entitySetting-utils';
import { inferIndexFromConceptType } from '../../src/database/utils';
import { getInstanceIds } from '../../src/schema/identifier';
import { mean, now, pool, round } from './bench-utils';

const SINGLE_REFS: Record<string, string> = { fromId: 'from', toId: 'to', createdBy: 'createdBy' };
const MULTI_REFS: Record<string, string> = { objectMarking: 'objectMarking', objectLabel: 'objectLabel' };

// Resolve every ref of a chunk in one search and build the input shape inputResolveRefs returns
export const bulkResolveRelations = async (inputs: Record<string, any>[], type: string) => {
  const ids = R.uniq(inputs.flatMap((input) => [
    ...Object.keys(SINGLE_REFS).map((key) => input[key]).filter(Boolean),
    ...Object.keys(MULTI_REFS).flatMap((key) => input[key] ?? []),
  ]));
  const elements = await internalFindByIds(testContext, ADMIN_USER, ids) as any[];
  const byId = new Map<string, any>();
  elements.forEach((element) => getInstanceIds(element).forEach((id: string) => byId.set(id, element)));
  const get = (id: string) => {
    const element = byId.get(id);
    if (!element) throw new Error(`Missing reference ${id}`);
    return element;
  };
  return inputs.map((input) => {
    const resolved: Record<string, any> = { _index: inferIndexFromConceptType(type), ...input, entity_type: type };
    Object.entries(SINGLE_REFS).forEach(([src, dst]) => {
      if (input[src]) {
        resolved[src] = null;
        resolved[dst] = { ...get(input[src]), i_group: { id: input[src], destKey: dst, multiple: false } };
      }
    });
    Object.entries(MULTI_REFS).forEach(([src, dst]) => {
      if (input[src]?.length) {
        resolved[src] = null;
        resolved[dst] = input[src].map((id: string) => ({ ...get(id), i_group: { id, destKey: dst, multiple: true } }));
      }
    });
    return resolved;
  });
};

// Compare the bulk resolution with the platform's resolver on one input: every key must hold the same ids
export const checkBulkResolution = async (input: Record<string, any>, type: string) => {
  const entitySetting: any = await getEntitySettingFromCache(testContext, type);
  const real: any = await inputResolveRefs(testContext, ADMIN_USER, input, type, entitySetting);
  const [bulk]: any[] = await bulkResolveRelations([input], type);
  const idsOf = (value: any) => (Array.isArray(value) ? value.map((e) => e.internal_id).sort() : value?.internal_id ?? value);
  const keys = R.uniq([...Object.keys(real), ...Object.keys(bulk)]).sort();
  const perKey = Object.fromEntries(keys.map((key) => [key, R.equals(idsOf(real[key]), idsOf(bulk[key]))]));
  return { identical: Object.values(perKey).every(Boolean), per_key: perKey };
};

// Lock ids as the platform computes them: the relationship ids, plus each endpoint on an impacted side
const lockIdsFor = (resolved: Record<string, any>[], built: any[], type: string) => R.uniq([
  ...built.map((b) => b.element.standard_id),
  ...resolved.flatMap((r) => [
    ...(isImpactedTypeAndSide(type, r.from.entity_type, r.to.entity_type, ROLE_FROM) ? [r.from.internal_id] : []),
    ...(isImpactedTypeAndSide(type, r.from.entity_type, r.to.entity_type, ROLE_TO) ? [r.to.internal_id] : []),
  ]),
]);

const writeChunks = async (inputs: Record<string, any>[], type: string, chunkSize: number, phases: Record<string, number[]>) => {
  const mark = (key: string, start: number) => {
    if (!phases[key]) phases[key] = [];
    phases[key].push(now() - start);
  };
  for (let c = 0; c < inputs.length; c += chunkSize) {
    const chunkStart = now();
    const chunk = inputs.slice(c, c + chunkSize);
    let t = now();
    const resolved = await bulkResolveRelations(chunk, type);
    mark('resolve', t);
    t = now();
    const built: any[] = [];
    for (let i = 0; i < resolved.length; i += 1) {
      built.push(await buildRelationData(testContext, ADMIN_USER, resolved[i], {}));
    }
    mark('build', t);
    t = now();
    const lock: any = await lockResources(lockIdsFor(resolved, built, type), {});
    mark('lock_wait', t);
    const heldStart = now();
    try {
      t = now();
      await elFindByIds(testContext, ADMIN_USER, built.map((b) => b.element.standard_id));
      mark('existing_search', t);
      t = now();
      const docs = built.flatMap((b) => [b.element, ...(b.relations ?? [])]);
      await elIndexElements(testContext, ADMIN_USER, type, docs);
      mark('index', t);
      if (!phases.indexed_docs) phases.indexed_docs = [];
      phases.indexed_docs.push(docs.length);
      t = now();
      await pool(built, 16, async (b, i) => {
        await storeCreateRelationEvent(testContext, ADMIN_USER, { ...resolved[i], ...b.element }, {});
      });
      mark('stream_events', t);
    } finally {
      await lock.unlock();
      mark('lock_held', heldStart);
    }
    mark('chunk_total', chunkStart);
  }
};

// Write the relationships with `writers` concurrent writers, each taking an equal share of the inputs
export const batchWriteRelations = async (inputs: Record<string, any>[], type: string, chunkSize: number, writers = 1) => {
  const phases: Record<string, number[]> = {};
  const shares = R.splitEvery(Math.ceil(inputs.length / writers), inputs);
  const start = now();
  await Promise.all(shares.map((share) => writeChunks(share, type, chunkSize, phases)));
  const wall = now() - start;
  return {
    count: inputs.length,
    chunk_size: chunkSize,
    writers,
    chunks: phases.chunk_total?.length ?? 0,
    wall_ms: round(wall),
    throughput_per_s: round((inputs.length / wall) * 1000),
    per_chunk_mean_ms: Object.fromEntries(Object.entries(phases).filter(([key]) => key !== 'indexed_docs').map(([key, values]) => [key, mean(values)])),
    indexed_docs_per_chunk: mean(phases.indexed_docs ?? []),
  };
};
