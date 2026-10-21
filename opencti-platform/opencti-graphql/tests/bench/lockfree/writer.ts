// Lock-free write path (prototype): what the platform would do with one chunk of a bundle, without Redis locks
// and without forced refreshes. See benchmarks/ingestion/README.md, "Lock-free prototype".
//
// Entities: identity keys are looked up in the identity index (realtime); a new object is created with
// internal_id = UUIDv5(standard_id) by `create`, then claims its keys; an existing one is merged with
// optimistic concurrency. A key lost to a concurrent writer schedules a reconciliation (merge of the duplicate).
// Relationships: both ends are resolved through the identity index. An end that is not there yet gets a
// provisional id derived from its STIX id; the settler re-points the relationship once the end is known.
// The relationship id is UUIDv5(type, from internal id, to internal id): time is not part of the identity,
// a copy with another time range widens the existing one.
import * as R from 'ramda';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { buildEntityData, buildRelationData } from '../../../src/database/data-builder';
import { inferIndexFromConceptType } from '../../../src/database/utils';
import { storeCreateEntityEvent, storeCreateRelationEvent } from '../../../src/database/stream/stream-handler';
import { generateStandardId } from '../../../src/schema/identifier';
import { isStixObjectAliased, resolveAliasesField } from '../../../src/schema/stixDomainObject';
import { claimKeys, deterministicId, identityKeys, lookupKeys, type Owner } from './identity';
import {
  add,
  buildMetaRelations,
  bulkCreate,
  type Counters,
  denormalizeOnSource,
  emitUpdateEvent,
  impactedMetaTargets,
  type Incoming,
  mergeInto,
  prepareDocs,
  provisionalStub,
  REF_FIELDS,
  relationKey,
  resolveRefs,
  standardIdWithoutTime,
} from './store';
import type { Settler } from './settler';
import { benchTimer } from '../../../src/utils/bench-timing';

export interface RefInput {
  createdBy?: string;
  objectMarking?: string[];
  objectLabel?: string[];
}
export interface EntityInput extends RefInput {
  type: string;
  name: string;
  stix_id?: string;
  aliases?: string[];
  description?: string;
  confidence?: number;
}
export interface RelationInput extends RefInput {
  relationship_type: string;
  source_ref: string;
  target_ref: string;
  // Needed only while an end is unknown: the STIX type of an id is not always enough (identity--, location--)
  source_type: string;
  target_type: string;
  stix_id?: string;
  description?: string;
  confidence?: number;
  start_time?: string;
  stop_time?: string;
}

const refIdsOf = (input: RefInput) => [input.createdBy, ...(input.objectMarking ?? []), ...(input.objectLabel ?? [])].filter(Boolean) as string[];
const refsFrom = (input: RefInput, resolved: Awaited<ReturnType<typeof resolveRefs>>) => ({
  createdBy: resolved.get(input.createdBy),
  objectMarking: (input.objectMarking ?? []).map((m) => resolved.get(m)).filter(Boolean),
  objectLabel: (input.objectLabel ?? []).map((l) => resolved.get(l)).filter(Boolean),
});
const missingRefs = (input: RefInput, resolved: Awaited<ReturnType<typeof resolveRefs>>) => refIdsOf(input).filter((r) => !resolved.get(r));

// Group inputs of a chunk that share any identity key (union-find), so a chunk never races with itself
const groupByKeys = <T>(items: T[], keysOf: (item: T) => string[]) => {
  const parent = items.map((_, i) => i);
  const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  const firstByKey = new Map<string, number>();
  items.forEach((item, i) => keysOf(item).forEach((key) => {
    const j = firstByKey.get(key);
    if (j === undefined) firstByKey.set(key, i);
    else parent[find(i)] = find(j);
  }));
  const groups = new Map<number, T[]>();
  items.forEach((item, i) => groups.set(find(i), [...(groups.get(find(i)) ?? []), item]));
  return [...groups.values()];
};

const combineEntityInputs = (inputs: EntityInput[]): EntityInput & { stix_ids: string[]; names: string[] } => {
  const [first, ...rest] = inputs;
  return {
    ...first,
    aliases: R.uniq([...inputs.flatMap((i) => i.aliases ?? []), ...rest.map((r) => r.name)]).filter((a) => a !== first.name),
    stix_ids: inputs.map((i) => i.stix_id).filter(Boolean) as string[],
    names: inputs.map((i) => i.name),
    description: R.last(inputs.filter((i) => i.description !== undefined))?.description,
    confidence: Math.max(...inputs.map((i) => i.confidence ?? 0)),
    objectMarking: R.uniq(inputs.flatMap((i) => i.objectMarking ?? [])),
    objectLabel: R.uniq(inputs.flatMap((i) => i.objectLabel ?? [])),
    createdBy: inputs.find((i) => i.createdBy)?.createdBy,
  };
};

const ownerOf = (element: any) => ({ owner_id: element.internal_id, owner_index: element._index, owner_type: element.entity_type, owner_standard_id: element.standard_id });

// Entities: one chunk
export const writeEntityChunk = async (inputs: EntityInput[], settler: Settler, counters: Counters) => {
  const bench = benchTimer('lf_entity');
  const keysOf = (input: EntityInput) => identityKeys(input.type, { name: input.name, stix_id: input.stix_id, aliases: input.aliases, x_opencti_aliases: input.aliases });
  const groups = groupByKeys(inputs, keysOf).map((group) => ({ input: combineEntityInputs(group), keys: R.uniq(group.flatMap(keysOf)) }));
  const resolved = await resolveRefs(inputs.flatMap(refIdsOf));
  const owners = await lookupKeys(groups.flatMap((g) => g.keys));
  bench.step('resolve');
  const toCreate: { input: any; keys: string[]; element: any; metas: any[] }[] = [];
  const toMerge: { input: any; keys: string[]; target: Owner }[] = [];
  for (const group of groups) {
    const missing = missingRefs(group.input, resolved);
    if (missing.length > 0) throw new Error(`Missing refs ${missing.join(', ')}`);
    const live = R.uniqBy((o: Owner) => o.owner_id, group.keys.map((k) => owners.get(k)).filter((o): o is Owner => o?.state === 'live'));
    if (live.length === 0) {
      const aliasField = isStixObjectAliased(group.input.type) ? resolveAliasesField(group.input.type).name : 'aliases';
      const standardId = generateStandardId(group.input.type, { name: group.input.name });
      const data: any = await buildEntityData(testContext, ADMIN_USER, {
        name: group.input.name,
        description: group.input.description,
        confidence: group.input.confidence,
        ...(group.input.aliases?.length ? { [aliasField]: group.input.aliases } : {}),
        x_opencti_stix_ids: group.input.stix_ids.filter((s) => s.toLowerCase() !== standardId),
        internal_id: deterministicId(standardId),
        entity_type: group.input.type,
        ...refsFrom(group.input, resolved),
      }, group.input.type);
      const metas = REF_FIELDS.flatMap((ref) => {
        const value = (refsFrom(group.input, resolved) as any)[ref.input];
        const targets = (ref.multiple ? value : [value]).filter(Boolean);
        return targets.length ? buildMetaRelations(data.element, ref.relation, targets) : [];
      });
      toCreate.push({ input: group.input, keys: group.keys, element: denormalizeOnSource(data.element, metas), metas });
    } else {
      // Several owners: the keys of two existing objects now meet; merge into one, reconcile the others
      const [target, ...others] = R.sortBy((o: Owner) => o.owner_id, live);
      others.forEach((other) => settler.reconcile(other, target));
      toMerge.push({ input: group.input, keys: group.keys, target });
    }
  }
  bench.step('build');
  // Create, then claim the keys. A 409 on create = the same standard id created concurrently: merge instead.
  const entityDocs = await prepareDocs(toCreate.map((c) => c.element));
  bench.step('prepare');
  const statuses = await bulkCreate(entityDocs);
  bench.step('create');
  const created = toCreate.filter((_, i) => statuses[i] === 201);
  toCreate.filter((_, i) => statuses[i] === 409).forEach((c) => toMerge.push({
    input: c.input, keys: c.keys, target: { ...ownerOf(c.element), key: '', state: 'live' },
  }));
  const metaDocs = await prepareDocs(created.flatMap((c) => c.metas));
  bench.step('meta_prepare');
  const metaStatuses = await bulkCreate(metaDocs);
  bench.step('meta_create');
  add(counters, 'meta_created', metaStatuses.filter((s: number) => s === 201).length);
  add(counters, 'entities_created', created.length);
  created.forEach((c) => impactedMetaTargets(c.metas).forEach((meta) => settler.addEndpoint(meta.to, meta.entity_type, c.element.internal_id, 'to')));
  const lost = await claimKeys(created.map((c) => ({ keys: [...c.keys, c.element.internal_id], owner: ownerOf(c.element) })));
  // A key claimed by another object in between: this object is a duplicate of it, merge it there in the background
  R.uniqBy((l: any) => `${l.claimant}|${l.holder.owner_id}`, lost).forEach((l: any) => {
    const mine = created.find((c) => c.element.internal_id === l.claimant);
    if (mine) settler.reconcile({ ...ownerOf(mine.element), key: '', state: 'live' }, l.holder);
  });
  add(counters, 'lost_key_races', lost.length);
  bench.step('claim');
  await Promise.all(created.map(async (c) => {
    await storeCreateEntityEvent(testContext, ADMIN_USER, { ...c.element, ...refsFrom(c.input, resolved) }, 'creates');
    add(counters, 'events_create');
  }));
  bench.step('events');
  for (const merge of toMerge) {
    const incoming: Incoming = {
      description: merge.input.description,
      confidence: merge.input.confidence,
      aliases: [...(merge.input.aliases ?? []), ...merge.input.names],
      stix_ids: merge.input.stix_ids,
      refs: refsFrom(merge.input, resolved),
    };
    const result = await mergeInto(merge.target.owner_index, merge.target.owner_id, incoming, counters);
    if (result.status === 'merged') {
      add(counters, 'entities_merged');
      await claimKeys([{ keys: merge.keys, owner: R.omit(['key', 'state'], merge.target) }]);
      impactedMetaTargets(result.metaToAdd).forEach((meta) => settler.addEndpoint(meta.to, meta.entity_type, merge.target.owner_id, 'to'));
      await emitUpdateEvent(result.previous, result.next, result.changedFields, {}, counters);
    } else add(counters, 'entities_unchanged');
  }
  bench.step('merges');
  bench.total();
};

// Relationships: one chunk

export const writeRelationChunk = async (inputs: RelationInput[], settler: Settler, counters: Counters) => {
  const bench = benchTimer('lf_relation');
  const resolved = await resolveRefs(inputs.flatMap((i) => [i.source_ref, i.target_ref, ...refIdsOf(i)]));
  const prepared: { input: RelationInput; from: any; to: any; id: string }[] = [];
  for (const input of inputs) {
    if ([input.source_ref, input.target_ref, ...refIdsOf(input)].some((r) => resolved.deleted.has(r.toLowerCase()))) {
      add(counters, 'rejected_deleted_ref');
      continue;
    }
    const missing = missingRefs(input, resolved);
    if (missing.length > 0) throw new Error(`Missing refs ${missing.join(', ')}`);
    const from = resolved.get(input.source_ref) ?? provisionalStub(input.source_ref, input.source_type);
    const to = resolved.get(input.target_ref) ?? provisionalStub(input.target_ref, input.target_type);
    prepared.push({ input, from, to, id: deterministicId(relationKey(input.relationship_type, from.internal_id, to.internal_id)) });
  }
  bench.step('resolve');
  // Same relationship twice in a chunk: one create, the other copies merge into it
  const groups = Object.values(R.groupBy((p) => p.id, prepared)) as typeof prepared[];
  const firsts = groups.map((g) => g[0]);
  const built = await Promise.all(firsts.map(async ({ input, from, to, id }) => {
    const refs = refsFrom(input, resolved);
    const data: any = await buildRelationData(testContext, ADMIN_USER, {
      relationship_type: input.relationship_type,
      from,
      to,
      internal_id: id,
      standard_id: standardIdWithoutTime(input.relationship_type, from, to),
      stix_id: input.stix_id,
      description: input.description,
      confidence: input.confidence,
      start_time: input.start_time,
      stop_time: input.stop_time,
      ...refs,
    }, {});
    const metas = (data.relations ?? []).map((meta: any) => {
      const metaId = deterministicId(`${meta.entity_type}|${id}|${meta.to.internal_id}`);
      return { ...meta, internal_id: metaId, id: metaId, standard_id: `relationship-meta--${metaId}` };
    });
    return { element: denormalizeOnSource(data.element, metas), metas, refs };
  }));
  bench.step('build');
  const relationDocs = await prepareDocs(built.map((b) => b.element));
  bench.step('prepare');
  const statuses = await bulkCreate(relationDocs);
  bench.step('create');
  const createdIndexes = built.map((_, i) => i).filter((i) => statuses[i] === 201);
  const created = createdIndexes.map((i) => built[i]);
  const metaDocs = await prepareDocs(created.flatMap((b) => b.metas));
  bench.step('meta_prepare');
  const metaStatuses = await bulkCreate(metaDocs);
  bench.step('meta_create');
  add(counters, 'meta_created', metaStatuses.filter((s: number) => s === 201).length);
  add(counters, 'relations_created', created.length);
  createdIndexes.forEach((i) => {
    const b = built[i];
    settler.addRelation(b.element, firsts[i].from, firsts[i].to, firsts[i].input);
    impactedMetaTargets(b.metas).forEach((meta) => settler.addEndpoint(meta.to, meta.entity_type, b.element.internal_id, 'to'));
  });
  bench.step('settler_queue');
  await Promise.all(created.map(async (b) => {
    await storeCreateRelationEvent(testContext, ADMIN_USER, { ...b.element, ...b.refs }, {});
    add(counters, 'events_create');
  }));
  bench.step('events');
  // Existing ones, and the extra copies of a chunk: merge with optimistic concurrency
  const merges = groups.flatMap((g, i) => (statuses[i] === 409 ? g : g.slice(1)));
  for (const { input, from, to, id } of merges) {
    const incoming: Incoming = {
      description: input.description,
      confidence: input.confidence,
      start_time: input.start_time,
      stop_time: input.stop_time,
      stix_ids: input.stix_id ? [input.stix_id] : [],
      refs: refsFrom(input, resolved),
    };
    const result = await mergeInto(inferIndexFromConceptType(input.relationship_type), id, incoming, counters);
    if (result.status === 'merged') {
      add(counters, 'relations_merged');
      await emitUpdateEvent(result.previous, result.next, result.changedFields, { from, to }, counters);
    } else add(counters, 'relations_unchanged');
  }
  bench.step('merges');
  bench.total();
};
