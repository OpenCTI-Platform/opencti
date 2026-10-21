// Document helpers of the lock-free prototype: realtime reads, reference resolution through the identity index,
// meta relationships with deterministic ids, and merges with optimistic concurrency (if_seq_no) instead of a lock.
import * as R from 'ramda';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { buildInnerRelation } from '../../../src/database/data-builder';
import { elRawBulk, elRawMget, isImpactedTypeAndSide, prepareIndexingElement, ROLE_FROM, ROLE_TO } from '../../../src/database/engine';
import { inferIndexFromConceptType } from '../../../src/database/utils';
import { generateAliasesIdsForInstance, generateStandardId } from '../../../src/schema/identifier';
import { getParentTypes } from '../../../src/schema/schemaUtils';
import { buildRefRelationKey, IDS_STIX, INTERNAL_IDS_ALIASES } from '../../../src/schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../../../src/schema/stixRefRelationship';
import { isStixObjectAliased, resolveAliasesField } from '../../../src/schema/stixDomainObject';
import { cleanMarkings } from '../../../src/utils/markingDefinition-utils';
import { FROM_START_STR, now, UNTIL_END_STR } from '../../../src/utils/format';
import { storeUpdateEvent } from '../../../src/database/stream/stream-handler';
import { buildChanges } from '../../../src/database/data-changes';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import { deterministicId, lookupKeys, type Owner } from './identity';

export const REF_FIELDS = [
  { input: 'createdBy', relation: RELATION_CREATED_BY, multiple: false },
  { input: 'objectMarking', relation: RELATION_OBJECT_MARKING, multiple: true },
  { input: 'objectLabel', relation: RELATION_OBJECT_LABEL, multiple: true },
] as const;

export interface Counters {
  [key: string]: number;
}
export const newCounters = (): Counters => ({
  entities_created: 0,
  entities_merged: 0,
  entities_unchanged: 0,
  relations_created: 0,
  relations_merged: 0,
  relations_unchanged: 0,
  meta_created: 0,
  meta_deleted: 0,
  occ_retries: 0,
  lost_key_races: 0,
  rejected_deleted_ref: 0,
  events_create: 0,
  events_update: 0,
});

export const add = (counters: Counters, key: string, value = 1) => {
  counters[key] = (counters[key] ?? 0) + value;
};

// A stored document as an element; i_source_keys remembers which keys are stored, to write back the same shape
const asElement = (doc: any) => ({
  ...doc._source,
  id: doc._source.internal_id,
  _index: doc._index,
  _seq_no: doc._seq_no,
  _primary_term: doc._primary_term,
  i_source_keys: Object.keys(doc._source),
});
export const storedShape = (element: any, changedFields: string[] = []) => {
  if (element.i_light) throw new Error('A document read without its rel_* lists cannot be written back');
  return R.pick(R.uniq([...element.i_source_keys, ...changedFields]), element);
};

// Realtime multi-get: sees writes that were not refreshed yet. `light` leaves out the rel_* lists, which grow
// with every relationship of a busy entity and are not needed to reference it.
export const fetchDocs = async (refs: { index: string; id: string }[], opts: { light?: boolean } = {}): Promise<Map<string, any>> => {
  const found = new Map<string, any>();
  const unique = R.uniqBy((r) => `${r.index}|${r.id}`, refs);
  for (const slice of R.splitEvery(1000, unique)) {
    const response: any = await elRawMget({ docs: slice.map((r) => ({ _index: r.index, _id: r.id, ...(opts.light ? { _source: { excludes: ['rel_*'] } } : {}) })) });
    response.docs.filter((d: any) => d.found).forEach((d: any) => found.set(d._id, { ...asElement(d), ...(opts.light ? { i_light: true } : {}) }));
  }
  return found;
};

// Resolve references (STIX ids, standard ids, aliases or internal ids) to the documents that own them
export const resolveRefs = async (refs: string[]) => {
  const keys = [...new Set(refs.filter(Boolean).map((r) => r.toLowerCase()))];
  const owners = await lookupKeys(keys);
  const live = [...owners.values()].filter((o) => o.state === 'live');
  const docsById = await fetchDocs(live.map((o) => ({ index: o.owner_index, id: o.owner_id })), { light: true });
  const docs = new Map<string, any>();
  const deleted = new Set<string>();
  keys.forEach((key) => {
    const owner = owners.get(key);
    if (owner?.state === 'deleted') deleted.add(key);
    else if (owner && docsById.has(owner.owner_id)) docs.set(key, docsById.get(owner.owner_id));
  });
  return { docs, owners, deleted, get: (ref?: string) => (ref ? docs.get(ref.toLowerCase()) : undefined) };
};

// An endpoint that is referenced before it exists: everything a reference needs is derived from its STIX id
export const provisionalStub = (stixId: string, entityType: string) => ({
  internal_id: deterministicId(stixId.toLowerCase()),
  id: deterministicId(stixId.toLowerCase()),
  standard_id: stixId.toLowerCase(),
  entity_type: entityType,
  parent_types: getParentTypes(entityType),
  base_type: 'ENTITY',
  _index: inferIndexFromConceptType(entityType),
  i_provisional: true,
});

// Meta relationships (created-by, markings, labels) get ids derived from their ends, so re-creating one is a no-op
export const buildMetaRelations = (source: Record<string, any>, relation: string, targets: any[]) => {
  return buildInnerRelation(source, targets, relation).map((meta: any) => {
    const id = deterministicId(`${relation}|${source.internal_id}|${meta.to.internal_id}`);
    return { ...meta, internal_id: id, id, standard_id: `relationship-meta--${id}` };
  });
};

// The source of a meta relationship lists its targets (rel_<type>.internal_id): written in the document itself
export const denormalizeOnSource = (source: Record<string, any>, metas: any[]) => {
  const out = { ...source };
  metas.forEach((meta) => {
    if (isImpactedTypeAndSide(meta.entity_type, source.entity_type, meta.to.entity_type, ROLE_FROM)) {
      const field = buildRefRelationKey(meta.entity_type);
      out[field] = R.uniq([...(out[field] ?? []), meta.to.internal_id]);
    }
  });
  return out;
};

// Targets of meta relationships that list their sources (none for markings and labels)
export const impactedMetaTargets = (metas: any[]) => metas.filter((meta) => isImpactedTypeAndSide(meta.entity_type, meta.from.entity_type, meta.to.entity_type, ROLE_TO));

export const prepareDocs = async (elements: any[]) => Promise.all(elements.map((e) => prepareIndexingElement(R.omit(['_seq_no', '_primary_term', 'i_source_keys', 'i_light'], e))));

// Bulk `create` without refresh: 201 = created, 409 = already there
export const bulkCreate = async (docs: any[]) => {
  if (docs.length === 0) return [];
  const body = docs.flatMap((doc) => [{ create: { _index: doc._index, _id: doc.internal_id } }, R.dissoc('_index', doc)]);
  const response: any = await elRawBulk(testContext, { refresh: false, body });
  return response.items.map((item: any) => {
    if (item.create.status !== 201 && item.create.status !== 409) throw new Error(`Create failed: ${JSON.stringify(item.create.error)}`);
    return item.create.status;
  });
};

export const bulkDelete = async (docs: { index: string; id: string }[]) => {
  if (docs.length === 0) return;
  await elRawBulk(testContext, { refresh: false, body: docs.map((d) => ({ delete: { _index: d.index, _id: d.id } })) });
};

// What an incoming copy brings to an existing object
export interface Incoming {
  description?: string;
  confidence?: number;
  start_time?: string;
  stop_time?: string;
  aliases?: string[];
  name?: string; // a merged duplicate's name becomes an alias
  stix_ids?: string[];
  refs: { createdBy?: any; objectMarking?: any[]; objectLabel?: any[] };
}

const isDefaultTime = (value: any) => !value || value === FROM_START_STR || value === UNTIL_END_STR
  || new Date(value).toISOString() === FROM_START_STR || new Date(value).toISOString() === UNTIL_END_STR;
const earliest = (a: any, b: any) => (isDefaultTime(a) ? b : (isDefaultTime(b) ? a : (new Date(a) < new Date(b) ? a : b)));
const latest = (a: any, b: any) => (isDefaultTime(a) ? b : (isDefaultTime(b) ? a : (new Date(a) > new Date(b) ? a : b)));

// Simplified upsert rules (the platform's upsertElement has more, see the README):
// - a copy with a confidence at least as high replaces description and confidence;
// - time ranges widen (earliest start, latest stop), defaults never win over a real time;
// - aliases, STIX ids, labels are unions; markings are a union cleaned like the platform does (highest per type);
// - created-by is set when missing.
const computeMerge = async (doc: any, incoming: Incoming) => {
  const next: any = { ...doc };
  const trusted = (incoming.confidence ?? 0) >= (doc.confidence ?? 0);
  if (trusted && incoming.description !== undefined && incoming.description !== doc.description) next.description = incoming.description;
  if (trusted && incoming.confidence !== undefined) next.confidence = incoming.confidence;
  if (incoming.start_time || incoming.stop_time) {
    next.start_time = earliest(doc.start_time, incoming.start_time);
    next.stop_time = latest(doc.stop_time, incoming.stop_time);
  }
  if (isStixObjectAliased(doc.entity_type)) {
    const field = resolveAliasesField(doc.entity_type).name;
    const extra = [...(incoming.aliases ?? []), ...(incoming.name && incoming.name !== doc.name ? [incoming.name] : [])];
    const merged = R.uniqBy((a: string) => a.toLowerCase().trim(), [...(doc[field] ?? []), ...extra]).filter((a) => a.toLowerCase() !== doc.name?.toLowerCase());
    if (merged.length !== (doc[field] ?? []).length) {
      next[field] = merged;
      next[INTERNAL_IDS_ALIASES] = generateAliasesIdsForInstance(next);
    }
  }
  const stixIds = R.uniq([...(doc[IDS_STIX] ?? []), ...(incoming.stix_ids ?? []).map((s) => s.toLowerCase())]).filter((s) => s !== doc.standard_id);
  if (stixIds.length !== (doc[IDS_STIX] ?? []).length) next[IDS_STIX] = stixIds;
  // Refs: compute the target set per ref type, then what to add and remove
  const metaToAdd: any[] = [];
  const metaToRemove: { relation: string; targetId: string }[] = [];
  for (const ref of REF_FIELDS) {
    const field = buildRefRelationKey(ref.relation);
    const current: string[] = doc[field] ?? [];
    let incomingTargets: any[] = [];
    const value = (incoming.refs as any)[ref.input];
    if (ref.multiple) incomingTargets = value ?? [];
    else if (value && current.length === 0) incomingTargets = [value];
    let finalIds = R.uniq([...current, ...incomingTargets.map((t) => t.internal_id)]);
    if (ref.relation === RELATION_OBJECT_MARKING && incomingTargets.length > 0) {
      const all = await fetchMarkings(finalIds, incomingTargets);
      finalIds = (await cleanMarkings(testContext, all)).map((m: any) => m.internal_id);
    }
    const added = incomingTargets.filter((t) => finalIds.includes(t.internal_id) && !current.includes(t.internal_id));
    const removed = current.filter((id) => !finalIds.includes(id));
    if (added.length || removed.length) next[field] = finalIds;
    if (added.length) metaToAdd.push(...buildMetaRelations(next, ref.relation, R.uniqBy((t: any) => t.internal_id, added)));
    removed.forEach((targetId) => metaToRemove.push({ relation: ref.relation, targetId }));
  }
  const changedFields = Object.keys(next).filter((k) => !['i_source_keys', 'i_light'].includes(k) && !R.equals(next[k], doc[k]));
  if (changedFields.length > 0) {
    const today = now();
    next.updated_at = today;
    next.modified = today;
  }
  return { next, changedFields, metaToAdd, metaToRemove };
};

const markingCache = new Map<string, any>();
const fetchMarkings = async (ids: string[], known: any[]) => {
  known.forEach((m) => markingCache.set(m.internal_id, m));
  const missing = ids.filter((id) => !markingCache.has(id));
  if (missing.length > 0) {
    const owners = await lookupKeys(missing);
    const docs = await fetchDocs([...owners.values()].map((o: Owner) => ({ index: o.owner_index, id: o.owner_id })));
    docs.forEach((doc) => markingCache.set(doc.internal_id, doc));
  }
  return ids.map((id) => markingCache.get(id)).filter(Boolean);
};

// Merge an incoming copy into an existing document: read with its sequence number, compute, write back only if
// nobody wrote in between (if_seq_no), otherwise read again. Returns what changed, for the stream event.
export const mergeInto = async (index: string, id: string, incoming: Incoming, counters: Counters, extra: Record<string, any> = {}) => {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const docs = await fetchDocs([{ index, id }]);
    const doc = docs.get(id);
    if (!doc) return { status: 'missing' as const };
    const { next, changedFields, metaToAdd, metaToRemove } = await computeMerge(doc, incoming);
    if (changedFields.length === 0) return { status: 'unchanged' as const, doc };
    const written = storedShape({ ...next, ...extra }, [...changedFields, ...Object.keys(extra)]);
    const response: any = await elRawBulk(testContext, {
      refresh: false,
      body: [{ index: { _index: doc._index, _id: id, if_seq_no: doc._seq_no, if_primary_term: doc._primary_term } }, written],
    });
    const item = response.items[0].index;
    if (item.status === 409) {
      add(counters, 'occ_retries');
      continue;
    }
    if (item.status >= 300) throw new Error(`Merge failed: ${JSON.stringify(item.error)}`);
    const created = await bulkCreate(await prepareDocs(metaToAdd));
    add(counters, 'meta_created', created.filter((s: number) => s === 201).length);
    await bulkDelete(metaToRemove.map((m) => {
      const metaId = deterministicId(`${m.relation}|${id}|${m.targetId}`);
      return { index: inferIndexFromConceptType(m.relation), id: metaId };
    }));
    add(counters, 'meta_deleted', metaToRemove.length);
    return { status: 'merged' as const, previous: doc, next, changedFields, metaToAdd };
  }
  throw new Error(`Merge of ${id} kept conflicting`);
};

// Stream event of a merge, with the refs resolved as the STIX converter needs them
export const emitUpdateEvent = async (previous: any, next: any, changedFields: string[], ends: { from?: any; to?: any }, counters: Counters) => {
  const withRefs = async (doc: any) => {
    const refIds = REF_FIELDS.flatMap((ref) => doc[buildRefRelationKey(ref.relation)] ?? []);
    const resolved = await resolveRefs(refIds);
    const relationEnds = ends.from && ends.to
      ? { from: ends.from, to: ends.to, fromId: ends.from.internal_id, toId: ends.to.internal_id, fromType: ends.from.entity_type, toType: ends.to.entity_type }
      : {};
    const out: any = { ...doc, ...relationEnds };
    REF_FIELDS.forEach((ref) => {
      const ids: string[] = doc[buildRefRelationKey(ref.relation)] ?? [];
      const objects = ids.map((rid) => resolved.get(rid)).filter(Boolean);
      out[ref.input] = ref.multiple ? objects : objects[0];
    });
    return out;
  };
  // The platform's own change format (the history index has a strict mapping for it): schema attributes as they
  // are, rel_* fields as their ref (createdBy, objectMarking...), internal fields left out
  const [previousFull, nextFull] = [await withRefs(previous), await withRefs(next)];
  const inputs = changedFields.flatMap((key) => {
    const ref = REF_FIELDS.find((r) => buildRefRelationKey(r.relation) === key);
    if (ref) return [{ key: ref.input, previous: [].concat(previousFull[ref.input] ?? []), value: [].concat(nextFull[ref.input] ?? []) }];
    if (['updated_at', 'modified'].includes(key) || !schemaAttributesDefinition.getAttribute(next.entity_type, key)) return [];
    return [{ key, previous: [].concat(previous[key] ?? []), value: [].concat(next[key] ?? []) }];
  });
  const changes = await buildChanges(testContext, ADMIN_USER, next.entity_type, inputs);
  await storeUpdateEvent(testContext, ADMIN_USER, previousFull, nextFull, changes);
  add(counters, 'events_update');
};

// A relationship is identified by its type and its two ends, not by its time range
export const relationKey = (type: string, fromId: string, toId: string) => `${type}|${fromId}|${toId}`;
export const standardIdWithoutTime = (type: string, from: any, to: any) => generateStandardId(type, { relationship_type: type, from, to });
