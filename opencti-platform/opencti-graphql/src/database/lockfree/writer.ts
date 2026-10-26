// Lock-free write path for entities and relationships, chunk by chunk. Same inputs as createEntity and
// createRelation, same rules, same stored documents and stream events; without Redis locks, forced refreshes or
// searches for existing copies. See benchmarks/ingestion/README.md, "Lock-free write path".
//
// Per chunk:
//  1. each input is prepared and resolved as today (confidence, access, custom fields, inputResolveRefs) with a
//     finder that reads by id through the identity index, prefetched for the whole chunk;
//  2. each input is matched against existing objects by identity keys (entities) or by its pair's duplicate
//     window (relationships), and today's rules pick create, merge or refuse;
//  3. new objects are written in bulk with `create`; entities claim their identity keys first so that two writers
//     never both create the same object; follow-up work on shared entities goes to the durable settler queue.
// Inputs left to today's path, unchanged: drafts, file uploads, explicit ref relationships (created-by,
// object-marking... sent as relationships) and relationships replacing a single ref.
import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import { buildEntityData, buildRelationData } from '../../database/data-builder';
import {
  cleanEntityForIdsCollision,
  createContainerSharingTask,
  createEntity,
  createRelation,
  inputResolveRefs,
  triggerCreateEntityAutoEnrichment,
  triggerEntityUpdateAutoEnrichment,
  updateAttribute,
  validateEntityAndRelationCreation,
} from '../../database/middleware';
import { elRawMget, isImpactedTypeAndSide, prepareIndexingElement, ROLE_FROM, ROLE_TO } from '../../database/engine';
import { storeCreateEvents } from '../../database/stream/stream-handler';
import { generateCreateMessage } from '../../database/data-changes';
import { inferIndexFromConceptType } from '../../database/utils';
import { fillDefaultCustomFieldValues, fillDefaultValues, getEntitySettingFromCache } from '../../modules/entitySetting/entitySetting-utils';
import { controlCreateInputWithUserConfidence } from '../../utils/confidence-level';
import { AccessOperation, userFilterStoreElements, validateUserAccessOperation } from '../../utils/access';
import { checkRelationConsistency } from '../../utils/modelConsistency';
import { getDraftContext } from '../../utils/draftContext';
import { rewriteEmbeddedDataUriImagesInDescriptions } from '../../database/middlewareEmbeddedImages';
import { transformCustomFieldValueAddInput } from '../../modules/customField/custom-field-validator';
import { initializeEntityWorkflow, resolveEntityWorkflowConfig, syncWorkflowInstanceFromExternalWrite } from '../../modules/workflow/domain/workflow-domain';
import { CUSTOM_FIELDS_FEATURE_FLAG, ENTITIES_WORKFLOW_FEATURE_FLAG, isFeatureEnabled } from '../../config/conf';
import { DOC_INSUFFICIENT_CONFIDENCE_LEVEL, ForbiddenAccess, FunctionalError, UnsupportedError } from '../../config/errors';
import { generateHashedObservableStandardIds, generateStandardId, getInputIds, getInstanceIds } from '../../schema/identifier';
import { isStixCyberObservableHashedObservable } from '../../schema/stixCyberObservable';
import { isStixRefRelationship } from '../../schema/stixRefRelationship';
import { isSingleRelationsRef } from '../../schema/stixEmbeddedRelationship';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { authorizedMembersActivationDate } from '../../schema/attribute-definition';
import { buildRefRelationKey } from '../../schema/general';
import { ENTITY_TYPE_SECURITY_COVERAGE, RELATION_COVERED } from '../../modules/securityCoverage/securityCoverage-types';
import { ACTION_TYPE_SHARE } from '../../domain/backgroundTask-common';
import { now } from '../../utils/format';
import { claimKeys, deterministicId, type Owner, setKeys } from './identity';
import { ChunkReads, findUnknownBySearch, liveOwners, mgetRaw, toElements } from './load';
import { addPending } from './pending';
import { pool } from './context';
import { type BenchTimer, benchTimer } from '../../utils/bench-timing';
import { reconcileEntities } from './reconcile';
import { appendPairs, findDuplicates, pairEntryOf, type PairEntry, pairKey, readPairs, withoutDeleted } from './pairs';
import { enqueue, type Task } from './queue';
import { add, type Counters } from './store';
import { bulkCreateDocs, metaTargetTasks, upsertLockFree, withMetaIds, type WriteOptions } from './upsert';
import { chunkEpoch, fingerprintOf, isUnchangedOn, readUnchanged, recordUnchanged, type Version } from './unchanged';

export interface EntityItem { type: string; input: Record<string, any> }
export interface ItemResult {
  status: 'created' | 'merged' | 'unchanged' | 'pending' | 'fallback' | 'error';
  id?: string;
  error?: string;
  cause?: unknown; // the error itself, for a caller that rethrows it
}

// Today's path, called for what the lock-free path leaves to it: marked so the platform does not send it back here
const todayContext = (context: AuthContext): AuthContext => ({ ...context, lockfree_bypass: true, lockfree_write: false } as AuthContext);

// Fields the access rules and hooks read, fetched beside otherwise light documents (no rel_* lists)
const ACCESS_FIELDS = ['rel_object-marking.*', 'rel_granted-to.*', `rel_${RELATION_COVERED}.*`, 'restricted_members', 'authorized_authorities'];

interface DocRef { index: string; id: string }

const mgetAccess = async (refs: DocRef[]) => {
  const found = new Map<string, any>();
  for (const batch of R.splitEvery(1000, refs)) {
    const response: any = await elRawMget({ docs: batch.map((ref) => ({ _index: ref.index, _id: ref.id, _source: { includes: ACCESS_FIELDS } })) });
    response.docs.filter((doc: any) => doc.found).forEach((doc: any) => found.set(doc._id, doc));
  }
  return found;
};

const loadWithAccessFields = async (ids: string[]) => {
  const { live } = await liveOwners(ids);
  const refs = live.map((owner) => ({ index: owner.owner_index, id: owner.owner_id }));
  if (refs.length === 0) return [];
  const [light, access] = await Promise.all([mgetRaw(refs, { light: true }), mgetAccess(refs)]);
  light.forEach((raw) => Object.assign(raw._source, access.get(raw._id)?._source ?? {}));
  return toElements([...light.values()], { owned: true });
};

// The finder handed to inputResolveRefs: reads by id, remembers what it read for the chunk, filters by the user's access
const chunkFinder = (context: AuthContext, user: AuthUser) => {
  const cache = new Map<string, any | null>();
  return async (ids: string[]) => {
    const missing = R.uniq(ids.filter((id) => id && !cache.has(id.toLowerCase())));
    if (missing.length > 0) {
      const loaded = await loadWithAccessFields(missing);
      const searched = await findUnknownBySearch(context, missing, loaded);
      missing.forEach((id) => cache.set(id.toLowerCase(), null));
      [...loaded, ...searched].forEach((element) => getInstanceIds(element).forEach((id: string) => cache.set(id.toLowerCase(), element)));
    }
    const elements = R.uniqBy((element: any) => element.internal_id, ids.map((id) => cache.get(id?.toLowerCase())).filter(Boolean));
    return userFilterStoreElements(context, user, elements) as Promise<any[]>;
  };
};
type Finder = ReturnType<typeof chunkFinder>;

// What every phase of a chunk works with. Phases write each input's outcome into results, at the input's position.
interface Chunk {
  context: AuthContext;
  user: AuthUser;
  finder: Finder;
  counters: Counters;
  opts: WriteOptions;
  results: ItemResult[];
}

const refInputIds = (type: string, input: Record<string, any>) => {
  const fields = schemaRelationsRefDefinition.getRelationsRef(type).map((ref) => ref.name);
  return [input.fromId, input.toId, ...fields.flatMap((field) => [].concat(input[field] ?? []))].filter((value) => typeof value === 'string');
};

// The input preparation of createEntityRaw / createRelationRaw before their lock
const prepareInput = async (context: AuthContext, user: AuthUser, rawInput: Record<string, any>, type: string) => {
  const input: Record<string, any> = { ...rawInput };
  const { confidenceLevelToApply } = controlCreateInputWithUserConfidence(user, input as any, type);
  input.confidence = confidenceLevelToApply;
  if (input.authorized_members?.length > 0) input.restricted_members = input.authorized_members;
  delete input.authorized_members;
  if (isFeatureEnabled(CUSTOM_FIELDS_FEATURE_FLAG)) {
    const values = await transformCustomFieldValueAddInput(context, user, input.customFieldValues ?? [], type);
    if (values.length > 0 || input.customFieldValues) input.custom_field_values = values;
  }
  delete input.customFieldValues;
  return input;
};

// The defaults and validation createEntityRaw / createRelationRaw apply to a new object, once it is known to be new
const completeNewInput = async ({ context, user, finder }: Chunk, item: { type: string; resolvedInput: Record<string, any>; entitySetting: any }) => {
  let resolvedInput = fillDefaultValues(user, item.resolvedInput, item.entitySetting);
  resolvedInput = await inputResolveRefs(context, user, resolvedInput, item.type, item.entitySetting, { finder });
  resolvedInput = await fillDefaultCustomFieldValues(context, user, resolvedInput, item.entitySetting);
  await validateEntityAndRelationCreation(context, user, resolvedInput, item.type, item.entitySetting, {});
  return resolvedInput;
};

const isNotEmpty = (value: any) => value !== undefined && value !== null && !(Array.isArray(value) && value.length === 0);

// Denormalized ref ids on the source of its meta relationships (what elIndexElements' impacts write today)
// (one Set per field: a container can have tens of thousands of refs)
const denormalizeOnSource = (source: Record<string, any>, metas: any[]) => {
  const out = { ...source };
  const ids = new Map<string, Set<string>>();
  metas.forEach((meta) => {
    if (isImpactedTypeAndSide(meta.entity_type, source.entity_type, meta.to.entity_type, ROLE_FROM)) {
      const field = buildRefRelationKey(meta.entity_type);
      if (!ids.has(field)) ids.set(field, new Set(out[field] ?? []));
      ids.get(field)!.add(meta.to.internal_id);
    }
  });
  ids.forEach((fieldIds, field) => {
    out[field] = [...fieldIds];
  });
  return out;
};

// The created element as createEntityRaw hands it to the stream: input, document, and ref ids by database name
const createdElementOf = (resolvedInput: Record<string, any>, element: Record<string, any>) => {
  const created: Record<string, any> = { ...resolvedInput, ...element };
  schemaRelationsRefDefinition.getRelationsRef(created.entity_type).forEach(({ name, databaseName }) => {
    created[databaseName] = Array.isArray(created[name]) ? created[name].map(({ id }: any) => id) : created[name];
  });
  return created;
};

const ownerOf = (element: any): Owner => ({
  key: '', state: 'live', owner_id: element.internal_id, owner_index: element._index, owner_type: element.entity_type, owner_standard_id: element.standard_id,
});

// An owner as the identity index stores it under a key
const keyOwner = (owner: Owner) => R.omit(['key', 'state'], owner);

const errorResult = (e: any): ItemResult => ({ status: 'error', error: e?.extensions?.data?.doc_code ?? e?.extensions?.code ?? e?.message ?? String(e), cause: e });

// Runs a phase on every input at once. An input whose phase throws gets the error as its result and leaves the chunk.
const settleAll = async <T, U>(
  items: T[], indexOf: (item: T, position: number) => number, phase: (item: T, position: number) => Promise<U | null>, results: ItemResult[],
): Promise<U[]> => {
  const settled: (U | null)[] = await Promise.all(items.map(async (item, position) => {
    try {
      return await phase(item, position);
    } catch (e) {
      results[indexOf(item, position)] = errorResult(e);
      return null;
    }
  }));
  return settled.filter((value): value is U => value !== null);
};

// An input the lock-free path leaves to today's path
interface Fallback { i: number; fallback: true }

const splitFallbacks = <T>(prepared: (T | Fallback)[]) => ({
  fallbacks: prepared.filter((value): value is Fallback => 'fallback' in (value as object)),
  work: prepared.filter((value): value is T => !('fallback' in (value as object))),
});

// Today's path for the fallbacks, one after the other
const writeFallbacks = async ({ counters, results }: Chunk, fallbacks: Fallback[], writeToday: (i: number) => Promise<any>) => {
  for (const { i } of fallbacks) {
    try {
      const element = await writeToday(i);
      results[i] = { status: 'fallback', id: element.internal_id };
      add(counters, 'fallbacks');
    } catch (e) {
      results[i] = errorResult(e);
    }
  }
};

// R.groupBy's groups, in the same order
const groupsOf = <T>(items: T[], keyOf: (item: T) => string): T[][] => Object.values(R.groupBy(keyOf, items)) as T[][];

// Items linked by any shared key, transitively (union-find), each group in input order
const groupByKeys = <T>(items: T[], keysOf: (item: T) => string[]) => {
  const parent = items.map((_, i) => i);
  const find = (i: number): number => {
    if (parent[i] !== i) parent[i] = find(parent[i]);
    return parent[i];
  };
  const firstByKey = new Map<string, number>();
  items.forEach((item, i) => keysOf(item).forEach((key) => {
    const first = firstByKey.get(key);
    if (first === undefined) firstByKey.set(key, i);
    else parent[find(i)] = find(first);
  }));
  const groups = new Map<number, T[]>();
  items.forEach((item, i) => {
    const group = groups.get(find(i));
    if (group) group.push(item);
    else groups.set(find(i), [item]);
  });
  return [...groups.values()];
};

// A merge found to change nothing on a version, recorded at the end of the chunk (see unchanged.ts)
interface UnchangedSeen { objectId: string; fingerprint: string; version: Version }

// ===============================================================================================================
// Entities
// ===============================================================================================================
interface PreparedEntity {
  i: number;
  type: string;
  input: Record<string, any>;
  resolvedInput: Record<string, any>;
  entitySetting: any;
  standardId: string;
  keys: string[]; // identity keys, lowercased
}
interface BuiltEntity extends PreparedEntity { element: Record<string, any>; metas: any[] }

// One input merged into an object: a known target, or (follow) wherever its group's first input ended up.
// reconcile: other copies of the object, merged into the target first, now (inline) or by the settler.
interface EntityMerge { item: PreparedEntity; target?: Owner; follow?: PreparedEntity; patch?: Record<string, any>; reconcile?: Owner[]; inline?: boolean }

type LostKey = Awaited<ReturnType<typeof claimKeys>>[number];

// 1. One input as createEntityRaw prepares it before its lock: confidence, access, refs, then the standard id and
// the identity keys that tell which object it is
const prepareEntity = async ({ context, user, finder }: Chunk, item: EntityItem, i: number): Promise<PreparedEntity | Fallback> => {
  const { type } = item;
  if (getDraftContext(context, user) || isNotEmpty(item.input.file) || isNotEmpty(item.input.files)) return { i, fallback: true };
  const input = await prepareInput(context, user, item.input, type);
  if (!validateUserAccessOperation(user, input, AccessOperation.EDIT, null)) throw ForbiddenAccess();
  if (input.restricted_members?.length > 0) {
    if (!validateUserAccessOperation(user, input, AccessOperation.MANAGE_ACCESS, null)) throw ForbiddenAccess();
    if (schemaAttributesDefinition.getAttribute(type, authorizedMembersActivationDate.name)) input.authorized_members_activation_date = now();
  }
  const entitySetting: any = await getEntitySettingFromCache(context, type);
  const resolvedInput = await inputResolveRefs(context, user, input, type, entitySetting, { finder });
  const standardId = resolvedInput.standard_id || generateStandardId(type, resolvedInput);
  // A hashed observable is always upserted, and known by the standard id of each of its hashes
  if (isStixCyberObservableHashedObservable(type)) {
    resolvedInput.update = true;
    if (resolvedInput.hashes) {
      const otherHashIds = generateHashedObservableStandardIds({ entity_type: type, ...resolvedInput }).filter((id: string) => id !== standardId);
      resolvedInput.x_opencti_stix_ids = R.uniq([...(resolvedInput.x_opencti_stix_ids ?? []), ...otherHashIds]);
    }
  }
  const keys = R.uniq(getInputIds(type, resolvedInput, undefined).map((key: string) => key.toLowerCase()));
  return { i, type, input, resolvedInput, entitySetting, standardId, keys };
};

// Today's choice of target among the existing objects matching an input (internalCreateEntityRaw)
const existingEntityTarget = async (
  context: AuthContext, user: AuthUser, item: PreparedEntity, existing: any[],
): Promise<EntityMerge & { target: Owner }> => {
  const filtered: any[] = await userFilterStoreElements(context, user, existing);
  if (filtered.length === 0) throw UnsupportedError('Restricted entity already exists', { doc_code: 'RESTRICTED_ELEMENT' });
  if (filtered.length === 1) return { item, target: ownerOf(filtered[0]), patch: item.resolvedInput };
  const { resolvedInput } = item;
  const existingByStandard = filtered.find((e) => e.standard_id === item.standardId);
  if (existingByStandard && !isStixCyberObservableHashedObservable(item.type)) {
    const reconcile: Owner[] = [];
    let target = existingByStandard;
    if (resolvedInput.stix_id) {
      const byStix = filtered.find((e) => e.standard_id === resolvedInput.stix_id || (e.x_opencti_stix_ids ?? []).includes(resolvedInput.stix_id));
      if (byStix && byStix.internal_id !== existingByStandard.internal_id) {
        const [mergeTarget, mergeSource] = byStix.confidence > existingByStandard.confidence ? [byStix, existingByStandard] : [existingByStandard, byStix];
        reconcile.push(ownerOf(mergeSource));
        target = mergeTarget;
      }
    }
    const others = filtered.filter((e) => e.standard_id !== item.standardId);
    return { item, target: ownerOf(target), patch: cleanEntityForIdsCollision(resolvedInput, item.type, existingByStandard, others), reconcile, inline: true };
  }
  if (resolvedInput.update === true) {
    const target = filtered.find((e) => e.standard_id === item.standardId) || filtered[0];
    const reconcile = filtered.filter((e) => e.internal_id !== target.internal_id).map(ownerOf);
    return { item, target: ownerOf(target), patch: resolvedInput, reconcile, inline: true };
  }
  let selected = filtered[0];
  if (resolvedInput.stix_id) selected = filtered.find((candidate) => getInstanceIds(candidate).includes(resolvedInput.stix_id)) ?? selected;
  return { item, target: ownerOf(selected), patch: cleanEntityForIdsCollision(resolvedInput, item.type, selected, filtered) };
};

interface EntityDecisions {
  toCreate: PreparedEntity[];
  merges: EntityMerge[];
  firstTarget: Map<number, Owner>; // where each group's first input ended up, by input position
}

// 2. Inputs sharing a key are one object: the first of each group decides create or merge, the others follow it
const decideEntities = async ({ context, user, results }: Chunk, work: PreparedEntity[]): Promise<EntityDecisions> => {
  const { owners } = await liveOwners(R.uniq(work.flatMap((item) => item.keys)));
  const decisions: EntityDecisions = { toCreate: [], merges: [], firstTarget: new Map() };
  const groups = groupByKeys(work, (item) => item.keys);
  const liveOf = (item: PreparedEntity) => R.uniqBy((owner: Owner) => owner.owner_id, item.keys.map((key) => owners.get(key)).filter((owner) => owner?.state === 'live') as Owner[]);
  // The existing objects of every group, read once for the chunk
  const candidates = await loadWithAccessFields(R.uniq(groups.flatMap(([first]) => liveOf(first).map((owner) => owner.owner_id))));
  const candidateById = new Map(candidates.map((element: any) => [element.internal_id, element]));
  for (const [first, ...followers] of groups) {
    const live = liveOf(first);
    try {
      if (live.length === 0) {
        decisions.toCreate.push(first);
      } else {
        const decision = await existingEntityTarget(context, user, first, live.map((owner) => candidateById.get(owner.owner_id)).filter(Boolean));
        decisions.merges.push(decision);
        decisions.firstTarget.set(first.i, decision.target);
      }
    } catch (e) {
      results[first.i] = errorResult(e);
    }
    followers.forEach((item) => decisions.merges.push({ item, follow: first }));
  }
  return decisions;
};

// 3. A new entity as createEntityRaw builds it: defaults, validation, document and meta relationships. Its id
// derives from its standard id, so that every writer gives the same object the same id.
const buildEntity = async (chunk: Chunk, item: PreparedEntity): Promise<BuiltEntity> => {
  const { context, user } = chunk;
  const resolvedInput = await completeNewInput(chunk, item);
  const internalId = deterministicId(item.standardId.toLowerCase());
  const data: any = await buildEntityData(context, user, { ...resolvedInput, internal_id: internalId }, item.type, {});
  await rewriteEmbeddedDataUriImagesInDescriptions(context, user, data.element, {
    entityType: item.type, entityId: internalId, entity: data.element, fileMarkings: (resolvedInput.objectMarking ?? []).map((marking: any) => marking.internal_id),
  });
  const metas = withMetaIds(data.relations ?? []);
  return { ...item, resolvedInput, element: denormalizeOnSource(data.element, metas), metas };
};

const sleep = (ms: number) => new Promise((resolve) => {
  setTimeout(resolve, ms);
});
const TAKE_OVER_AFTER_MS = 1000;
const GIVE_UP_AFTER_MS = 5000;
// An object that lost identity keys to other objects: wait for one of them to exist and point every key to it.
// If none appears (each lost a key to the other), the smallest id creates; past GIVE_UP_AFTER_MS (a writer that
// stopped between claiming and creating), create anyway and let the settler merge the other one later.
const resolveContested = async (entity: BuiltEntity, lostKeys: LostKey[]): Promise<{ target?: Owner; reconcile?: Owner[] }> => {
  const holders = R.sortBy((holder: Owner) => holder.owner_id, R.uniqBy((holder: Owner) => holder.owner_id, lostKeys.map((lost) => lost.holder)));
  const ownId = entity.element.internal_id;
  const allKeys = [...entity.keys, ownId];
  const started = Date.now();
  for (;;) {
    const found = await mgetRaw(holders.map((holder) => ({ id: holder.owner_id, index: holder.owner_index })), { light: true });
    const existing = holders.find((holder) => found.has(holder.owner_id));
    if (existing) {
      await setKeys(allKeys.map((key: string) => ({ key, owner: keyOwner(existing) })));
      return { target: existing };
    }
    const waited = Date.now() - started;
    const isSmallest = [ownId, ...holders.map((holder) => holder.owner_id)].sort()[0] === ownId;
    if ((isSmallest && waited > TAKE_OVER_AFTER_MS) || waited > GIVE_UP_AFTER_MS) {
      await setKeys(lostKeys.map((lost) => ({ key: lost.key, owner: keyOwner(ownerOf(entity.element)) })));
      return { reconcile: waited > GIVE_UP_AFTER_MS ? holders : [] };
    }
    await sleep(20);
  }
};

// Claim the keys before creating. An object that claims all its keys creates. One that lost a key to another
// writer's object is that object: it waits for it to exist and merges into it, so no reader ever sees two.
// When two objects each lost a key to the other, neither creates: after a second the smallest id takes over.
// Returns the entities to create; the others become merges.
const claimEntityKeys = async (built: BuiltEntity[], decisions: EntityDecisions, counters: Counters): Promise<BuiltEntity[]> => {
  const { merges, firstTarget } = decisions;
  const lost = await claimKeys(built.map((entity) => ({ keys: [...entity.keys, entity.element.internal_id], owner: keyOwner(ownerOf(entity.element)) })));
  add(counters, 'lost_key_races', lost.length);
  const lostByClaimant = R.groupBy((lostKey: LostKey) => lostKey.claimant, lost);
  const creators: BuiltEntity[] = [];
  await Promise.all(built.map(async (entity) => {
    const lostKeys = lostByClaimant[entity.element.internal_id] ?? [];
    if (lostKeys.length === 0) {
      creators.push(entity);
      firstTarget.set(entity.i, ownerOf(entity.element));
      return;
    }
    const contested = await resolveContested(entity, lostKeys);
    if (contested.target) {
      merges.push({ item: entity, target: contested.target, patch: entity.resolvedInput });
      firstTarget.set(entity.i, contested.target);
      return;
    }
    creators.push(entity);
    firstTarget.set(entity.i, ownerOf(entity.element));
    if ((contested.reconcile ?? []).length > 0) {
      merges.push({ item: entity, target: ownerOf(entity.element), patch: entity.resolvedInput, reconcile: contested.reconcile });
    }
  }));
  return creators;
};

// The new documents in bulk, then what createEntityRaw writes with them: meta relationships, their targets'
// denormalized refs (settler queue), container sharing and the creation events. A document already there under
// the same id is merged into instead.
const createEntities = async (
  { context, user, counters, opts }: Chunk, creators: BuiltEntity[], merges: EntityMerge[], bench: BenchTimer,
) => {
  const statuses = await bulkCreateDocs(await Promise.all(creators.map((entity) => prepareIndexingElement(entity.element))), opts);
  const created = creators.filter((_, k) => statuses[k] === 201);
  creators.filter((_, k) => statuses[k] === 409).forEach((entity) => merges.push({ item: entity, target: ownerOf(entity.element), patch: entity.resolvedInput }));
  bench.step('create.docs');
  const metaDocs = await Promise.all(created.flatMap((entity) => entity.metas).map((meta: any) => prepareIndexingElement(meta)));
  bench.step('create.metas_prepare');
  const metaStatuses = await bulkCreateDocs(metaDocs, opts);
  add(counters, 'meta_created', metaStatuses.filter((status: number) => status === 201).length);
  bench.step('create.metas');
  await enqueue(created.flatMap((entity) => metaTargetTasks(entity.metas, 'add')));
  bench.step('create.enqueue');
  await pool(created, 16, async (entity) => {
    await createContainerSharingTask(context, ACTION_TYPE_SHARE, entity.element, entity.metas);
  });
  bench.step('create.sharing');
  const createdElements = created.map((entity) => createdElementOf(entity.resolvedInput, entity.element));
  const events = await storeCreateEvents(context, user, created.map((entity, k) => ({ instance: createdElements[k] as any, message: generateCreateMessage(entity.element) })));
  add(counters, 'events_create', events.length);
  add(counters, 'entities_created', created.length);
  bench.step('create.events');
  return { created, createdElements };
};

// What createEntity does after the creation, for each object (independent of each other). The workflow
// configuration is read once per type for the chunk, not once per entity.
const afterEntityCreation = async ({ context, user, results }: Chunk, created: BuiltEntity[], createdElements: Record<string, any>[]) => {
  const workflowTypes = isFeatureEnabled(ENTITIES_WORKFLOW_FEATURE_FLAG) ? R.uniq(createdElements.map((element) => element.entity_type as string)) : [];
  const workflowConfigs = new Map(await Promise.all(workflowTypes.map(async (type) => [type, await resolveEntityWorkflowConfig(context, user, type)] as const)));
  await pool(created, 64, async (entity, k) => {
    const element = createdElements[k] as any;
    await triggerCreateEntityAutoEnrichment(context, user, element);
    const workflowConfig = workflowConfigs.get(element.entity_type);
    if (workflowConfig) await initializeEntityWorkflow(context, user, element, workflowConfig);
    results[entity.i] = { status: 'created', id: entity.element.internal_id };
  });
};

// createEntityRaw's retry: an insufficient confidence stops merging objects, then the input is upserted as is
const mergeEntityWithRetry = async (
  context: AuthContext, user: AuthUser, target: Owner, item: PreparedEntity, patch: Record<string, any>, counters: Counters, opts: WriteOptions, reads: ChunkReads,
  remember?: (version: Version) => void, // called with the version on which the patch changed nothing
): Promise<ItemResult> => {
  const upsert = async (attemptPatch: Record<string, any>): Promise<ItemResult> => {
    const preloaded = await reads.take(target.owner_id);
    const result: any = await upsertLockFree(context, user, { index: target.owner_index, id: target.owner_id }, item.type, attemptPatch, counters, opts, preloaded);
    if (result.status === 'missing') throw FunctionalError('Cant find element to resolve', { id: target.owner_id });
    if (result.status === 'merged') {
      reads.written(target.owner_id);
      add(counters, 'entities_merged');
      if (result.event) await triggerEntityUpdateAutoEnrichment(context, user, result.element);
      if (result.workflowStatusChanged && isFeatureEnabled(ENTITIES_WORKFLOW_FEATURE_FLAG)) {
        await syncWorkflowInstanceFromExternalWrite(context, user, result.element, result.element.x_opencti_workflow_id);
      }
      return { status: 'merged', id: target.owner_id };
    }
    add(counters, 'entities_unchanged');
    if (result.pure && attemptPatch === patch) remember?.(result.version);
    return { status: 'unchanged', id: target.owner_id };
  };
  try {
    return await upsert(patch);
  } catch (e: any) {
    if (item.input.update !== false && e?.extensions?.data?.doc_code === DOC_INSUFFICIENT_CONFIDENCE_LEVEL) return upsert({ ...patch, update: false });
    throw e;
  }
};

// The merges of a chunk with what they need, read once: grouped by target (one target in order, targets in
// parallel), the target documents, and which merges are known to change nothing on the version read
interface EntityMergePlan {
  groups: EntityMerge[][];
  targetOf: (merge: EntityMerge) => Owner | undefined;
  fingerprints: Map<EntityMerge, string | undefined>;
  reads: ChunkReads;
  isKnown: (merge: EntityMerge, target: Owner | undefined) => boolean;
}

const planEntityMerges = async ({ context, user }: Chunk, { merges, firstTarget }: EntityDecisions): Promise<EntityMergePlan> => {
  const targetOf = (merge: EntityMerge) => merge.target ?? (merge.follow ? firstTarget.get(merge.follow.i) : undefined);
  const groups = groupsOf(merges, (merge) => targetOf(merge)?.owner_id ?? `none-${merge.item.i}`);
  // A merge known to change nothing on the version read is answered without computing it (see unchanged.ts)
  const epoch = await chunkEpoch(context, user);
  const fingerprints = new Map(merges.filter((merge) => (merge.reconcile ?? []).length === 0 && targetOf(merge))
    .map((merge) => [merge, fingerprintOf(epoch, merge.item.type, merge.item.entitySetting, merge.patch ?? merge.item.resolvedInput)]));
  const reads = new ChunkReads();
  const fingerprinted = [...fingerprints].filter(([, fingerprint]) => fingerprint);
  const targets = merges.map(targetOf).filter((target): target is Owner => !!target).map((target) => ({ index: target.owner_index, id: target.owner_id }));
  const [known] = await Promise.all([
    readUnchanged(fingerprinted.map(([merge, fingerprint]) => ({ objectId: (targetOf(merge) as Owner).owner_id, fingerprint: fingerprint as string }))),
    reads.loadDocuments(R.uniqBy((target) => target.id, targets)),
  ]);
  const isKnown = (merge: EntityMerge, target: Owner | undefined) => !!target
    && isUnchangedOn(known, target.owner_id, fingerprints.get(merge), reads.version(target.owner_id));
  // Refs only for the targets some merge will actually compute
  await reads.loadRefs(groups.filter((group) => !group.every((merge) => isKnown(merge, targetOf(merge))))
    .map((group) => targetOf(group[0])?.owner_id).filter((id): id is string => !!id));
  return { groups, targetOf, fingerprints, reads, isKnown };
};

// 4. One merge. Where today merges matching objects during the create, merge them first, before the upsert, as today.
const mergeEntity = async (chunk: Chunk, plan: EntityMergePlan, merge: EntityMerge, unchangedSeen: UnchangedSeen[]) => {
  const { context, user, counters, opts, results } = chunk;
  const { item } = merge;
  const target = plan.targetOf(merge);
  try {
    if (!target) throw FunctionalError('No object to merge into');
    const reconcile = merge.reconcile ?? [];
    if (reconcile.length > 0) {
      plan.reads.written(target.owner_id);
      if (merge.inline) add(counters, 'entities_reconciled', await reconcileEntities(reconcile, target, { context, user }));
      else await enqueue(reconcile.map((loser) => ({ kind: 'reconcile', loser, winner: target } as Task)));
    }
    if (plan.isKnown(merge, target)) {
      add(counters, 'entities_unchanged');
      add(counters, 'unchanged_known');
      results[item.i] = { status: 'unchanged', id: target.owner_id };
      return;
    }
    const fingerprint = plan.fingerprints.get(merge);
    const remember = fingerprint ? (version: Version) => unchangedSeen.push({ objectId: target.owner_id, fingerprint, version }) : undefined;
    const merged = await mergeEntityWithRetry(context, user, target, item, merge.patch ?? item.resolvedInput, counters, opts, plan.reads, remember);
    // A merge that only reconciles copies into an object created by this chunk keeps its 'created' result
    if (reconcile.length === 0 || results[item.i] === undefined) results[item.i] = merged;
  } catch (e) {
    results[item.i] = errorResult(e);
  }
};

export const writeEntityChunk = async (
  context: AuthContext, user: AuthUser, items: EntityItem[], counters: Counters, opts: WriteOptions = {},
): Promise<ItemResult[]> => {
  const bench = benchTimer('lf_entity');
  const results: ItemResult[] = new Array(items.length);
  const chunk: Chunk = { context, user, finder: chunkFinder(context, user), counters, opts, results };
  await chunk.finder(R.uniq(items.flatMap((item) => refInputIds(item.type, item.input))));
  bench.step('prefetch');
  // 1. Prepare and resolve, as today before the lock
  const prepared = await settleAll(items, (_, i) => i, (item, i) => prepareEntity(chunk, item, i), results);
  const { fallbacks, work } = splitFallbacks<PreparedEntity>(prepared);
  await writeFallbacks(chunk, fallbacks, (i) => createEntity(todayContext(context), user, items[i].input, items[i].type));
  bench.step('prepare');
  // 2. Decide create or merge
  const decisions = await decideEntities(chunk, work);
  bench.step('decide');
  // 3. New objects: build, claim keys, create
  const built = await settleAll(decisions.toCreate, (item) => item.i, (item) => buildEntity(chunk, item), results);
  bench.step('build');
  const creators = await claimEntityKeys(built, decisions, counters);
  bench.step('claim');
  const { created, createdElements } = await createEntities(chunk, creators, decisions.merges, bench);
  await afterEntityCreation(chunk, created, createdElements);
  bench.step('after_create');
  // 4. Merges, after the creations they may target: in order for one target, targets in parallel
  const plan = await planEntityMerges(chunk, decisions);
  bench.step('merges.read');
  const unchangedSeen: UnchangedSeen[] = [];
  await pool(plan.groups, 16, async (group) => {
    for (const merge of group) await mergeEntity(chunk, plan, merge, unchangedSeen);
  });
  bench.step('merges');
  await recordUnchanged(unchangedSeen);
  bench.step('merges.remember');
  bench.total();
  return results;
};

// ===============================================================================================================
// Relationships (core relationships and sightings)
// ===============================================================================================================
interface PreparedRelation {
  i: number;
  type: string;
  input: Record<string, any>;
  resolvedInput: Record<string, any>;
  entitySetting: any;
  pair: string;
  element?: Record<string, any>; // set once built, for the later inputs of the chunk that duplicate it
}
interface BuiltRelation extends PreparedRelation { element: Record<string, any>; metas: any[] }

// One input merged into a relationship: an existing one (target), or one an earlier input of the chunk creates (follow)
interface RelationMerge { item: PreparedRelation; target?: DocRef; follow?: PreparedRelation }

// A candidate duplicate on a pair: a stored relationship, or an input of this chunk about to be created
type PairCandidate = PairEntry & { creating?: PreparedRelation };

type PendingItem = Parameters<typeof addPending>[0][number];

const iso = (value: any) => (value ? new Date(value).toISOString() : undefined);
const timeKey = (input: Record<string, any>) => ['start_time', 'stop_time', 'first_seen', 'last_seen'].map((field) => iso(input[field]) ?? '-').join('|');
const relationInternalId = (type: string, fromId: string, toId: string, input: Record<string, any>) => deterministicId(`${type}|${fromId}|${toId}|${timeKey(input)}`);

const selfReferencingError = (data: Record<string, any>) => UnsupportedError('Relation cant be created with the same source and target', { ...data, doc_code: 'SELF_REFERENCING_RELATION' });

// When an input's refs do not resolve because one of its ends has not arrived yet, those ends; the error is
// rethrown when it is about anything else, when an end was deleted, or when the caller refuses missing ends.
const missingEndsOf = async ({ counters, opts }: Chunk, error: any, input: Record<string, any>) => {
  const unresolved: string[] = error?.extensions?.data?.unresolvedIds ?? [];
  const missingEnds = unresolved.filter((id) => id === input.fromId || id === input.toId);
  if (missingEnds.length === 0) throw error;
  const { owners } = await liveOwners(missingEnds);
  if (missingEnds.some((id) => owners.get(id.toLowerCase())?.state === 'deleted')) {
    add(counters, 'rejected_deleted_ref');
    throw error;
  }
  if (opts.missingEnds === 'error') throw error;
  return missingEnds;
};

// 1. One input as createRelationRaw prepares, resolves and checks it before its lock. An input whose end has not
// arrived waits in pendingItems, invisible, instead of being refused and sent again (null: no further phase).
const prepareRelation = async (
  chunk: Chunk, raw: Record<string, any>, i: number, pendingItems: PendingItem[],
): Promise<PreparedRelation | Fallback | null> => {
  const { context, user, finder, results } = chunk;
  const type = raw.relationship_type;
  if (getDraftContext(context, user) || isStixRefRelationship(type)) return { i, fallback: true };
  const input = await prepareInput(context, user, structuredClone(raw), type);
  if (input.fromId === input.toId) throw selfReferencingError({ from: input.fromId, relationshipType: type });
  const entitySetting: any = await getEntitySettingFromCache(context, type);
  let resolvedInput: any;
  try {
    resolvedInput = await inputResolveRefs(context, user, input, type, entitySetting, { finder });
  } catch (e: any) {
    const missing = await missingEndsOf(chunk, e, input);
    pendingItems.push({ input: raw, missing, user_id: user.internal_id });
    results[i] = { status: 'pending' };
    return null;
  }
  const { from, to } = resolvedInput;
  if (!validateUserAccessOperation(user, from, AccessOperation.EDIT, null) || !validateUserAccessOperation(user, to, AccessOperation.EDIT, null)) throw ForbiddenAccess();
  await checkRelationConsistency(context, user, type, from, to);
  if (from.internal_id === to.internal_id) throw selfReferencingError({ from: input.fromId, to: input.toId, relationshipType: type });
  if (isSingleRelationsRef(from.entity_type, type)) return { i, fallback: true };
  return { i, type, input, resolvedInput, entitySetting, pair: pairKey(type, from.internal_id, to.internal_id) };
};

// 2. Match each input against its pair's relationships, and against earlier inputs of the chunk on that pair:
// the first of duplicates creates, the others merge into it
const decideRelations = async (work: PreparedRelation[]) => {
  const pairs = await withoutDeleted(await readPairs(work.map((item) => item.pair)));
  const toCreate: PreparedRelation[] = [];
  const merges: RelationMerge[] = [];
  for (const [pair, group] of Object.entries(R.groupBy((item: PreparedRelation) => item.pair, work))) {
    const candidates: PairCandidate[] = [...(pairs.get(pair) ?? [])];
    for (const item of group ?? []) {
      const duplicates = findDuplicates(item.resolvedInput, candidates);
      if (duplicates.length > 0) {
        const first = duplicates[0] as PairCandidate;
        merges.push(first.creating ? { item, follow: first.creating } : { item, target: { id: first.id, index: first.index } });
        continue;
      }
      const probe = pairEntryOf({ ...item.resolvedInput, internal_id: '', _index: '', standard_id: '' }, item.resolvedInput.createdBy?.internal_id);
      candidates.push({ ...probe, ids: [], creating: item });
      toCreate.push(item);
    }
  }
  return { toCreate, merges };
};

// 3. A new relationship as createRelationRaw builds it, with an id from its type, ends and time (the same for
// every writer). The element is kept on the prepared input too: the inputs that follow it merge into it.
const buildRelation = async (chunk: Chunk, item: PreparedRelation): Promise<BuiltRelation> => {
  const { context, user } = chunk;
  const resolvedInput = await completeNewInput(chunk, item);
  const { from, to } = resolvedInput;
  const internalId = relationInternalId(item.type, from.internal_id, to.internal_id, resolvedInput);
  const data: any = await buildRelationData(context, user, { ...resolvedInput, internal_id: internalId }, {});
  const metas = withMetaIds(data.relations ?? []);
  item.element = denormalizeOnSource(data.element, metas);
  return { ...item, resolvedInput, element: item.element, metas };
};

// A relationship created at the same time by another writer and recorded earlier in the pair makes this one the
// duplicate: the settler merges it into the earlier one
const raceReconcileTasks = (created: BuiltRelation[], pairsAfter: Map<string, PairEntry[]>): Task[] => created.flatMap((relation) => {
  const entries = pairsAfter.get(relation.pair) ?? [];
  const position = entries.findIndex((entry) => entry.id === relation.element.internal_id);
  // (its standard id is known now: not generated again)
  const earlier = findDuplicates({ ...relation.resolvedInput, standard_id: relation.element.standard_id }, entries.slice(0, Math.max(0, position)));
  if (earlier.length === 0) return [];
  const keep = { id: earlier[0].id, index: earlier[0].index };
  const drop = { id: relation.element.internal_id, index: relation.element._index };
  return [{ kind: 'relation-reconcile', keep, drop, pair: relation.pair }];
});

// The relationship's id denormalized on the ends that carry it, as elIndexElements' impacts write today
const endpointTasksOf = (relation: BuiltRelation): Task[] => {
  const { from, to } = relation.resolvedInput;
  const base = { kind: 'endpoint' as const, op: 'add' as const, relation_type: relation.type, relation: relation.element.internal_id, relation_index: relation.element._index };
  const tasks: Task[] = [];
  if (isImpactedTypeAndSide(relation.type, from.entity_type, to.entity_type, ROLE_FROM)) {
    tasks.push({ ...base, endpoint: from.internal_id, index: from._index, type: from.entity_type, other: to.internal_id, side: 'from' });
  }
  if (isImpactedTypeAndSide(relation.type, from.entity_type, to.entity_type, ROLE_TO)) {
    tasks.push({ ...base, endpoint: to.internal_id, index: to._index, type: to.entity_type, other: from.internal_id, side: 'to' });
  }
  return tasks;
};

// The new documents in bulk, then their keys, pair entries and meta relationships, the follow-up work for the
// settler and the creation events. A document already there under the same id is merged into instead.
const createRelations = async ({ context, user, counters, opts }: Chunk, built: BuiltRelation[], merges: RelationMerge[], bench: BenchTimer) => {
  const statuses = await bulkCreateDocs(await Promise.all(built.map((relation) => prepareIndexingElement(relation.element))), opts);
  const created = built.filter((_, k) => statuses[k] === 201);
  built.filter((_, k) => statuses[k] === 409).forEach((relation) => merges.push({ item: relation, target: { id: relation.element.internal_id, index: relation.element._index } }));
  bench.step('create.docs');
  // Once the relationships exist, their keys, their pair entries and their meta relationships do not depend on each
  // other: written at once
  const keysOf = (relation: BuiltRelation): string[] => [relation.element.internal_id, relation.element.standard_id, ...(relation.element.x_opencti_stix_ids ?? [])];
  const [, pairsAfter, metaStatuses] = await Promise.all([
    setKeys(created.flatMap((relation) => keysOf(relation).map((key) => ({ key: key.toLowerCase(), owner: keyOwner(ownerOf(relation.element)) })))),
    appendPairs(created.map((relation) => ({ key: relation.pair, entry: pairEntryOf(relation.element, relation.resolvedInput.createdBy?.internal_id) }))),
    Promise.all(created.flatMap((relation) => relation.metas).map((meta: any) => prepareIndexingElement(meta))).then((docs) => bulkCreateDocs(docs, opts)),
  ]);
  add(counters, 'meta_created', metaStatuses.filter((status: number) => status === 201).length);
  bench.step('create.keys_pairs_metas');
  const reconcileTasks = raceReconcileTasks(created, pairsAfter);
  const endpointTasks = created.flatMap(endpointTasksOf);
  await enqueue([...endpointTasks, ...created.flatMap((relation) => metaTargetTasks(relation.metas, 'add')), ...reconcileTasks]);
  add(counters, 'relation_races', reconcileTasks.length);
  bench.step('create.enqueue');
  const events = await storeCreateEvents(context, user, created.map((relation) => ({ instance: { ...relation.resolvedInput, ...relation.element } as any })));
  add(counters, 'events_create', events.length);
  add(counters, 'relations_created', created.length);
  bench.step('create.events');
  return created;
};

// createRelationRaw's security coverage hook: a covered entity that now targets a vulnerability or uses an attack
// pattern has its coverage modified, and enriched again
const touchSecurityCoverages = async ({ context, user }: Chunk, created: BuiltRelation[]) => {
  for (const relation of created.filter((candidate) => candidate.resolvedInput.from?.[RELATION_COVERED])) {
    const { from, to } = relation.resolvedInput;
    const isVuln = relation.type === 'targets' && to.entity_type === 'Vulnerability';
    const isAttackPattern = relation.type === 'uses' && to.entity_type === 'Attack-Pattern';
    if (isVuln || isAttackPattern) {
      const { element: coverage } = await updateAttribute(context, user, from[RELATION_COVERED], ENTITY_TYPE_SECURITY_COVERAGE, [{ key: 'modified', value: [now()] }], { noEnrich: true });
      await triggerEntityUpdateAutoEnrichment(context, user, coverage as any);
    }
  }
};

const relationTargetOf = (merge: RelationMerge): DocRef | undefined => {
  if (merge.target) return merge.target;
  const element = merge.follow?.element;
  return element ? { id: element.internal_id, index: element._index ?? inferIndexFromConceptType(merge.item.type) } : undefined;
};

// The merges of a chunk with what they need, read once: grouped by target (one target in order, targets in
// parallel), the target documents, and which merges are known to change nothing on the version read
interface RelationMergePlan {
  groups: RelationMerge[][];
  fingerprints: Map<RelationMerge, string | undefined>;
  reads: ChunkReads;
  isKnown: (merge: RelationMerge, target: DocRef) => boolean;
}

const planRelationMerges = async ({ context, user }: Chunk, merges: RelationMerge[]): Promise<RelationMergePlan> => {
  const groups = groupsOf(merges, (merge) => relationTargetOf(merge)?.id ?? `none-${merge.item.i}`);
  const epoch = await chunkEpoch(context, user);
  const fingerprints = new Map(merges.map((merge) => [merge, fingerprintOf(epoch, merge.item.type, merge.item.entitySetting, merge.item.resolvedInput)]));
  const reads = new ChunkReads();
  const fingerprinted = merges.filter((merge) => relationTargetOf(merge) && fingerprints.get(merge));
  const targets = merges.map(relationTargetOf).filter((target): target is DocRef => !!target);
  const [known] = await Promise.all([
    readUnchanged(fingerprinted.map((merge) => ({ objectId: (relationTargetOf(merge) as DocRef).id, fingerprint: fingerprints.get(merge) as string }))),
    reads.loadDocuments(R.uniqBy((target) => target.id, targets)),
  ]);
  const isKnown = (merge: RelationMerge, target: DocRef) => reads.isLive(target.id) && isUnchangedOn(known, target.id, fingerprints.get(merge), reads.version(target.id));
  const isKnownMerge = (merge: RelationMerge) => {
    const target = relationTargetOf(merge);
    return !!target && isKnown(merge, target);
  };
  // Refs only for the targets some merge will actually compute
  await reads.loadRefs(groups.filter((group) => !group.every(isKnownMerge))
    .map((group) => relationTargetOf(group[0])?.id).filter((id): id is string => !!id));
  return { groups, fingerprints, reads, isKnown };
};

// 4. One merge, refused as today when the user cannot see the relationship
const mergeRelation = async (chunk: Chunk, plan: RelationMergePlan, merge: RelationMerge, unchangedSeen: UnchangedSeen[]) => {
  const { context, user, counters, opts, results } = chunk;
  const { item } = merge;
  const { reads } = plan;
  try {
    const target = relationTargetOf(merge);
    if (!target) throw FunctionalError('No relationship to merge into');
    if (plan.isKnown(merge, target)) {
      add(counters, 'relations_unchanged');
      add(counters, 'unchanged_known');
      results[item.i] = { status: 'unchanged', id: target.id };
      return;
    }
    const read = await reads.take(target.id);
    let existing: any[];
    if (read) existing = reads.isLive(target.id) ? [read.element] : [];
    else existing = await loadWithAccessFields([target.id]);
    if ((await userFilterStoreElements(context, user, existing)).length === 0) throw UnsupportedError('Restricted relation already exists');
    const result: any = await upsertLockFree(context, user, target, item.type, item.resolvedInput, counters, opts, read);
    if (result.status === 'missing') throw FunctionalError('Cant find element to resolve', { id: target.id });
    if (result.status === 'merged') reads.written(target.id);
    const fingerprint = plan.fingerprints.get(merge);
    if (result.status === 'unchanged' && result.pure && fingerprint) unchangedSeen.push({ objectId: target.id, fingerprint, version: result.version });
    add(counters, result.status === 'merged' ? 'relations_merged' : 'relations_unchanged');
    results[item.i] = { status: result.status, id: target.id };
  } catch (e) {
    results[item.i] = errorResult(e);
  }
};

export const writeRelationChunk = async (
  context: AuthContext, user: AuthUser, rawInputs: Record<string, any>[], counters: Counters, opts: WriteOptions = {},
): Promise<ItemResult[]> => {
  const bench = benchTimer('lf_relation');
  const results: ItemResult[] = new Array(rawInputs.length);
  const chunk: Chunk = { context, user, finder: chunkFinder(context, user), counters, opts, results };
  await chunk.finder(R.uniq(rawInputs.flatMap((input) => refInputIds(input.relationship_type, input))));
  bench.step('prefetch');
  // 1. Prepare, resolve and check, as createRelationRaw does before its lock
  const pendingItems: PendingItem[] = [];
  const prepared = await settleAll(rawInputs, (_, i) => i, (raw, i) => prepareRelation(chunk, raw, i, pendingItems), results);
  await addPending(pendingItems);
  add(counters, 'pending_added', pendingItems.length);
  const { fallbacks, work } = splitFallbacks<PreparedRelation>(prepared);
  await writeFallbacks(chunk, fallbacks, (i) => createRelation(todayContext(context), user, rawInputs[i]));
  bench.step('prepare');
  // 2. Decide create or merge
  const { toCreate, merges } = await decideRelations(work);
  bench.step('decide');
  // 3. New relationships: build, create in bulk
  const built = await settleAll(toCreate, (item) => item.i, (item) => buildRelation(chunk, item), results);
  bench.step('build');
  const created = await createRelations(chunk, built, merges, bench);
  created.forEach((relation) => {
    results[relation.i] = { status: 'created', id: relation.element.internal_id };
  });
  await touchSecurityCoverages(chunk, created);
  // 4. Merges into existing relationships, and into ones created above: in order per target, targets in parallel
  const plan = await planRelationMerges(chunk, merges);
  bench.step('merges.read');
  const unchangedSeen: UnchangedSeen[] = [];
  await pool(plan.groups, 16, async (group) => {
    for (const merge of group) await mergeRelation(chunk, plan, merge, unchangedSeen);
  });
  bench.step('merges');
  await recordUnchanged(unchangedSeen);
  bench.step('merges.remember');
  bench.total();
  return results;
};
