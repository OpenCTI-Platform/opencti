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
import { liveOwners, mgetRaw, toElements } from './load';
import { addPending } from './pending';
import { pool } from './context';
import { benchTimer } from '../../utils/bench-timing';
import { reconcileEntities } from './reconcile';
import { appendPairs, findDuplicates, pairEntryOf, type PairEntry, pairKey, readPairs, withoutDeleted } from './pairs';
import { enqueue, type Task } from './queue';
import { add, type Counters } from './store';
import { bulkCreateDocs, metaTargetTasks, upsertLockFree, withMetaIds, type WriteOptions } from './upsert';

export interface EntityItem { type: string; input: Record<string, any> }
export interface ItemResult {
  status: 'created' | 'merged' | 'unchanged' | 'pending' | 'fallback' | 'error';
  id?: string;
  error?: string;
  cause?: unknown; // the error itself, for a caller that rethrows it
}

// Today's path, called for what the lock-free path leaves to it: marked so the platform does not send it back here
export const todayContext = (context: AuthContext): AuthContext => ({ ...context, lockfree_bypass: true, lockfree_write: false } as AuthContext);

// Fields the access rules and hooks read, fetched beside otherwise light documents (no rel_* lists)
const ACCESS_FIELDS = ['rel_object-marking.*', 'rel_granted-to.*', `rel_${RELATION_COVERED}.*`, 'restricted_members', 'authorized_authorities'];

const mgetAccess = async (refs: { index: string; id: string }[]) => {
  const out = new Map<string, any>();
  for (const slice of R.splitEvery(1000, refs)) {
    const response: any = await elRawMget({ docs: slice.map((r) => ({ _index: r.index, _id: r.id, _source: { includes: ACCESS_FIELDS } })) });
    response.docs.filter((d: any) => d.found).forEach((d: any) => out.set(d._id, d));
  }
  return out;
};

const loadWithAccessFields = async (ids: string[]) => {
  const { live } = await liveOwners(ids);
  const refs = live.map((o) => ({ index: o.owner_index, id: o.owner_id }));
  if (refs.length === 0) return [];
  const [light, access] = await Promise.all([mgetRaw(refs, { light: true }), mgetAccess(refs)]);
  return toElements([...light.values()].map((raw) => ({ ...raw, _source: { ...raw._source, ...(access.get(raw._id)?._source ?? {}) } })));
};

// The finder handed to inputResolveRefs: reads by id, remembers what it read for the chunk, filters by the user's access
const chunkFinder = (context: AuthContext, user: AuthUser) => {
  const cache = new Map<string, any | null>();
  return async (ids: string[]) => {
    const missing = R.uniq(ids.filter((id) => id && !cache.has(id.toLowerCase())));
    if (missing.length > 0) {
      const loaded = await loadWithAccessFields(missing);
      missing.forEach((id) => cache.set(id.toLowerCase(), null));
      loaded.forEach((element) => getInstanceIds(element).forEach((id: string) => cache.set(id.toLowerCase(), element)));
    }
    const elements = R.uniqBy((e: any) => e.internal_id, ids.map((id) => cache.get(id?.toLowerCase())).filter(Boolean));
    return userFilterStoreElements(context, user, elements) as Promise<any[]>;
  };
};

const refInputIds = (type: string, input: Record<string, any>) => {
  const fields = schemaRelationsRefDefinition.getRelationsRef(type).map((r) => r.name);
  return [input.fromId, input.toId, ...fields.flatMap((f) => [].concat(input[f] ?? []))].filter((v) => typeof v === 'string');
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

const isNotEmpty = (v: any) => v !== undefined && v !== null && !(Array.isArray(v) && v.length === 0);

// Denormalized ref ids on the source of its meta relationships (what elIndexElements' impacts write today)
const denormalizeOnSource = (source: Record<string, any>, metas: any[]) => {
  const out = { ...source };
  metas.forEach((meta) => {
    if (isImpactedTypeAndSide(meta.entity_type, source.entity_type, meta.to.entity_type, ROLE_FROM)) {
      const field = buildRefRelationKey(meta.entity_type);
      out[field] = R.uniq([...(out[field] ?? []), meta.to.internal_id]);
    }
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

const errorResult = (e: any): ItemResult => ({ status: 'error', error: e?.extensions?.data?.doc_code ?? e?.extensions?.code ?? e?.message ?? String(e), cause: e });

const groupByKeys = <T>(items: T[], keysOf: (item: T) => string[]) => {
  const parent = items.map((_, i) => i);
  const find = (i: number): number => {
    if (parent[i] !== i) parent[i] = find(parent[i]);
    return parent[i];
  };
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

// ===============================================================================================================
// Entities
// ===============================================================================================================
interface Merge { w: any; target?: Owner; follow?: any; patch?: Record<string, any>; reconcile?: Owner[]; inline?: boolean }

export const writeEntityChunk = async (
  context: AuthContext, user: AuthUser, items: EntityItem[], counters: Counters, opts: WriteOptions = {},
): Promise<ItemResult[]> => {
  const bench = benchTimer('lf_entity');
  const results: ItemResult[] = new Array(items.length);
  const finder = chunkFinder(context, user);
  await finder(R.uniq(items.flatMap((item) => refInputIds(item.type, item.input))));
  bench.step('prefetch');
  // 1. Prepare and resolve, as today before the lock
  const prepared = (await Promise.all(items.map(async (item, i) => {
    try {
      if (getDraftContext(context, user) || isNotEmpty(item.input.file) || isNotEmpty(item.input.files)) return { i, fallback: true };
      const input = await prepareInput(context, user, item.input, item.type);
      if (!validateUserAccessOperation(user, input, AccessOperation.EDIT, null)) throw ForbiddenAccess();
      if (input.restricted_members?.length > 0) {
        if (!validateUserAccessOperation(user, input, AccessOperation.MANAGE_ACCESS, null)) throw ForbiddenAccess();
        if (schemaAttributesDefinition.getAttribute(item.type, authorizedMembersActivationDate.name)) input.authorized_members_activation_date = now();
      }
      const entitySetting: any = await getEntitySettingFromCache(context, item.type);
      const resolvedInput = await inputResolveRefs(context, user, input, item.type, entitySetting, { finder });
      const standardId = resolvedInput.standard_id || generateStandardId(item.type, resolvedInput);
      if (isStixCyberObservableHashedObservable(item.type)) {
        resolvedInput.update = true;
        if (resolvedInput.hashes) {
          const others = generateHashedObservableStandardIds({ entity_type: item.type, ...resolvedInput }).filter((id: string) => id !== standardId);
          resolvedInput.x_opencti_stix_ids = R.uniq([...(resolvedInput.x_opencti_stix_ids ?? []), ...others]);
        }
      }
      const keys = R.uniq(getInputIds(item.type, resolvedInput, undefined).map((k: string) => k.toLowerCase()));
      return { i, type: item.type, input, resolvedInput, entitySetting, standardId, keys };
    } catch (e) {
      results[i] = errorResult(e);
      return null;
    }
  }))).filter(Boolean) as any[];
  for (const p of prepared.filter((v) => v.fallback)) {
    try {
      const element: any = await createEntity(todayContext(context), user, items[p.i].input, items[p.i].type);
      results[p.i] = { status: 'fallback', id: element.internal_id };
      add(counters, 'fallbacks');
    } catch (e) {
      results[p.i] = errorResult(e);
    }
  }
  const work = prepared.filter((v) => !v.fallback);
  bench.step('prepare');
  // 2. Inputs sharing a key are one object: the first decides, the others follow it
  const { owners } = await liveOwners(R.uniq(work.flatMap((w) => w.keys)));
  const toCreate: any[] = [];
  const merges: Merge[] = [];
  const firstTarget = new Map<number, Owner>(); // where each group's first input ended up
  for (const group of groupByKeys(work, (w) => w.keys)) {
    const [first, ...rest] = group;
    const live = R.uniqBy((o: Owner) => o.owner_id, first.keys.map((k: string) => owners.get(k)).filter((o: any) => o?.state === 'live')) as Owner[];
    try {
      if (live.length === 0) toCreate.push(first);
      else {
        const decision = await existingEntityTarget(context, user, first, live);
        merges.push(decision);
        firstTarget.set(first.i, decision.target as Owner);
      }
    } catch (e) {
      results[first.i] = errorResult(e);
    }
    rest.forEach((w: any) => merges.push({ w, follow: first }));
  }
  bench.step('decide');
  // 3. New objects: defaults and validation as today, build, claim keys, create
  const built = (await Promise.all(toCreate.map(async (w) => {
    try {
      let resolvedInput = fillDefaultValues(user, w.resolvedInput, w.entitySetting);
      resolvedInput = await inputResolveRefs(context, user, resolvedInput, w.type, w.entitySetting, { finder });
      resolvedInput = await fillDefaultCustomFieldValues(context, user, resolvedInput, w.entitySetting);
      await validateEntityAndRelationCreation(context, user, resolvedInput, w.type, w.entitySetting, {});
      const internalId = deterministicId(w.standardId.toLowerCase());
      const data: any = await buildEntityData(context, user, { ...resolvedInput, internal_id: internalId }, w.type, {});
      await rewriteEmbeddedDataUriImagesInDescriptions(context, user, data.element, {
        entityType: w.type, entityId: internalId, entity: data.element, fileMarkings: (resolvedInput.objectMarking ?? []).map((m: any) => m.internal_id),
      });
      const metas = withMetaIds(data.relations ?? []);
      return { ...w, resolvedInput, element: denormalizeOnSource(data.element, metas), metas };
    } catch (e) {
      results[w.i] = errorResult(e);
      return null;
    }
  }))).filter(Boolean) as any[];
  bench.step('build');
  // Claim the keys before creating. An object that claims all its keys creates. One that lost a key to another
  // writer's object is that object: it waits for it to exist and merges into it, so no reader ever sees two.
  // When two objects each lost a key to the other, neither creates: after a second the smallest id takes over.
  const lost = await claimKeys(built.map((b) => ({ keys: [...b.keys, b.element.internal_id], owner: R.omit(['key', 'state'], ownerOf(b.element)) })));
  add(counters, 'lost_key_races', lost.length);
  const lostByClaimant = R.groupBy((l: any) => l.claimant, lost);
  const creators: any[] = [];
  await Promise.all(built.map(async (b) => {
    const mine = lostByClaimant[b.element.internal_id] ?? [];
    if (mine.length === 0) {
      creators.push(b);
      firstTarget.set(b.i, ownerOf(b.element));
      return;
    }
    const decision = await resolveContested(b, mine);
    if (decision.target) {
      merges.push({ w: b, target: decision.target, patch: b.resolvedInput });
      firstTarget.set(b.i, decision.target);
    } else {
      creators.push(b);
      firstTarget.set(b.i, ownerOf(b.element));
      if ((decision.reconcile ?? []).length > 0) merges.push({ w: b, target: ownerOf(b.element), patch: b.resolvedInput, reconcile: decision.reconcile });
    }
  }));
  bench.step('claim');
  const statuses = await bulkCreateDocs(await Promise.all(creators.map((c) => prepareIndexingElement(c.element))), opts);
  const created = creators.filter((_, k) => statuses[k] === 201);
  creators.filter((_, k) => statuses[k] === 409).forEach((c) => merges.push({ w: c, target: ownerOf(c.element), patch: c.resolvedInput }));
  bench.step('create.docs');
  const entityMetaDocs = await Promise.all(created.flatMap((c) => c.metas).map((m: any) => prepareIndexingElement(m)));
  bench.step('create.metas_prepare');
  const metaStatuses = await bulkCreateDocs(entityMetaDocs, opts);
  add(counters, 'meta_created', metaStatuses.filter((s: number) => s === 201).length);
  bench.step('create.metas');
  await enqueue(created.flatMap((c) => metaTargetTasks(c.metas, 'add')));
  bench.step('create.enqueue');
  await pool(created, 16, async (c) => {
    await createContainerSharingTask(context, ACTION_TYPE_SHARE, c.element, c.metas);
  });
  bench.step('create.sharing');
  const createdElements = created.map((c) => createdElementOf(c.resolvedInput, c.element));
  const events = await storeCreateEvents(context, user, created.map((c, k) => ({ instance: createdElements[k] as any, message: generateCreateMessage(c.element) })));
  add(counters, 'events_create', events.length);
  add(counters, 'entities_created', created.length);
  bench.step('create.events');
  // What createEntity does after the creation, for each object (independent of each other). The workflow
  // configuration is read once per type for the chunk, not once per entity.
  const workflowTypes = isFeatureEnabled(ENTITIES_WORKFLOW_FEATURE_FLAG) ? R.uniq(createdElements.map((e: any) => e.entity_type as string)) : [];
  const workflowConfigs = new Map(await Promise.all(workflowTypes.map(async (t) => [t, await resolveEntityWorkflowConfig(context, user, t)] as const)));
  await pool(created.map((_, k) => k), 64, async (k) => {
    await triggerCreateEntityAutoEnrichment(context, user, createdElements[k] as any);
    const workflowConfig = workflowConfigs.get((createdElements[k] as any).entity_type);
    if (workflowConfig) await initializeEntityWorkflow(context, user, createdElements[k] as any, workflowConfig);
    results[created[k].i] = { status: 'created', id: created[k].element.internal_id };
  });
  bench.step('after_create');
  // 4. Merges, after the creations they may target: in order for one target, targets in parallel
  const mergeGroups = Object.values(R.groupBy((m: Merge) => (m.target ?? firstTarget.get(m.follow?.i))?.owner_id ?? `none-${m.w.i}`, merges));
  await pool(mergeGroups, 16, async (group) => {
    for (const m of group ?? []) {
      const target = m.target ?? firstTarget.get(m.follow?.i);
      try {
        if (!target) throw FunctionalError('No object to merge into');
        // Where today merges matching objects during the create, merge them now, before the upsert, as today
        if ((m.reconcile ?? []).length > 0) {
          if (m.inline) add(counters, 'entities_reconciled', await reconcileEntities(m.reconcile ?? [], target, { context, user }));
          else await enqueue((m.reconcile ?? []).map((loser) => ({ kind: 'reconcile', loser, winner: target } as Task)));
        }
        const merged = await mergeEntityWithRetry(context, user, target, m.w, m.patch ?? m.w.resolvedInput, counters, opts);
        if (!(m.reconcile ?? []).length || results[m.w.i] === undefined) results[m.w.i] = merged;
      } catch (e) {
        results[m.w.i] = errorResult(e);
      }
    }
  });
  bench.step('merges');
  bench.total();
  return results;
};

const sleep = (ms: number) => new Promise((resolve) => {
  setTimeout(resolve, ms);
});
const TAKE_OVER_AFTER_MS = 1000;
const GIVE_UP_AFTER_MS = 5000;
// An object that lost identity keys to other objects: wait for one of them to exist and point every key to it.
// If none appears (each lost a key to the other), the smallest id creates; past GIVE_UP_AFTER_MS (a writer that
// stopped between claiming and creating), create anyway and let the settler merge the other one later.
const resolveContested = async (b: any, mine: any[]): Promise<{ target?: Owner; reconcile?: Owner[] }> => {
  const holders = R.sortBy((h: Owner) => h.owner_id, R.uniqBy((h: Owner) => h.owner_id, mine.map((l: any) => l.holder)));
  const allKeys = [...b.keys, b.element.internal_id];
  const started = Date.now();
  for (;;) {
    const found = await mgetRaw(holders.map((h) => ({ id: h.owner_id, index: h.owner_index })), { light: true });
    const existing = holders.find((h) => found.has(h.owner_id));
    if (existing) {
      await setKeys(allKeys.map((key: string) => ({ key, owner: R.omit(['key', 'state'], existing) })));
      return { target: existing };
    }
    const waited = Date.now() - started;
    const smallest = [b.element.internal_id, ...holders.map((h) => h.owner_id)].sort()[0] === b.element.internal_id;
    if ((smallest && waited > TAKE_OVER_AFTER_MS) || waited > GIVE_UP_AFTER_MS) {
      await setKeys(mine.map((l: any) => ({ key: l.key, owner: R.omit(['key', 'state'], ownerOf(b.element)) })));
      return { reconcile: waited > GIVE_UP_AFTER_MS ? holders : [] };
    }
    await sleep(20);
  }
};

// Today's choice of target among the existing objects matching an input (internalCreateEntityRaw)
const existingEntityTarget = async (context: AuthContext, user: AuthUser, w: any, live: Owner[]): Promise<Merge> => {
  const existing = await loadWithAccessFields(live.map((o) => o.owner_id));
  const filtered: any[] = await userFilterStoreElements(context, user, existing);
  if (filtered.length === 0) throw UnsupportedError('Restricted entity already exists', { doc_code: 'RESTRICTED_ELEMENT' });
  if (filtered.length === 1) return { w, target: ownerOf(filtered[0]), patch: w.resolvedInput };
  const existingByStandard = filtered.find((e) => e.standard_id === w.standardId);
  if (existingByStandard && !isStixCyberObservableHashedObservable(w.type)) {
    const reconcile: Owner[] = [];
    let target = existingByStandard;
    if (w.resolvedInput.stix_id) {
      const byStix = filtered.find((e) => e.standard_id === w.resolvedInput.stix_id || (e.x_opencti_stix_ids ?? []).includes(w.resolvedInput.stix_id));
      if (byStix && byStix.internal_id !== existingByStandard.internal_id) {
        const [mergeTarget, mergeSource] = byStix.confidence > existingByStandard.confidence ? [byStix, existingByStandard] : [existingByStandard, byStix];
        reconcile.push(ownerOf(mergeSource));
        target = mergeTarget;
      }
    }
    const others = filtered.filter((e) => e.standard_id !== w.standardId);
    return { w, target: ownerOf(target), patch: cleanEntityForIdsCollision(w.resolvedInput, w.type, existingByStandard, others), reconcile, inline: true };
  }
  if (w.resolvedInput.update === true) {
    const target = filtered.find((e) => e.standard_id === w.standardId) || filtered[0];
    return { w, target: ownerOf(target), patch: w.resolvedInput, reconcile: filtered.filter((e) => e.internal_id !== target.internal_id).map(ownerOf), inline: true };
  }
  let selected = filtered[0];
  if (w.resolvedInput.stix_id) selected = filtered.find((n) => getInstanceIds(n).includes(w.resolvedInput.stix_id)) ?? selected;
  return { w, target: ownerOf(selected), patch: cleanEntityForIdsCollision(w.resolvedInput, w.type, selected, filtered) };
};

// createEntityRaw's retry: an insufficient confidence stops merging objects, then the input is upserted as is
const mergeEntityWithRetry = async (
  context: AuthContext, user: AuthUser, target: Owner, w: any, patch: Record<string, any>, counters: Counters, opts: WriteOptions,
): Promise<ItemResult> => {
  const run = async (p: Record<string, any>): Promise<ItemResult> => {
    const result: any = await upsertLockFree(context, user, { index: target.owner_index, id: target.owner_id }, w.type, p, counters, opts);
    if (result.status === 'missing') throw FunctionalError('Cant find element to resolve', { id: target.owner_id });
    if (result.status === 'merged') {
      add(counters, 'entities_merged');
      if (result.event) await triggerEntityUpdateAutoEnrichment(context, user, result.element);
      if (result.workflowStatusChanged && isFeatureEnabled(ENTITIES_WORKFLOW_FEATURE_FLAG)) {
        await syncWorkflowInstanceFromExternalWrite(context, user, result.element, result.element.x_opencti_workflow_id);
      }
      return { status: 'merged', id: target.owner_id };
    }
    add(counters, 'entities_unchanged');
    return { status: 'unchanged', id: target.owner_id };
  };
  try {
    return await run(patch);
  } catch (e: any) {
    if (w.input.update !== false && e?.extensions?.data?.doc_code === DOC_INSUFFICIENT_CONFIDENCE_LEVEL) return run({ ...patch, update: false });
    throw e;
  }
};

// ===============================================================================================================
// Relationships (core relationships and sightings)
// ===============================================================================================================
const iso = (v: any) => (v ? new Date(v).toISOString() : undefined);
const timeKey = (input: Record<string, any>) => ['start_time', 'stop_time', 'first_seen', 'last_seen'].map((k) => iso(input[k]) ?? '-').join('|');
export const relationInternalId = (type: string, fromId: string, toId: string, input: Record<string, any>) => deterministicId(`${type}|${fromId}|${toId}|${timeKey(input)}`);

export const writeRelationChunk = async (
  context: AuthContext, user: AuthUser, rawInputs: Record<string, any>[], counters: Counters, opts: WriteOptions = {},
): Promise<ItemResult[]> => {
  const bench = benchTimer('lf_relation');
  const results: ItemResult[] = new Array(rawInputs.length);
  const finder = chunkFinder(context, user);
  await finder(R.uniq(rawInputs.flatMap((input) => refInputIds(input.relationship_type, input))));
  bench.step('prefetch');
  const pendingItems: { input: Record<string, any>; missing: string[]; user_id: string }[] = [];
  // 1. Prepare, resolve and check, as createRelationRaw does before its lock
  const prepared = (await Promise.all(rawInputs.map(async (raw, i) => {
    const type = raw.relationship_type;
    try {
      if (getDraftContext(context, user) || isStixRefRelationship(type)) return { i, fallback: true };
      const input = await prepareInput(context, user, structuredClone(raw), type);
      if (input.fromId === input.toId) throw UnsupportedError('Relation cant be created with the same source and target', { from: input.fromId, relationshipType: type, doc_code: 'SELF_REFERENCING_RELATION' });
      const entitySetting: any = await getEntitySettingFromCache(context, type);
      let resolvedInput: any;
      try {
        resolvedInput = await inputResolveRefs(context, user, input, type, entitySetting, { finder });
      } catch (e: any) {
        const unresolved: string[] = e?.extensions?.data?.unresolvedIds ?? [];
        const missingEnds = unresolved.filter((u) => u === input.fromId || u === input.toId);
        if (missingEnds.length === 0) throw e;
        const { owners } = await liveOwners(missingEnds);
        if (missingEnds.some((m) => owners.get(m.toLowerCase())?.state === 'deleted')) {
          add(counters, 'rejected_deleted_ref');
          throw e;
        }
        if (opts.missingEnds === 'error') throw e;
        // Its end has not arrived: it waits, invisible, instead of being refused and sent again
        pendingItems.push({ input: raw, missing: missingEnds, user_id: user.internal_id });
        results[i] = { status: 'pending' };
        return null;
      }
      const { from, to } = resolvedInput;
      if (!validateUserAccessOperation(user, from, AccessOperation.EDIT, null) || !validateUserAccessOperation(user, to, AccessOperation.EDIT, null)) throw ForbiddenAccess();
      await checkRelationConsistency(context, user, type, from, to);
      if (from.internal_id === to.internal_id) throw UnsupportedError('Relation cant be created with the same source and target', { from: input.fromId, to: input.toId, relationshipType: type, doc_code: 'SELF_REFERENCING_RELATION' });
      if (isSingleRelationsRef(from.entity_type, type)) return { i, fallback: true };
      return { i, type, input, resolvedInput, entitySetting, pair: pairKey(type, from.internal_id, to.internal_id) };
    } catch (e) {
      results[i] = errorResult(e);
      return null;
    }
  }))).filter(Boolean) as any[];
  await addPending(pendingItems);
  add(counters, 'pending_added', pendingItems.length);
  for (const p of prepared.filter((v) => v.fallback)) {
    try {
      const element: any = await createRelation(todayContext(context), user, rawInputs[p.i]);
      results[p.i] = { status: 'fallback', id: element.internal_id };
      add(counters, 'fallbacks');
    } catch (e) {
      results[p.i] = errorResult(e);
    }
  }
  const work = prepared.filter((v) => !v.fallback);
  bench.step('prepare');
  // 2. Match each input against its pair's relationships, and against earlier inputs of the chunk on that pair
  const pairs = await withoutDeleted(await readPairs(work.map((w) => w.pair)));
  const toCreate: any[] = [];
  const merges: { w: any; target?: { id: string; index: string }; after?: any }[] = [];
  for (const [key, group] of Object.entries(R.groupBy((w: any) => w.pair, work))) {
    const candidates: any[] = [...(pairs.get(key) ?? [])];
    for (const w of group ?? []) {
      const duplicates = findDuplicates(w.resolvedInput, candidates);
      if (duplicates.length > 0) {
        const first: any = duplicates[0];
        merges.push(first.i_creating ? { w, after: first.i_creating } : { w, target: { id: first.id, index: first.index } });
      } else {
        const probe = pairEntryOf({ ...w.resolvedInput, internal_id: '', _index: '', standard_id: '' }, w.resolvedInput.createdBy?.internal_id);
        candidates.push({ ...probe, ids: [], i_creating: w });
        toCreate.push(w);
      }
    }
  }
  bench.step('decide');
  // 3. New relationships: defaults and validation as today, an id from type, ends and time, created in bulk
  const built = (await Promise.all(toCreate.map(async (w) => {
    try {
      let resolvedInput = fillDefaultValues(user, w.resolvedInput, w.entitySetting);
      resolvedInput = await inputResolveRefs(context, user, resolvedInput, w.type, w.entitySetting, { finder });
      resolvedInput = await fillDefaultCustomFieldValues(context, user, resolvedInput, w.entitySetting);
      await validateEntityAndRelationCreation(context, user, resolvedInput, w.type, w.entitySetting, {});
      const { from, to } = resolvedInput;
      const internalId = relationInternalId(w.type, from.internal_id, to.internal_id, resolvedInput);
      const data: any = await buildRelationData(context, user, { ...resolvedInput, internal_id: internalId }, {});
      const metas = withMetaIds(data.relations ?? []);
      w.element = denormalizeOnSource(data.element, metas);
      return { ...w, resolvedInput, element: w.element, metas };
    } catch (e) {
      results[w.i] = errorResult(e);
      return null;
    }
  }))).filter(Boolean) as any[];
  bench.step('build');
  const statuses = await bulkCreateDocs(await Promise.all(built.map((b) => prepareIndexingElement(b.element))), opts);
  const created = built.filter((_, k) => statuses[k] === 201);
  built.filter((_, k) => statuses[k] === 409).forEach((b) => merges.push({ w: b, target: { id: b.element.internal_id, index: b.element._index } }));
  bench.step('create.docs');
  // Once the relationships exist, their keys, their pair entries and their meta relationships do not depend on each
  // other: written at once. A duplicate recorded earlier in the pair by another writer makes this one the duplicate.
  const [, after, metaStatuses] = await Promise.all([
    setKeys(created.flatMap((c) => [c.element.internal_id, c.element.standard_id, ...(c.element.x_opencti_stix_ids ?? [])]
      .map((key: string) => ({ key: key.toLowerCase(), owner: R.omit(['key', 'state'], ownerOf(c.element)) })))),
    appendPairs(created.map((c) => ({ key: c.pair, entry: pairEntryOf(c.element, c.resolvedInput.createdBy?.internal_id) }))),
    Promise.all(created.flatMap((c) => c.metas).map((m: any) => prepareIndexingElement(m))).then((docs) => bulkCreateDocs(docs, opts)),
  ]);
  add(counters, 'meta_created', metaStatuses.filter((s: number) => s === 201).length);
  bench.step('create.keys_pairs_metas');
  const reconcileTasks: Task[] = [];
  created.forEach((c) => {
    const list = after.get(c.pair) ?? [];
    const position = list.findIndex((e: PairEntry) => e.id === c.element.internal_id);
    const earlier = findDuplicates(c.resolvedInput, list.slice(0, Math.max(0, position)));
    if (earlier.length > 0) {
      reconcileTasks.push({ kind: 'relation-reconcile', keep: { id: earlier[0].id, index: earlier[0].index }, drop: { id: c.element.internal_id, index: c.element._index }, pair: c.pair });
    }
  });
  const endpointTasks: Task[] = created.flatMap((c) => {
    const { from, to } = c.resolvedInput;
    const base = { kind: 'endpoint' as const, op: 'add' as const, relation_type: c.type, relation: c.element.internal_id, relation_index: c.element._index };
    const tasks: Task[] = [];
    if (isImpactedTypeAndSide(c.type, from.entity_type, to.entity_type, ROLE_FROM)) tasks.push({ ...base, endpoint: from.internal_id, index: from._index, type: from.entity_type, other: to.internal_id, side: 'from' });
    if (isImpactedTypeAndSide(c.type, from.entity_type, to.entity_type, ROLE_TO)) tasks.push({ ...base, endpoint: to.internal_id, index: to._index, type: to.entity_type, other: from.internal_id, side: 'to' });
    return tasks;
  });
  await enqueue([...endpointTasks, ...created.flatMap((c) => metaTargetTasks(c.metas, 'add')), ...reconcileTasks]);
  add(counters, 'relation_races', reconcileTasks.length);
  bench.step('create.enqueue');
  const events = await storeCreateEvents(context, user, created.map((c) => ({ instance: { ...c.resolvedInput, ...c.element } as any })));
  add(counters, 'events_create', events.length);
  add(counters, 'relations_created', created.length);
  bench.step('create.events');
  for (const c of created) results[c.i] = { status: 'created', id: c.element.internal_id };
  for (const c of created.filter((x) => x.resolvedInput.from?.[RELATION_COVERED])) {
    const { from, to } = c.resolvedInput;
    {
      const isVuln = c.type === 'targets' && to.entity_type === 'Vulnerability';
      const isAttackPattern = c.type === 'uses' && to.entity_type === 'Attack-Pattern';
      if (isVuln || isAttackPattern) {
        const { element: coverage } = await updateAttribute(context, user, from[RELATION_COVERED], ENTITY_TYPE_SECURITY_COVERAGE, [{ key: 'modified', value: [now()] }], { noEnrich: true });
        await triggerEntityUpdateAutoEnrichment(context, user, coverage as any);
      }
    }
  }
  // 4. Merges into existing relationships, and into ones created above: in order per target, targets in parallel
  const targetOf = (m: any) => m.target
    ?? (m.after?.element ? { id: m.after.element.internal_id, index: m.after.element._index ?? inferIndexFromConceptType(m.w.type) } : undefined);
  const relationMergeGroups = Object.values(R.groupBy((m: any) => targetOf(m)?.id ?? `none-${m.w.i}`, merges));
  await pool(relationMergeGroups, 16, async (group) => {
    for (const m of group ?? []) {
      try {
        const target = m.target ?? (m.after?.element ? { id: m.after.element.internal_id, index: m.after.element._index ?? inferIndexFromConceptType(m.w.type) } : undefined);
        if (!target) throw FunctionalError('No relationship to merge into');
        const existing = await loadWithAccessFields([target.id]);
        if ((await userFilterStoreElements(context, user, existing)).length === 0) throw UnsupportedError('Restricted relation already exists');
        const result: any = await upsertLockFree(context, user, target, m.w.type, m.w.resolvedInput, counters, opts);
        if (result.status === 'missing') throw FunctionalError('Cant find element to resolve', { id: target.id });
        add(counters, result.status === 'merged' ? 'relations_merged' : 'relations_unchanged');
        results[m.w.i] = { status: result.status, id: target.id };
      } catch (e) {
        results[m.w.i] = errorResult(e);
      }
    }
  });
  bench.step('merges');
  bench.total();
  return results;
};
