// The lock-free write path inside the platform. When app:lockfree_ingestion:enabled is set and the identity backfill
// has run, worker imports (requests carrying a work id) of STIX core objects, relationships and sightings are
// written by it; a missing end fails as today, so the worker retries as today. Every other write keeps today's
// path and keeps the identity index in step through the sync functions, called where the platform stores its
// create, update, merge and delete events.
import * as R from 'ramda';
import { booleanConf, logApp, REDIS_PREFIX } from '../../config/conf';
import { getClientBase } from '../redis';
import { inferIndexFromConceptType } from '../utils';
import { getDraftContext } from '../../utils/draftContext';
import type { AuthContext, AuthUser } from '../../types/user';
import { isStixCoreObject } from '../../schema/stixCoreObject';
import { isStixCoreRelationship } from '../../schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../../schema/stixSightingRelationship';
import { buildRefRelationKey } from '../../schema/general';
import { RELATION_CREATED_BY } from '../../schema/stixRefRelationship';
import { FunctionalError } from '../../config/errors';
import { claimKeys, identityKeys, setKeys } from './identity';
import { mgetRaw, toElements } from './load';
import { appendPairs, pairEntryOf, pairKey, removeFromPair } from './pairs';
import { enqueue, type Task } from './queue';
import { newCounters } from './store';
import { type ItemResult, writeEntityChunk, writeRelationChunk } from './writer';

export const LOCKFREE_INGESTION_ENABLED = booleanConf('app:lockfree_ingestion:enabled', false);
const BACKFILL_DONE_KEY = `${REDIS_PREFIX}lockfree:backfill:done`;

// The backfill marker, read at most every 5 seconds until it is set
let backfillDone = false;
let backfillCheckedAt = 0;
export const isIdentityBackfillDone = async () => {
  if (backfillDone) return true;
  if (Date.now() - backfillCheckedAt < 5000) return false;
  backfillCheckedAt = Date.now();
  backfillDone = (await getClientBase().get(BACKFILL_DONE_KEY)) !== null;
  return backfillDone;
};
export const markIdentityBackfillDone = async () => {
  await getClientBase().set(BACKFILL_DONE_KEY, new Date().toISOString());
  backfillDone = true;
};

const isMarked = (context: AuthContext, mark: 'lockfree_bypass' | 'lockfree_write') => (context as any)[mark] === true;

// Whether a create goes through the lock-free path
export const isLockFreeIngestion = async (context: AuthContext, user: AuthUser, type: string) => {
  if (!LOCKFREE_INGESTION_ENABLED || !context.workId || isMarked(context, 'lockfree_bypass')) return false;
  if (getDraftContext(context, user)) return false;
  if (!isStixCoreObject(type) && !isStixCoreRelationship(type) && !isStixSightingRelationship(type)) return false;
  return isIdentityBackfillDone();
};

// The element as stored, read by id (realtime), as createEntity / createRelation return it
const storedElement = async (result: ItemResult, type: string) => {
  if (result.status === 'error') throw result.cause;
  if (!result.id) throw FunctionalError('Lock-free write returned no element', { status: result.status, type });
  const raws = await mgetRaw([{ id: result.id, index: inferIndexFromConceptType(type) }]);
  const raw = raws.get(result.id);
  if (!raw) throw FunctionalError('Lock-free write cannot read its element', { id: result.id, type });
  const [element] = await toElements([raw]);
  return element;
};

const lockFreeContext = (context: AuthContext): AuthContext => ({ ...context, lockfree_write: true } as AuthContext);

export const createEntityLockFree = async (context: AuthContext, user: AuthUser, input: Record<string, any>, type: string) => {
  const [result] = await writeEntityChunk(lockFreeContext(context), user, [{ type, input }], newCounters(), { missingEnds: 'error' });
  return storedElement(result, type);
};

export const createRelationLockFree = async (context: AuthContext, user: AuthUser, input: Record<string, any>) => {
  const [result] = await writeRelationChunk(lockFreeContext(context), user, [input], newCounters(), { missingEnds: 'error' });
  return storedElement(result, input.relationship_type);
};

// region identity index in step with today's path
const ownerOf = (element: any) => ({ owner_id: element.internal_id, owner_index: element._index, owner_type: element.entity_type, owner_standard_id: element.standard_id });
const isRelationshipElement = (element: any) => isStixCoreRelationship(element.entity_type) || isStixSightingRelationship(element.entity_type);
const keysOf = (element: any): string[] => {
  if (isRelationshipElement(element)) {
    return R.uniq([element.internal_id, element.standard_id, ...(element.x_opencti_stix_ids ?? [])].filter(Boolean).map((k: string) => k.toLowerCase()));
  }
  return R.uniq([...identityKeys(element.entity_type, { ...element, stix_id: element.standard_id }), element.internal_id.toLowerCase()]);
};
const createdByOf = (element: any): string | undefined => {
  const value = element.createdBy?.internal_id ?? element[buildRefRelationKey(RELATION_CREATED_BY)] ?? element['created-by'];
  return Array.isArray(value) ? value[0] : value;
};
// Only the objects the lock-free path reads: live STIX core objects and relationships, outside drafts and inferences
const isSynced = (context: AuthContext, user: AuthUser, element: any) => {
  if (!LOCKFREE_INGESTION_ENABLED || isMarked(context, 'lockfree_write')) return false;
  if (!element?.internal_id || !element.entity_type || getDraftContext(context, user)) return false;
  if (element.is_inferred || element._index?.includes('inferred')) return false;
  return isStixCoreObject(element.entity_type) || isRelationshipElement(element);
};
const safely = async (operation: string, element: any, fn: () => Promise<void>) => {
  try {
    await fn();
  } catch (e) {
    logApp.error('[LOCKFREE] Identity index out of step', { cause: e, operation, id: element?.internal_id });
  }
};

// Created by today's path: its keys, unless a lock-free write holds them already (then the two are merged, as two
// lock-free writes would be), and its pair entry for a relationship
export const syncIdentityOnCreate = async (context: AuthContext, user: AuthUser, element: any) => {
  if (!isSynced(context, user, element)) return;
  await safely('create', element, async () => {
    const conflicts: any[] = await claimKeys([{ keys: keysOf(element), owner: ownerOf(element) }]);
    const holders = R.uniqBy((c: any) => c.holder.owner_id, conflicts.filter((c: any) => c.holder.owner_id !== element.internal_id));
    if (holders.length > 0 && !isRelationshipElement(element)) {
      await enqueue(holders.map((c: any) => ({ kind: 'reconcile', loser: { ...ownerOf(element), key: c.key, state: 'live' }, winner: c.holder } as Task)));
    }
    if (isRelationshipElement(element)) {
      await appendPairs([{ key: pairKey(element.entity_type, element.fromId, element.toId), entry: pairEntryOf(element, createdByOf(element)) }]);
    }
  });
};

// Updated by today's path (an edit, an upsert): new keys (a new alias, a rename) lead to it too
export const syncIdentityOnUpdate = async (context: AuthContext, user: AuthUser, element: any) => {
  if (!isSynced(context, user, element)) return;
  await safely('update', element, async () => {
    await claimKeys([{ keys: keysOf(element), owner: ownerOf(element) }]);
  });
};

// Merged by today's path: every key of the merged object, the sources' too, leads to it
export const syncIdentityOnMerge = async (context: AuthContext, user: AuthUser, target: any, sources: any[]) => {
  if (!isSynced(context, user, target)) return;
  await safely('merge', target, async () => {
    const keys = R.uniq([...keysOf(target), ...sources.flatMap((s) => keysOf({ ...s, entity_type: s.entity_type ?? target.entity_type }))]);
    await setKeys(keys.map((key) => ({ key, owner: ownerOf(target) })));
  });
};

// Deleted by today's path: its keys become tombstones (new references to it are refused, as today), and a
// relationship leaves its pair
export const syncIdentityOnDelete = async (context: AuthContext, user: AuthUser, element: any) => {
  if (!isSynced(context, user, element)) return;
  await safely('delete', element, async () => {
    await setKeys(keysOf(element).map((key) => ({ key, owner: ownerOf(element), state: 'deleted' as const })));
    if (isRelationshipElement(element) && element.fromId && element.toId) {
      await removeFromPair(pairKey(element.entity_type, element.fromId, element.toId), element.internal_id);
    }
  });
};
// endregion
