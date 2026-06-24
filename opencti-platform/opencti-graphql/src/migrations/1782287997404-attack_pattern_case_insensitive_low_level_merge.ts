import * as R from 'ramda';
import { Promise as BluePromise } from 'bluebird';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { generateStandardId } from '../schema/identifier';
import { ATTRIBUTE_ALIASES, ATTRIBUTE_ALIASES_OPENCTI, ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION } from '../schema/stixDomainObject';
import { isNotEmptyField, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { fullEntitiesList, fullRelationsList } from '../database/middleware-loader';
import {
  BULK_TIMEOUT,
  elBatchIdsWithRelCount,
  elBulk,
  elDeleteElements,
  elFindByIds,
  elLoadById,
  elUpdateEntityConnections,
  elUpdateRelationConnections,
  ES_MAX_CONCURRENCY,
  ES_RETRY_ON_CONFLICT,
  isImpactedTypeAndSide,
  MAX_BULK_OPERATIONS,
  ROLE_FROM,
  ROLE_TO,
} from '../database/engine';
import { ABSTRACT_STIX_RELATIONSHIP, IDS_STIX } from '../schema/general';
import { isSingleRelationsRef } from '../schema/stixEmbeddedRelationship';
import { logApp, logMigration } from '../config/conf';
import type { AuthContext } from '../types/user';
import type { BasicStoreBase, BasicStoreEntity, BasicStoreObject, BasicStoreRelation } from '../types/store';

const message = '[MIGRATION] Attack Pattern / Course of Action case-insensitive duplicate low-level merge';

const REL_PREFIX = 'rel_';
const REL_SUFFIX = '.internal_id';

type DynEntity = BasicStoreEntity & Record<string, any>;

// Build the "already connected" map from the target's own denormalized rel_<type>.internal_id fields.
// It is the cheap source of truth to deduplicate source relations against the target without ever
// loading the (potentially huge) target neighborhood.
const buildTargetConnected = (target: DynEntity): Record<string, Set<string>> => {
  const connected: Record<string, Set<string>> = {};
  const keys = Object.keys(target);
  for (let i = 0; i < keys.length; i += 1) {
    const key = keys[i];
    if (key.startsWith(REL_PREFIX) && key.endsWith(REL_SUFFIX)) {
      const relType = key.substring(REL_PREFIX.length, key.length - REL_SUFFIX.length);
      const ids = (target[key] ?? []).flat(Infinity).filter((id: string) => isNotEmptyField(id));
      connected[relType] = new Set(ids);
    }
  }
  return connected;
};

// Low-level equivalent of mergeEntities for the migration: it redirects every relation of the sources
// onto the target and merges identity attributes, using only engine primitives and painless scripts.
// It deliberately skips the high-level overhead of mergeEntities (locks, full ref resolution of the
// canonical entity, stream merge events, bus notifications, redis deletions, trash).
const lowLevelMergeGroup = async (
  context: AuthContext,
  entityType: string,
  target: DynEntity,
  sources: DynEntity[],
  newId: string,
) => {
  // `target` was loaded by fullEntitiesList, which paginates with the default withoutRels=true and therefore
  // strips the denormalized rel_<type>.internal_id fields from _source. Reload it with the rels present so the
  // dedup map below reflects the edges the target already holds; otherwise existing edges go undetected and the
  // merge creates duplicate relations (and breaks the single-ref dedup, e.g. created-by).
  const fullTarget = (await elLoadById<DynEntity>(context, SYSTEM_USER, target.internal_id, { type: entityType })) ?? target;
  const targetId = fullTarget.internal_id;
  const targetName = fullTarget.name;
  const targetIndex = fullTarget._index;
  const sourceIds = sources.map((s) => s.internal_id);
  const sourceIdSet = new Set(sourceIds);
  const internalIds = new Set([targetId, ...sourceIds]);
  const aliasField = entityType === ENTITY_TYPE_COURSE_OF_ACTION ? ATTRIBUTE_ALIASES_OPENCTI : ATTRIBUTE_ALIASES;

  // In-memory dedup state: neighbors already connected to the target per relationship type. It is seeded
  // from the target denormalization and grown as source relations get redirected, so that two sources
  // pointing to the same neighbor do not create a duplicate edge.
  const targetConnected = buildTargetConnected(fullTarget);
  // Neighbors to add to the target denormalization, applied once at the end (grouped to avoid self conflicts).
  const targetAddByRelType: Record<string, Set<string>> = {};

  // Streamed, page-by-page processing of every relation attached to the sources (both directions),
  // keeping memory flat and parallelizing the elastic writes.
  const processRelations = async (relations: BasicStoreRelation[]) => {
    const neighborIds = R.uniq(
      relations
        .map((rel) => (sourceIdSet.has(rel.fromId) ? rel.toId : rel.fromId))
        .filter((id) => isNotEmptyField(id) && !internalIds.has(id)),
    );
    const indexByNeighborId: Record<string, string> = {};
    if (neighborIds.length > 0) {
      const neighbors = await elFindByIds(context, SYSTEM_USER, neighborIds, { baseData: true }) as BasicStoreBase[];
      for (let i = 0; i < neighbors.length; i += 1) {
        indexByNeighborId[neighbors[i].internal_id] = neighbors[i]._index;
      }
    }
    const relConnectionUpdates: any[] = [];
    const neighborUpdates: any[] = [];
    for (let i = 0; i < relations.length; i += 1) {
      const rel = relations[i];
      const relType = rel.entity_type;
      const fromIsSource = sourceIdSet.has(rel.fromId);
      const sourceSideId = fromIsSource ? rel.fromId : rel.toId;
      const neighborId = fromIsSource ? rel.toId : rel.fromId;
      // Self / internal relation (neighbor is the target or another merged source): keep it on the source,
      // it will be removed when the source is deleted (no self-loop on the target).
      if (internalIds.has(neighborId)) {
        continue;
      }
      // Single ref already held by the target (e.g. created-by): the target keeps its own, drop the source one.
      if (isSingleRelationsRef(entityType, relType) && (targetConnected[relType]?.size ?? 0) > 0) {
        continue;
      }
      // Duplicate edge: the target is already connected to this neighbor through the same type, drop it.
      if (targetConnected[relType]?.has(neighborId)) {
        continue;
      }
      // Redirect the source side of the relation onto the target. Only the connections array is rewritten:
      // fromId / toId / fromName / toName are reconstructed from connections on read (engine-data-converter).
      relConnectionUpdates.push({
        _index: rel._index,
        id: rel.internal_id,
        toReplace: sourceSideId,
        data: { internal_id: targetId, name: targetName },
      });
      // Replace the source id by the target id in the neighbor's denormalized rel_<type>.internal_id.
      const neighborRole = fromIsSource ? ROLE_TO : ROLE_FROM;
      if (isImpactedTypeAndSide(relType, rel.fromType, rel.toType, neighborRole) && indexByNeighborId[neighborId]) {
        neighborUpdates.push({
          _index: indexByNeighborId[neighborId],
          id: neighborId,
          toReplace: sourceSideId,
          relationType: relType,
          data: { internal_id: targetId },
        });
      }
      // The neighbor must be added to the target denormalization (applied once at the end).
      const targetRole = fromIsSource ? ROLE_FROM : ROLE_TO;
      if (isImpactedTypeAndSide(relType, rel.fromType, rel.toType, targetRole)) {
        if (!targetAddByRelType[relType]) targetAddByRelType[relType] = new Set();
        targetAddByRelType[relType].add(neighborId);
      }
      // Mark the neighbor as connected so the next source relation to it (same type) is deduplicated.
      if (!targetConnected[relType]) targetConnected[relType] = new Set();
      targetConnected[relType].add(neighborId);
    }
    // Apply this page in parallel bulks.
    await BluePromise.map(
      R.splitEvery(MAX_BULK_OPERATIONS, relConnectionUpdates),
      (batch) => elUpdateRelationConnections(context, batch),
      { concurrency: ES_MAX_CONCURRENCY },
    );
    await BluePromise.map(
      R.splitEvery(MAX_BULK_OPERATIONS, neighborUpdates),
      (batch) => elUpdateEntityConnections(context, batch),
      { concurrency: ES_MAX_CONCURRENCY },
    );
    return true;
  };

  await fullRelationsList(context, SYSTEM_USER, ABSTRACT_STIX_RELATIONSHIP, { fromId: sourceIds, callback: processRelations });
  await fullRelationsList(context, SYSTEM_USER, ABSTRACT_STIX_RELATIONSHIP, { toId: sourceIds, callback: processRelations });

  // Add all redirected neighbors to the target denormalization, one update per type to avoid conflicts on the target doc.
  const targetAddEntries = Object.entries(targetAddByRelType);
  for (let i = 0; i < targetAddEntries.length; i += 1) {
    const [relType, neighbors] = targetAddEntries[i];
    await elUpdateEntityConnections(context, [{
      _index: targetIndex,
      id: targetId,
      toReplace: null,
      relationType: relType,
      data: { internal_id: Array.from(neighbors) },
    }]);
  }

  // Merge identity-bearing attributes onto the target and move its standard_id to the new value. The
  // previous standard_id and all source ids are archived in x_opencti_stix_ids so older references resolve.
  const stixIds = R.uniq([
    ...(fullTarget[IDS_STIX] ?? []),
    ...(fullTarget.standard_id !== newId ? [fullTarget.standard_id] : []),
    ...sources.flatMap((s) => [s.standard_id, ...(s[IDS_STIX] ?? [])]),
  ]).filter((id) => isNotEmptyField(id) && id !== newId);
  const aliasValues = R.uniq([
    ...(fullTarget[aliasField] ?? []),
    ...sources.flatMap((s) => [...(s[aliasField] ?? []), s.name]),
  ]).filter((value) => isNotEmptyField(value));
  await elBulk(context, {
    refresh: true,
    timeout: BULK_TIMEOUT,
    body: [
      { update: { _index: targetIndex, _id: fullTarget._id, retry_on_conflict: ES_RETRY_ON_CONFLICT } },
      { doc: { standard_id: newId, [IDS_STIX]: stixIds, [aliasField]: aliasValues } },
    ],
  });

  // Remove the source entities. elDeleteElements also deletes the leftover (duplicate / internal) relations
  // still attached to the sources - found through a live connections query, not the stale denormalization -
  // and cleans the corresponding rel_<type>.internal_id on their neighbors. forceDelete skips the trash.
  await elDeleteElements(context, SYSTEM_USER, sources as unknown as BasicStoreObject[], { forceDelete: true });
};

const migrateEntityType = async (context: AuthContext, entityType: string) => {
  const allEntities = await fullEntitiesList(
    context,
    SYSTEM_USER,
    [entityType],
    { indices: [READ_INDEX_STIX_DOMAIN_OBJECTS] },
  ) as DynEntity[];
  if (allEntities.length === 0) {
    logMigration.info(`${message} > no ${entityType} found, skipping`);
    return { merged: 0, collisions: 0 };
  }
  logMigration.info(`${message} > ${allEntities.length} ${entityType}(s) to evaluate`);

  // Recompute the new (case-insensitive) standard_id and group by it. Groups with more than one element
  // are duplicates that collide under the new rule and must be merged.
  const entitiesWithNewId = allEntities.map((entity) => ({ entity, newId: generateStandardId(entityType, entity) }));
  const groupedByNewId = R.groupBy((e) => e.newId, entitiesWithNewId);
  const collisionGroups = Object.values(groupedByNewId).filter((g) => (g?.length ?? 0) > 1) as { entity: DynEntity; newId: string }[][];
  logMigration.info(`${message} > ${collisionGroups.length} ${entityType} collision group(s) to merge`);
  if (collisionGroups.length === 0) {
    return { merged: 0, collisions: 0 };
  }

  // Batch-resolve the relation count of every colliding entity in a single request. The most-connected
  // entity is picked as the merge target so the amount of relation rewriting is minimized.
  const collidingEntities = collisionGroups.flat().map((e) => e.entity);
  const relCountByInternalId = new Map<string, number>();
  const batchInput = collidingEntities.map((e) => ({ id: e.internal_id, type: e.entity_type }));
  const reloaded = await elBatchIdsWithRelCount(context, SYSTEM_USER, batchInput);
  for (let i = 0; i < batchInput.length; i += 1) {
    const reloadedEntity = reloaded[i] as any;
    const count = reloadedEntity?.script_field_denormalization_count?.[0] ?? 0;
    relCountByInternalId.set(batchInput[i].id, count);
  }

  // Groups are merged sequentially on purpose: without distributed locks, sequential processing keeps
  // relations between two distinct duplicates consistent (each group fully completes, with refresh,
  // before the next one). The heavy per-group elastic work is parallelized inside lowLevelMergeGroup.
  let mergedEntities = 0;
  for (let index = 0; index < collisionGroups.length; index += 1) {
    const group = collisionGroups[index];
    const { newId } = group[0];
    const sorted = R.sortWith(
      [
        R.descend((e) => relCountByInternalId.get(e.entity.internal_id) ?? 0),
        R.ascend((e) => e.entity.created_at || ''),
        R.ascend((e) => e.entity.internal_id || ''),
      ],
      group,
    );
    const target = sorted[0].entity;
    const sources = sorted.slice(1).map((e) => e.entity);
    try {
      await lowLevelMergeGroup(context, entityType, target, sources, newId);
      mergedEntities += sources.length;
      logMigration.info(
        `${message} > merged ${sources.length} ${entityType} into ${target.internal_id}`
        + ` (target rel_count=${relCountByInternalId.get(target.internal_id) ?? 0})`
        + ` (${index + 1}/${collisionGroups.length})`,
      );
    } catch (err) {
      // Do not abort the whole migration if one group fails: log and keep going.
      logApp.error(`${message} > failed to merge group for ${newId}`, { cause: err, targetId: target.internal_id, sourceIds: sources.map((s) => s.internal_id) });
    }
  }

  return { merged: mergedEntities, collisions: collisionGroups.length };
};

export const up = async (next: (error?: Error) => void) => {
  const context = executionContext('migration');
  const start = new Date().getTime();
  logMigration.info(`${message} > started`);

  const stats = { merged: 0, collisions: 0 };
  for (const entityType of [ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION]) {
    const typeStats = await migrateEntityType(context, entityType);
    stats.merged += typeStats.merged;
    stats.collisions += typeStats.collisions;
  }

  logMigration.info(
    `${message} > done in ${new Date().getTime() - start} ms`
    + ` (${stats.merged} duplicate(s) merged across ${stats.collisions} group(s))`,
  );
  next();
};

export const down = async (next: (error?: Error) => void) => {
  // Not reversible: source standard_ids are preserved in x_opencti_stix_ids so nothing is lost, but the
  // pre-merge state required to recompute previous ids is no longer available after the merges.
  next();
};
