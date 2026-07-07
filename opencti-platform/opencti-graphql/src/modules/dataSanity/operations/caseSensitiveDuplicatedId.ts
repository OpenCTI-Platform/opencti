import type { AuthContext } from '../../../types/user';
import { logApp } from '../../../config/conf';
import { fullEntitiesList } from '../../../database/middleware-loader';
import { DATA_SANITY_MANAGER_USER } from '../../../utils/access';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../../database/utils';
import { generateStandardId } from '../../../schema/identifier';
import { elBatchIdsWithRelCount, elUpdate } from '../../../database/engine';
import type { BasicStoreEntity } from '../../../types/store';
import { mergeEntities } from '../../../database/middleware';
import * as R from 'ramda';
import type { SanityOperationRunOutput } from '../dataSanity-operations';

const message = 'caseSensitiveDuplicatedId';

export const computeCollisionGroup = async (context: AuthContext, entityType: string) => {
  const allEntities = await fullEntitiesList(
    context,
    DATA_SANITY_MANAGER_USER,
    [entityType],
    { indices: [READ_INDEX_STIX_DOMAIN_OBJECTS] },
  );
  if (allEntities.length === 0) {
    logApp.info(`${message} > no ${entityType} found, skipping`);
    return [];
  }
  logApp.info(`${message} > ${allEntities.length} ${entityType}(s) to evaluate`);

  // Compute the new standard_id (with the now case-insensitive resolver) for each
  // entity and group by it. Groups with more than one element are duplicates that collide
  // under the new rule and must be merged.
  const entitiesWithNewId = allEntities.map((entity) => ({ entity, newId: generateStandardId(entityType, entity) }));
  const groupedByNewId = R.groupBy((e) => e.newId, entitiesWithNewId);
  const groups = Object.values(groupedByNewId);

  // Merge colliding siblings into a single target. We pick the entity with the most
  // relations as the merge target (richest, most connected) so we minimize the amount of
  // relation rewriting performed by mergeEntities and we keep the most-connected node as
  // the canonical one. Ties are broken by oldest created_at then lowest internal_id for
  // deterministic behaviour. All the other entities are merged into the target so that
  // their relations, markings, labels, stix ids... are preserved. The merge target's
  // standard_id is moved to the new value via a direct ES update.
  // (Unlike patchAttribute, this does NOT archive the previous standard_id inside x_opencti_stix_ids.)
  const collisionGroups = groups.filter((g: any) => g.length > 1);
  return collisionGroups;
};

export const migrateEntityType = async (context: AuthContext, entityType: string) => {
  const collisionGroups = await computeCollisionGroup(context, entityType);
  logApp.info(`${message} > ${collisionGroups.length} ${entityType} collision group(s) to merge`);

  // Batch-resolve the relation count for every entity participating in a collision group
  // (singletons don't need it). elBatchIdsWithRelCount issues a single ES request per batch
  // and computes the denormalized relation count via a Painless script field.
  const collidingEntities = collisionGroups.flat().map((e) => e?.entity);
  const relCountByInternalId = new Map();
  if (collidingEntities.length > 0) {
    const batchInput = collidingEntities.map((e: any) => ({ id: e.internal_id, type: e.entity_type }));
    const reloaded = await elBatchIdsWithRelCount(context, DATA_SANITY_MANAGER_USER, batchInput);
    for (let i = 0; i < batchInput.length; i += 1) {
      const reloadedEntity = reloaded[i] as any;
      const count = reloadedEntity?.script_field_denormalization_count?.[0] ?? 0;
      relCountByInternalId.set(batchInput[i].id, count);
    }
  }

  let mergedEntities = 0;
  for (let index = 0; index < collisionGroups.length; index += 1) {
    const group = collisionGroups[index] as { entity: BasicStoreEntity; newId: string }[];
    const { newId } = group[0];
    // Sort by relation count DESC, then created_at ASC, then internal_id ASC.
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
      if (target.standard_id !== newId) {
        await elUpdate(context, target._index, target.internal_id, { doc: { standard_id: newId } });
      }
      await mergeEntities(context, DATA_SANITY_MANAGER_USER, target.internal_id, sources.map((s) => s.internal_id));
      mergedEntities += sources.length;
      // Use logApp.info so the operator can follow merge progress in the migration log channel.
      logApp.info(
        `${message} > merged ${sources.length} ${entityType} into ${target.internal_id}`
        + ` (target rel_count=${relCountByInternalId.get(target.internal_id) ?? 0},`
        + ` sources rel_count=[${sources.map((s) => relCountByInternalId.get(s.internal_id) ?? 0).join(', ')}])`
        + ` (${index + 1}/${collisionGroups.length})`,
      );
    } catch (err) {
      // Do not abort the whole migration if one group fails: log and keep going.
      logApp.error(`${message} > failed to merge group for ${newId}`, { cause: err, targetId: target.internal_id, sourceIds: sources.map((s) => s.internal_id) });
    }
  }

  return {
    merged: mergedEntities,
    collisions: collisionGroups.length,
  };
};

export const caseSensitiveDuplicatedIdDryRun = (entityTypes: string[]) => async (context: AuthContext): Promise<SanityOperationRunOutput> => {
  let total = 0;
  const detail: Record<string, number> = {};
  for (const entityType of entityTypes) {
    const collisionGroups = await computeCollisionGroup(context, entityType);
    detail[entityType] = collisionGroups.length;
    total += collisionGroups.length;
  }
  return { impact: { total, detail } };
};

export const caseSensitiveDuplicatedId = (entityTypes: string[]) => async (context: AuthContext): Promise<SanityOperationRunOutput> => {
  let total = 0;
  const detail: Record<string, number> = {};
  for (const entityType of entityTypes) {
    const stat = await migrateEntityType(context, entityType);
    detail[entityType] = stat.merged;
    total += stat.merged;
  }
  return { impact: { total, detail } };
};
