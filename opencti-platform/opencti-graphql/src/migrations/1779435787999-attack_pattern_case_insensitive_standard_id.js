import * as R from 'ramda';
import { Promise } from 'bluebird';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION } from '../schema/stixDomainObject';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { fullEntitiesList } from '../database/middleware-loader';
import { mergeEntities, patchAttribute } from '../database/middleware';
import { BULK_TIMEOUT, elBulk, ES_MAX_CONCURRENCY, MAX_BULK_OPERATIONS } from '../database/engine';
import { logApp, logMigration } from '../config/conf';

const message = '[MIGRATION] Attack Pattern / Course of Action standard_id case-insensitive rewrite';

// Recompute and rewrite the standard_id of all entities of a given STIX domain entity type,
// merging duplicates that collide after the new (case-insensitive) x_mitre_id normalization.
const migrateEntityType = async (context, entityType) => {
  const allEntities = await fullEntitiesList(
    context,
    SYSTEM_USER,
    [entityType],
    { indices: [READ_INDEX_STIX_DOMAIN_OBJECTS] },
  );
  if (allEntities.length === 0) {
    logMigration.info(`${message} > no ${entityType} found, skipping`);
    return { rewritten: 0, merged: 0, collisions: 0 };
  }
  logMigration.info(`${message} > ${allEntities.length} ${entityType}(s) to evaluate`);

  // Compute the new standard_id (with the now case-insensitive x_mitre_id resolver) for each
  // entity and group by it. Groups with more than one element are duplicates that collide
  // under the new rule and must be merged.
  const entitiesWithNewId = allEntities.map((entity) => ({ entity, newId: generateStandardId(entityType, entity) }));
  const groupedByNewId = R.groupBy((e) => e.newId, entitiesWithNewId);
  const groups = Object.values(groupedByNewId);

  // Merge colliding siblings into a single target. We pick the oldest entity (by created_at,
  // falling back to internal_id) as the merge target to preserve provenance; all the other
  // entities are merged into it so that their relations, markings, labels, stix ids... are
  // kept. The merge target's standard_id is moved to the new value via patchAttribute so the
  // middleware automatically archives the previous standard_id inside x_opencti_stix_ids.
  const collisionGroups = groups.filter((g) => g.length > 1);
  logMigration.info(`${message} > ${collisionGroups.length} ${entityType} collision group(s) to merge`);
  let mergedEntities = 0;
  for (let index = 0; index < collisionGroups.length; index += 1) {
    const group = collisionGroups[index];
    const { newId } = group[0];
    const sorted = R.sortWith(
      [
        R.ascend((e) => e.entity.created_at || ''),
        R.ascend((e) => e.entity.internal_id || ''),
      ],
      group,
    );
    const target = sorted[0].entity;
    const sources = sorted.slice(1).map((e) => e.entity);
    try {
      if (target.standard_id !== newId) {
        await patchAttribute(context, SYSTEM_USER, target.internal_id, target.entity_type, { standard_id: newId });
      }
      await mergeEntities(context, SYSTEM_USER, target.internal_id, sources.map((s) => s.internal_id));
      mergedEntities += sources.length;
      logApp.info(`${message} > merged ${sources.length} ${entityType} into ${target.internal_id} (${index + 1}/${collisionGroups.length})`);
    } catch (err) {
      // Do not abort the whole migration if one group fails: log and keep going, the
      // remaining entities can still have their standard_id rewritten.
      logApp.error(`${message} > failed to merge group for ${newId}`, { cause: err, targetId: target.internal_id, sourceIds: sources.map((s) => s.internal_id) });
    }
  }

  // Bulk-rewrite the standard_id of all remaining (non-colliding) entities whose id actually
  // changed. The previous standard_id is archived in x_opencti_stix_ids so older STIX IDs
  // keep resolving to the same entity.
  const bulkOperations = [];
  const singletonGroups = groups.filter((g) => g.length === 1);
  for (let index = 0; index < singletonGroups.length; index += 1) {
    const { entity, newId } = singletonGroups[index][0];
    if (entity.standard_id === newId) continue;
    const existingStixIds = entity.x_opencti_stix_ids ?? [];
    const updatedStixIds = R.uniq([...existingStixIds, entity.standard_id]);
    bulkOperations.push(
      { update: { _index: entity._index, _id: entity._id } },
      { doc: { standard_id: newId, x_opencti_stix_ids: updatedStixIds } },
    );
  }

  if (bulkOperations.length > 0) {
    let currentProcessing = 0;
    const groupsOfOperations = R.splitEvery(MAX_BULK_OPERATIONS, bulkOperations);
    const concurrentUpdate = async (bulk) => {
      await elBulk(context, { refresh: true, timeout: BULK_TIMEOUT, body: bulk });
      currentProcessing += bulk.length;
      logApp.info(`${message} > bulk rewrote ${entityType} standard ids: ${currentProcessing} / ${bulkOperations.length}`);
    };
    await Promise.map(groupsOfOperations, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  }

  return {
    rewritten: bulkOperations.length / 2,
    merged: mergedEntities,
    collisions: collisionGroups.length,
  };
};

export const up = async (next) => {
  const context = executionContext('migration');
  const start = new Date().getTime();
  logMigration.info(`${message} > started`);

  const stats = { rewritten: 0, merged: 0, collisions: 0 };
  for (const entityType of [ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION]) {
    const typeStats = await migrateEntityType(context, entityType);
    stats.rewritten += typeStats.rewritten;
    stats.merged += typeStats.merged;
    stats.collisions += typeStats.collisions;
  }

  logMigration.info(
    `${message} > done in ${new Date().getTime() - start} ms`
    + ` (${stats.rewritten} standard_id rewritten, ${stats.merged} duplicate(s) merged across ${stats.collisions} group(s))`,
  );
  next();
};

export const down = async (next) => {
  // This migration is intentionally not reversible: the old standard_ids are preserved in
  // x_opencti_stix_ids so data is not lost, but recomputing the previous case-sensitive ids
  // would require the original pre-merge state which is no longer available after merges.
  next();
};
