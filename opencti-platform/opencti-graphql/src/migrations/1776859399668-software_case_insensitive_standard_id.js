import * as R from 'ramda';
import { Promise } from 'bluebird';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { generateStandardId } from '../schema/identifier';
import { ENTITY_SOFTWARE } from '../schema/stixCyberObservable';
import { READ_INDEX_STIX_CYBER_OBSERVABLES } from '../database/utils';
import { fullEntitiesList } from '../database/middleware-loader';
import { mergeEntities, patchAttribute } from '../database/middleware';
import { BULK_TIMEOUT, elBulk, ES_MAX_CONCURRENCY, MAX_BULK_OPERATIONS } from '../database/engine';
import { logApp, logMigration } from '../config/conf';

const message = '[MIGRATION] Software standard_id case-insensitive rewrite';

export const up = async (next) => {
  const context = executionContext('migration');
  const start = new Date().getTime();
  logMigration.info(`${message} > started`);

  // 1. Load every existing Software observable (minimal but sufficient field set to
  // recompute a standard_id and to build the bulk update / merge operations).
  const allSoftwares = await fullEntitiesList(
    context,
    SYSTEM_USER,
    [ENTITY_SOFTWARE],
    { indices: [READ_INDEX_STIX_CYBER_OBSERVABLES] },
  );
  if (allSoftwares.length === 0) {
    logMigration.info(`${message} > no Software observable found, nothing to do`);
    next();
    return;
  }
  logMigration.info(`${message} > ${allSoftwares.length} Software observable(s) to evaluate`);

  // 2. Compute the new standard_id (lowercased name) for each Software and group them.
  // Entities sharing the same new id would collide after the code change and must be merged.
  const softwaresWithNewId = allSoftwares.map((sw) => ({ sw, newId: generateStandardId(ENTITY_SOFTWARE, sw) }));
  const groupedByNewId = R.groupBy((e) => e.newId, softwaresWithNewId);
  const groups = Object.values(groupedByNewId);

  // 3. Handle groups that collide: merge siblings into a single target entity.
  // We pick the oldest entity (by created_at, falling back to internal_id) as the merge target
  // to preserve provenance; all the other entities are merged into it so that their relations,
  // markings, labels, stix ids... are kept. The merge target's standard_id is moved to the new
  // value with patchAttribute so the middleware automatically archives the previous standard_id
  // inside x_opencti_stix_ids.
  const collisionGroups = groups.filter((g) => g.length > 1);
  logMigration.info(`${message} > ${collisionGroups.length} collision group(s) to merge`);
  let mergedEntities = 0;
  for (let index = 0; index < collisionGroups.length; index += 1) {
    const group = collisionGroups[index];
    const { newId } = group[0];
    const sorted = R.sortWith(
      [
        R.ascend((e) => e.sw.created_at || ''),
        R.ascend((e) => e.sw.internal_id || ''),
      ],
      group,
    );
    const target = sorted[0].sw;
    const sources = sorted.slice(1).map((e) => e.sw);
    try {
      if (target.standard_id !== newId) {
        await patchAttribute(context, SYSTEM_USER, target.internal_id, target.entity_type, { standard_id: newId });
      }
      await mergeEntities(context, SYSTEM_USER, target.internal_id, sources.map((s) => s.internal_id));
      mergedEntities += sources.length;
      logApp.info(`${message} > merged ${sources.length} Software into ${target.internal_id} (${index + 1}/${collisionGroups.length})`);
    } catch (err) {
      // Do not abort the whole migration if one group fails: log and keep going,
      // the remaining Software observables can still have their standard_id rewritten.
      logApp.error(`${message} > failed to merge group for ${newId}`, { cause: err, targetId: target.internal_id, sourceIds: sources.map((s) => s.internal_id) });
    }
  }

  // 4. Bulk-rewrite the standard_id of all remaining (non-colliding) Software observables
  // whose id actually changed. The previous standard_id is archived in x_opencti_stix_ids
  // so older STIX IDs keep resolving to the same entity.
  const bulkOperations = [];
  const singletonGroups = groups.filter((g) => g.length === 1);
  for (let index = 0; index < singletonGroups.length; index += 1) {
    const { sw, newId } = singletonGroups[index][0];
    if (sw.standard_id === newId) continue;
    const existingStixIds = sw.x_opencti_stix_ids ?? [];
    const updatedStixIds = R.uniq([...existingStixIds, sw.standard_id]);
    bulkOperations.push(
      { update: { _index: sw._index, _id: sw._id } },
      { doc: { standard_id: newId, x_opencti_stix_ids: updatedStixIds } },
    );
  }

  if (bulkOperations.length > 0) {
    let currentProcessing = 0;
    const groupsOfOperations = R.splitEvery(MAX_BULK_OPERATIONS, bulkOperations);
    const concurrentUpdate = async (bulk) => {
      await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bulk });
      currentProcessing += bulk.length;
      logApp.info(`${message} > bulk rewrote Software standard ids: ${currentProcessing} / ${bulkOperations.length}`);
    };
    await Promise.map(groupsOfOperations, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  }

  logMigration.info(
    `${message} > done in ${new Date().getTime() - start} ms`
    + ` (${bulkOperations.length / 2} standard_id rewritten, ${mergedEntities} duplicate(s) merged across ${collisionGroups.length} group(s))`,
  );
  next();
};

export const down = async (next) => {
  // This migration is intentionally not reversible: the old standard_ids are preserved in
  // x_opencti_stix_ids so data is not lost, but recomputing the previous case-sensitive ids
  // would require the original pre-merge state which is no longer available after merges.
  next();
};
