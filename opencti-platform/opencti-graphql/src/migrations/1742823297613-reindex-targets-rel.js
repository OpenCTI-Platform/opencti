import * as R from 'ramda';
import { Promise } from 'bluebird';
import conf, { logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_IDENTITY_SECTOR, ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION } from '../schema/stixDomainObject';
import { elBulk, elList } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { RELATION_TARGETS } from '../schema/stixCoreRelationship';
import { fullRelationsList } from '../database/middleware-loader';

export const MIGRATION_MAX_BULK_OPERATIONS = conf.get('migrations:reindex_targets_rel:max_bulk_operations') || 1000;
export const MIGRATION_BULK_TIMEOUT = conf.get('migrations:reindex_targets_rel:bulk_timeout') || '30m';
export const MIGRATION_MAX_CONCURRENCY = conf.get('migrations:reindex_targets_rel:max_concurrency') || 2;

export const up = async (next) => {
  const context = executionContext('migration');
  logMigration.info('[OPENCTI] Re-indexing targets for region / countries / sectors...');
  const bulkOperationsTargets = [];
  const startTargets = new Date().getTime();
  const reIndexTargetsRel = async (locations) => {
    let currentProcessingLocations = 0;
    for (let i = 0; i < locations.length; i += 1) {
      logMigration.info(`[OPENCTI] Resolving targets relationships ${currentProcessingLocations} / ${locations.length}`);
      const location = locations[i];
      // Resolve targets relationships
      const args = { toId: location.internal_id, withInferences: true };
      const targetsRelationships = await fullRelationsList(context, SYSTEM_USER, RELATION_TARGETS, args);
      const fromIds = targetsRelationships.map((rel) => rel.fromId);
      const updateQuery = [
        { update: { _index: location._index, _id: location._id, retry_on_conflict: 5 } },
        {
          script: {
            params: { 'rel_targets.internal_id': fromIds },
            source: 'ctx._source[\'rel_targets.internal_id\'] = []; ctx._source[\'rel_targets.internal_id\'].addAll(params[\'rel_targets.internal_id\']);'
          }
        }
      ];
      bulkOperationsTargets.push(...updateQuery);
      currentProcessingLocations += 1;
    }
  };
  const opts = { types: [ENTITY_TYPE_LOCATION_REGION, ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_IDENTITY_SECTOR], logForMigration: true, callback: reIndexTargetsRel };
  await elList(context, SYSTEM_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, opts);
  // Apply operations.
  let currentProcessing = 0;
  const groupsOfOperations = R.splitEvery(MIGRATION_MAX_BULK_OPERATIONS, bulkOperationsTargets);
  const concurrentUpdate = async (bulk) => {
    currentProcessing += bulk.length;
    logMigration.info(`[OPENCTI] Re-indexing targets for region / countries / sectors ${currentProcessing} / ${bulkOperationsTargets.length}`);
    await elBulk({ refresh: true, timeout: MIGRATION_BULK_TIMEOUT, body: bulk });
  };
  await Promise.map(groupsOfOperations, concurrentUpdate, { concurrency: MIGRATION_MAX_CONCURRENCY });
  logMigration.info(`[MIGRATION] Re-indexed targets for region / countries / sectors in ${new Date() - startTargets} ms`);
  next();
};

export const down = async (next) => {
  next();
};
