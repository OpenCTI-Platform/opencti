import * as R from 'ramda';
import { Promise } from 'bluebird';
import { logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_IDENTITY_SECTOR, ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION } from '../schema/stixDomainObject';
import { BULK_TIMEOUT, elBulk, elList, ES_MAX_CONCURRENCY, MAX_BULK_OPERATIONS } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { RELATION_TARGETS } from '../schema/stixCoreRelationship';
import { listAllRelations } from '../database/middleware-loader';

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
      const targetsRelationships = await listAllRelations(context, SYSTEM_USER, RELATION_TARGETS, args);
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
  const groupsOfOperations = R.splitEvery(MAX_BULK_OPERATIONS, bulkOperationsTargets);
  const concurrentUpdate = async (bulk) => {
    await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bulk });
    currentProcessing += bulk.length;
    logMigration.info(`[OPENCTI] Re-indexing targets for region / countries / sectors ${currentProcessing} / ${bulkOperationsTargets.length}`);
  };
  await Promise.map(groupsOfOperations, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  logMigration.info(`[MIGRATION] Re-indexed targets for region / countries / sectors in ${new Date() - startTargets} ms`);
  next();
};

export const down = async (next) => {
  next();
};
