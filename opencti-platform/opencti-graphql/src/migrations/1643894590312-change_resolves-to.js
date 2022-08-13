import * as R from 'ramda';
import { Promise } from 'bluebird';
import { READ_RELATIONSHIPS_INDICES } from '../database/utils';
import { BULK_TIMEOUT, elBulk, elUpdateByQueryForMigration, ES_MAX_CONCURRENCY, MAX_SPLIT } from '../database/engine';
import { logApp } from '../config/conf';

export const up = async (next) => {
  const start = new Date().getTime();
  logApp.info('[MIGRATION] Rewriting resolves-to relationships');
  const bulkOperations = [];
  // Old type
  // Apply operations.
  let currentProcessing = 0;
  const groupsOfOperations = R.splitEvery(MAX_SPLIT, bulkOperations);
  const concurrentUpdate = async (bulk) => {
    await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bulk });
    currentProcessing += bulk.length;
    logApp.info(`[OPENCTI] Rewriting IDs and types: ${currentProcessing} / ${bulkOperations.length}`);
  };
  await Promise.map(groupsOfOperations, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  logApp.info(`[MIGRATION] Rewriting IDs and types done in ${new Date() - start} ms`);
  const source = `if (ctx._source.entity_type == params.type) {
      ctx._source.entity_type = params.targetType;
    }
    if (ctx._source.relationship_type == params.type) {
      ctx._source.relationship_type = params.targetType;
    }
    for (connection in ctx._source.connections) {
      if (connection.role == params.roleFrom ) {
        connection.role = params.targetRoleFrom;
      }
      if (connection.role == params.roleTo ) {
        connection.role = params.targetRoleTo;
      }
  }`;
  const startMigrateRelationships = new Date().getTime();
  const updateQuery = {
    script: {
      source,
      params: {
        type: 'resolves-to',
        targetType: 'obs_resolves-to',
        roleFrom: 'resolves-to_from',
        targetRoleFrom: 'obs_resolves-to_from',
        roleTo: 'resolves-to_to',
        targetRoleTo: 'obs_resolves-to_to',
      },
    },
    query: {
      bool: {
        must: [{ match_phrase: { relationship_type: 'resolves-to' } }],
      },
    },
  };
  await elUpdateByQueryForMigration(
    '[MIGRATION] Migrating relationships connections',
    READ_RELATIONSHIPS_INDICES,
    updateQuery
  );
  logApp.info(`[MIGRATION] Migrating all relationships connections done in ${new Date() - startMigrateRelationships} ms`);
  next();
};

export const down = async (next) => {
  next();
};
