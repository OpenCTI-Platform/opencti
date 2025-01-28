import * as R from 'ramda';
import { Promise } from 'bluebird';
import { READ_INDEX_STIX_DOMAIN_OBJECTS, READ_RELATIONSHIPS_INDICES } from '../database/utils';
import { BULK_TIMEOUT, elBulk, elList, elUpdateByQueryForMigration, ES_MAX_CONCURRENCY, MAX_BULK_OPERATIONS } from '../database/engine';
import { generateStandardId } from '../schema/identifier';
import { logApp } from '../config/conf';
import { ENTITY_TYPE_INCIDENT } from '../schema/stixDomainObject';
import { executionContext, SYSTEM_USER } from '../utils/access';

export const up = async (next) => {
  const context = executionContext('migration');
  const start = new Date().getTime();
  logApp.info('[MIGRATION] Rewriting IDs and types of Incidents');
  const bulkOperations = [];
  const callback = (entities) => {
    const op = entities
      .map((entity) => {
        const newStandardId = generateStandardId(ENTITY_TYPE_INCIDENT, entity);
        return [
          { update: { _index: entity._index, _id: entity._id } },
          {
            doc: {
              // Fix bad fields
              entity_type: ENTITY_TYPE_INCIDENT,
              standard_id: newStandardId,
            },
          },
        ];
      })
      .flat();
    bulkOperations.push(...op);
  };
  // Old type
  const opts = { types: ['X-OpenCTI-Incident'], callback };
  await elList(context, SYSTEM_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, opts);
  // Apply operations.
  let currentProcessing = 0;
  const groupsOfOperations = R.splitEvery(MAX_BULK_OPERATIONS, bulkOperations);
  const concurrentUpdate = async (bulk) => {
    await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bulk });
    currentProcessing += bulk.length;
    logApp.info(`[OPENCTI] Rewriting IDs and types: ${currentProcessing} / ${bulkOperations.length}`);
  };
  await Promise.map(groupsOfOperations, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  logApp.info(`[MIGRATION] Rewriting IDs and types done in ${new Date() - start} ms`);
  const source = `if (ctx._source.fromType == params.type) {
      ctx._source.fromType = params.target;
    }
    if (ctx._source.toType == params.type) {
      ctx._source.toType = params.target;
    }
    for(connection in ctx._source.connections) {
      def values = [];
      for(current in connection.types) {
        if( current != params.type ) {
          values.add(current);
        } else {
          values.add(params.target);
        }
      }
      connection.types = values;
  }`;
  const startMigrateRelationships = new Date().getTime();
  const updateQuery = {
    script: { source, params: { type: 'X-OpenCTI-Incident', target: 'Incident' } },
    query: {
      nested: {
        path: 'connections',
        query: {
          bool: {
            must: [{ match_phrase: { 'connections.types': 'X-OpenCTI-Incident' } }],
          },
        },
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
