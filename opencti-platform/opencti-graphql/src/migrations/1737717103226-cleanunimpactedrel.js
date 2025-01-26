import * as R from 'ramda';
import { Promise } from 'bluebird';
import { logApp } from '../config/conf';
import { BULK_TIMEOUT, elBulk, elFindByIds, elList, elUpdateByQueryForMigration, ES_MAX_CONCURRENCY, MAX_BULK_OPERATIONS } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { executionContext, SYSTEM_USER } from '../utils/access';
import {
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP
} from '../schema/stixDomainObject';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../modules/threatActorIndividual/threatActorIndividual-types';
import { isStixCyberObservable } from '../schema/stixCyberObservable';

const message = '[MIGRATION] Cleaning deprecated rels';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // 1st pass
  // Cleaning all threats from any re_related-to related to observables
  const rel_key = 'rel_related-to.internal_id';
  const bulkOperations = [];
  const start = new Date().getTime();
  const clearRelatedToObservableRels = async (threats) => {
    for (let i = 0; i < threats.length; i += 1) {
      const threat = threats[i];
      const relatedToIds = threat[rel_key] ?? [];
      const newIds = [];
      const groupIds = R.splitEvery(5000, relatedToIds);
      for (let index = 0; index < groupIds.length; index += 1) {
        const workingIds = groupIds[index];
        const entitiesBaseData = await elFindByIds(context, SYSTEM_USER, workingIds, { baseData: true });
        newIds.push(...entitiesBaseData.filter((n) => !isStixCyberObservable(n.entity_type)).map((n) => n.internal_id));
      }
      if (newIds.length > 0) {
        const updateQuery = [
          { update: { _index: threat._index, _id: threat.internal_id, retry_on_conflict: 5 } },
          { doc: { [rel_key]: newIds } },
        ];
        bulkOperations.push(...updateQuery);
      } else {
        const updateQuery = [
          { update: { _index: threat._index, _id: threat.internal_id, retry_on_conflict: 5 } },
          { script: `ctx._source.remove('${rel_key}')` }
        ];
        bulkOperations.push(...updateQuery);
      }
    }
  };
  const threatTypes = [
    ENTITY_TYPE_THREAT_ACTOR_GROUP,
    ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL,
    ENTITY_TYPE_INTRUSION_SET,
    ENTITY_TYPE_CAMPAIGN,
    ENTITY_TYPE_MALWARE,
    ENTITY_TYPE_INCIDENT,
  ];
  const opts = { types: threatTypes, callback: clearRelatedToObservableRels };
  await elList(context, SYSTEM_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, opts);
  // Apply operations.
  let currentProcessing = 0;
  const groupsOfOperations = R.splitEvery(MAX_BULK_OPERATIONS, bulkOperations);
  const concurrentUpdate = async (bulk) => {
    await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bulk });
    currentProcessing += bulk.length;
    logApp.info(`[OPENCTI] Cleaning deprecated rels for observable related-to ${currentProcessing} / ${bulkOperations.length}`);
  };
  await Promise.map(groupsOfOperations, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  logApp.info(`[MIGRATION] Cleaning deprecated rels for observable related-to done in ${new Date() - start} ms`);

  // 2nd pass
  // Cleaning all locations
  const updateQueryForLocatedAt = {
    script: {
      params: { fieldToRemove: 'rel_located-at' },
      source: 'ctx._source.remove(params.fieldToRemove)',
    },
    query: {
      bool: {
        should: [
          {
            bool: {
              must: [{ term: { 'entity_type.keyword': { value: ENTITY_TYPE_LOCATION_REGION } } }],
            }
          },
          {
            bool: {
              must: [{ term: { 'entity_type.keyword': { value: ENTITY_TYPE_LOCATION_COUNTRY } } }],
            }
          },
        ],
        minimum_should_match: 1,
      },
    },
  };
  await elUpdateByQueryForMigration(
    message,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    updateQueryForLocatedAt
  );

  // 3rd pass
  // Cleaning all locations
  const updateQueryForTargets = {
    script: {
      params: { fieldToRemove: 'rel_targets' },
      source: 'ctx._source.remove(params.fieldToRemove)',
    },
    query: {
      bool: {
        should: [
          {
            bool: {
              must: [{ term: { 'entity_type.keyword': { value: ENTITY_TYPE_LOCATION_REGION } } }],
            }
          },
          {
            bool: {
              must: [{ term: { 'entity_type.keyword': { value: ENTITY_TYPE_LOCATION_COUNTRY } } }],
            }
          },
        ],
        minimum_should_match: 1,
      },
    },
  };
  await elUpdateByQueryForMigration(
    message,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    updateQueryForTargets
  );
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
