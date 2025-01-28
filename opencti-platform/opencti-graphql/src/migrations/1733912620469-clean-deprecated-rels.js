import * as R from 'ramda';
import { Promise } from 'bluebird';
import { logMigration } from '../config/conf';
import { BULK_TIMEOUT, elBulk, elFindByIds, elList, elUpdateByQueryForMigration, ES_MAX_CONCURRENCY, MAX_BULK_OPERATIONS } from '../database/engine';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { executionContext, SYSTEM_USER } from '../utils/access';
import {
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP
} from '../schema/stixDomainObject';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../modules/threatActorIndividual/threatActorIndividual-types';
import { ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, isStixCyberObservable } from '../schema/stixCyberObservable';

const message = '[MIGRATION] Cleaning deprecated rels';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  // 1st pass
  // Cleaning all threats from any re_related-to related to observables
  logMigration.info('[OPENCTI] Cleaning deprecated rels for observable related-to...');
  const relKeyRelatedTo = 'rel_related-to.internal_id';
  const bulkOperationsRelatedTo = [];
  const startRelatedTo = new Date().getTime();
  const clearRelatedToObservableRels = async (threats) => {
    let currentProcessingThreats = 0;
    for (let i = 0; i < threats.length; i += 1) {
      logMigration.info(`[OPENCTI] Cleaning deprecated rels for related-to ${currentProcessingThreats} / ${threats.length}`);
      const threat = threats[i];
      const relatedToIds = threat[relKeyRelatedTo] ?? [];
      const newIds = [];
      const groupIds = R.splitEvery(5000, relatedToIds);
      for (let index = 0; index < groupIds.length; index += 1) {
        const workingIds = groupIds[index];
        const entitiesBaseData = await elFindByIds(context, SYSTEM_USER, workingIds, { baseData: true });
        const entitiesIdsWithoutObservables = entitiesBaseData.filter((n) => !isStixCyberObservable(n.entity_type)).map((n) => n.internal_id);
        newIds.push(...entitiesIdsWithoutObservables);
      }
      if (newIds.length > 0) {
        const updateQuery = [
          { update: { _index: threat._index, _id: threat._id, retry_on_conflict: 5 } },
          { doc: { [relKeyRelatedTo]: newIds } },
        ];
        bulkOperationsRelatedTo.push(...updateQuery);
      } else {
        const updateQuery = [
          { update: { _index: threat._index, _id: threat._id, retry_on_conflict: 5 } },
          { script: `ctx._source.remove('${relKeyRelatedTo}')` }
        ];
        bulkOperationsRelatedTo.push(...updateQuery);
      }
      currentProcessingThreats += 1;
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
  const optsRelatedTo = { types: threatTypes, callback: clearRelatedToObservableRels };
  await elList(context, SYSTEM_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, optsRelatedTo);
  // Apply operations.
  let currentProcessingRelatedTo = 0;
  const groupsOfOperationsRelatedTo = R.splitEvery(MAX_BULK_OPERATIONS, bulkOperationsRelatedTo);
  const concurrentUpdateRelatedTo = async (bulk) => {
    await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bulk });
    currentProcessingRelatedTo += bulk.length;
    logMigration.info(`[OPENCTI] Cleaning deprecated rels for observable related-to ${currentProcessingRelatedTo} / ${bulkOperationsRelatedTo.length}`);
  };
  await Promise.map(groupsOfOperationsRelatedTo, concurrentUpdateRelatedTo, { concurrency: ES_MAX_CONCURRENCY });
  logMigration.info(`[MIGRATION] Cleaning deprecated rels for observable related-to done in ${new Date() - startRelatedTo} ms`);

  // 2nd pass
  // Cleaning located-at when pointing a country or a region
  logMigration.info('[OPENCTI] Cleaning deprecated rels for located-at...');
  const relKeyLocatedAt = 'rel_located-at.internal_id';
  const bulkOperationsLocatedAt = [];
  const startLocatedAt = new Date().getTime();
  const cleanTypes = [ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_TYPE_LOCATION_CITY];
  const clearLocatedAtRegionAndCountryRels = async (locations) => {
    let currentProcessingLocations = 0;
    for (let i = 0; i < locations.length; i += 1) {
      logMigration.info(`[OPENCTI] Cleaning deprecated rels for located-at ${currentProcessingLocations} / ${locations.length}`);
      const location = locations[i];
      const locatedAtIds = location[relKeyLocatedAt] ?? [];
      const newIds = [];
      const groupIds = R.splitEvery(5000, locatedAtIds);
      for (let index = 0; index < groupIds.length; index += 1) {
        const workingIds = groupIds[index];
        const entitiesBaseData = await elFindByIds(context, SYSTEM_USER, workingIds, { baseData: true });
        const entitiesIdsOnlyWithoutClearedTypes = entitiesBaseData.filter((n) => !cleanTypes.includes(n.entity_type)).map((n) => n.internal_id);
        newIds.push(...entitiesIdsOnlyWithoutClearedTypes);
      }
      if (newIds.length > 0) {
        const updateQuery = [
          { update: { _index: location._index, _id: location._id, retry_on_conflict: 5 } },
          { doc: { [relKeyLocatedAt]: newIds } },
        ];
        bulkOperationsLocatedAt.push(...updateQuery);
      } else {
        const updateQuery = [
          { update: { _index: location._index, _id: location._id, retry_on_conflict: 5 } },
          { script: `ctx._source.remove('${relKeyLocatedAt}')` }
        ];
        bulkOperationsLocatedAt.push(...updateQuery);
      }
      currentProcessingLocations += 1;
    }
  };
  const opts = { types: [ENTITY_TYPE_LOCATION_REGION, ENTITY_TYPE_LOCATION_COUNTRY], callback: clearLocatedAtRegionAndCountryRels };
  await elList(context, SYSTEM_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, opts);
  // Apply operations.
  let currentProcessing = 0;
  const groupsOfOperations = R.splitEvery(MAX_BULK_OPERATIONS, bulkOperationsLocatedAt);
  const concurrentUpdate = async (bulk) => {
    await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bulk });
    currentProcessing += bulk.length;
    logMigration.info(`[OPENCTI] Cleaning deprecated rels for located-at to country / region ${currentProcessing} / ${bulkOperationsLocatedAt.length}`);
  };
  await Promise.map(groupsOfOperations, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  logMigration.info(`[MIGRATION] Cleaning deprecated rels for located-at to country / region in ${new Date() - startLocatedAt} ms`);

  // 3rd pass
  // Cleaning all targets to countries, regions and sectors
  logMigration.info('[OPENCTI] Cleaning deprecated rels for targets...');
  const updateQueryForTargets = {
    script: {
      params: { fieldToRemove: 'rel_targets.internal_id' },
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
          {
            bool: {
              must: [{ term: { 'entity_type.keyword': { value: ENTITY_TYPE_IDENTITY_SECTOR } } }],
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

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
