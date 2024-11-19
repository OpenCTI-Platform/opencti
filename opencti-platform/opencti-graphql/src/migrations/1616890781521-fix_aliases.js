import * as R from 'ramda';
import { Promise } from 'bluebird';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { BULK_TIMEOUT, elBulk, elList, ES_MAX_CONCURRENCY, MAX_BULK_OPERATIONS } from '../database/engine';
import { generateStandardId, idGen, normalizeName } from '../schema/identifier';
import { logApp } from '../config/conf';
import { ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION, OPENCTI_NAMESPACE } from '../schema/general';
import { isStixDomainObjectIdentity } from '../schema/stixDomainObject';
import { executionContext, SYSTEM_USER } from '../utils/access';

const generateAliases = (aliases, additionalFields = {}) => {
  return R.map((a) => {
    const dataUUID = { name: normalizeName(a), ...additionalFields };
    const uuid = idGen('ALIAS', dataUUID, OPENCTI_NAMESPACE);
    return `aliases--${uuid}`;
  }, aliases);
};

export const up = async (next) => {
  const context = executionContext('migration');
  const start = new Date().getTime();
  logApp.info('[MIGRATION] Rewriting i_aliases_ids for Locations and Identities');
  const bulkOperations = [];
  const callback = (entities) => {
    const op = entities
      .map((entity) => {
        if (isStixDomainObjectIdentity(entity.entity_type)) {
          const newStandardId = generateStandardId(
            entity.entity_type,
            R.assoc('identity_class', entity.identity_class === 'sector' ? 'class' : entity.identity_class, entity)
          );
          const newAliasIds = generateAliases([entity.name, ...(entity.x_opencti_aliases || [])], {
            identity_class: entity.identity_class === 'sector' ? 'class' : entity.identity_class,
          });
          return [
            { update: { _index: entity._index, _id: entity.id } },
            {
              doc: {
                i_aliases_ids: newAliasIds,
                // Fix bad identity class....
                identity_class: entity.identity_class === 'sector' ? 'class' : entity.identity_class,
                standard_id: newStandardId,
                x_opencti_stix_ids: [],
              },
            },
          ];
        }
        const newAliasIds = generateAliases([entity.name, ...(entity.x_opencti_aliases || [])], {
          x_opencti_location_type: entity.x_opencti_location_type,
        });
        return [{ update: { _index: entity._index, _id: entity.id } }, { doc: { i_aliases_ids: newAliasIds } }];
      })
      .flat();
    bulkOperations.push(...op);
  };
  const opts = { types: [ENTITY_TYPE_LOCATION, ENTITY_TYPE_IDENTITY], callback };
  await elList(context, SYSTEM_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, opts);
  // Apply operations.
  let currentProcessing = 0;
  const groupsOfOperations = R.splitEvery(MAX_BULK_OPERATIONS, bulkOperations);
  const concurrentUpdate = async (bulk) => {
    await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bulk });
    currentProcessing += bulk.length;
    logApp.info(`[OPENCTI] Rewriting i_aliases_ids: ${currentProcessing} / ${bulkOperations.length}`);
  };
  await Promise.map(groupsOfOperations, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  logApp.info(`[MIGRATION] Rewriting i_aliases_ids done in ${new Date() - start} ms`);
  next();
};

export const down = async (next) => {
  next();
};
