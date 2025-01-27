import * as R from 'ramda';
import { Promise } from 'bluebird';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { BULK_TIMEOUT, elBulk, elList, ES_MAX_CONCURRENCY, MAX_BULK_OPERATIONS } from '../database/engine';
import { generateStandardId } from '../schema/identifier';
import { logApp } from '../config/conf';
import { ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION } from '../schema/general';
import { executionContext, SYSTEM_USER } from '../utils/access';

export const up = async (next) => {
  const context = executionContext('migration');
  const start = new Date().getTime();
  logApp.info('[MIGRATION] Rewriting standard ids for Locations and Identities');
  const bulkOperations = [];
  const callback = (attacks) => {
    const op = attacks
      .map((att) => {
        const newId = generateStandardId(att.entity_type, att);
        return [
          { update: { _index: att._index, _id: att._id } },
          { doc: { standard_id: newId, x_opencti_stix_ids: [] } },
        ];
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
    logApp.info(`[OPENCTI] Rewriting standard ids: ${currentProcessing} / ${bulkOperations.length}`);
  };
  await Promise.map(groupsOfOperations, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  logApp.info(`[MIGRATION] Rewriting standard ids done in ${new Date() - start} ms`);
  next();
};

export const down = async (next) => {
  next();
};
