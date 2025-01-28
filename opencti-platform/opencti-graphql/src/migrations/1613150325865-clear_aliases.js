import * as R from 'ramda';
import { Promise } from 'bluebird';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../schema/stixDomainObject';
import { BULK_TIMEOUT, elBulk, elList, ES_MAX_CONCURRENCY, MAX_BULK_OPERATIONS } from '../database/engine';
import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';

export const up = async (next) => {
  const context = executionContext('migration');
  const start = new Date().getTime();
  logApp.info('[MIGRATION] Cleaning aliases and STIX IDs (pass 2) of Attack Patterns');
  const bulkOperations = [];
  const callback = (attacks) => {
    const op = attacks
      .map((att) => {
        return [
          { update: { _index: att._index, _id: att._id } },
          { doc: { aliases: [], i_aliases_ids: [], x_opencti_stix_ids: [] } },
        ];
      })
      .flat();
    bulkOperations.push(...op);
  };
  const opts = { types: [ENTITY_TYPE_ATTACK_PATTERN], callback };
  await elList(context, SYSTEM_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, opts);
  // Apply operations.
  let currentProcessing = 0;
  const groupsOfOperations = R.splitEvery(MAX_BULK_OPERATIONS, bulkOperations);
  const concurrentUpdate = async (bulk) => {
    await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bulk });
    currentProcessing += bulk.length;
    logApp.info(`[OPENCTI] Cleaning aliases and STIX IDs (pass 2) ${currentProcessing} / ${bulkOperations.length}`);
  };
  await Promise.map(groupsOfOperations, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  logApp.info(`[MIGRATION] Cleaning aliases and STIX IDs (pass 2) of attack patterns done in ${new Date() - start} ms`);
  next();
};

export const down = async (next) => {
  next();
};
