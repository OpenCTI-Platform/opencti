import * as R from 'ramda';
import { Promise } from 'bluebird';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_CONTAINER_NOTE } from '../schema/stixDomainObject';
import { BULK_TIMEOUT, elBulk, elList, ES_MAX_CONCURRENCY, MAX_BULK_OPERATIONS } from '../database/engine';
import { generateStandardId } from '../schema/identifier';
import { logApp, logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { pushAll } from '../utils/arrayUtil';

const message = '[MIGRATION] Rewriting standard ids for Notes to include attribute_abstract';

export const up = async (next) => {
  const context = executionContext('migration');
  const start = new Date().getTime();
  logMigration.info(`${message} > started`);
  const bulkOperations = [];
  const callback = (notes) => {
    const op = notes
      .map((note) => {
        const newId = generateStandardId(note.entity_type, note);
        if (newId === note.standard_id) {
          return [];
        }
        const previousStixIds = note.x_opencti_stix_ids ?? [];
        const updatedStixIds = R.uniq([...previousStixIds, note.standard_id]);
        return [
          { update: { _index: note._index, _id: note._id } },
          { doc: { standard_id: newId, x_opencti_stix_ids: updatedStixIds } },
        ];
      })
      .flat();
    pushAll(bulkOperations, op);
  };
  const opts = { types: [ENTITY_TYPE_CONTAINER_NOTE], callback };
  await elList(context, SYSTEM_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, opts);
  let currentProcessing = 0;
  const groupsOfOperations = R.splitEvery(MAX_BULK_OPERATIONS, bulkOperations);
  const concurrentUpdate = async (bulk) => {
    await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bulk });
    currentProcessing += bulk.length;
    logApp.info(`[OPENCTI] Rewriting Note standard ids: ${currentProcessing} / ${bulkOperations.length}`);
  };
  await Promise.map(groupsOfOperations, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  logMigration.info(`${message} > done in ${new Date().getTime() - start} ms`);
  next();
};

export const down = async (next) => {
  next();
};
