import * as R from 'ramda';
import { Promise } from 'bluebird';
import { logApp, logMigration } from '../config/conf';
import { elBulk, elList, BULK_TIMEOUT, MAX_BULK_OPERATIONS, ES_MAX_CONCURRENCY } from '../database/engine';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { pushAll } from '../utils/arrayUtil';

const message = '[MIGRATION] Migration of decay_observable_types to decay_filters';

export const up = async (next) => {
  const context = executionContext('migration');
  const start = new Date().getTime();
  logMigration.info(`${message} > started`);

  const bulkOperations = [];
  const callback = (rules) => {
    const op = rules
      .filter((rule) => rule.decay_observable_types !== undefined)
      .map((rule) => {
        let generatedFilters = '';
        if (rule.decay_observable_types && rule.decay_observable_types.length > 0) {
          generatedFilters = JSON.stringify({
            mode: 'and',
            filters: [
              {
                key: ['x_opencti_main_observable_type'],
                operator: 'eq',
                values: rule.decay_observable_types,
                mode: 'or',
              },
            ],
            filterGroups: [],
          });
        }

        return [
          { update: { _index: rule._index, _id: rule._id } },
          {
            script: {
              source: "ctx._source.decay_filters = params.decay_filters; ctx._source.remove('decay_observable_types');",
              params: { decay_filters: generatedFilters },
            },
          },
        ];
      })
      .flat();
    pushAll(bulkOperations, op);
  };

  const opts = { types: ['DecayRule'], callback };
  await elList(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, opts);

  let currentProcessing = 0;
  const groupsOfOperations = R.splitEvery(MAX_BULK_OPERATIONS, bulkOperations);
  const concurrentUpdate = async (bulk) => {
    if (bulk.length > 0) {
      await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bulk });
      currentProcessing += bulk.length / 2;
      logApp.info(`[OPENCTI] Migrating decay rule filters: ${currentProcessing} / ${bulkOperations.length / 2}`);
    }
  };

  await Promise.map(groupsOfOperations, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });

  logMigration.info(`${message} > done in ${new Date().getTime() - start} ms`);
  next();
};

export const down = async (next) => {
  next();
};
