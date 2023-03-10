import * as R from 'ramda';
import { Promise as BluePromise } from 'bluebird';
import { listAllEntities } from '../database/middleware-loader';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_HISTORY } from '../schema/internalObject';
import { READ_INDEX_HISTORY } from '../database/utils';
import { elLoadById, elUpdate, ES_MAX_CONCURRENCY } from '../database/engine';
import { logApp } from '../config/conf';

export const up = async (next) => {
  const context = executionContext('migration');
  logApp.info('[OPENCTI] Migration denormalized cleanup started');
  const mergedEvents = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_HISTORY], {
    indices: [READ_INDEX_HISTORY],
    filters: [{ key: 'event_type', values: ['merge'] }],
    orderBy: 'created_at',
    orderMode: 'asc'
  });
  let currentProcessing = 0;
  const filteredElementsIds = R.uniq(mergedEvents.map((event) => event.context_data.id));
  logApp.info(`[OPENCTI] Migration denormalized cleanup find ${filteredElementsIds.length} to clean`);
  const concurrentUpdate = async (mergedId) => {
    const data = await elLoadById(context, SYSTEM_USER, mergedId);
    if (data) {
      const params = {};
      for (let i = 0; i < Object.keys(data).length; i += 1) {
        const key = Object.keys(data)[i];
        if (key.startsWith('rel_')) {
          params[key] = Array.isArray(data[key]) ? data[key].flat() : data[key];
        }
      }
      await elUpdate(data._index, mergedId, {
        script: {
          source: 'for (key in ctx._source.keySet()) { '
                + "if (key.startsWith('rel_')) { "
                    + 'ctx._source[key] = params[key];'
                + '}'
            + '}',
          lang: 'painless',
          params,
        }
      });
    }
    currentProcessing += 1;
    logApp.info(`[OPENCTI] Cleaning denormalized relations ids: ${currentProcessing} / ${filteredElementsIds.length}`);
  };
  await BluePromise.map(filteredElementsIds, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  logApp.info('[OPENCTI] Migration denormalized cleanup done');
  next();
};

export const down = async (next) => {
  next();
};
