import { logApp } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_HISTORY } from '../database/utils';

export const up = async (next) => {
  logApp.info('[MIGRATION] Starting the migration of truncating history message');
  await elUpdateByQueryForMigration('[MIGRATION] Truncating history message', READ_INDEX_HISTORY, {
    script: {
      source: "def message = ctx._source.context_data.message.substring(0, (int)Math.min(160, ctx._source.context_data.message.length())); if (message.indexOf('in `object_refs`') == -1) { ctx._source.context_data.message = message + (message.endsWith('`') ? '' : '...`') + ' in `object_refs`' }",
    },
    query: {
      bool: {
        must: [{
          bool: {
            should: [{
              multi_match: {
                fields: ['event_type.keyword'],
                query: 'update'
              }
            }]
          }
        }, {
          bool: {
            should: [{
              query_string: {
                query: '"*in `object_refs`"',
                fields: ['context_data.message']
              }
            }]
          }
        }]
      }
    }
  });
  logApp.info('[MIGRATION] End truncating history message');
  next();
};

export const down = async (next) => {
  next();
};
