import { logApp } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_HISTORY } from '../database/utils';

export const up = async (next) => {
  logApp.info('[MIGRATION] Starting the migration of truncating history message');
  await elUpdateByQueryForMigration('[MIGRATION] Truncating history message', READ_INDEX_HISTORY, {
    script: {
      // Keep the data length under 512 chars
      source: "def size = ctx._source.context_data.message.length(); if (size > 512) { def message = ctx._source.context_data.message.substring(size - 498, size); ctx._source.context_data.message = (message.startsWith('`') ? 'changes ... ' : 'changes ... `') + message}",
    },
    query: {
      bool: {
        must_not: [
          {
            exists: {
              field: 'context_data.message.keyword' // Keyword is not available for field size > 512
            }
          }
        ],
        must: [
          {
            match: {
              entity_type: 'History' // Prevent work fetching
            }
          }, {
            bool: {
              should: [{
                multi_match: {
                  fields: ['event_type.keyword'],
                  query: 'update' // Only update must be cleaned
                }
              }]
            }
          }
        ]
      }
    }
  });
  logApp.info('[MIGRATION] End truncating history message');
  next();
};

export const down = async (next) => {
  next();
};
