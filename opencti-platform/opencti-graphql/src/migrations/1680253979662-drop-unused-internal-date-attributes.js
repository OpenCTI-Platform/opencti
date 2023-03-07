import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_DATA_INDICES } from '../database/utils';
import { logApp } from '../config/conf';

const statsDateAttributes = [
  'created_at',
  'first_seen',
  'last_seen',
  'start_time',
  'stop_time',
  'published',
  'valid_from',
  'valid_until',
  'first_observed',
  'last_observed',
];

export const up = async (next) => {
  const buildStatsDateAttributes = statsDateAttributes.map((attr) => [
    `i_${attr}_day`,
    `i_${attr}_month`,
    `i_${attr}_year`,
  ])
    .flat();
  logApp.info('[MIGRATION] Starting 1679409198437-drop-unused-internal-date-attributes.js');
  const source = buildStatsDateAttributes.map((attr) => `ctx._source.remove('${attr}')`).join(';');
  const shouldArray = buildStatsDateAttributes.map((attr) => {
    return {
      exists: {
        field: attr
      }
    };
  });
  const updateQuery = {
    script: { source },
    query: {
      bool: {
        should: shouldArray
      }
    }
  };

  await elUpdateByQueryForMigration('[MIGRATION] Dropping unused split date attributes', READ_DATA_INDICES, updateQuery);
  logApp.info('[MIGRATION] 1679409198437-drop-unused-internal-date-attributes.js finished');
  next();
};

export const down = async (next) => {
  next();
};
