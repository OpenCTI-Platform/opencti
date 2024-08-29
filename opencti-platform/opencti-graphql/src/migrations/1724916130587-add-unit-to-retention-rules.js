import { logApp } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_DATA_INDICES } from '../database/utils';

const message = '[MIGRATION] Add unit "days" to retention rules with no unit';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const updateQuery = {
    script: {
      params: { days: 'days' },
      source: 'ctx._source.retention_unit = params.days',
    },
    query: {
      bool: {
        must: [{ term: { 'entity_type.keyword': { value: 'RetentionRule' } } }],
        must_not: [{ exists: { field: 'retention_unit' } }],
      },
    },
  };
  await elUpdateByQueryForMigration(
    message,
    READ_DATA_INDICES,
    updateQuery
  );
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
