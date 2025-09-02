import { booleanConf, logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

const message = '[MIGRATION] adding ai configuration in settings';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const isAiInsightEnabled = booleanConf('ai:enabled', true);
  const updateQuery = {
    script: {
      source: `ctx._source.filigran_chatbot_ai_cgu_status = "pending"; ctx._source.platform_ai_enabled = ${isAiInsightEnabled};`,
    },
    query: {
      term: { 'entity_type.keyword': { value: 'Settings' } }
    },
  };
  await elUpdateByQueryForMigration(
    message,
    READ_INDEX_INTERNAL_OBJECTS,
    updateQuery
  );
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
