import { logApp } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_DATA_INDICES } from '../database/utils';

export const up = async (next) => {
  logApp.info('[MIGRATION] Starting 1652175522433-main_observable_rename.js');
  // Migration x_opencti_main_observable_type attribute
  const entities = [
    { source: 'X-OpenCTI-Cryptographic-Key', destination: 'Cryptographic-Key' },
    { source: 'X-OpenCTI-Cryptocurrency-Wallet', destination: 'Cryptocurrency-Wallet' },
    { source: 'X-OpenCTI-Hostname', destination: 'Hostname' },
    { source: 'X-OpenCTI-Text', destination: 'Text' },
    { source: 'X-OpenCTI-User-Agent', destination: 'User-Agent' },
  ];
  for (let index = 0; index < entities.length; index += 1) {
    const { source, destination } = entities[index];
    const updateQuery = {
      script: {
        params: { name: destination },
        source: 'ctx._source.x_opencti_main_observable_type = params.name;',
      },
      query: {
        bool: {
          must: [
            { term: { 'x_opencti_main_observable_type.keyword': { value: source } } },
          ],
        },
      },
    };
    await elUpdateByQueryForMigration(
      `[MIGRATION] Renaming main observable ${source}`,
      READ_DATA_INDICES,
      updateQuery
    );
  }
  // Migrate pattern attribute.
  for (let index = 0; index < entities.length; index += 1) {
    const { source, destination } = entities[index];
    const updateQuery = {
      script: {
        params: { from: source.toLowerCase(), to: destination.toLowerCase() },
        source: 'ctx._source.pattern = ctx._source.pattern.replace(params.from, params.to)',
      },
      query: {
        wildcard: {
          'pattern.keyword': {
            value: `[${source.toLowerCase()}:value*`
          }
        }
      }
    };
    await elUpdateByQueryForMigration(
      `[MIGRATION] Migrating pattern [${source.toLowerCase()}:value = *****]`,
      READ_DATA_INDICES,
      updateQuery
    );
  }
  logApp.info('[MIGRATION] 1652175522433-main_observable_rename.js finished');
  next();
};

export const down = async (next) => {
  next();
};
