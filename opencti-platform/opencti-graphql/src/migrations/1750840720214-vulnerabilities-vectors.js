import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_PLATFORM_INDICES } from '../database/utils';

const message = '[MIGRATION] Copy CVSS vector fields to *_string fields';

export const up = async (next) => {
  logMigration.info(`${message} > started`);

  const updateQuery = {
    script: {
      source: `
        if (ctx._source.containsKey('x_opencti_cvss_vector')) {
          ctx._source.x_opencti_cvss_vector_string = ctx._source.x_opencti_cvss_vector;
        }
        if (ctx._source.containsKey('x_opencti_cvss_v2_vector')) {
          ctx._source.x_opencti_cvss_v2_vector_string = ctx._source.x_opencti_cvss_v2_vector;
        }
        if (ctx._source.containsKey('x_opencti_cvss_v4_vector')) {
          ctx._source.x_opencti_cvss_v4_vector_string = ctx._source.x_opencti_cvss_v4_vector;
        }
      `
    },
    query: {
      bool: {
        should: [
          { exists: { field: 'x_opencti_cvss_vector' } },
          { exists: { field: 'x_opencti_cvss_v2_vector' } },
          { exists: { field: 'x_opencti_cvss_v4_vector' } }
        ],
        minimum_should_match: 1
      }
    }
  };

  await elUpdateByQueryForMigration(message, READ_PLATFORM_INDICES, updateQuery);
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
