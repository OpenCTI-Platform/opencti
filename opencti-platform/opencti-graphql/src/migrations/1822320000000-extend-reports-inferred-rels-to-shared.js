import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { listAllEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';

const message = '[MIGRATION] Extend inferred relationships in reports to shared organizations';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration', SYSTEM_USER);

  const reports = await listAllEntities(
    context,
    context.user,
    [ENTITY_TYPE_CONTAINER_REPORT],
    {
      filters: {
        filterGroups: [],
        mode: 'and',
        filters: [
          { key: 'objectOrganization', values: [], operator: 'not_nil' }
        ]
      }
    }
  );
  console.log(reports);

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
