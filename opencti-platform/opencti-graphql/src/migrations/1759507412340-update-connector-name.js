import { logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { connectors } from '../database/repository';
import { patchAttribute } from '../database/middleware';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';

const message = '[MIGRATION] connector update container_name with title';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  const connectorsList = await connectors(context, SYSTEM_USER);

  const managedConnectors = connectorsList.filter((connector) => connector.is_managed);
  logMigration.info(`${message} > updating ${managedConnectors.length} managed connectors`);

  await Promise.all(
    managedConnectors.map(async (connector) => {
      try {
        const patch = {
          container_name: connector.name,
          name: connector.title || connector.manager_contract_excerpt?.title
        };

        await patchAttribute(context, SYSTEM_USER, connector.id, ENTITY_TYPE_CONNECTOR, patch);
      } catch (error) {
        logMigration.error(`${message} > failed to update connector ${connector.id}`, { error });
      }
    })
  );

  // do your migration
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
