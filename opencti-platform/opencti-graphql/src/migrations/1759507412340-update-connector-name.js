import { logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { connectors } from '../database/repository';
import { patchAttribute } from '../database/middleware';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { DatabaseError } from '../config/errors';

const message = '[MIGRATION] connector update container_name with title';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  const connectorsList = await connectors(context, SYSTEM_USER);

  const managedConnectors = connectorsList.filter((connector) => connector.is_managed);
  logMigration.info(`${message} > found ${managedConnectors.length} managed connectors to update`);

  let successCount = 0;

  await Promise.all(
    managedConnectors.map(async (connector) => {
      try {
        // Log connector details for debugging
        logMigration.info(`${message} > processing connector ${connector.id}`, {
          internal_id: connector.internal_id,
          name: connector.name,
          title: connector.title,
        });

        const internalId = connector.internal_id;

        const containerNameSuffix = internalId.substring(0, 8);
        const newName = connector.title || connector.manager_contract_excerpt?.title || connector.name;

        const patch = {
          container_name: `${connector.name}-${containerNameSuffix}`,
          name: newName
        };

        logMigration.info(`${message} > applying patch to connector ${connector.id}`, patch);
        await patchAttribute(context, SYSTEM_USER, connector.id, ENTITY_TYPE_CONNECTOR, patch);
        successCount += 1;
      } catch (error) {
        throw DatabaseError(`${message} > failed to update connector ${connector.id}`, { cause: error });
      }
    })
  );

  logMigration.info(`${message} > completed - ${successCount} connectors updated`);
  next();
};

export const down = async (next) => {
  next();
};
