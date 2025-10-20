import { logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { connectors } from '../database/repository';
import { patchAttribute } from '../database/middleware';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { DatabaseError } from '../config/errors';

const message = '[MIGRATION] Connector update container_name with title';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  const connectorsList = await connectors(context, SYSTEM_USER);

  const managedConnectors = connectorsList.filter((connector) => connector.is_managed);
  logMigration.info(`${message} > found ${managedConnectors.length} managed connectors to update`);

  const results = await Promise.allSettled(
    managedConnectors.map(async (connector) => {
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

      return connector.id;
    })
  );

  const successCount = results.filter((result) => result.status === 'fulfilled').length;
  const failures = results.filter((result) => result.status === 'rejected');

  if (successCount.length > 0) {
    logMigration.info(`${message} > completed - ${successCount}/${managedConnectors.length} connectors updated successfully`);
  }

  if (failures.length > 0) {
    logMigration.error(`${message} > ${failures.length} connector(s) failed to update:`);
    failures.forEach((failure, index) => {
      logMigration.error(`${message} > failure ${index + 1}:`, failure.reason);
    });

    throw DatabaseError(`${message} > migration completed with ${failures.length} failure(s)`);
  }

  if (successCount.length === 0 && failures.length === 0) {
    logMigration.error(`${message} > No existing connector to update`);
  }

  next();
};

export const down = async (next) => {
  next();
};
