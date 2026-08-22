import { logMigration } from '../config/conf';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { FilterMode } from '../generated/graphql';
import { fullEntitiesList } from '../database/middleware-loader';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { patchAttribute } from '../database/middleware';
import { getSupportedContractByImage, mapCatalogContractToConnectorManagerContract } from '../modules/catalog/catalog-domain';

const message = '[MIGRATION] managed connectors contract snapshot';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const managedConnectorsArgs = {
    indices: [READ_INDEX_INTERNAL_OBJECTS],
    filters: { mode: FilterMode.And, filters: [{ key: ['catalog_id'], values: ['EXISTS'] }], filterGroups: [] },
  };
  const managedConnectors = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_CONNECTOR], managedConnectorsArgs);
  logMigration.info(`${message} > ${managedConnectors.length} managed connector(s) to evaluate`);

  for (let i = 0; i < managedConnectors.length; i += 1) {
    const connector = managedConnectors[i];
    const patch = {};
    if (!connector.manager_contract && connector.manager_contract_image) {
      const contract = await getSupportedContractByImage(connector.manager_contract_image);
      if (!contract) {
        logMigration.warn(`${message} > connector ${connector.id} missing catalog contract`, {
          manager_contract_image: connector.manager_contract_image,
        });
      } else {
        patch.manager_contract = mapCatalogContractToConnectorManagerContract(contract);
      }
    }
    if (!connector.manager_upgrade_strategy) {
      patch.manager_upgrade_strategy = 'latest';
    }
    if (Object.keys(patch).length > 0) {
      await patchAttribute(context, SYSTEM_USER, connector.id, ENTITY_TYPE_CONNECTOR, patch);
      logMigration.info(`${message} > connector ${connector.id} patched`, { fields: Object.keys(patch) });
    }
  }
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
