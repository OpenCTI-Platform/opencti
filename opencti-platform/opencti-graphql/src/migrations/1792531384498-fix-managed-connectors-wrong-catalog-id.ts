import { logMigration } from '../config/conf';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { FilterMode, FilterOperator } from '../generated/graphql';
import { fullEntitiesList } from '../database/middleware-loader';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { patchAttribute } from '../database/middleware';
import type { BasicStoreEntityConnector } from '../modules/connector/connector-types';
import openCtiManifest from '../__generated__/opencti-manifest.json';
import type { CatalogContract, CatalogDefinition } from '../modules/catalog/catalog-types';
import { mapContractDtoV0ToContractEntityFields, mapContractEntityFieldsToEmbeddedConnectorManagerContract } from '../modules/catalog/catalog-domain';
import { findCatalogByCatalogId, findLatestCompatibleCatalogContractByImageName } from '../modules/catalog/catalog-repository';
import { listCatalogContractLogos, storeCatalogContractLogo } from '../modules/catalog/catalog-logo-storage';
import { computeContractContentHash } from '../modules/catalog/sync/catalog-sync-domain';
import { mapCatalogContractDtoToCatalogContractSyncSource } from '../modules/catalog/sync/catalog-sync-source-gateway';

const message = '[MIGRATION] managed connectors leftover contract snapshot';

// The 1789637887081 migration only handled the connectors bound to the embedded catalog id: the ones bound to another
// catalog, or to a wrong catalog id (managedConnectorAdd used to accept any value, e.g. the connector slug),
// have no contract snapshot (no image for the manager) and no upgrade strategy.
export const up = async (next: (error?: Error) => void) => {
  const start = new Date().getTime();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  const filigranCatalog = openCtiManifest as unknown as CatalogDefinition;

  const managedConnectorsArgs = {
    indices: [READ_INDEX_INTERNAL_OBJECTS],
    filters: { mode: FilterMode.And, filters: [{ key: ['catalog_id'], values: [], operator: FilterOperator.NotNil }], filterGroups: [] },
  };
  const managedConnectors = await fullEntitiesList<BasicStoreEntityConnector>(context, SYSTEM_USER, [ENTITY_TYPE_CONNECTOR], managedConnectorsArgs);
  const connectorsToFix = managedConnectors.filter((connector) => !connector.manager_contract || !connector.manager_upgrade_strategy);
  logMigration.info(`${message} > ${connectorsToFix.length} managed connector(s) to evaluate`);

  // Read the contracts from the embedded catalog file
  const contractsByImage: Record<string, CatalogContract> = {};
  filigranCatalog.contracts.forEach((contract: CatalogContract) => {
    contractsByImage[contract.container_image] = contract;
  });

  let storedLogos: Set<string> | undefined;
  for (let i = 0; i < connectorsToFix.length; i += 1) {
    const connector = connectorsToFix[i];
    logMigration.info(`${message} > processing connector ${connector.id} (${i + 1}/${connectorsToFix.length})`);
    const patch: Pick<BasicStoreEntityConnector, 'catalog_id' | 'manager_contract' | 'manager_upgrade_strategy'> = {};
    if (!connector.manager_contract && !connector.manager_contract_image) {
      logMigration.error(`${message} > connector ${connector.id} has neither a contract snapshot nor a contract image`);
    } else if (!connector.manager_contract && connector.manager_contract_image) {
      const catalog = await findCatalogByCatalogId(context, SYSTEM_USER, connector.catalog_id as string);
      if (catalog) {
        const contract = await findLatestCompatibleCatalogContractByImageName(context, SYSTEM_USER, connector.manager_contract_image, catalog.catalog_id);
        if (!contract) {
          logMigration.error(`${message} > connector ${connector.id} missing contract ${connector.manager_contract_image} in catalog ${catalog.catalog_id}`);
        } else {
          patch.manager_contract = mapContractEntityFieldsToEmbeddedConnectorManagerContract(contract);
        }
      } else {
        logMigration.info(`${message} > connector ${connector.id} catalog ${connector.catalog_id} not found, fallback to the embedded catalog`);
        const contractDto = contractsByImage[connector.manager_contract_image];
        if (!contractDto) {
          logMigration.error(`${message} > connector ${connector.id} missing contract ${connector.manager_contract_image} in the embedded catalog`);
        } else {
          storedLogos ??= await listCatalogContractLogos();
          const result = await storeCatalogContractLogo(contractDto, storedLogos);
          if (result.result === 'failed') {
            logMigration.error(`${message} > failed to store logo into file storage for connector ${connector.id} (${result.error?.message ?? 'Unknown error'})`);
          } else if (result.result === 'success') {
            if (result.existed) {
              logMigration.info(`${message} > deduped logo file for connector ${connector.id}`);
            } else {
              storedLogos.add(result.filename);
            }
          }
          const contractContentHash = computeContractContentHash(
            mapCatalogContractDtoToCatalogContractSyncSource(contractDto),
          );
          patch.manager_contract = mapContractDtoV0ToContractEntityFields({
            catalogId: filigranCatalog.id,
            contractDto,
            contractContentHash,
            logoUri: result.logoUri,
          });
          // Bind the connector to the catalog its contract comes from, for the auto-upgrades
          if (connector.catalog_id !== filigranCatalog.id) {
            patch.catalog_id = filigranCatalog.id;
          }
        }
      }
    }
    if (!connector.manager_upgrade_strategy) {
      patch.manager_upgrade_strategy = 'latest';
    }
    if (Object.keys(patch).length > 0) {
      await patchAttribute(context, SYSTEM_USER, connector.id, ENTITY_TYPE_CONNECTOR, patch);
      logMigration.info(`${message} > connector ${connector.id} patched`);
    }
  }
  logMigration.info(`${message} > done in ${new Date().getTime() - start} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
