import { logMigration } from '../config/conf';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { FilterMode } from '../generated/graphql';
import { fullEntitiesList } from '../database/middleware-loader';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_CONNECTOR } from '../schema/internalObject';
import { patchAttribute } from '../database/middleware';
import type { BasicStoreEntityConnector } from '../types/connector';
import openCtiManifest from '../__generated__/opencti-manifest.json';
import type { CatalogContract, CatalogDefinition } from '../modules/catalog/catalog-types';
import { mapContractDtoV0ToContractEntityFields } from '../modules/catalog/catalog-domain';
import { listCatalogContractLogos, storeCatalogContractLogo } from '../modules/catalog/catalog-logo-storage';

const message = '[MIGRATION] managed connectors contract snapshot';

export const up = async (next: (error?: Error) => void) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  const filigranCatalog = openCtiManifest as CatalogDefinition;

  // Load all managed connectors which have their contract definition in the embedded catalog manifest
  const managedConnectorsArgs = {
    indices: [READ_INDEX_INTERNAL_OBJECTS],
    filters: { mode: FilterMode.And, filters: [{ key: ['catalog_id'], values: [filigranCatalog.id] }], filterGroups: [] },
  };
  const managedConnectors = await fullEntitiesList<BasicStoreEntityConnector>(context, SYSTEM_USER, [ENTITY_TYPE_CONNECTOR], managedConnectorsArgs);
  logMigration.info(`${message} > ${managedConnectors.length} managed connector(s) to evaluate`);

  // Read the contracts from the embedded catalog file
  const contractsByImage: Record<string, CatalogContract> = {};
  filigranCatalog.contracts.forEach((contract: CatalogContract) => {
    contractsByImage[contract.container_image] = contract;
  });

  const storedLogos = managedConnectors.length > 0 ? (await listCatalogContractLogos()) : new Set<string>();
  for (let i = 0; i < managedConnectors.length; i += 1) {
    const connector = managedConnectors[i];
    const patch: Pick<BasicStoreEntityConnector, 'manager_contract' | 'manager_upgrade_strategy'> = {};
    if (!connector.manager_contract && connector.manager_contract_image) {
      const contractDto = contractsByImage[connector.manager_contract_image];
      if (!contractDto) {
        logMigration.info(`${message} > connector ${connector.id} missing catalog contract ${connector.manager_contract_image}`);
      } else {
        const result = await storeCatalogContractLogo(contractDto, storedLogos);
        if (result.result === 'failed') {
          logMigration.info(`${message} > failed to store logo into file storage for connector ${connector.id} (${result.error?.message ?? 'Unknown error'})`);
        } else if (result.result === 'success') {
          if (result.existed) {
            logMigration.info(`${message} > deduped logo file for connector ${connector.id}`);
          } else {
            storedLogos.add(result.filename);
          }
        }
        patch.manager_contract = mapContractDtoV0ToContractEntityFields({
          catalogId: filigranCatalog.id,
          contractDto,
          logoUri: result.logoUri,
        });
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
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
