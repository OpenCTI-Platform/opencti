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
import { findCatalogContractsBySlugs } from '../modules/catalog/catalog-repository';

const message = '[MIGRATION] managed connectors options order';

// Every update of a connector rewrote its contract snapshot in another order of options, as Elasticsearch loses the
// order of the keys of an object updated through a script. The order is now kept as a list in the snapshot: it is taken
// back from the catalog contract of the same version, always indexed as a whole, or else from the embedded catalog.
export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');

  const managedConnectorsArgs = {
    indices: [READ_INDEX_INTERNAL_OBJECTS],
    filters: { mode: FilterMode.And, filters: [{ key: ['catalog_id'], values: [], operator: FilterOperator.NotNil }], filterGroups: [] },
  };
  const managedConnectors = (await fullEntitiesList<BasicStoreEntityConnector>(context, SYSTEM_USER, [ENTITY_TYPE_CONNECTOR], managedConnectorsArgs))
    .filter((connector) => connector.manager_contract?.config_schema?.properties && !connector.manager_contract.config_schema.properties_order);
  logMigration.info(`${message} > ${managedConnectors.length} managed connector(s) to evaluate`);

  // Order of the options of each contract version, from the catalogs then from the embedded catalog file.
  // A contract is identified by its catalog and its id: two catalogs can ship the same version in another order.
  const contractKey = (catalogId: string, contractId: string) => `${catalogId}|${contractId}`;
  const ordersByContract = new Map<string, string[]>();
  const slugs = [...new Set(managedConnectors.map((connector) => connector.manager_contract?.slug as string))];
  const catalogContracts = slugs.length > 0 ? await findCatalogContractsBySlugs(context, SYSTEM_USER, slugs) : [];
  catalogContracts.forEach((contract) => {
    if (contract.config_schema?.properties) {
      ordersByContract.set(contractKey(contract.catalog_id, contract.contract_id), Object.keys(contract.config_schema.properties));
    }
  });
  const filigranCatalog = openCtiManifest as unknown as CatalogDefinition;
  filigranCatalog.contracts.forEach((contract: CatalogContract) => {
    const key = contractKey(filigranCatalog.id, `${contract.slug}-${contract.container_version}`);
    if (!ordersByContract.has(key) && contract.config_schema?.properties) {
      ordersByContract.set(key, Object.keys(contract.config_schema.properties));
    }
  });

  for (let i = 0; i < managedConnectors.length; i += 1) {
    const connector = managedConnectors[i];
    const contract = connector.manager_contract as NonNullable<BasicStoreEntityConnector['manager_contract']>;
    logMigration.info(`${message} > processing connector ${connector.id} (${i + 1}/${managedConnectors.length})`);
    const catalogId = contract.catalog_id ?? connector.catalog_id as string;
    const order = ordersByContract.get(contractKey(catalogId, contract.contract_id));
    if (!order) {
      logMigration.info(`${message} > connector ${connector.id} contract ${contract.contract_id} of catalog ${catalogId} not found, order of options left as is`);
    } else {
      const patch = { manager_contract: { ...contract, config_schema: { ...contract.config_schema, properties_order: order } } };
      await patchAttribute(context, SYSTEM_USER, connector.id, ENTITY_TYPE_CONNECTOR, patch);
      logMigration.info(`${message} > connector ${connector.id} patched`);
    }
  }
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
