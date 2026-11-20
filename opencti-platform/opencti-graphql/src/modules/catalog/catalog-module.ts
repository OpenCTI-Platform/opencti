import type { ModuleDescriptor } from '../module-descriptor';
import { CATALOG_CONTRACT_DEFINITION, CATALOG_DEFINITION } from './catalog';
import catalogTypeDefs from './catalog.graphql';
import catalogResolvers from './catalog-resolver';
import { CATALOG_MANAGER_DEFINITION } from './catalog-manager';

const catalogModule: ModuleDescriptor = {
  id: 'catalog',
  dataModel: [CATALOG_CONTRACT_DEFINITION, CATALOG_DEFINITION],
  graphqlSchemas: [{ schema: catalogTypeDefs, resolver: catalogResolvers }],
  managers: [CATALOG_MANAGER_DEFINITION],
};

export default catalogModule;
