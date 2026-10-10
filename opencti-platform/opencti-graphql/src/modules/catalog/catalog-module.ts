import type { ModuleDescriptor } from '../module-descriptor';
import catalogTypeDefs from './catalog.graphql';
import catalogResolvers from './catalog-resolver';
import { CATALOG_MANAGER_DEFINITION } from './catalog-manager';

const catalogModule: ModuleDescriptor = {
  id: 'catalog',
  graphqlSchemas: [{ schema: catalogTypeDefs, resolver: catalogResolvers }],
  managers: [CATALOG_MANAGER_DEFINITION],
};

export default catalogModule;
