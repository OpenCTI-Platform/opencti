import type { ModuleDescriptor } from '../module-descriptor';
import { ENTITY_PIR_DEFINITION } from './pir';
import pirTypeDefs from './pir.graphql';
import pirResolvers from './pir-resolvers';
import { PIR_MANAGER_DEFINITION } from '../../manager/pirManager';

const pirModule: ModuleDescriptor = {
  id: 'pir',
  dataModel: [ENTITY_PIR_DEFINITION],
  graphqlSchemas: [{ schema: pirTypeDefs, resolver: pirResolvers }],
  managers: [PIR_MANAGER_DEFINITION],
};

export default pirModule;
