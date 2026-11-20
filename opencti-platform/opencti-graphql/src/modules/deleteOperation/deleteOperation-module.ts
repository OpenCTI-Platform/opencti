import type { ModuleDescriptor } from '../module-descriptor';
import { DELETE_OPERATION_DEFINITION } from './deleteOperation';
import deleteOperationTypeDefs from './deleteOperation.graphql';
import deleteOperationResolvers from './deleteOperation-resolvers';
import { GARBAGE_COLLECTION_MANAGER_DEFINITION } from '../../manager/garbageCollectionManager';

const deleteOperationModule: ModuleDescriptor = {
  id: 'deleteOperation',
  dataModel: [DELETE_OPERATION_DEFINITION],
  graphqlSchemas: [{ schema: deleteOperationTypeDefs, resolver: deleteOperationResolvers }],
  // Purges the delete operations past their retention, then the offloaded stream event files and expired configuration preset exports
  managers: [GARBAGE_COLLECTION_MANAGER_DEFINITION],
};

export default deleteOperationModule;
