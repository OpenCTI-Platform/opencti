import type { ModuleDescriptor } from '../module-descriptor';
import { DELETE_OPERATION_DEFINITION } from './deleteOperation';
import deleteOperationTypeDefs from './deleteOperation.graphql';
import deleteOperationResolvers from './deleteOperation-resolvers';

const deleteOperationModule: ModuleDescriptor = {
  id: 'deleteOperation',
  dataModel: [DELETE_OPERATION_DEFINITION],
  graphqlSchemas: [{ schema: deleteOperationTypeDefs, resolver: deleteOperationResolvers }],
};

export default deleteOperationModule;
