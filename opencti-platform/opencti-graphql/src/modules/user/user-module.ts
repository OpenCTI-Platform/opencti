import type { ModuleDescriptor } from '../module-descriptor';
import { USER_DEFINITION } from './user';
import userResolvers from './user-resolver';
import userTypeDefs from './user.graphql';

const userModule: ModuleDescriptor = {
  id: 'user',
  dataModel: [USER_DEFINITION],
  graphqlSchemas: [{ schema: userTypeDefs, resolver: userResolvers }],
};

export default userModule;
