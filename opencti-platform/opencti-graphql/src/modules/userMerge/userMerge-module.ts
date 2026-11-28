import type { ModuleDescriptor } from '../module-descriptor';
import userMergeTypeDefs from './userMerge.graphql';
import userMergeResolvers from './userMerge-resolvers';
import { registerUserMergeHandlers } from './userMerge-handlers';

const userMergeModule: ModuleDescriptor = {
  id: 'userMerge',
  graphqlSchemas: [{ schema: userMergeTypeDefs, resolver: userMergeResolvers }],
  // The handlers derive part of their targets from the attributes of every module.
  init: registerUserMergeHandlers,
};

export default userMergeModule;
