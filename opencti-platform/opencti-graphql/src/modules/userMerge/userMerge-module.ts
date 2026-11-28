import type { ModuleDescriptor } from '../module-descriptor';
import type { Resolvers } from '../../generated/graphql';
import userMergeTypeDefs from './userMerge.graphql';
import userMergeResolvers from './userMerge-resolvers';
import { registerUserMergeHandlers } from './userMerge-handlers';

const userMergeModule: ModuleDescriptor = {
  id: 'userMerge',
  // TODO the domain return types (UserMergeApiCoverage) diverge from the generated graphql types,
  // which the untyped registerGraphqlSchema never checked.
  graphqlSchemas: [{ schema: userMergeTypeDefs, resolver: userMergeResolvers as Resolvers }],
  // The handlers derive part of their targets from the attributes of every module.
  init: registerUserMergeHandlers,
};

export default userMergeModule;
