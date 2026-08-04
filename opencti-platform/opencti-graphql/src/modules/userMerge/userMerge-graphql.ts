import { registerGraphqlSchema } from '../../graphql/schema';
import userMergeTypeDefs from './userMerge.graphql';
import userMergeResolvers from './userMerge-resolvers';

registerGraphqlSchema({
  schema: userMergeTypeDefs,
  resolver: userMergeResolvers,
});
