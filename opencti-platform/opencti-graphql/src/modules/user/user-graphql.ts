import { registerGraphqlSchema } from '../../graphql/schema';
import userResolvers from './user-resolver';
import userTypeDefs from './user.graphql';

registerGraphqlSchema({
  schema: userTypeDefs,
  resolver: userResolvers,
});
