import { registerGraphqlSchema } from '../../graphql/schema';
import templateTypeDefs from './template.graphql';
import templateResolvers from './template-resolvers';

registerGraphqlSchema({
  schema: templateTypeDefs,
  resolver: templateResolvers,
});
