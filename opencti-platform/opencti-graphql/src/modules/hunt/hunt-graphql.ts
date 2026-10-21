import { registerGraphqlSchema } from '../../graphql/schema';
import huntResolvers from './hunt-resolvers';
import huntTypeDefs from './hunt.graphql';

registerGraphqlSchema({
  schema: huntTypeDefs,
  resolver: huntResolvers,
});
