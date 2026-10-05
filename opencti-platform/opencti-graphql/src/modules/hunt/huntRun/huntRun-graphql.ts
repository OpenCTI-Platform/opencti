import { registerGraphqlSchema } from '../../../graphql/schema';
import huntRunResolvers from './huntRun-resolvers';
import huntRunTypeDefs from './huntRun.graphql';

registerGraphqlSchema({
  schema: huntRunTypeDefs,
  resolver: huntRunResolvers,
});
