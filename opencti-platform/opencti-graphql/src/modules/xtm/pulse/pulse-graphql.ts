import { registerGraphqlSchema } from '../../../graphql/schema';
import pulseTypeDefs from './pulse.graphql';
import pulseResolvers from './pulse-resolvers';

registerGraphqlSchema({
  schema: pulseTypeDefs,
  resolver: pulseResolvers,
});
