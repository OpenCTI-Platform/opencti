import { registerGraphqlSchema } from '../../graphql/schema';
import dataSanityTypeDefs from './dataSanity.graphql';
import dataSanityResolvers from './dataSanity-resolvers';

registerGraphqlSchema({
  schema: dataSanityTypeDefs,
  resolver: dataSanityResolvers,
});
