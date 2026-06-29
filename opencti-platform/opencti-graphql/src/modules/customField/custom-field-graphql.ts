import { registerGraphqlSchema } from '../../graphql/schema';
import customFieldTypeDefs from './custom-field.graphql';
import customFieldResolvers from './custom-field-resolvers';

registerGraphqlSchema({
  schema: customFieldTypeDefs,
  resolver: customFieldResolvers,
});

