import { registerGraphqlSchema } from '../../graphql/schema';
import pirTypeDefs from './pir.graphql';
import pirResolvers from './pir-resolvers';
import { isFeatureEnabled } from '../../config/conf';

if (isFeatureEnabled('PIR')) {
  registerGraphqlSchema({
    schema: pirTypeDefs,
    resolver: pirResolvers,
  });
}
