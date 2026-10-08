import { registerGraphqlSchema } from '../../graphql/schema';
import { APP_MODULE } from '../../config/error-origin';
import catalogTypeDefs from './catalog.graphql';
import catalogResolvers from './catalog-resolver';

registerGraphqlSchema({
  schema: catalogTypeDefs,
  resolver: catalogResolvers,
  module: APP_MODULE.CATALOG,
});
