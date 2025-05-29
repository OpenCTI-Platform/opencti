import { registerGraphqlSchema } from '../../graphql/schema';
import catalogTypeDefs from './catalog.graphql';
import catalogResolvers from './catalog-resolver';

registerGraphqlSchema({
  schema: catalogTypeDefs,
  resolver: catalogResolvers,
});
