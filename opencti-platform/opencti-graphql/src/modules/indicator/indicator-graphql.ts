import { registerGraphqlSchema } from '../../graphql/schema';
import indicatorTypeDefs from './indicator.graphql';
import indicatorResolvers from './indicator-resolver';

registerGraphqlSchema({
  schema: indicatorTypeDefs,
  resolver: indicatorResolvers,
});
