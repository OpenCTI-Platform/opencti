import { registerGraphqlSchema } from '../../graphql/schema';
import metricsResolver from './metrics-resolver';
import metricsTypeDefs from './metrics.graphql';

registerGraphqlSchema({
  schema: metricsTypeDefs,
  resolver: metricsResolver,
});
