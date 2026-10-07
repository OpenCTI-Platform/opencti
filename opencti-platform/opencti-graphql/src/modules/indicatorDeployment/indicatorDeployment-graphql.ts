import { registerGraphqlSchema } from '../../graphql/schema';
import indicatorDeploymentTypeDefs from './indicatorDeployment.graphql';
import indicatorDeploymentResolvers from './indicatorDeployment-resolver';

registerGraphqlSchema({
  schema: indicatorDeploymentTypeDefs,
  resolver: indicatorDeploymentResolvers,
});
