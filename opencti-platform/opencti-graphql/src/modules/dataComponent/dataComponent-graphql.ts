import { registerGraphqlSchema } from '../../graphql/schema';
import dataComponentTypeDefs from './dataComponent.graphql';
import dataComponentResolvers from './dataComponent-resolver';

registerGraphqlSchema({
  schema: dataComponentTypeDefs,
  resolver: dataComponentResolvers,
});
