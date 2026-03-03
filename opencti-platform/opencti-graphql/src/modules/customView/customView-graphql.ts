import { registerGraphqlSchema } from '../../graphql/schema';
import customViewTypeDefs from './customView.graphql';
import customViewResolvers from './customView-resolver';

registerGraphqlSchema({
  schema: customViewTypeDefs,
  resolver: customViewResolvers,
});
