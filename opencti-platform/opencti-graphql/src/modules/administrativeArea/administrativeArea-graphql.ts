import { registerGraphqlSchema } from '../../graphql/schema';
import administrativeAreaTypeDefs from './administrativeArea.graphql';
import administrativeAreaResolvers from './administrativeArea-resolver';

registerGraphqlSchema({
  schema: administrativeAreaTypeDefs,
  resolver: administrativeAreaResolvers,
});
