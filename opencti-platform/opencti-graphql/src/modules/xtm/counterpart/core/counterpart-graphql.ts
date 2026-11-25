import { registerGraphqlSchema } from '../../../../graphql/schema';
import counterpartTypeDefs from './counterpart.graphql';
import counterpartResolvers from './counterpart-resolver';

registerGraphqlSchema({
  schema: counterpartTypeDefs,
  resolver: counterpartResolvers,
});
