import { registerGraphqlSchema } from '../../graphql/schema';
import procedureResolvers from './procedure-resolver';
import procedureTypeDefs from './procedure.graphql';

registerGraphqlSchema({
  schema: procedureTypeDefs,
  resolver: procedureResolvers,
});
