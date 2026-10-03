import { registerGraphqlSchema } from '../../graphql/schema';
import iocValidationTypeDefs from './iocValidation.graphql';
import iocValidationResolvers from './iocValidation-resolver';

registerGraphqlSchema({
  schema: iocValidationTypeDefs,
  resolver: iocValidationResolvers,
});
