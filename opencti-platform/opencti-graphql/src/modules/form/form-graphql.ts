import { registerGraphqlSchema } from '../../graphql/schema';
import formTypeDefs from './form.graphql';
import formResolvers from './form-resolver';

registerGraphqlSchema({
  schema: formTypeDefs,
  resolver: formResolvers,
});
