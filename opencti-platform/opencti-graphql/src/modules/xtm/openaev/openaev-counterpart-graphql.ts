import { registerGraphqlSchema } from '../../../graphql/schema';
import openAevCounterpartTypeDefs from './openaev-counterpart.graphql';
import openAevCounterpartResolvers from './openaev-counterpart-resolver';

registerGraphqlSchema({
  schema: openAevCounterpartTypeDefs,
  resolver: openAevCounterpartResolvers,
});
