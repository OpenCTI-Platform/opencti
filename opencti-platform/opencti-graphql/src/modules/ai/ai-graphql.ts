import { registerGraphqlSchema } from '../../graphql/schema';
import aiTypeDefs from './ai.graphql';
import aiResolvers from './ai-resolver';

registerGraphqlSchema({
  schema: aiTypeDefs,
  resolver: aiResolvers,
});
