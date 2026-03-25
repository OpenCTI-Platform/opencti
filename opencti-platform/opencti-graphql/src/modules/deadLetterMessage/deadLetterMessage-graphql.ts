import { registerGraphqlSchema } from '../../graphql/schema';
import deadLetterMessageTypeDefs from './deadLetterMessage.graphql';
import deadLetterMessageResolvers from './deadLetterMessage-resolver';

registerGraphqlSchema({
  schema: deadLetterMessageTypeDefs,
  resolver: deadLetterMessageResolvers,
});
