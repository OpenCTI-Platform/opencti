import { registerGraphqlSchema } from '../../graphql/schema';
import languageTypeDefs from './language.graphql';
import languageResolvers from './language-resolver';

registerGraphqlSchema({
  schema: languageTypeDefs,
  resolver: languageResolvers,
});
