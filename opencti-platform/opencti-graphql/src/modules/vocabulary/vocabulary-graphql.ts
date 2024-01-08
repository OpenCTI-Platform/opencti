import { registerGraphqlSchema } from '../../graphql/schema';
import vocabularyTypeDefs from './vocabulary.graphql';
import vocabularyResolvers from './vocabulary-resolver';

registerGraphqlSchema({
  schema: vocabularyTypeDefs,
  resolver: vocabularyResolvers,
});
