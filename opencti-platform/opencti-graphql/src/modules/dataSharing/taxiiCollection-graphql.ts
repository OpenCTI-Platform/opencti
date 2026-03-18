import { registerGraphqlSchema } from '../../graphql/schema';
import taxiiCollectionTypeDefs from './taxiiCollection.graphql';
import taxiiCollectionResolvers from './taxiiCollection-resolver';

registerGraphqlSchema({
  schema: taxiiCollectionTypeDefs,
  resolver: taxiiCollectionResolvers,
});
