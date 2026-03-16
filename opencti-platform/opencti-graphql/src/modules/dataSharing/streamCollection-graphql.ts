import { registerGraphqlSchema } from '../../graphql/schema';
import streamCollectionTypeDefs from './streamCollection.graphql';
import streamCollectionResolvers from './streamCollection-resolver';

registerGraphqlSchema({
  schema: streamCollectionTypeDefs,
  resolver: streamCollectionResolvers,
});
