import { registerGraphqlSchema } from '../../graphql/schema';
import feedTypeDefs from './feed.graphql';
import feedResolvers from './feed-resolver';

registerGraphqlSchema({
  schema: feedTypeDefs,
  resolver: feedResolvers,
});
