import { registerGraphqlSchema } from '../../../../graphql/schema';
import newsFeedTypeDefs from './news-feed.graphql';
import newsFeedResolvers from './news-feed-resolver';

registerGraphqlSchema({
  schema: newsFeedTypeDefs,
  resolver: newsFeedResolvers,
});
