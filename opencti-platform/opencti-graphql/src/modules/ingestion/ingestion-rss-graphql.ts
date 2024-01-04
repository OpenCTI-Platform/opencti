import { registerGraphqlSchema } from '../../graphql/schema';
import ingestionTypeDefs from './ingestion-rss.graphql';
import ingestionRssResolvers from './ingestion-rss-resolver';

registerGraphqlSchema({
  schema: ingestionTypeDefs,
  resolver: ingestionRssResolvers,
});
