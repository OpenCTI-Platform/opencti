import type { ModuleDescriptor } from '../../../module-descriptor';
import { NEWS_FEED_DEFINITION } from './news-feed';
import newsFeedTypeDefs from './news-feed.graphql';
import newsFeedResolvers from './news-feed-resolver';

const newsFeedModule: ModuleDescriptor = {
  id: 'newsFeed',
  dataModel: [NEWS_FEED_DEFINITION],
  graphqlSchemas: [{ schema: newsFeedTypeDefs, resolver: newsFeedResolvers }],
};

export default newsFeedModule;
