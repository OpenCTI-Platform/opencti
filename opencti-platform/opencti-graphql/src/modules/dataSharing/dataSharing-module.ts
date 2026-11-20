import type { ModuleDescriptor } from '../module-descriptor';
import { FEED_DEFINITION } from './feed';
import { TAXII_COLLECTION_DEFINITION } from './taxiiCollection';
import { STREAM_COLLECTION_DEFINITION } from './streamCollection';
import taxiiCollectionTypeDefs from './taxiiCollection.graphql';
import taxiiCollectionResolvers from './taxiiCollection-resolver';
import feedTypeDefs from './feed.graphql';
import feedResolvers from './feed-resolver';
import streamCollectionTypeDefs from './streamCollection.graphql';
import streamCollectionResolvers from './streamCollection-resolver';

const dataSharingModule: ModuleDescriptor = {
  id: 'dataSharing',
  dataModel: [FEED_DEFINITION, TAXII_COLLECTION_DEFINITION, STREAM_COLLECTION_DEFINITION],
  graphqlSchemas: [
    { schema: taxiiCollectionTypeDefs, resolver: taxiiCollectionResolvers },
    { schema: feedTypeDefs, resolver: feedResolvers },
    { schema: streamCollectionTypeDefs, resolver: streamCollectionResolvers },
  ],
};

export default dataSharingModule;
