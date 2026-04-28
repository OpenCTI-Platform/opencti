import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../../../schema/module';
import { ENTITY_TYPE_NEWS_FEED_ITEM, type StixNewsFeedItem, type StoreEntityNewsFeedItem } from './news-feed-types';
import { convertNewsFeedItemToStix } from './news-feed-converter';
import { ABSTRACT_INTERNAL_OBJECT } from '../../../../schema/general';
import { booleanConf } from '../../../../config/conf';

const NEWS_FEED_DEFINITION: ModuleDefinition<StoreEntityNewsFeedItem, StixNewsFeedItem> = {
  type: {
    id: 'news-feed-item',
    name: ENTITY_TYPE_NEWS_FEED_ITEM,
    category: ABSTRACT_INTERNAL_OBJECT,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_NEWS_FEED_ITEM]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'title', label: 'Title', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'news_feed_type', label: 'News feed type', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'tags', label: 'Tags', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: true },
    { name: 'metadata', label: 'Metadata', type: 'object', format: 'flat', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'creation_date', label: 'Creation date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'is_read', label: 'Is read', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'user_id', label: 'User ID', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  ],
  relations: [],
  relationsRefs: [],
  representative: (stix: StixNewsFeedItem) => {
    return stix.title;
  },
  converter_2_1: convertNewsFeedItemToStix,
};

const isEnabled = booleanConf('XTMHUB_NEWS_FEED_ENABLED', true);
if (isEnabled) {
  registerDefinition(NEWS_FEED_DEFINITION);
}
