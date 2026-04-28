import { STIX_EXT_OCTI } from '../../../../types/stix-2-1-extensions';
import { buildStixObject } from '../../../../database/stix-2-1-converter';
import type { StixNewsFeedItem, StoreEntityNewsFeedItem } from './news-feed-types';
import { cleanObject } from '../../../../database/stix-converter-utils';

export const convertNewsFeedItemToStix = (instance: StoreEntityNewsFeedItem): StixNewsFeedItem => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    title: instance.title,
    news_feed_type: instance.news_feed_type,
    tags: instance.tags,
    metadata: instance.metadata,
    creation_date: instance.creation_date,
    is_read: instance.is_read,
    user_id: instance.user_id,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};
