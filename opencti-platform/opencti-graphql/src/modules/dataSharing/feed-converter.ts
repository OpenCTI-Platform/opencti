import type { StixFeed, StoreEntityFeed } from './feed-types';
import { buildStixObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { cleanObject } from '../../database/stix-converter-utils';

const convertFeedToStix = (instance: StoreEntityFeed): StixFeed => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    filters: instance.filters,
    separator: instance.separator,
    rolling_time: instance.rolling_time,
    include_header: instance.include_header,
    feed_types: instance.feed_types,
    feed_date_attribute: instance.feed_date_attribute,
    feed_attributes: instance.feed_attributes,
    feed_public: instance.feed_public,
    feed_public_user_id: instance.feed_public_user_id ?? '',
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertFeedToStix;
