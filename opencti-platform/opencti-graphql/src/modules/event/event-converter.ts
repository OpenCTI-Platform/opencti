import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixDomain } from '../../database/stix-2-1-converter';
import { ENTITY_TYPE_EVENT, type Stix2Event, type StixEvent, type StoreEntityEvent } from './event-types';
import { assertType, cleanObject, convertToStixDate } from '../../database/stix-converter-utils';
import { buildStixDomain as buildStixDomain2 } from '../../database/stix-2-0-converter';
import type { StoreEntity } from '../../types/store';

const convertEventToStix = (instance: StoreEntityEvent): StixEvent => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    event_types: instance.event_types,
    start_time: convertToStixDate(instance.start_time),
    stop_time: convertToStixDate(instance.stop_time),
    aliases: instance.x_opencti_aliases ?? [],
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export const convertEventToStix_2_0 = (instance: StoreEntity): Stix2Event => {
  assertType(ENTITY_TYPE_EVENT, instance.entity_type);
  const event = instance as StoreEntityEvent;
  return {
    ...buildStixDomain2(instance),
    name: instance.name,
    description: instance.description,
    event_types: event.event_types,
    start_time: convertToStixDate(event.start_time),
    stop_time: convertToStixDate(event.stop_time),
    aliases: instance.x_opencti_aliases ?? [],
  };
};

export default convertEventToStix;
