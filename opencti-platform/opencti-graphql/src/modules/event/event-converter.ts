import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixDomain, cleanObject, convertToStixDate } from '../../database/stix-2-1-converter';
import type { StixEvent, StoreEntityEvent } from './event-types';

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
      })
    }
  };
};

export default convertEventToStix;
