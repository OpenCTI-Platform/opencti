import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixDomain } from '../../database/stix-2-1-converter';
import { ENTITY_TYPE_CHANNEL, type Stix2Channel, type StixChannel, type StoreEntityChannel } from './channel-types';
import { assertType, cleanObject } from '../../database/stix-converter-utils';
import { buildStixDomain as buildStixDomain2 } from '../../database/stix-2-0-converter';

export const convertChannelToStix_2_1 = (instance: StoreEntityChannel): StixChannel => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    channel_types: instance.channel_types,
    aliases: instance.x_opencti_aliases ?? [],
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export const convertChannelToStix_2_0 = (instance: StoreEntityChannel): Stix2Channel => {
  assertType(ENTITY_TYPE_CHANNEL, instance.entity_type);
  const channel = buildStixDomain2(instance);
  return {
    ...channel,
    name: instance.name,
    description: instance.description,
    channel_types: instance.channel_types,
    aliases: instance.x_opencti_aliases ?? [],
  };
};
