import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixObject, cleanObject } from '../../database/stix-converter';
import type { StixChannel, StoreEntityChannel } from './channel-types';
import { INPUT_CREATED_BY, INPUT_LABELS, INPUT_MARKINGS } from '../../schema/general';

const convertChannelToStix = (instance: StoreEntityChannel): StixChannel => {
  const stixDomainObject = buildStixObject(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    category: instance.channel_type,
    // languages: instance.channel_languages,
    aliases: instance.x_opencti_aliases ?? [],
    labels: (instance[INPUT_LABELS] ?? []).map((m) => m.value),
    object_marking_refs: (instance[INPUT_MARKINGS] ?? []).map((m) => m.standard_id),
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertChannelToStix;
