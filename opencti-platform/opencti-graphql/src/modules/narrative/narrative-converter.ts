import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixDomain, cleanObject } from '../../database/stix-2-1-converter';
import type { StixNarrative, StoreEntityNarrative } from './narrative-types';

const convertNarrativeToStix = (instance: StoreEntityNarrative): StixNarrative => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    aliases: instance.x_opencti_aliases ?? [],
    narrative_types: instance.narrative_types ?? [],
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertNarrativeToStix;
