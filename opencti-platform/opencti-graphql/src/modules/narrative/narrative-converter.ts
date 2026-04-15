import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixDomain } from '../../database/stix-2-1-converter';
import { ENTITY_TYPE_NARRATIVE, type Stix2Narrative, type StixNarrative, type StoreEntityNarrative } from './narrative-types';
import { assertType, cleanObject } from '../../database/stix-converter-utils';
import { buildStixDomain as buildStixDomain2 } from '../../database/stix-2-0-converter';

export const convertNarrativeToStix_2_1 = (instance: StoreEntityNarrative): StixNarrative => {
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
      }),
    },
  };
};

export const convertNarrativeToStix_2_0 = (instance: StoreEntityNarrative): Stix2Narrative => {
  assertType(ENTITY_TYPE_NARRATIVE, instance.entity_type);
  const narrative = buildStixDomain2(instance);
  return {
    ...narrative,
    name: instance.name,
    description: instance.description,
    narrative_types: instance.narrative_types ?? [],
    aliases: instance.x_opencti_aliases ?? [],
  };
};
