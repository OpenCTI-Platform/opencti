import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixDomain } from '../../database/stix-2-1-converter';
import { buildStixDomain as buildStixDomain2 } from '../../database/stix-2-0-converter';
import { INPUT_OBJECTS } from '../../schema/general';
import { assertType, cleanObject, convertObjectReferences } from '../../database/stix-converter-utils';
import { type Stix2Grouping, ENTITY_TYPE_CONTAINER_GROUPING, type StixGrouping, type StoreEntityGrouping, type StoreEntityGrouping2 } from './grouping-types';

export const convertGroupingToStix_2_1 = (instance: StoreEntityGrouping): StixGrouping => {
  const grouping = buildStixDomain(instance);
  return {
    ...grouping,
    name: instance.name,
    description: instance.description,
    context: instance.context,
    object_refs: (instance[INPUT_OBJECTS] ?? []).map((m) => m.standard_id),
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...grouping.extensions[STIX_EXT_OCTI],
        extension_type: 'property-extension',
        content: instance.content,
        content_mapping: instance.content_mapping,
        object_refs_inferred: convertObjectReferences(instance, true),
      })
    }
  };
};

export const convertGroupingToStix_2_0 = (instance: StoreEntityGrouping2, type: string): Stix2Grouping => {
  assertType(ENTITY_TYPE_CONTAINER_GROUPING, type);
  const grouping = buildStixDomain2(instance);
  return {
    ...grouping,
    name: instance.name,
    description: instance.description,
    context: instance.context,
    object_refs: convertObjectReferences(instance),
  };
};
