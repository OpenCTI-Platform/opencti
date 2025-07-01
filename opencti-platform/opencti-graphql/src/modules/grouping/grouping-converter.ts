import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixDomain, convertObjectReferences } from '../../database/stix-2-1-converter';
import { ENTITY_TYPE_CONTAINER_GROUPING, type StixGrouping, type StoreEntityGrouping } from './grouping-types';
import type * as SDO from '../../types/stix-2-0-sdo';
import { buildStixDomain as buildStixDomain2 } from '../../database/stix-2-0-converter';
import { INPUT_OBJECTS } from '../../schema/general';
import { assertType, cleanObject } from '../../database/stix-converter-utils';
import type { StoreEntity } from '../../types/store';

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

export const convertGroupingToStix_2_0 = (instance: StoreEntity, type: string): SDO.StixGrouping => {
  assertType(ENTITY_TYPE_CONTAINER_GROUPING, type);
  const grouping = buildStixDomain2(instance);
  return {
    ...grouping,
    name: instance.name,
    description: instance.description,
    context: instance.context,
    object_refs: (instance[INPUT_OBJECTS] ?? []).map((m) => m.standard_id),
  };
};
