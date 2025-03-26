import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixDomain, cleanObject, convertObjectReferences } from '../../database/stix-2-1-converter';
import type { StixGrouping, StoreEntityGrouping } from './grouping-types';
import { INPUT_OBJECTS } from '../../schema/general';

const convertGroupingToStix = (instance: StoreEntityGrouping): StixGrouping => {
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

export default convertGroupingToStix;
