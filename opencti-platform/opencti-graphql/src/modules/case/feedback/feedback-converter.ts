import { buildStixDomain } from '../../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import { INPUT_OBJECTS } from '../../../schema/general';
import { assertType, cleanObject, convertObjectReferences } from '../../../database/stix-converter-utils';
import { buildStixDomain as buildStixDomain2 } from '../../../database/stix-2-0-converter';
import { ENTITY_TYPE_CONTAINER_FEEDBACK, type StixFeedback, type StoreEntityFeedback, type StoreEntityStix2Feedback, type Stix2Feedback } from './feedback-types';

export const convertFeedbackToStix_2_1 = (instance: StoreEntityFeedback): StixFeedback => {
  const feedback = buildStixDomain(instance);
  return {
    ...feedback,
    name: instance.name,
    description: instance.description,
    content: instance.content,
    content_mapping: instance.content_mapping,
    rating: instance.rating,
    object_refs: (instance[INPUT_OBJECTS] ?? []).map((m) => m.standard_id),
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...feedback.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export const convertFeedbackToStix_2_0 = (instance: StoreEntityStix2Feedback, type: string): Stix2Feedback => {
  assertType(ENTITY_TYPE_CONTAINER_FEEDBACK, type);
  const feedback = buildStixDomain2(instance);
  return {
    ...feedback,
    name: instance.name,
    description: instance.description,
    rating: instance.rating,
    object_refs: convertObjectReferences(instance),
  };
};
