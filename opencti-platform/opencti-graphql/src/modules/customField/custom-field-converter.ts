import { buildStixDomain } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixCustomField, StoreEntityCustomField } from './custom-field-types';
import { cleanObject } from '../../database/stix-converter-utils';

const convertCustomFieldToStix = (instance: StoreEntityCustomField): StixCustomField => {
  const customField = buildStixDomain(instance);
  return {
    ...customField,
    name: instance.name,
    description: instance.description,
    label: instance.label,
    field_type: instance.field_type,
    entity_types: instance.entity_types,
    mandatory: instance.mandatory,
    default_value: instance.default_value,
    min_value: instance.min_value,
    max_value: instance.max_value,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...customField.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertCustomFieldToStix;

