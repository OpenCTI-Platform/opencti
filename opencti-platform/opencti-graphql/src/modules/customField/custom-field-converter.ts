import { buildStixDomain } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixCustomFieldDefinition, StoreEntityCustomFieldDefinition } from './custom-field-types';
import { cleanObject } from '../../database/stix-converter-utils';

const convertCustomFieldDefinitionToStix = (instance: StoreEntityCustomFieldDefinition): StixCustomFieldDefinition => {
  const customFieldDefinition = buildStixDomain(instance);
  return {
    ...customFieldDefinition,
    name: instance.name,
    description: instance.description,
    label: instance.label,
    field_type: instance.field_type,
    entity_types: instance.entity_types,
    entity_type_settings: instance.entity_type_settings,
    multiple: instance.multiple,
    min_value: instance.min_value,
    max_value: instance.max_value,
    select_options: instance.select_options,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...customFieldDefinition.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export default convertCustomFieldDefinitionToStix;
