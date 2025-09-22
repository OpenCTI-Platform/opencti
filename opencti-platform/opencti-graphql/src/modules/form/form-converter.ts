import { buildStixObject } from '../../database/stix-2-1-converter';
import { cleanObject } from '../../database/stix-converter-utils';
import type { StixForm, StoreEntityForm } from './form-types';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const convertFormToStix = (instance: StoreEntityForm): StixForm => {
  const stixObject = buildStixObject(instance);
  return cleanObject({
    ...stixObject,
    name: instance.name,
    description: instance.description,
    form_schema: instance.form_schema,
    main_entity_type: instance.main_entity_type,
    active: instance.active,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  });
};
