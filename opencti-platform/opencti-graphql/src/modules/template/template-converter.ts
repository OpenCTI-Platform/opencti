import { buildStixObject, cleanObject } from '../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixTemplate, StoreEntityTemplate } from './template-types';

export const convertTemplateToStix = (instance: StoreEntityTemplate): StixTemplate => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    entityType: instance.entityType,
    filters: instance.filters,
    content: instance.content,
    template_widget_ids: instance.template_widget_ids ?? [],
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};
