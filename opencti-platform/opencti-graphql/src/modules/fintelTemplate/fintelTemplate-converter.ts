import { buildStixObject, cleanObject } from '../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixFintelTemplate, StoreEntityFintelTemplate } from './fintelTemplate-types';

export const convertFintelTemplateToStix = (instance: StoreEntityFintelTemplate): StixFintelTemplate => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    settings_types: instance.settings_types,
    instance_filters: instance.instance_filters,
    content: instance.content,
    template_widgets_ids: instance.template_widgets_ids ?? [],
    start_date: instance.start_date,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};
