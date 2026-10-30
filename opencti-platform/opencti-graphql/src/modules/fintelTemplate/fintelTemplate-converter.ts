import { buildStixObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixFintelTemplate, StoreEntityFintelTemplate } from './fintelTemplate-types';
import { cleanObject } from '../../database/stix-converter-utils';

export const convertFintelTemplateToStix = (instance: StoreEntityFintelTemplate): StixFintelTemplate => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    settings_types: instance.settings_types,
    instance_filters: instance.instance_filters,
    template_content: instance.template_content,
    fintel_template_widgets: instance.fintel_template_widgets ?? [],
    start_date: instance.start_date,
    default: Boolean(instance.default),
    include_cover_page_by_default: instance.include_cover_page_by_default ?? true,
    include_back_page_by_default: instance.include_back_page_by_default ?? true,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};
