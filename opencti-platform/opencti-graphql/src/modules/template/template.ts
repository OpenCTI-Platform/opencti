import { v4 as uuidv4 } from 'uuid';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_TEMPLATE, type StixTemplate, type StoreEntityTemplate } from './template-types';
import { ENTITY_TYPE_WIDGET } from '../widget/widget';
import { convertTemplateToStix } from './template-converter';

export const TEMPLATE_DEFINITION: ModuleDefinition<StoreEntityTemplate, StixTemplate> = {
  type: {
    id: 'templates',
    name: ENTITY_TYPE_TEMPLATE,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_TEMPLATE]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'entityType', label: 'Entity type', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'filters', label: 'Filters', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'content', label: 'Content', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'template_widgets_ids', label: 'Widget ids', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_WIDGET], editDefault: false, mandatoryType: 'no', multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixTemplate) => {
    return stix.name;
  },
  converter: convertTemplateToStix
};

registerDefinition(TEMPLATE_DEFINITION);
