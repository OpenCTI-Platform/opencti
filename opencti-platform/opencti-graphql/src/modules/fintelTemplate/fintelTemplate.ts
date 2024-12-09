import { v4 as uuidv4 } from 'uuid';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import {
  ENTITY_TYPE_FINTEL_TEMPLATE,
  type StixFintelTemplate,
  type StoreEntityFintelTemplate
} from './fintelTemplate-types';
import { convertFintelTemplateToStix } from './fintelTemplate-converter';

export const FINTEL_TEMPLATE_DEFINITION: ModuleDefinition<StoreEntityFintelTemplate, StixFintelTemplate> = {
  type: {
    id: 'fintelTemplates',
    name: ENTITY_TYPE_FINTEL_TEMPLATE,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_FINTEL_TEMPLATE]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'settings_types', label: 'Available for types', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'instance_filters', label: 'Instance filters', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'content', label: 'Content', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: false },
    { name: 'start_date', label: 'Available since', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'fintel_template_widgets', label: 'Fintel template widgets', type: 'object', format: 'flat', mandatoryType: 'external', editDefault: false, multiple: true, upsert: false, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixFintelTemplate) => {
    return stix.name;
  },
  converter: convertFintelTemplateToStix
};

registerDefinition(FINTEL_TEMPLATE_DEFINITION);
