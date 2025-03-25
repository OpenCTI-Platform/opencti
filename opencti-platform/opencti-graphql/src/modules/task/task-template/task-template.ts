import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import { NAME_FIELD, normalizeName } from '../../../schema/identifier';
import { type ModuleDefinition, registerDefinition } from '../../../schema/module';
import convertCaseTaskToStix from './task-template-converter';
import type { StixTaskTemplate, StoreEntityTaskTemplate } from './task-template-types';
import { ENTITY_TYPE_TASK_TEMPLATE } from './task-template-types';

const TASK_TEMPLATE_DEFINITION: ModuleDefinition<StoreEntityTaskTemplate, StixTaskTemplate> = {
  type: {
    id: 'task-template',
    name: ENTITY_TYPE_TASK_TEMPLATE,
    category: ABSTRACT_INTERNAL_OBJECT
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_TASK_TEMPLATE]: [{ src: NAME_FIELD }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [],
  relationsRefs: [],
  representative: (stix: StixTaskTemplate) => {
    return stix.name;
  },
  converter_2_1: convertCaseTaskToStix
};
registerDefinition(TASK_TEMPLATE_DEFINITION);
