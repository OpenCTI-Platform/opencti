import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import { NAME_FIELD, normalizeName } from '../../../schema/identifier';
import { type InternalObjectModuleDefinition, registerInternalObjectDefinition } from '../../../schema/module';
import { ENTITY_TYPE_TASK_TEMPLATE } from './task-template-types';

const TASK_TEMPLATE_DEFINITION: InternalObjectModuleDefinition = {
  type: {
    id: 'task-template',
    name: ENTITY_TYPE_TASK_TEMPLATE,
    category: ABSTRACT_INTERNAL_OBJECT,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_TASK_TEMPLATE]: [{ src: NAME_FIELD }],
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
};
registerInternalObjectDefinition(TASK_TEMPLATE_DEFINITION);
