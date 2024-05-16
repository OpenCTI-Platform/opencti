import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import type { StixCaseTemplate, StoreEntityCaseTemplate } from './case-template-types';
import { ENTITY_TYPE_CASE_TEMPLATE, TEMPLATE_TASK_RELATION } from './case-template-types';
import convertCaseTemplateToStix from './case-template-converter';
import { ENTITY_TYPE_TASK_TEMPLATE } from '../../task/task-template/task-template-types';
import type { RefAttribute } from '../../../schema/attribute-definition';

const CaseTemplateToTaskTemplateRelation: RefAttribute = {
  name: 'tasks',
  type: 'ref',
  databaseName: TEMPLATE_TASK_RELATION,
  label: 'Tasks',
  stixName: 'task_refs',
  mandatoryType: 'internal',
  editDefault: false,
  multiple: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  datable: false,
  upsert: true,
  isFilterable: true,
  toTypes: [ENTITY_TYPE_TASK_TEMPLATE],
};

const CASE_TEMPLATE_DEFINITION: ModuleDefinition<StoreEntityCaseTemplate, StixCaseTemplate> = {
  type: {
    id: 'case-template',
    name: ENTITY_TYPE_CASE_TEMPLATE,
    category: ABSTRACT_INTERNAL_OBJECT
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CASE_TEMPLATE]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'created', label: 'Original creation date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [],
  relationsRefs: [CaseTemplateToTaskTemplateRelation],
  representative: (stix: StixCaseTemplate) => {
    return stix.name;
  },
  converter: convertCaseTemplateToStix
};
registerDefinition(CASE_TEMPLATE_DEFINITION);
