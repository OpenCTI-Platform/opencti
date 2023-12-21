import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import type { StixCaseTemplate, StoreEntityCaseTemplate } from './case-template-types';
import { ENTITY_TYPE_CASE_TEMPLATE, TEMPLATE_TASK_RELATION } from './case-template-types';
import caseTemplateTypeDefs from './case-template.graphql';
import convertCaseTemplateToStix from './case-template-converter';
import caseTemplateResolvers from './case-template-resolvers';
import { ENTITY_TYPE_TASK_TEMPLATE } from '../../task/task-template/task-template-types';
import type { RelationRefDefinition } from '../../../schema/relationRef-definition';

const CaseTemplateToTaskTemplateRelation: RelationRefDefinition = {
  inputName: 'tasks',
  label: 'Tasks',
  databaseName: TEMPLATE_TASK_RELATION,
  stixName: 'task_refs',
  mandatoryType: 'internal',
  editDefault: false,
  multiple: true,
  checker: (_, toType) => toType === ENTITY_TYPE_TASK_TEMPLATE,
  datable: false,
  isFilterable: true,
};

const CASE_TEMPLATE_DEFINITION: ModuleDefinition<StoreEntityCaseTemplate, StixCaseTemplate> = {
  type: {
    id: 'case-template',
    name: ENTITY_TYPE_CASE_TEMPLATE,
    category: ABSTRACT_INTERNAL_OBJECT
  },
  graphql: {
    schema: caseTemplateTypeDefs,
    resolver: caseTemplateResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CASE_TEMPLATE]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [],
  relationsRefs: [CaseTemplateToTaskTemplateRelation],
  representative: (stix: StixCaseTemplate) => {
    return stix.name;
  },
  converter: convertCaseTemplateToStix
};
registerDefinition(CASE_TEMPLATE_DEFINITION);
