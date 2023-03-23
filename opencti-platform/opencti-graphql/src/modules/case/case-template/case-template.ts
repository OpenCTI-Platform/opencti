import { v4 as uuidv4 } from 'uuid';
import { ModuleDefinition, registerDefinition } from '../../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import type { StixCaseTemplate, StoreEntityCaseTemplate } from './case-template-types';
import { ENTITY_TYPE_CASE_TEMPLATE } from './case-template-types';
import caseTemplateTypeDefs from './case-template.graphql';
import convertCaseTemplateToStix from './case-template-converter';
import caseTemplateResolvers from './case-template-resolvers';

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
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'tasks', type: 'string', mandatoryType: 'no', multiple: true, upsert: false },
  ],
  relations: [],
  representative: (stix: StixCaseTemplate) => {
    return stix.name;
  },
  converter: convertCaseTemplateToStix
};
registerDefinition(CASE_TEMPLATE_DEFINITION);
