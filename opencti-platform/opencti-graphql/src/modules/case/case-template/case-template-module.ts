import type { ModuleDescriptor } from '../../module-descriptor';
import { CASE_TEMPLATE_DEFINITION } from './case-template';
import caseTemplateTypeDefs from './case-template.graphql';
import caseTemplateResolvers from './case-template-resolvers';

const caseTemplateModule: ModuleDescriptor = {
  id: 'caseTemplate',
  dataModel: [CASE_TEMPLATE_DEFINITION],
  graphqlSchemas: [{ schema: caseTemplateTypeDefs, resolver: caseTemplateResolvers }],
};

export default caseTemplateModule;
