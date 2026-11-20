import type { ModuleDescriptor } from '../module-descriptor';
import { FINTEL_TEMPLATE_DEFINITION } from './fintelTemplate';
import templateTypeDefs from './fintelTemplate.graphql';
import fintelTemplateResolvers from './fintel-template-resolvers';

const fintelTemplateModule: ModuleDescriptor = {
  id: 'fintelTemplate',
  dataModel: [FINTEL_TEMPLATE_DEFINITION],
  graphqlSchemas: [{ schema: templateTypeDefs, resolver: fintelTemplateResolvers }],
};

export default fintelTemplateModule;
