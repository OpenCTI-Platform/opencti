import type { ModuleDescriptor } from '../module-descriptor';
import { EMAIL_TEMPLATE_DEFINITION } from './emailTemplate';
import emailTemplateTypeDefs from './emailTemplate.graphql';
import emailTemplateResolvers from './emailTemplate-resolver';

const emailTemplateModule: ModuleDescriptor = {
  id: 'emailTemplate',
  dataModel: [EMAIL_TEMPLATE_DEFINITION],
  graphqlSchemas: [{ schema: emailTemplateTypeDefs, resolver: emailTemplateResolvers }],
};

export default emailTemplateModule;
