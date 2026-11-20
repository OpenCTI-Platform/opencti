import type { ModuleDescriptor } from '../../module-descriptor';
import { TASK_TEMPLATE_DEFINITION } from './task-template';
import caseTaskTypeDefs from './task-template.graphql';
import taskTemplateResolvers from './task-template-resolvers';

const taskTemplateModule: ModuleDescriptor = {
  id: 'taskTemplate',
  dataModel: [TASK_TEMPLATE_DEFINITION],
  graphqlSchemas: [{ schema: caseTaskTypeDefs, resolver: taskTemplateResolvers }],
};

export default taskTemplateModule;
