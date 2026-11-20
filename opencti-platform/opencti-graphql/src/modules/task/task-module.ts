import type { ModuleDescriptor } from '../module-descriptor';
import { CASE_TASK_DEFINITION } from './task';
import taskTypeDefs from './task.graphql';
import taskResolvers from './task-resolvers';

const taskModule: ModuleDescriptor = {
  id: 'task',
  dataModel: [CASE_TASK_DEFINITION],
  graphqlSchemas: [{ schema: taskTypeDefs, resolver: taskResolvers }],
};

export default taskModule;
