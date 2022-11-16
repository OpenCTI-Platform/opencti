import { deleteTask, createQueryTask, findAll, findById } from '../domain/task';
import { createListTask } from '../domain/task-common';
import { batchLoader } from '../database/middleware';
import { batchUsers } from '../domain/user';

const initiatorLoader = batchLoader(batchUsers);

const taskResolvers = {
  Query: {
    task: (_, { id }, context) => findById(context, context.user, id),
    tasks: (_, args, context) => findAll(context, context.user, args),
  },
  Mutation: {
    listTaskAdd: (_, { input }, context) => createListTask(context.user, input),
    queryTaskAdd: (_, { input }, context) => createQueryTask(context, context.user, input),
    deleteTask: (_, { id }, context) => deleteTask(context, context.user, id),
  },
  Task: {
    // eslint-disable-next-line
    __resolveType(obj) {
      if (obj.type === 'QUERY') return 'QueryTask';
      if (obj.type === 'LIST') return 'ListTask';
      if (obj.type === 'RULE') return 'RuleTask';
      /* istanbul ignore next */
      return 'Unknown';
    },
    initiator: (task, _, context) => initiatorLoader.load(task.initiator_id, context, context.user),
  },
};

export default taskResolvers;
