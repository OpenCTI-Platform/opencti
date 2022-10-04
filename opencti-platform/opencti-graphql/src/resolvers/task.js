import { deleteTask, createListTask, createQueryTask, findAll, findById } from '../domain/task';
import { findById as findUser } from '../domain/user';

const taskResolvers = {
  Query: {
    task: (_, { id }, context) => findById(context, context.user, id),
    tasks: (_, args, context) => findAll(context, context.user, args),
  },
  Mutation: {
    listTaskAdd: (_, { input }, context) => createListTask(context, context.user, input),
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
    initiator: (task, _, context) => findUser(context, context.user, task.initiator_id),
  },
};

export default taskResolvers;
