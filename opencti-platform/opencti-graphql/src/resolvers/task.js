import { deleteTask, createListTask, createQueryTask, findAll, findById } from '../domain/task';
import { findById as findUser } from '../domain/user';

const taskResolvers = {
  Query: {
    task: (_, { id }, { user }) => findById(user, id),
    tasks: (_, args, { user }) => findAll(user, args),
  },
  Mutation: {
    listTaskAdd: (_, { input }, { user }) => createListTask(user, input),
    queryTaskAdd: (_, { input }, { user }) => createQueryTask(user, input),
    deleteTask: (_, { id }, { user }) => deleteTask(user, id),
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
    initiator: (task, _, { user }) => findUser(user, task.initiator_id),
  },
};

export default taskResolvers;
