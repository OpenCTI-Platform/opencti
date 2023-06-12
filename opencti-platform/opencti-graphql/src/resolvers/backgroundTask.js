import { deleteTask, createQueryTask, findAll, findById, createNotificationQueryTask } from '../domain/backgroundTask';
import { createListTask, createNotificationListTask } from '../domain/backgroundTask-common';
import { batchLoader } from '../database/middleware';
import { batchCreator } from '../domain/user';

const creatorLoader = batchLoader(batchCreator);

const taskResolvers = {
  Query: {
    backgroundTask: (_, { id }, context) => findById(context, context.user, id),
    backgroundTasks: (_, args, context) => findAll(context, context.user, args),
  },
  Mutation: {
    listTaskAdd: (_, { input }, context) => createListTask(context.user, input),
    listNotificationTaskAdd: (_, { input }, context) => createNotificationListTask(context, context.user, input),
    queryTaskAdd: (_, { input }, context) => createQueryTask(context, context.user, input),
    queryNotificationTaskAdd: (_, { input }, context) => createNotificationQueryTask(context, context.user, input),
    deleteBackgroundTask: (_, { id }, context) => deleteTask(context, context.user, id),
  },
  BackgroundTask: {
    // eslint-disable-next-line
    __resolveType(obj) {
      if (obj.type === 'QUERY') return 'QueryTask';
      if (obj.type === 'LIST') return 'ListTask';
      if (obj.type === 'RULE') return 'RuleTask';
      /* istanbul ignore next */
      return 'Unknown';
    },
    initiator: (task, _, context) => creatorLoader.load(task.initiator_id, context, context.user),
  },
};

export default taskResolvers;
