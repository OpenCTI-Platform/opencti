import { deleteTask, createQueryTask, findBackgroundTaskPaginated, findById } from '../domain/backgroundTask';
import { createListTask } from '../domain/backgroundTask-common';
import { ENTITY_TYPE_WORK } from '../schema/internalObject';

const taskResolvers = {
  Query: {
    backgroundTask: (_, { id }, context) => findById(context, context.user, id),
    backgroundTasks: (_, args, context) => findBackgroundTaskPaginated(context, context.user, args),
  },
  Mutation: {
    listTaskAdd: (_, { input }, context) => createListTask(context, context.user, input),
    queryTaskAdd: (_, { input }, context) => createQueryTask(context, context.user, input),
    deleteBackgroundTask: (_, { id }, context) => deleteTask(context, context.user, id),
  },
  BackgroundTask: {
    // eslint-disable-next-line
    __resolveType(obj) {
      if (obj.type === 'QUERY') return 'QueryTask';
      if (obj.type === 'LIST') return 'ListTask';
      if (obj.type === 'RULE') return 'RuleTask';
      /* v8 ignore next */
      return 'Unknown';
    },
    initiator: (task, _, context) => context.batch.creatorBatchLoader.load(task.initiator_id),
    work: (task, _, context) => {
      return task.work_id ? context.batch.idsBatchLoader.load({ id: task.work_id, type: ENTITY_TYPE_WORK }) : undefined;
    },
  },
};

export default taskResolvers;
