import { deleteTask, createQueryTask, findAll, findById } from '../domain/backgroundTask';
import { createListTask } from '../domain/backgroundTask-common';
import { batchLoader } from '../database/middleware';
import { batchCreator } from '../domain/user';
import { elBatchIds } from '../database/engine';
import { ENTITY_TYPE_WORK } from '../schema/internalObject';

const loadByIdLoader = batchLoader(elBatchIds);
const creatorLoader = batchLoader(batchCreator);

const taskResolvers = {
  Query: {
    backgroundTask: (_, { id }, context) => findById(context, context.user, id),
    backgroundTasks: (_, args, context) => findAll(context, context.user, args),
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
    initiator: (task, _, context) => creatorLoader.load(task.initiator_id, context, context.user),
    work: (task, _, context) => {
      return task.work_id ? loadByIdLoader.load({ id: task.work_id, type: ENTITY_TYPE_WORK }, context, context.user) : undefined;
    },
  },
};

export default taskResolvers;
