import type { Resolvers } from '../../generated/graphql';
import {
  findDeadLetterPaginated,
  findById,
  getDeadLetterQueueMessageCount,
  deleteDeadLetterMessage,
  importDeadLetterMessages,
  retryDeadLetterMessage,
} from './deadLetterMessage-domain';

const deadLetterMessageResolvers: Resolvers = {
  Query: {
    deadLetterQueueMessageCount: (_, args, context) => getDeadLetterQueueMessageCount(context, context.user),
    deadLetterMessage: (_, { id }, context) => findById(context, context.user, id),
    deadLetterMessages: (_, args, context) => findDeadLetterPaginated(context, context.user, args),
  },
  Mutation: {
    importDeadLetterMessages: (_, args, context) => importDeadLetterMessages(context, context.user),
    deadLetterMessageDelete: (_, { id }, context) => deleteDeadLetterMessage(context, context.user, id),
    deadLetterMessageRetry: (_, { id }, context) => retryDeadLetterMessage(context, context.user, id),
  },
};

export default deadLetterMessageResolvers;
