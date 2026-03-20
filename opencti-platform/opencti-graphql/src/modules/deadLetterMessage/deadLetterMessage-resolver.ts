import type { Resolvers } from '../../generated/graphql';
import { findDeadLetterPaginated, findById } from './deadLetterMessage-domain';

const deadLetterMessageResolvers: Resolvers = {
  Query: {
    deadLetterMessage: (_, { id }, context) => findById(context, context.user, id),
    deadLetterMessages: (_, args, context) => findDeadLetterPaginated(context, context.user, args),
  },
  Mutation: {
  },
};

export default deadLetterMessageResolvers;
