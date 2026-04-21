import type { Resolvers } from '../../generated/graphql';
import { draftEntityMarkRead, draftEntityMarkUnread, findDraftEntityRead } from './draftEntityRead-domain';

const draftEntityReadResolver: Resolvers = {
  Query: {
    draftEntityRead: (_, { entityId, draftId }, context) => {
      return findDraftEntityRead(context, context.user, entityId, draftId);
    },
  },
  Mutation: {
    draftEntityMarkRead: (_, { entityId, draftId }, context) => {
      return draftEntityMarkRead(context, context.user, entityId, draftId);
    },
    draftEntityMarkUnread: (_, { entityId, draftId }, context) => {
      return draftEntityMarkUnread(context, context.user, entityId, draftId);
    },
  },
};

export default draftEntityReadResolver;
