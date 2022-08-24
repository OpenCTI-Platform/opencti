import type { Resolvers } from '../../generated/graphql';
import { addEvent, findById, findAll } from './event-domain';
import { buildRefRelationKey } from '../../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../../schema/stixMetaRelationship';

const eventResolvers: Resolvers = {
  Query: {
    event: (_, { id }, { user }) => findById(user, id),
    events: (_, args, { user }) => findAll(user, args),
  },
  EventsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
  },
  Mutation: {
    eventAdd: (_, { input }, { user }) => addEvent(user, input),
  },
};

export default eventResolvers;
