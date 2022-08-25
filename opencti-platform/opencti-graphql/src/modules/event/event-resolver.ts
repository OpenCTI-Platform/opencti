import type { Resolvers } from '../../generated/graphql';
import { addEvent, findById, findAll } from './event-domain';
import { buildRefRelationKey } from '../../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../../schema/stixMetaRelationship';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete, stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField
} from '../../domain/stixDomainObject';

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
    eventAdd: (_, { input }, { user }) => {
      return addEvent(user, input);
    },
    eventDelete: (_, { id }, { user }) => {
      return stixDomainObjectDelete(user, id);
    },
    eventFieldPatch: (_, { id, input, commitMessage, references }, { user }) => {
      return stixDomainObjectEditField(user, id, input, { commitMessage, references });
    },
    eventContextPatch: (_, { id, input }, { user }) => {
      return stixDomainObjectEditContext(user, id, input);
    },
    eventContextClean: (_, { id }, { user }) => {
      return stixDomainObjectCleanContext(user, id);
    },
    eventRelationAdd: (_, { id, input }, { user }) => {
      return stixDomainObjectAddRelation(user, id, input);
    },
    eventRelationDelete: (_, { id, toId, relationship_type: relationshipType }, { user }) => {
      return stixDomainObjectDeleteRelation(user, id, toId, relationshipType);
    },
  },
};

export default eventResolvers;
