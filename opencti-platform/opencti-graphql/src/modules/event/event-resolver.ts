import type { Resolvers } from '../../generated/graphql';
import { addEvent, findEventPaginated, findById } from './event-domain';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField
} from '../../domain/stixDomainObject';

const eventResolvers: Resolvers = {
  Query: {
    event: (_, { id }, context) => findById(context, context.user, id),
    events: (_, args, context) => findEventPaginated(context, context.user, args),
  },
  Mutation: {
    eventAdd: (_, { input }, context) => {
      return addEvent(context, context.user, input);
    },
    eventDelete: (_, { id }, context) => {
      return stixDomainObjectDelete(context, context.user, id);
    },
    eventFieldPatch: (_, { id, input, commitMessage, references }, context) => {
      return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
    },
    eventContextPatch: (_, { id, input }, context) => {
      return stixDomainObjectEditContext(context, context.user, id, input);
    },
    eventContextClean: (_, { id }, context) => {
      return stixDomainObjectCleanContext(context, context.user, id);
    },
    eventRelationAdd: (_, { id, input }, context) => {
      return stixDomainObjectAddRelation(context, context.user, id, input);
    },
    eventRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
    },
  },
};

export default eventResolvers;
