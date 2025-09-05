import type { Resolvers } from '../../generated/graphql';
import { addChannel, findChannelPaginated, findById } from './channel-domain';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField
} from '../../domain/stixDomainObject';

const channelResolvers: Resolvers = {
  Query: {
    channel: (_, { id }, context) => findById(context, context.user, id),
    channels: (_, args, context) => findChannelPaginated(context, context.user, args),
  },
  Mutation: {
    channelAdd: (_, { input }, context) => {
      return addChannel(context, context.user, input);
    },
    channelDelete: (_, { id }, context) => {
      return stixDomainObjectDelete(context, context.user, id);
    },
    channelFieldPatch: (_, { id, input, commitMessage, references }, context) => {
      return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
    },
    channelContextPatch: (_, { id, input }, context) => {
      return stixDomainObjectEditContext(context, context.user, id, input);
    },
    channelContextClean: (_, { id }, context) => {
      return stixDomainObjectCleanContext(context, context.user, id);
    },
    channelRelationAdd: (_, { id, input }, context) => {
      return stixDomainObjectAddRelation(context, context.user, id, input);
    },
    channelRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
    },
  },
};

export default channelResolvers;
