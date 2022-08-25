import type { Resolvers } from '../../generated/graphql';
import { addChannel, findById, findAll } from './channel-domain';
import { buildRefRelationKey } from '../../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../../schema/stixMetaRelationship';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete, stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField
} from '../../domain/stixDomainObject';

const channelResolvers: Resolvers = {
  Query: {
    channel: (_, { id }, { user }) => findById(user, id),
    channels: (_, args, { user }) => findAll(user, args),
  },
  ChannelsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
  },
  Mutation: {
    channelAdd: (_, { input }, { user }) => {
      return addChannel(user, input);
    },
    channelDelete: (_, { id }, { user }) => {
      return stixDomainObjectDelete(user, id);
    },
    channelFieldPatch: (_, { id, input, commitMessage, references }, { user }) => {
      return stixDomainObjectEditField(user, id, input, { commitMessage, references });
    },
    channelContextPatch: (_, { id, input }, { user }) => {
      return stixDomainObjectEditContext(user, id, input);
    },
    channelContextClean: (_, { id }, { user }) => {
      return stixDomainObjectCleanContext(user, id);
    },
    channelRelationAdd: (_, { id, input }, { user }) => {
      return stixDomainObjectAddRelation(user, id, input);
    },
    channelRelationDelete: (_, { id, toId, relationship_type: relationshipType }, { user }) => {
      return stixDomainObjectDeleteRelation(user, id, toId, relationshipType);
    },
  },
};

export default channelResolvers;
