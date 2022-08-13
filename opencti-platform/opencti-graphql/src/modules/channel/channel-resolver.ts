import type { Resolvers } from '../../generated/graphql';
import { addChannel, findById, findAll } from './channel-domain';
import { buildRefRelationKey } from '../../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../../schema/stixMetaRelationship';

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
    channelAdd: (_, { input }, { user }) => addChannel(user, input),
  },
};

export default channelResolvers;
