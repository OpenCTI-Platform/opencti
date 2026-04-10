import type { EditContext, EditInput, Resolvers, RedisStreamInfo } from '../../generated/graphql';
import {
  createStreamCollection,
  findById,
  findStreamCollectionPaginated,
  getStreamCollectionConsumers,
  streamCollectionCleanContext,
  streamCollectionDelete,
  streamCollectionEditContext,
  streamCollectionEditField,
} from './streamCollection-domain';
import { getAuthorizedMembers } from '../../utils/authorizedMembers';
import { fetchStreamInfo } from '../../database/stream/stream-handler';
import { loadCreator } from '../../database/members';

const streamCollectionResolvers: Resolvers = {
  Query: {
    streamCollection: (_, { id }, context) => findById(context, context.user, id),
    streamCollections: (_, args, context) => findStreamCollectionPaginated(context, context.user, args),
    redisStreamInfo: () => fetchStreamInfo() as unknown as Promise<RedisStreamInfo>,
  },
  StreamCollection: {
    authorized_members: (stream, _, context) => getAuthorizedMembers(context, context.user, stream),
    consumers: (stream) => getStreamCollectionConsumers(stream.id),
    stream_public_user: (stream, _, context) => stream.stream_public_user_id ? loadCreator(context, context.user, stream.stream_public_user_id) : null,
  },
  Mutation: {
    streamCollectionAdd: (_, { input }, context) => createStreamCollection(context, context.user, input),
    streamCollectionEdit: (_, { id }, context) => ({
      delete: () => streamCollectionDelete(context, context.user, id),
      fieldPatch: ({ input }: { input: EditInput[] }) => streamCollectionEditField(context, context.user, id, input),
      contextPatch: ({ input }: { input: EditContext }) => streamCollectionEditContext(context, context.user, id, input),
      contextClean: () => streamCollectionCleanContext(context, context.user, id),
    }) as any,
  },
};

export default streamCollectionResolvers;
