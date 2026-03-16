import type { EditContext, EditInput, Resolvers, StreamCollection, StreamCollectionConnection, StreamCollectionEditMutations, RedisStreamInfo } from '../../generated/graphql';
import type { BasicStoreEntity } from '../../types/store';
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

const streamCollectionResolvers: Resolvers = {
  Query: {
    streamCollection: (_, { id }, context) => findById(context, context.user, id) as unknown as Promise<StreamCollection>,
    streamCollections: (_, args, context) => findStreamCollectionPaginated(context, context.user, args) as unknown as Promise<StreamCollectionConnection>,
    redisStreamInfo: () => fetchStreamInfo() as unknown as Promise<RedisStreamInfo>,
  },
  StreamCollection: {
    authorized_members: (stream, _, context) => getAuthorizedMembers(context, context.user, stream as unknown as BasicStoreEntity),
    consumers: (stream) => getStreamCollectionConsumers(stream.id),
  },
  Mutation: {
    streamCollectionAdd: (_, { input }, context) => createStreamCollection(context, context.user, input) as unknown as Promise<StreamCollection>,
    streamCollectionEdit: (_, { id }, context) => ({
      delete: () => streamCollectionDelete(context, context.user, id),
      fieldPatch: ({ input }: { input: EditInput[] }) => streamCollectionEditField(context, context.user, id, input),
      contextPatch: ({ input }: { input: EditContext }) => streamCollectionEditContext(context, context.user, id, input),
      contextClean: () => streamCollectionCleanContext(context, context.user, id),
    }) as unknown as StreamCollectionEditMutations,
  },
};

export default streamCollectionResolvers;
