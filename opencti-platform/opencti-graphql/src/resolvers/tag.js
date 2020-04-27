import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addTag,
  findAll,
  findById,
  tagCleanContext,
  tagDelete,
  tagEditContext,
  tagEditField,
} from '../domain/tag';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';

const tagResolvers = {
  Query: {
    tag: (_, { id }) => findById(id),
    tags: (_, args) => findAll(args),
  },
  TagsFilter: {
    tagsFor: `${REL_INDEX_PREFIX}tagged.internal_id_key`,
  },
  Tag: {
    editContext: (tag) => fetchEditContext(tag.id),
  },
  Mutation: {
    tagEdit: (_, { id }, { user }) => ({
      delete: () => tagDelete(user, id),
      fieldPatch: ({ input }) => tagEditField(user, id, input),
      contextPatch: ({ input }) => tagEditContext(user, id, input),
      contextClean: () => tagCleanContext(user, id),
    }),
    tagAdd: (_, { input }, { user }) => addTag(user, input),
  },
  Subscription: {
    tag: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        tagEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.Tag.EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          tagCleanContext(user, id);
        });
      },
    },
  },
};

export default tagResolvers;
