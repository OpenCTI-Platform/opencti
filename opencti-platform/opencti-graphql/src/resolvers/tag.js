import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addTag,
  tagDelete,
  findAll,
  findByValue,
  findById,
  findByEntity,
  tagEditContext,
  tagEditField,
  tagAddRelation,
  tagDeleteRelation,
  tagCleanContext
} from '../domain/tag';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../schema/subscriptionWrapper';

const tagResolvers = {
  Query: {
    tag: (_, { id }) => findById(id),
    tags: (_, args) => {
      if (args.tag_type && args.tag_type.length > 0 && args.value && args.value.length > 0) {
        return findByValue(args);
      }
      if (args.objectId && args.objectId.length > 0) {
        return findByEntity(args);
      }
      return findAll(args);
    }
  },
  Tag: {
    editContext: tag => fetchEditContext(tag.id)
  },
  Mutation: {
    tagEdit: (_, { id }, { user }) => ({
      delete: () => tagDelete(id),
      fieldPatch: ({ input }) => tagEditField(user, id, input),
      contextPatch: ({ input }) => tagEditContext(user, id, input),
      relationAdd: ({ input }) => tagAddRelation(user, id, input),
      relationDelete: ({ relationId }) => tagDeleteRelation(user, id, relationId)
    }),
    tagAdd: (_, { input }, { user }) => addTag(user, input)
  },
  Subscription: {
    tag: {
      resolve: payload => payload.instance,
      subscribe: (_, { id }, { user }) => {
        tagEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.Tag.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          tagCleanContext(user, id);
        });
      }
    }
  }
};

export default tagResolvers;
