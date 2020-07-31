import { withFilter } from 'graphql-subscriptions';
import {
  addGroup,
  groupDelete,
  findAll,
  findById,
  members,
  groupEditField,
  groupDeleteRelation,
  groupAddRelation,
  groupCleanContext,
  groupEditContext,
} from '../domain/group';
import { fetchEditContext, pubsub } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { ENTITY_TYPE_GROUP } from '../utils/idGenerator';
import withCancel from '../graphql/subscriptionWrapper';

const groupResolvers = {
  Query: {
    group: (_, { id }) => findById(id),
    groups: (_, args) => findAll(args),
  },
  Group: {
    members: (group) => members(group.id),
    editContext: (group) => fetchEditContext(group.id),
  },
  Mutation: {
    groupEdit: (_, { id }, { user }) => ({
      delete: () => groupDelete(user, id),
      fieldPatch: ({ input }) => groupEditField(user, id, input),
      contextPatch: ({ input }) => groupEditContext(user, id, input),
      contextClean: () => groupCleanContext(user, id),
      relationAdd: ({ input }) => groupAddRelation(user, id, input),
      relationDelete: ({ relationId }) => groupDeleteRelation(user, id, relationId),
    }),
    groupAdd: (_, { input }, { user }) => addGroup(user, input),
  },
  Subscription: {
    group: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        groupEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          groupCleanContext(user, id);
        });
      },
    },
  },
};

export default groupResolvers;
