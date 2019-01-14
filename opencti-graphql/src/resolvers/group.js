import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addGroup,
  groupDelete,
  findAll,
  findById,
  members,
  permissions,
  groupEditContext,
  groupEditField,
  groupAddRelation,
  groupDeleteRelation,
  groupCleanContext
} from '../domain/group';
import { fetchEditContext, pubsub } from '../database/redis';
import { admin, auth, withCancel } from './wrapper';

const groupResolvers = {
  Query: {
    group: auth((_, { id }) => findById(id)),
    groups: auth((_, args) => findAll(args))
  },
  Group: {
    members: (group, args) => members(group.id, args),
    permissions: (group, args) => permissions(group.id, args),
    editContext: admin(group => fetchEditContext(group.id))
  },
  Mutation: {
    groupEdit: admin((_, { id }, { user }) => ({
      delete: () => groupDelete(id),
      fieldPatch: ({ input }) => groupEditField(user, id, input),
      contextPatch: ({ input }) => groupEditContext(user, id, input),
      relationAdd: ({ input }) => groupAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        groupDeleteRelation(user, id, relationId)
    })),
    groupAdd: admin((_, { input }, { user }) => addGroup(user, input))
  },
  Subscription: {
    group: {
      resolve: payload => payload.instance,
      subscribe: admin((_, { id }, { user }) => {
        groupEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.Group.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          groupCleanContext(user, id);
        });
      })
    }
  }
};

export default groupResolvers;
