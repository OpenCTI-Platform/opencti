import { BUS_TOPICS } from '../config/conf';
import {
  addGroup,
  groupDelete,
  findAll,
  findById,
  users,
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
    users: (group, args) => users(group.id, args),
    permissions: (group, args) => permissions(group.id, args),
    editContext: admin(group => fetchEditContext(group.id))
  },
  Mutation: {
    groupEdit: admin((_, { id }, { user }) => ({
      delete: () => groupDelete(id),
      fieldPatch: ({ input }) => groupEditField(id, input),
      contextPatch: ({ input }) => groupEditContext(user, id, input),
      relationAdd: ({ input }) => groupAddRelation(id, input),
      relationDelete: ({ relationId }) => groupDeleteRelation(relationId)
    })),
    groupAdd: admin((_, { input }, { user }) => addGroup(user, input))
  },
  Subscription: {
    group: {
      resolve: payload => payload.instance,
      subscribe: admin((_, { id }, { user }) => {
        groupEditContext(user, id);
        return withCancel(
          pubsub.asyncIterator(BUS_TOPICS.Group.EDIT_TOPIC),
          () => {
            groupCleanContext(user, id);
          }
        );
      })
    }
  }
};

export default groupResolvers;
