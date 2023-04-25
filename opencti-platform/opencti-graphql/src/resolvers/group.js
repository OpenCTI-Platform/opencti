import { withFilter } from 'graphql-subscriptions';
import {
  groupDelete,
  findAll,
  findById,
  batchMarkingDefinitions,
  batchMembers,
  groupEditField,
  groupDeleteRelation,
  groupAddRelation,
  groupCleanContext,
  groupEditContext, batchRoles,
} from '../domain/group';
import { fetchEditContext, pubSubAsyncIterator } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import withCancel from '../graphql/subscriptionWrapper';
import { ENTITY_TYPE_GROUP } from '../schema/internalObject';
import { batchLoader } from '../database/middleware';
import { addGroup } from '../domain/grant';

const markingsLoader = batchLoader(batchMarkingDefinitions);
const membersLoader = batchLoader(batchMembers);
const rolesLoader = batchLoader(batchRoles);

const groupResolvers = {
  Query: {
    group: (_, { id }, context) => findById(context, context.user, id),
    groups: (_, args, context) => findAll(context, context.user, args),
  },
  Group: {
    allowed_marking: (stixCoreObject, _, context) => markingsLoader.load(stixCoreObject.id, context, context.user),
    roles: (stixCoreObject, _, context) => rolesLoader.load(stixCoreObject.id, context, context.user),
    members: (group, _, context) => membersLoader.load(group.id, context, context.user),
    editContext: (group) => fetchEditContext(group.id),
  },
  Mutation: {
    groupEdit: (_, { id }, context) => ({
      delete: () => groupDelete(context, context.user, id),
      fieldPatch: ({ input }) => groupEditField(context, context.user, id, input),
      contextPatch: ({ input }) => groupEditContext(context, context.user, id, input),
      contextClean: () => groupCleanContext(context, context.user, id),
      relationAdd: ({ input }) => groupAddRelation(context, context.user, id, input),
      relationDelete: ({ fromId, toId, relationship_type: relationshipType }) => groupDeleteRelation(context, context.user, id, fromId, toId, relationshipType),
    }),
    groupAdd: (_, { input }, context) => addGroup(context, context.user, input),
  },
  Subscription: {
    group: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, context) => {
        groupEditContext(context, context.user, id);
        const filtering = withFilter(
          () => pubSubAsyncIterator(BUS_TOPICS[ENTITY_TYPE_GROUP].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== context.user.id && payload.instance.id === id;
          }
        )(_, { id }, context);
        return withCancel(filtering, () => {
          groupCleanContext(context, context.user, id);
        });
      },
    },
  },
};

export default groupResolvers;
