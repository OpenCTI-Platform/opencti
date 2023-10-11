import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import { elBatchIds } from '../database/engine';
import { batchLoader } from '../database/middleware';
import { fetchEditContext, pubSubAsyncIterator } from '../database/redis';
import { addGroup } from '../domain/grant';
import { batchMarkingDefinitions, batchMembers, batchRoles, defaultMarkingDefinitions, findAll, findById, groupAddRelation, groupCleanContext, groupDelete, groupDeleteRelation, groupEditContext, groupEditDefaultMarking, groupEditField, } from '../domain/group';
import withCancel from '../graphql/subscriptionWrapper';
import { ENTITY_TYPE_GROUP } from '../schema/internalObject';

const loadByIdLoader = batchLoader(elBatchIds);
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
    default_marking: (group, _, context) => defaultMarkingDefinitions(context, group),
    roles: (stixCoreObject, _, context) => rolesLoader.load(stixCoreObject.id, context, context.user),
    members: (group, args, context) => membersLoader.load(group.id, context, context.user, args),
    editContext: (group) => fetchEditContext(group.id),
    default_dashboard: (current, _, context) => loadByIdLoader.load(current.default_dashboard, context, context.user),
  },
  Mutation: {
    groupEdit: (_, { id }, context) => ({
      delete: () => groupDelete(context, context.user, id),
      fieldPatch: ({ input }) => groupEditField(context, context.user, id, input),
      contextPatch: ({ input }) => groupEditContext(context, context.user, id, input),
      contextClean: () => groupCleanContext(context, context.user, id),
      relationAdd: ({ input }) => groupAddRelation(context, context.user, id, input),
      relationDelete: ({ fromId, toId, relationship_type: relationshipType }) => groupDeleteRelation(context, context.user, id, fromId, toId, relationshipType),
      editDefaultMarking: ({ input }) => groupEditDefaultMarking(context, context.user, id, input),
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
