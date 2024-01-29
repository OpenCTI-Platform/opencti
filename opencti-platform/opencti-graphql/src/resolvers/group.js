import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import { elBatchIds } from '../database/engine';
import { batchLoader } from '../database/middleware';
import { fetchEditContext, pubSubAsyncIterator } from '../database/redis';
import { addGroup } from '../domain/grant';
import {
  defaultMarkingDefinitions,
  findAll,
  findById,
  groupAddRelation,
  groupAllowedMarkings,
  groupCleanContext,
  groupDelete,
  groupDeleteRelation,
  groupEditContext,
  groupEditDefaultMarking,
  groupEditField,
  membersPaginated,
  rolesPaginated
} from '../domain/group';
import withCancel from '../graphql/subscriptionWrapper';
import { ENTITY_TYPE_GROUP } from '../schema/internalObject';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';

const loadByIdLoader = batchLoader(elBatchIds);

const groupResolvers = {
  Query: {
    group: (_, { id }, context) => findById(context, context.user, id),
    groups: (_, args, context) => findAll(context, context.user, args),
  },
  Group: {
    default_marking: (group, _, context) => defaultMarkingDefinitions(context, group),
    allowed_marking: (stixCoreObject, _, context) => groupAllowedMarkings(context, context.user, stixCoreObject.id),
    roles: (stixCoreObject, args, context) => rolesPaginated(context, context.user, stixCoreObject.id, args),
    members: (group, args, context) => membersPaginated(context, context.user, group.id, args),
    default_dashboard: (current, _, context) => loadByIdLoader.load({ id: current.default_dashboard, type: ENTITY_TYPE_WORKSPACE }, context, context.user),
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
      editDefaultMarking: ({ input }) => groupEditDefaultMarking(context, context.user, id, input),
    }),
    groupAdd: (_, { input }, context) => addGroup(context, context.user, input),
  },
  Subscription: {
    group: {
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
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
