import { BUS_TOPICS } from '../config/conf';
import { elBatchIds } from '../database/engine';
import { batchLoader } from '../database/middleware';
import { fetchEditContext } from '../database/redis';
import { addGroup } from '../domain/grant';
import {
  defaultMarkingDefinitions,
  findAll,
  findById,
  groupAddRelation,
  groupAllowedMarkings,
  groupCleanContext,
  groupMaxShareableMarkings,
  groupDelete,
  groupDeleteRelation,
  groupEditContext,
  groupEditDefaultMarking,
  groupEditField,
  membersPaginated,
  rolesPaginated,
  groupNotShareableMarkingTypes
} from '../domain/group';
import { subscribeToInstanceEvents } from '../graphql/subscriptionWrapper';
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
    allowed_marking: (group, _, context) => groupAllowedMarkings(context, context.user, group.id),
    not_shareable_marking_types: (group) => groupNotShareableMarkingTypes(group),
    max_shareable_marking: (group, _, context) => groupMaxShareableMarkings(context, context.user, group),
    roles: (group, args, context) => rolesPaginated(context, context.user, group.id, args),
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
        const preFn = () => groupEditContext(context, context.user, id);
        const cleanFn = () => groupCleanContext(context, context.user, id);
        const bus = BUS_TOPICS[ENTITY_TYPE_GROUP];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { preFn, cleanFn });
      },
    },
  },
};

export default groupResolvers;
