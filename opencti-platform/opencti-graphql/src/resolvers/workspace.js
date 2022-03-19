import { withFilter } from 'graphql-subscriptions';
import {
  addWorkspace,
  findAll,
  findById,
  objects,
  workspaceCleanContext,
  workspaceDelete,
  workspaceEditContext,
  workspaceEditField,
  workspaceAddRelation,
  workspaceAddRelations,
  workspaceDeleteRelation,
  workspaceDeleteRelations,
} from '../domain/workspace';
import { findById as findUserById } from '../domain/user';
import { fetchEditContext, pubsub } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { ENTITY_TYPE_WORKSPACE } from '../schema/internalObject';
import withCancel from '../graphql/subscriptionWrapper';
import { SYSTEM_USER } from '../utils/access';

const workspaceResolvers = {
  Query: {
    workspace: (_, { id }, { user }) => findById(user, id),
    workspaces: (_, args, { user }) => findAll(user, args),
  },
  Workspace: {
    owner: async (workspace, { user }) => {
      const findUser = await findUserById(user, workspace.owner);
      return findUser || SYSTEM_USER;
    },
    objects: (workspace, args, { user }) => objects(user, workspace.id, args),
    editContext: (workspace) => fetchEditContext(workspace.id),
  },
  Mutation: {
    workspaceEdit: (_, { id }, { user }) => ({
      delete: () => workspaceDelete(user, id),
      fieldPatch: ({ input }) => workspaceEditField(user, id, input),
      contextPatch: ({ input }) => workspaceEditContext(user, id, input),
      contextClean: () => workspaceCleanContext(user, id),
      relationAdd: ({ input }) => workspaceAddRelation(user, id, input),
      relationsAdd: ({ input }) => workspaceAddRelations(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => workspaceDeleteRelation(user, id, toId, relationshipType),
      relationsDelete: ({ toIds, relationship_type: relationshipType }) => workspaceDeleteRelations(user, id, toIds, relationshipType),
    }),
    workspaceAdd: (_, { input }, { user }) => addWorkspace(user, input),
  },
  Subscription: {
    workspace: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        workspaceEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          workspaceCleanContext(user, id);
        });
      },
    },
  },
};

export default workspaceResolvers;
