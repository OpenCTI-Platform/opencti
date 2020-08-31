import { withFilter } from 'graphql-subscriptions';
import {
  addWorkspace,
  workspaceDelete,
  findAll,
  findById,
  workspacesNumber,
  workspaceEditContext,
  workspaceEditField,
  workspaceAddRelation,
  workspaceAddRelations,
  workspaceDeleteRelation,
  workspaceCleanContext,
} from '../domain/workspace';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { BUS_TOPICS } from '../config/conf';

const workspaceResolvers = {
  Query: {
    workspace: (_, { id }) => findById(id),
    workspaces: (_, args) => findAll(args),
    workspacesNumber: (_, args) => workspacesNumber(args),
  },
  Workspace: {
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
      relationDelete: ({ relationId }) => workspaceDeleteRelation(user, id, relationId),
    }),
    workspaceAdd: (_, { input }, { user }) => addWorkspace(user, input),
  },
  Subscription: {
    workspace: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        workspaceEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.Workspace.EDIT_TOPIC),
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
