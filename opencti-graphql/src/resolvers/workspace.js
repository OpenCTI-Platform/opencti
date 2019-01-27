import { withFilter } from 'graphql-subscriptions/dist/index';
import {
  addWorkspace,
  workspaceDelete,
  findAll,
  findById,
  markingDefinitions,
  ownedBy,
  objectRefs,
  relationRefs,
  workspaceEditContext,
  workspaceEditField,
  workspaceAddRelation,
  workspaceDeleteRelation,
  workspaceCleanContext
} from '../domain/workspace';
import { fetchEditContext, pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';
import { BUS_TOPICS } from '../config/conf';

const workspaceResolvers = {
  Query: {
    workspace: auth((_, { id }) => findById(id)),
    workspaces: auth((_, args) => findAll(args))
  },
  Workspace: {
    ownedBy: (workspace, args) => ownedBy(workspace.id, args),
    markingDefinitions: (workspace, args) =>
      markingDefinitions(workspace.id, args),
    objectRefs: (workspace, args) => objectRefs(workspace.id, args),
    relationRefs: (workspace, args) => relationRefs(workspace.id, args),
    editContext: auth(workspace => fetchEditContext(workspace.id))
  },
  Mutation: {
    workspaceEdit: auth((_, { id }, { user }) => ({
      delete: () => workspaceDelete(id),
      fieldPatch: ({ input }) => workspaceEditField(user, id, input),
      contextPatch: ({ input }) => workspaceEditContext(user, id, input),
      relationAdd: ({ input }) => workspaceAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        workspaceDeleteRelation(user, id, relationId)
    })),
    workspaceAdd: auth((_, { input }, { user }) => addWorkspace(user, input))
  },
  Subscription: {
    workspace: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        workspaceEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.Workspace.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          workspaceCleanContext(user, id);
        });
      })
    }
  }
};

export default workspaceResolvers;
