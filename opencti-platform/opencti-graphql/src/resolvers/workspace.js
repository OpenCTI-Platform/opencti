import { withFilter } from 'graphql-subscriptions';
import {
  addWorkspace,
  findAll,
  findById,
  findUserById,
  objects,
  fetchEditContext,
  workspaceCleanContext,
  workspaceDelete,
  workspaceEditContext,
  workspaceEditField,
  workspaceAddRelation,
  workspaceAddRelations,
  workspaceDeleteRelation,
  workspaceDeleteRelations,
} from '../domain/cyio-workspace.js';
// import { findById as findUserById } from '../domain/user';
// import { fetchEditContext, pubsub } from '../database/redis';
// import { BUS_TOPICS } from '../config/conf';
// import { ENTITY_TYPE_WORKSPACE } from '../schema/internalObject';
// import withCancel from '../graphql/subscriptionWrapper';
// import { SYSTEM_USER } from '../utils/access';


const workspaceResolvers = {
  Query: {
    workspace: (_, { id }, { user, dbName, dataSources, selectMap }) => findById(user, id, dbName, dataSources, selectMap),
    workspaces: (_, args, { user, dbName, dataSources, selectMap }) => findAll(user, args, dbName, dataSources, selectMap),
  },
  Mutation: {
    workspaceEdit: (_, { id }, { user, dbName, dataSources, selectMap }) => ({
      delete: () => workspaceDelete(user, id, dbName, dataSources),
      fieldPatch: ({ input }) => workspaceEditField(user, id, input, dbName, dataSources, selectMap),
      contextPatch: ({ input }) => workspaceEditContext(user, id, input, dbName, dataSources, selectMap),
      contextClean: () => workspaceCleanContext(user, id, dbName, dataSources, selectMap),
      relationAdd: ({ input }) => workspaceAddRelation(user, id, input, dbName, dataSources, selectMap),
      relationsAdd: ({ input }) => workspaceAddRelations(user, id, input, dbName, dataSources, selectMap),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        workspaceDeleteRelation(user, id, toId, relationshipType, dbName, dataSources, selectMap),
      relationsDelete: ({ toIds, relationship_type: relationshipType }) =>
        workspaceDeleteRelations(user, id, toIds, relationshipType, dbName, dataSources, selectMap),
    }),
    workspaceAdd: (_, { input }, { user, dbName, dataSources, selectMap }) => addWorkspace(user, input, dbName, dataSources, selectMap),
  },
  Workspace: {
    owner: async (workspace, { user, dbName, dataSources, selectMap }) => findUserById(user, workspace.owner, dbName, dataSources, selectMap),
    objects: (workspace, args, { user, dbName, dataSources, selectMap }) => objects(user, workspace.id, args, dbName, dataSources, selectMap),
    editContext: (workspace, { user, dbName, dataSources, selectMap }) => fetchEditContext(workspace.id, dbName, dataSources, selectMap),
  },
  //   Subscription: {
  //     workspace: {
  //       resolve: /* istanbul ignore next */ (payload) => payload.instance,
  //       subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
  //         workspaceEditContext(user, id);
  //         const filtering = withFilter(
  //           () => pubsub.asyncIterator(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC),
  //           (payload) => {
  //             if (!payload) return false; // When disconnect, an empty payload is dispatched.
  //             return payload.user.id !== user.id && payload.instance.id === id;
  //           }
  //         )(_, { id }, { user });
  //         return withCancel(filtering, () => {
  //           workspaceCleanContext(user, id);
  //         });
  //       },
  //     },
  //   },
};

export default workspaceResolvers;
