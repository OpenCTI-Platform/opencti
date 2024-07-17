import type { Resolvers } from '../../generated/graphql';
import { findById, findAll, addDraftWorkspace, deleteDraftWorkspace, validateDraftWorkspace, findAllEntities } from './draftWorkspace-domain';

const draftWorkspaceResolvers: Resolvers = {
  Query: {
    draftWorkspace: (_, { id }, context) => findById(context, context.user, id),
    draftWorkspaces: (_, args, context) => findAll(context, context.user, args),
    draftWorkspaceEntities: (_, args, context) => findAllEntities(context, context.user, args),
  },
  Mutation: {
    draftWorkspaceAdd: (_, { input }, context) => {
      return addDraftWorkspace(context, context.user, input);
    },
    draftWorkspaceDelete: (_, { id }, context) => {
      return deleteDraftWorkspace(context, context.user, id);
    },
    draftWorkspaceValidate: (_, { id }, context) => {
      return validateDraftWorkspace(context, context.user, id);
    },
  }
};

export default draftWorkspaceResolvers;
