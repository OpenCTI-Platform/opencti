import { batchLoader } from '../../database/middleware';
import type { Resolvers } from '../../generated/graphql';
import { findById, findAll, addDraftWorkspace, deleteDraftWorkspace, listDraftObjects, validateDraftWorkspace, listDraftRelations } from './draftWorkspace-domain';
import { batchCreators } from '../../domain/user';

const creatorsLoader = batchLoader(batchCreators);

const draftWorkspaceResolvers: Resolvers = {
  Query: {
    draftWorkspace: (_, { id }, context) => findById(context, context.user, id),
    draftWorkspaces: (_, args, context) => findAll(context, context.user, args),
    draftWorkspaceEntities: (_, args, context) => listDraftObjects(context, context.user, args),
    draftWorkspaceRelationships: (_, args, context) => listDraftRelations(context, context.user, args),
  },
  DraftWorkspace: {
    creators: (draft, _, context) => creatorsLoader.load(draft.creator_id, context, context.user),
  },
  Mutation: {
    draftWorkspaceAdd: (_, { input }, context) => {
      return addDraftWorkspace(context, context.user, input);
    },
    draftWorkspaceValidate: (_, { id }, context) => {
      return validateDraftWorkspace(context, context.user, id);
    },
    draftWorkspaceDelete: (_, { id }, context) => {
      return deleteDraftWorkspace(context, context.user, id);
    },
  }
};

export default draftWorkspaceResolvers;
