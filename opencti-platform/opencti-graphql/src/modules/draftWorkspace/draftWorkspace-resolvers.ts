import { batchLoader } from '../../database/middleware';
import type { Resolvers } from '../../generated/graphql';
import {
  findById,
  findAll,
  addDraftWorkspace,
  deleteDraftWorkspace,
  getObjectsCount,
  listDraftObjects,
  validateDraftWorkspace,
  listDraftRelations,
  listDraftSightingRelations,
  getProcessingCount
} from './draftWorkspace-domain';
import { batchCreators } from '../../domain/user';
import { findById as findWorkById, worksForDraft } from '../../domain/work';

const creatorsLoader = batchLoader(batchCreators);

const draftWorkspaceResolvers: Resolvers = {
  Query: {
    draftWorkspace: (_, { id }, context) => findById(context, context.user, id),
    draftWorkspaces: (_, args, context) => findAll(context, context.user, args),
    draftWorkspaceEntities: (_, args, context) => listDraftObjects(context, context.user, args),
    draftWorkspaceRelationships: (_, args, context) => listDraftRelations(context, context.user, args),
    draftWorkspaceSightingRelationships: (_, args, context) => listDraftSightingRelations(context, context.user, args),
  },
  DraftWorkspace: {
    creators: (draft, _, context) => creatorsLoader.load(draft.creator_id, context, context.user),
    objectsCount: (draft, _, context) => getObjectsCount(context, context.user, draft),
    processingCount: (draft, _, context) => getProcessingCount(context, context.user, draft),
    works: (draft, args, context) => worksForDraft(context, context.user, draft.id, args),
    validationWork: (draft, _, context) => (draft.validation_work_id ? findWorkById(context, context.user, draft.validation_work_id) as any : null),
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
