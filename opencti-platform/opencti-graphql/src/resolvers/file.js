import { guessMimeType, loadFile } from '../database/file-storage';
import { deleteImport, filesMetrics, uploadAndAskJobImport, uploadImport, uploadPending } from '../domain/file';
import { paginatedForPathWithEnrichment } from '../modules/internal/document/document-domain';
import { buildDraftVersion } from '../modules/draftWorkspace/draftWorkspace-domain';
import { getDraftContextFilesPrefix } from '../database/draft-utils';
import { askJobImport } from '../domain/connector';

const fileResolvers = {
  Query: {
    file: (_, { id }, context) => loadFile(context, context.user, id),
    importFiles: (_, opts, context) => {
      const globalFilesPath = `${getDraftContextFilesPrefix(context)}import/global`;
      return paginatedForPathWithEnrichment(context, context.user, globalFilesPath, undefined, opts);
    },
    pendingFiles: (_, opts, context) => { // correspond to global workbenches (i.e. worbenches in Data > Import)
      return paginatedForPathWithEnrichment(context, context.user, 'import/pending', undefined, opts);
    },
    filesMetrics: (_, args, context) => filesMetrics(context, context.user),
    guessMimeType: (_, { fileId }) => guessMimeType(fileId),
  },
  File: {
    objectMarking: (rel, _, context) => context.batch.fileMarkingsBatchLoader.load(rel),
    works: (file, _, context) => context.batch.fileWorksBatchLoader.load(file.id),
    draftVersion: (file) => buildDraftVersion(file),
  },
  FileMetadata: {
    entity: (metadata, _, context) => context.batch.domainsBatchLoader.load(metadata.entity_id),
    creator: (metadata, _, context) => context.batch.creatorBatchLoader.load(metadata.creator_id),
  },
  Mutation: {
    uploadImport: (_, args, context) => uploadImport(context, context.user, args),
    uploadPending: (_, args, context) => uploadPending(context, context.user, args),
    deleteImport: (_, { fileName }, context) => deleteImport(context, context.user, fileName),
    askJobImport: (_, args, context) => askJobImport(context, context.user, args),
    uploadAndAskJobImport: (_, args, context) => uploadAndAskJobImport(context, context.user, args),
  },
};

export default fileResolvers;
