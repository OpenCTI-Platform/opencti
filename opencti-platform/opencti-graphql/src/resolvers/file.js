import { loadFile } from '../database/file-storage';
import {
  askJobImport,
  deleteImport,
  filesMetrics,
  uploadImport,
  uploadPending
} from '../domain/file';
import { worksForSource } from '../domain/work';
import { batchLoader } from '../database/middleware';
import { batchCreator } from '../domain/user';
import { batchStixDomainObjects } from '../domain/stixDomainObject';
import { paginatedForPathsWithEnrichment } from '../modules/document/document-domain';

const creatorLoader = batchLoader(batchCreator);
const domainLoader = batchLoader(batchStixDomainObjects);

const fileResolvers = {
  Query: {
    file: (_, { id }, context) => loadFile(context.user, id),
    importFiles: (_, { first }, context) => {
      return paginatedForPathsWithEnrichment(context, context.user, ['import/global'], { first });
    },
    pendingFiles: (_, { first }, context) => {
      return paginatedForPathsWithEnrichment(context, context.user, ['import/pending'], { first });
    },
    filesMetrics: (_, args, context) => filesMetrics(context, context.user, args),
  },
  File: {
    works: (file, _, context) => worksForSource(context, context.user, file.id),
  },
  FileMetadata: {
    entity: (metadata, _, context) => domainLoader.load(metadata.entity_id, context, context.user),
    creator: (metadata, _, context) => creatorLoader.load(metadata.creator_id, context, context.user),
  },
  Mutation: {
    uploadImport: (_, { file }, context) => uploadImport(context, context.user, file),
    uploadPending: (_, { file, entityId, labels, errorOnExisting }, context) => {
      return uploadPending(context, context.user, file, entityId, labels, errorOnExisting);
    },
    deleteImport: (_, { fileName }, context) => deleteImport(context, context.user, fileName),
    askJobImport: (_, args, context) => askJobImport(context, context.user, args),
  },
};

export default fileResolvers;
