import GraphQLUpload from 'graphql-upload/GraphQLUpload.mjs';
import { deleteFile, filesListing, loadFile } from '../database/file-storage';
import { askJobImport, uploadImport, uploadPending } from '../domain/file';
import { worksForSource } from '../domain/work';
import { stixCoreObjectImportDelete } from '../domain/stixCoreObject';
import { internalLoadById } from '../database/middleware';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

const fileResolvers = {
  Query: {
    file: (_, { id }, context) => loadFile(context, context.user, id),
    importFiles: (_, { first }, context) => filesListing(context, context.user, first, 'import/global/'),
    pendingFiles: (_, { first }, context) => filesListing(context, context.user, first, 'import/pending/'),
  },
  File: {
    works: (file, _, context) => worksForSource(context, context.user, file.id),
    metaData: (file, _, context) => {
      if (file.metaData.entity_id) {
        return { ...file.metaData, entity: internalLoadById(context, context.user, file.metaData.entity_id, { type: ABSTRACT_STIX_DOMAIN_OBJECT }) };
      }
      return file.metaData;
    },
  },
  Upload: GraphQLUpload, // Maps the `Upload` scalar to the implementation provided by the `graphql-upload` package.
  Mutation: {
    uploadImport: (_, { file }, context) => uploadImport(context, context.user, file),
    uploadPending: (_, { file, entityId }, context) => uploadPending(context, context.user, file, entityId),
    deleteImport: (_, { fileName }, context) => {
      // Imported file must be handle specifically
      // File deletion must publish a specific event
      // and update the updated_at field of the source entity
      if (fileName.startsWith('import') && !fileName.includes('global') && !fileName.includes('pending')) {
        return stixCoreObjectImportDelete(context, context.user, fileName);
      }
      // If not, a simple deletion is enough
      return deleteFile(context, context.user, fileName);
    },
    askJobImport: (_, args, context) => askJobImport(context, context.user, args),
  },
};

export default fileResolvers;
