import { GraphQLUpload } from 'graphql-upload';
import { deleteFile, filesListing, loadFile } from '../database/file-storage';
import { askJobImport, uploadImport, uploadPending } from '../domain/file';
import { worksForSource } from '../domain/work';
import { stixCoreObjectImportDelete } from '../domain/stixCoreObject';
import { internalLoadById } from '../database/middleware';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

const fileResolvers = {
  Query: {
    file: (_, { id }, { user }) => loadFile(user, id),
    importFiles: (_, { first }, { user }) => filesListing(user, first, 'import/global/'),
    pendingFiles: (_, { first }, { user }) => filesListing(user, first, 'import/pending/'),
  },
  File: {
    works: (file, _, { user }) => worksForSource(user, file.id),
    metaData: (file, _, { user }) => {
      if (file.metaData.entity_id) {
        return { ...file.metaData, entity: internalLoadById(user, file.metaData.entity_id, { type: ABSTRACT_STIX_DOMAIN_OBJECT }) };
      }
      return file.metaData;
    },
  },
  Upload: GraphQLUpload, // Maps the `Upload` scalar to the implementation provided by the `graphql-upload` package.
  Mutation: {
    uploadImport: (_, { file }, { user }) => uploadImport(user, file),
    uploadPending: (_, { file, entityId }, { user }) => uploadPending(user, file, entityId),
    deleteImport: (_, { fileName }, { user }) => {
      // Imported file must be handle specifically
      // File deletion must publish a specific event
      // and update the updated_at field of the source entity
      if (fileName.startsWith('import') && !fileName.includes('global') && !fileName.includes('pending')) {
        return stixCoreObjectImportDelete(user, fileName);
      }
      // If not, a simple deletion is enough
      return deleteFile(user, fileName);
    },
    askJobImport: (_, args, { user }) => askJobImport(user, args),
  },
};

export default fileResolvers;
