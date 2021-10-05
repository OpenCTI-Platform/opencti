import { deleteFile, filesListing } from '../database/minio';
import { askJobImport, uploadImport } from '../domain/file';
import { worksForSource } from '../domain/work';
import { stixCoreObjectImportDelete } from '../domain/stixCoreObject';

const fileResolvers = {
  Query: {
    importFiles: (entity, { first }, { user }) => filesListing(user, first, 'import/global/'),
  },
  File: {
    works: (file, _, { user }) => worksForSource(user, file.id),
  },
  Mutation: {
    uploadImport: (_, { file }, { user }) => uploadImport(user, file),
    deleteImport: (_, { fileName }, { user }) => {
      // Imported file must be handle specifically
      // File deletion must publish a specific event
      // and update the updated_at field of the source entity
      if (fileName.startsWith('import')) {
        return stixCoreObjectImportDelete(user, fileName);
      }
      // If not, a simple deletion is enough
      return deleteFile(user, fileName);
    },
    askJobImport: (_, args, { user }) => askJobImport(user, args),
  },
};

export default fileResolvers;
